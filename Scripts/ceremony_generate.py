#!/usr/bin/env python3
"""
ceremony_generate.py
Génère le secret maître S, les clés, et les parts Shamir.
"""
import os
import json
import base64
import getpass
import secrets
import shutil
from typing import List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import qrcode
from PIL import Image

PBKDF2_ITERATIONS = 501_000
SALT_SIZE = 16
NONCE_SIZE = 12
WRAP_SALT_SIZE = 16
KEY_SIZE = 32
MIN_PASSPHRASE_LEN = 20
P = 2**521 - 1

UTILITY_FILES = ["rsa_hybrid_encrypt.py", "verify_ed25519.py"]

def verify_tails_environment():
    """Vérifie sommairement que nous sommes dans un environnement Tails live."""
    user = os.environ.get("USER", "")
    if user != "amnesia":
        print("[AVERTISSEMENT] Utilisateur non standard (USER=%r). Cette procédure est prévue pour Tails." % user)
    # Indice simple de mode live Tails
    if not os.path.exists("/lib/live/mount/rootfs/filesystem.squashfs"):
        print("[AVERTISSEMENT] Le système ne ressemble pas à un Tails live. Vérifiez l'environnement avant de continuer.")

def clean_path(p):
    p = p.strip()
    if (p.startswith("'") and p.endswith("'")) or (p.startswith('"') and p.endswith('"')):
        p = p[1:-1]
    return p.strip()

def shamir_split(S: int, k: int, n: int) -> List[Tuple[int, int]]:
    """Retourne une liste de parts (x, y) pour le secret S."""
    coeffs = [S] + [secrets.randbelow(P) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        xx = 1
        for c in coeffs:
            y = (y + c * xx) % P
            xx = (xx * x) % P
        shares.append((x, y))
    return shares

def shamir_reconstruct(shares: List[Tuple[int, int]]) -> bytearray:
    """Reconstruction de S (retour en bytearray pour effacement mémoire)."""
    s = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, ym) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm)) % P
            den = (den * (xj - xm)) % P
        s = (s + yj * (num * pow(den, -1, P))) % P
    return bytearray(s.to_bytes(32, "big"))

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), KEY_SIZE, salt, PBKDF2_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))

def encrypt_share_payload(share_dict: dict, password: str) -> str:
    plaintext = json.dumps(share_dict, separators=(",", ":")).encode("utf-8")
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_password(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    envelope = {
        "v": 1, "alg": "AESGCM+PBKDF2", "k": share_dict["k"], "n": share_dict["n"],
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "pub_hash": share_dict.get("pub_hash")
    }
    return base64.urlsafe_b64encode(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

def make_qr_triple_image(data: str, out_path: str):
    """
    Génère une image PNG contenant 3 exemplaires identiques du QR code,
    empilés verticalement (pratique pour impression et découpe).
    """
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    single = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    w, h = single.size
    combo = Image.new("RGB", (w, h * 3), "white")
    combo.paste(single, (0, 0))
    combo.paste(single, (0, h))
    combo.paste(single, (0, 2 * h))
    combo.save(out_path)

def secure_wipe(b: bytearray):
    for i in range(len(b)):
        b[i] = 0

def main():
    verify_tails_environment()
    print("=== Cérémonie k-sur-n (NO-GUI) ===\n")

    # 1. Configuration k, n
    while True:
        try:
            n = int(input("Nombre total de personnes (n) : ").strip())
            k = int(input("Seuil (k, nombre minimal de parts pour recomposer le secret) : ").strip())
            if 1 < k <= n:
                break
            else:
                print("k doit être > 1 et <= n.")
        except ValueError:
            print("Veuillez entrer des entiers valides.")
    print(f"\n[INFO] Schéma {k}-sur-{n} sélectionné.")

    # 2. Génération du secret maître S
    S_int = int.from_bytes(os.urandom(32), "big")
    S = bytearray(S_int.to_bytes(32, "big"))
    print("[INFO] Secret maître S généré (256 bits).")

    # 3. Dérivation Ed25519 + wrap RSA
    print("\n[ETAPE] Génération et dérivation des clés...")
    hkdf_ed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ed25519-salt",
        info=b"ed25519-master-key"
    )
    ed_seed = bytearray(hkdf_ed.derive(S))
    ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(ed_seed))
    ed_pub = ed_priv.public_key()
    pub_raw = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_pem = ed_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("master_public_ed25519.pem", "wb") as f:
        f.write(pub_pem)
    print("[OK] Clé publique Ed25519 écrite dans master_public_ed25519.pem.")

    # RSA
    print("[ETAPE] Génération de la clé RSA 4096 bits (cela peut prendre un peu de temps)...")
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    rsa_pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    rsa_pub = rsa_priv.public_key()
    rsa_pub_pem = rsa_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("master_public_rsa_4096.pem", "wb") as f:
        f.write(rsa_pub_pem)
    print("[OK] Clé publique RSA écrite dans master_public_rsa_4096.pem.")

    # Wrap RSA private key avec clé dérivée de S
    wrap_salt = os.urandom(WRAP_SALT_SIZE)
    hkdf_wrap = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=wrap_salt,
        info=b"rsa-wrap-key"
    )
    wrap_key = hkdf_wrap.derive(S)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(wrap_key)
    ct = aesgcm.encrypt(nonce, rsa_pem, None)
    rsa_wrapped = {
        "v": 1,
        "alg": "AESGCM+HKDF",
        "salt": base64.b64encode(wrap_salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    with open("rsa_wrapped.json", "w") as f:
        json.dump(rsa_wrapped, f, separators=(",", ":"))
    print("[OK] Clé RSA privée protégée dans rsa_wrapped.json.")

    # 4. Hash de la clé publique Ed25519 pour rattacher les parts
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_raw)
    pub_hash = base64.b16encode(digest.finalize()).decode("ascii")

    # 5. Shamir
    print("\n[ETAPE] Génération des parts Shamir...")
    shares = shamir_split(S_int, k, n)
    print(f"[OK] {len(shares)} parts générées.")

    # 6. Collecte des noms & phrases de passe
    participants = []
    for i in range(1, n + 1):
        print(f"\n--- Participant {i}/{n} ---")
        name = input("Nom (ou identifiant) : ").strip() or f"Participant_{i}"
        while True:
            pw = getpass.getpass(f"Phrase de passe pour {name} (>= {MIN_PASSPHRASE_LEN} caractères) : ")
            if len(pw) < MIN_PASSPHRASE_LEN:
                print(f"Minimum {MIN_PASSPHRASE_LEN} caractères.")
                continue
            pw2 = getpass.getpass("Confirmer la phrase de passe : ")
            if pw != pw2:
                print("Les deux entrées ne correspondent pas.")
                continue
            break
        participants.append((name, pw))

    # 7. Dossiers Personnels / Public / Utilitaire
    root = os.path.abspath("Coffre_kofn")
    os.makedirs(root, exist_ok=True)
    for (idx, ((name, pw), (x, y))) in enumerate(zip(participants, shares), start=1):
        person_dir = os.path.join(root, f"{idx:02d}_{name.replace(' ', '_')}")
        os.makedirs(person_dir, exist_ok=True)
        pers = os.path.join(person_dir, "Personnel")
        publ = os.path.join(person_dir, "Publique")
        util = os.path.join(person_dir, "Utilitaire")
        os.makedirs(pers, exist_ok=True)
        os.makedirs(publ, exist_ok=True)
        os.makedirs(util, exist_ok=True)

        share_dict = {
            "k": k,
            "n": n,
            "x": x,
            "y": format(y, "x"),
            "pub_hash": pub_hash,
            "holder": name,
        }
        enc = encrypt_share_payload(share_dict, pw)
        txt_path = os.path.join(pers, "part_chiffree.txt")
        with open(txt_path, "w") as f:
            f.write(enc)
        qr_path = os.path.join(pers, "part_qr_triple.png")
        make_qr_triple_image(enc, qr_path)

        shutil.copy("rsa_wrapped.json", pers)

        # Copie clés publiques
        shutil.copy("master_public_ed25519.pem", publ)
        shutil.copy("master_public_rsa_4096.pem", publ)

        # Copie utilitaires
        for uf in UTILITY_FILES:
            if os.path.exists(uf):
                shutil.copy(uf, os.path.join(util, uf))

        print(f"[OK] Part pour {name} enregistrée dans {person_dir}")

    secure_wipe(S)
    for i in range(len(ed_seed)):
        ed_seed[i] = 0
    print("\n[OK] Cérémonie terminée avec succès.")

if __name__ == "__main__":
    main()
