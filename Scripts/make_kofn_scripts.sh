#!/bin/sh
# make_kofn_scripts.sh
# Génère tous les scripts .py (VERSION v1)

set -e

# --- 1. GENERATEUR CEREMONIE ---
cat > ceremony_generate.py << 'EOF'
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
EOF

cat > kofn_sign.py << 'EOF'
#!/usr/bin/env python3
"""
kofn_sign.py (No-GUI + Memory Fix)
Signe un FICHIER unique ou tous les fichiers d'un DOSSIER.
"""
import os, json, base64, getpass, time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = 2**521 - 1

def verify_tails_environment():
    """Vérifie sommairement que nous sommes dans un environnement Tails live."""
    user = os.environ.get("USER", "")
    if user != "amnesia":
        print("[AVERTISSEMENT] Utilisateur non standard (USER=%r). Cette procédure est prévue pour Tails." % user)
    if not os.path.exists("/lib/live/mount/rootfs/filesystem.squashfs"):
        print("[AVERTISSEMENT] Le système ne ressemble pas à un Tails live. Vérifiez l'environnement avant de continuer.")

def clean_path(p):
    """Nettoie les guillemets et espaces du glisser-déposer."""
    p = p.strip()
    if (p.startswith("'") and p.endswith("'")) or (p.startswith('"') and p.endswith('"')):
        p = p[1:-1]
    return p.strip()

def derive_key(pw, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 501000).derive(pw.encode())

def decrypt_share(enc, pw):
    env = json.loads(base64.urlsafe_b64decode(enc))
    key = derive_key(pw, base64.b64decode(env["salt"]))
    pt = AESGCM(key).decrypt(base64.b64decode(env["nonce"]), base64.b64decode(env["ct"]), None)
    return json.loads(pt)

def shamir_reconstruct(shares):
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

def main():
    verify_tails_environment()
    print("=== Signature Ed25519 (Fichier ou Dossier) ===\n")

    # 1. Collecte des parts
    shares = []
    k, n, pub_hash = None, None, None

    while True:
        if k is None:
            print("--- Entrez la première part ---")
        elif len(shares) < k:
            print(f"--- Entrez la part suivante ({len(shares)}/{k}) ---")
        else:
            break

        enc = input("Part chiffrée (texte/QR) : ").strip()
        if not enc:
            continue
        pw = getpass.getpass("Phrase de passe : ")

        try:
            sh = decrypt_share(enc, pw)
            if k is None:
                k, n, pub_hash = sh["k"], sh["n"], sh.get("pub_hash")
                print(f"[INFO] Schéma {k}-sur-{n} détecté.")

            # Vérifs
            if sh["k"] != k or sh["n"] != n:
                print("Part incohérente (k/n).")
                continue
            if pub_hash and sh.get("pub_hash") != pub_hash:
                print("Part incohérente (Master différent).")
                continue

            shares.append((sh["x"], int(sh["y"], 16)))
        except Exception:
            print("[ERREUR] Déchiffrement de part impossible (phrase de passe ou part invalide).")
            time.sleep(1)

    print("\n[INFO] Reconstruction du secret...")
    S = shamir_reconstruct(shares)

    # Dérivation Clés (FIX: bytearray pour permettre le wipe)
    hkdf_ed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ed25519-salt",
        info=b"ed25519-master-key"
    )
    ed_seed = bytearray(hkdf_ed.derive(S))
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(ed_seed))
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with open("master_public_ed25519.pem", "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[OK] Clé publique Ed25519 régénérée dans master_public_ed25519.pem (pour vérification).")

    # Choix Fichier/Dossier
    target = clean_path(input("\nGlissez un FICHIER ou un DOSSIER à signer : "))
    if not os.path.exists(target):
        print("Chemin invalide.")
        for i in range(len(S)): S[i] = 0
        for i in range(len(ed_seed)): ed_seed[i] = 0
        return

    # Construction du contexte
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_raw)
    ctx_prefix = b"kofn-ed25519-v1" + digest.finalize()

    def sign_data(data: bytes) -> bytes:
        ctx = ctx_prefix + data
        return priv.sign(ctx)

    def sign_file(path: str):
        with open(path, "rb") as f:
            data = f.read()
        sig = sign_data(data)
        sig_path = path + ".sig"
        with open(sig_path, "wb") as f:
            f.write(base64.b64encode(sig))
        print(f"[OK] Fichier signé : {path} -> {sig_path}")

    if os.path.isfile(target):
        sign_file(target)
    else:
        # Parcours du dossier
        for root, dirs, files in os.walk(target):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                sign_file(full)

    # Wipe
    for i in range(len(S)):
        S[i] = 0
    for i in range(len(ed_seed)):
        ed_seed[i] = 0
    print("\n[OK] Signature(s) terminée(s).")

if __name__ == "__main__":
    main()
EOF

cat > kofn_rsa_decrypt.py << 'EOF'
#!/usr/bin/env python3
"""
kofn_rsa_decrypt.py (No-GUI + Memory Fix + Single File)
Déchiffre UN fichier unique .hyb.b64
"""
import os, json, base64, getpass, time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def verify_tails_environment():
    """Vérifie sommairement que nous sommes dans un environnement Tails live."""
    user = os.environ.get("USER", "")
    if user != "amnesia":
        print("[AVERTISSEMENT] Utilisateur non standard (USER=%r). Cette procédure est prévue pour Tails." % user)
    # Indice simple de mode live Tails
    if not os.path.exists("/lib/live/mount/rootfs/filesystem.squashfs"):
        print("[AVERTISSEMENT] Le système ne ressemble pas à un Tails live. Vérifiez l'environnement avant de continuer.")

P = 2**521 - 1

def clean_path(p):
    p = p.strip()
    if (p.startswith("'") and p.endswith("'")) or (p.startswith('"') and p.endswith('"')):
        p = p[1:-1]
    return p.strip()

def derive_key(pw, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 501000).derive(pw.encode())

def decrypt_share(enc, pw):
    env = json.loads(base64.urlsafe_b64decode(enc))
    key = derive_key(pw, base64.b64decode(env["salt"]))
    pt = AESGCM(key).decrypt(base64.b64decode(env["nonce"]), base64.b64decode(env["ct"]), None)
    return json.loads(pt)

def shamir_reconstruct(shares) -> bytearray:
    s = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, ym) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm)) % P
            den = (den * (xj - xm)) % P
        s = (s + yj * (num * pow(den, -1, P))) % P
    # FIX: Renvoie un bytearray mutable pour permettre le wipe
    return bytearray(s.to_bytes(32, "big"))

def main():
    verify_tails_environment()
    print("=== Déchiffrement RSA k-sur-n (NO-GUI / Fichier unique) ===\n")

    # 0. RSA Wrapped
    print("Glissez le fichier rsa_wrapped.json ci-dessous :")
    rsa_path = clean_path(input("Chemin > "))
    if not os.path.isfile(rsa_path):
        print("Erreur: fichier introuvable.")
        return

    # 1. Shares
    shares = []
    k, n = None, None
    failed_attempts = 0

    while True:
        if k is None:
            print("--- Première part ---")
        elif len(shares) < k:
            print(f"--- Part suivante ({len(shares)}/{k}) ---")
        else:
            break

        enc = input("Part : ").strip()
        if not enc:
            continue
        pw = getpass.getpass("Phrase : ")
        try:
            sh = decrypt_share(enc, pw)
            if k is None:
                k, n = sh["k"], sh["n"]
            shares.append((sh["x"], int(sh["y"], 16)))
        except:
            failed_attempts += 1
            print("Erreur déchiffrement part ou phrase invalide.")
            time.sleep(min(1 * (2 ** failed_attempts), 30))

    print("[INFO] Reconstruction S...")
    S = shamir_reconstruct(shares)

    # 2. Unwrap RSA
    try:
        with open(rsa_path, "r") as f:
            w = json.load(f)
        wrap_key = HKDF(hashes.SHA256(), 32, base64.b64decode(w["salt"]), b"rsa-wrap-key").derive(S)
        rsa_pem = AESGCM(wrap_key).decrypt(base64.b64decode(w["nonce"]), base64.b64decode(w["ct"]), None)
        rsa_priv = serialization.load_pem_private_key(rsa_pem, None)
    except:
        print("[ERREUR] Echec déverrouillage RSA (S incorrect ?).")
        for i in range(len(S)):
            S[i] = 0
        return

    # 3. Target FILE (Single file)
    print("\n[ACTION] Glissez le fichier .hyb.b64 à déchiffrer :")
    f_path = clean_path(input("Fichier > "))
    if not os.path.isfile(f_path):
        print("Fichier invalide.")
        for i in range(len(S)):
            S[i] = 0
        return

    try:
        with open(f_path, "r") as f:
            blob = json.loads(base64.b64decode(f.read().strip()))
        aes_key = rsa_priv.decrypt(
            base64.b64decode(blob["ek"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        pt = AESGCM(aes_key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ct"]), None)

        out = f_path.replace(".hyb.b64", "") + ".decrypted"
        with open(out, "wb") as f:
            f.write(pt)
        print(f"[OK] Déchiffré : {os.path.basename(out)}")
    except Exception as e:
        print(f"[FAIL] Erreur déchiffrement : {e}")

    # Wipe
    for i in range(len(S)):
        S[i] = 0

if __name__ == "__main__":
    main()
EOF

cat > rsa_hybrid_encrypt.py << 'EOF'
#!/usr/bin/env python3
"""
rsa_hybrid_encrypt.py
Chiffrement hybride RSA-OAEP + AES-GCM pour UN fichier.
"""
import os, json, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def clean_path(p):
    p = p.strip()
    if (p.startswith("'") and p.endswith("'")) or (p.startswith('"') and p.endswith('"')):
        p = p[1:-1]
    return p.strip()

def main():
    print("=== Chiffrement Hybride RSA ===\n")
    pub_path = clean_path(input("Chemin de la clé publique RSA (ex: master_public_rsa_4096.pem) : "))
    if not os.path.isfile(pub_path):
        print("Clé publique introuvable.")
        return

    target = clean_path(input("Glissez le fichier à chiffrer : "))
    if not os.path.isfile(target):
        print("Fichier introuvable.")
        return

    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    with open(target, "rb") as f:
        pt = f.read()
    ct = aesgcm.encrypt(nonce, pt, None)

    ek = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    blob = {
        "v": 1,
        "alg": "RSA-OAEP+AESGCM",
        "ek": base64.b64encode(ek).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    out = target + ".hyb.b64"
    with open(out, "w") as f:
        f.write(
            base64.b64encode(
                json.dumps(blob, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
        )
    print(f"[OK] Fichier chiffré écrit dans {out}")

if __name__ == "__main__":
    main()
EOF

cat > verify_ed25519.py << 'EOF'
#!/usr/bin/env python3
"""
verify_ed25519.py
Vérifie une signature Ed25519 sur un fichier, en tenant compte du contexte utilisé par kofn_sign.py.
"""
import os, base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, serialization

def clean_path(p):
    p = p.strip()
    if (p.startswith("'") and p.endswith("'")) or (p.startswith('"') and p.endswith('"')):
        p = p[1:-1]
    return p.strip()

def main():
    print("=== Vérification de Signature Ed25519 ===\n")
    pub_path = clean_path(input("Chemin de la clé publique (master_public_ed25519.pem) : "))
    if not os.path.isfile(pub_path):
        print("Fichier clé publique introuvable.")
        return

    file_path = clean_path(input("Glissez le FICHIER dont on veut vérifier la signature : "))
    if not os.path.isfile(file_path):
        print("Fichier introuvable.")
        return

    sig_path = clean_path(input("Glissez le fichier de signature (.sig) : "))
    if not os.path.isfile(sig_path):
        print("Fichier signature introuvable.")
        return

    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        print("Clé publique fournie n'est pas une Ed25519.")
        return

    with open(file_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        sig = base64.b64decode(f.read().strip())

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_raw)
    ctx = b"kofn-ed25519-v1" + digest.finalize() + data

    try:
        pub.verify(sig, ctx)
        print("\n[SUCCES] La signature est VALIDE.")
    except Exception:
        print("\n[ECHEC] Signature INVALIDE.")

if __name__ == "__main__":
    main()
EOF

chmod +x ceremony_generate.py kofn_sign.py kofn_rsa_decrypt.py rsa_hybrid_encrypt.py verify_ed25519.py

echo "Tous les scripts (No-GUI + Fix Mémoire) ont été générés dans $(pwd)."
