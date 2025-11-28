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
