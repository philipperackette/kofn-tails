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
