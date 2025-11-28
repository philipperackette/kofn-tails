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
