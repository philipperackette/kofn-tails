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
