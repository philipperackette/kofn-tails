# kofn-tails — k-of-n secret sharing on Tails

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## English

Standalone HTML procedure for implementing **k-of-n secret sharing** (Shamir scheme) on **Tails OS**, with **PGP signature verification** material.

### Context

This repository is the technical companion to the book **[Quorum Cryptography on Tails OS](https://www.amazon.fr/dp/B0GLGC8GWP)** by Philippe Rackette.

Its goal is to provide a practical, offline-friendly procedure for splitting a secret into *n* shares such that any *k* shares can reconstruct it.

### Repository contents

| File | Role |
|---|---|
| `procedure_kofn_tails_v1.html` | Main standalone procedure |
| `procedure_kofn_tails_v1.html.sig` | PGP signature for integrity verification |
| `philipperackette-pgp-public.asc` | Public key used to verify the signature |

### Integrity verification

```bash
gpg --import philipperackette-pgp-public.asc
gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
```

### Intended audience

- readers of the book,
- users interested in threshold cryptography on Tails,
- technically careful users working offline.

---

## Français

Procédure HTML autonome pour mettre en place un **partage de secret k-sur-n** (schéma de Shamir) sur **Tails OS**, avec matériel de **vérification PGP**.

### Contexte

Ce dépôt accompagne techniquement le livre **[Quorum Cryptography on Tails OS](https://www.amazon.fr/dp/B0GLGC8GWP)** de Philippe Rackette.

L'objectif est de fournir une procédure pratique, utilisable hors ligne, pour découper un secret en *n* parts, dont *k* suffisent pour le reconstituer.

### Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `procedure_kofn_tails_v1.html` | Procédure principale autonome |
| `procedure_kofn_tails_v1.html.sig` | Signature PGP de vérification d'intégrité |
| `philipperackette-pgp-public.asc` | Clé publique de vérification |

### Vérification d'intégrité

```bash
gpg --import philipperackette-pgp-public.asc
gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
```

### Public visé

- lecteurs du livre,
- utilisateurs intéressés par la cryptographie à seuil sur Tails,
- utilisateurs techniquement rigoureux travaillant hors ligne.

---

## Licence / License

Ce projet est distribué sous licence [MIT](LICENSE).  
This project is distributed under the [MIT License](LICENSE).
