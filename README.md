# kofn-tails — Partage de secret k-sur-n sur Tails

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Procédure HTML autonome pour mettre en place un **partage de secret k-sur-n** (schéma de Shamir) sur **Tails OS**, avec vérification par signature PGP.

---

## Contexte

Ce dépôt est le compagnon technique du livre **[Quorum Cryptography on Tails OS](https://www.amazon.fr/dp/B0GLGC8GWP)** de Philippe Rackette. Il fournit une procédure clé-en-main utilisable hors ligne dans un environnement Tails, sans dépendance externe.

Le principe : un secret (par exemple une phrase de passe, une clé privée) est découpé en *n* parts, dont *k* suffisent pour le reconstituer. Aucune part individuelle ne révèle d'information sur le secret.

---

## Cas d'usage

- **Héritage numérique** : distribuer des parts à des proches de confiance.
- **Sécurité organisationnelle** : protéger une clé maîtresse avec un quorum de détenteurs.
- **Exercice pédagogique** : illustrer concrètement le schéma de Shamir.

---

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `procedure_kofn_tails_v1.html` | Procédure principale (document HTML autonome) |
| `procedure_kofn_tails_v1.html.sig` | Signature PGP du fichier HTML |
| `philipperackette-pgp-public.asc` | Clé publique PGP pour vérification |

---

## Vérification d'intégrité (GPG)

Avant d'utiliser la procédure, vérifiez que le fichier n'a pas été altéré :

```bash
# Importer la clé publique
gpg --import philipperackette-pgp-public.asc

# Vérifier la signature
gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
```

Si la signature est valide, GPG l'indique explicitement.

---

## Utilisation

1. Démarrer sur **Tails OS** (recommandé pour l'isolation réseau et l'amnésie).
2. Copier `procedure_kofn_tails_v1.html` sur le système (clé USB, stockage persistant).
3. Ouvrir le fichier dans le navigateur Tor de Tails.
4. Suivre les étapes de la procédure pour découper ou reconstituer un secret.

> **Avertissement** : cette procédure est un outil pédagogique et expérimental. Pour un usage à enjeux élevés, faites-la auditer par un professionnel de la sécurité.

---

## Lien avec le livre

La procédure est décrite en détail dans *Quorum Cryptography on Tails OS*, qui couvre la théorie (corps finis, polynômes de Lagrange) et les aspects pratiques (environnement Tails, gestion des parts, menaces). Le dépôt fournit le code ; le livre fournit le raisonnement.

---

## Licence

Ce projet est distribué sous licence [MIT](LICENSE).
