# kofn-tails

Ce dépôt contient une procédure autonome (HTML) pour mettre en place un partage de secret **k-sur-n (Shamir)** sur **Tails**, ainsi que les fichiers nécessaires pour vérifier son intégrité.

## Contenu

- `procedure_kofn_tails_v1.html` : la procédure (document principal).
- `procedure_kofn_tails_v1.html.sig` : signature PGP du fichier HTML.
- `philipperackette-pgp-public.asc` : clé publique PGP utilisée pour la vérification.

## Vérification (GPG)

Importer la clé publique :

```bash
gpg --import philipperackette-pgp-public.asc
```

Vérifier la signature :

```bash
gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
```

Si la signature est valide, GPG l’indique explicitement.
