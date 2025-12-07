# Solution en code source ouvert de partage de secret (Shamir) sur Tails

Ce dépôt contient une solution de partage de secret **k-sur-n** (schéma de Shamir) fonctionnant sous **Tails**, avec :

- Une **procédure HTML autonome** sous Tails pour organiser une cérémonie de partage de secret (génération, protection et distribution d’un secret maître : RSA 4096, Ed25519, AES-GCM).
- Un **document LaTeX/PDF** expliquant les fondements mathématiques du protocole (corps finis, Shamir, HKDF, PBKDF2, Ed25519, RSA-OAEP, AES-GCM).
- Des **scripts** dans `Scripts/` pour automatiser certaines étapes.
- La **clé PGP publique** utilisée pour signer la procédure.

**Exemple d’application concrète :**
> Il faut **3 personnes de confiance parmi 5** pour pouvoir accéder à un téléphone protégé par un code à six chiffres.

---

## 🧭 Philosophie du projet *kofn-tails*

*kofn-tails* repose sur une idée directrice :

> Les techniques cryptographiques sérieuses — partage de secrets k-sur-n, cérémonies de clés, durcissement hors ligne — ne doivent pas être réservées aux grandes organisations dotées d’HSM, de PKI et d’équipes spécialisées.

Le projet offre une méthode libre, reproductible et transparente pour réaliser une cérémonie sécurisée sous Tails, avec des moyens modestes, en gardant l’utilisateur au centre :

- environnement **hors ligne**,
- scripts simples et auditables,
- justification mathématique rigoureuse,
- absence de dépendance à une plateforme ou un cloud propriétaire.

### 🇫🇷 Une démarche francophone, scientifique et souveraine

Le projet *kofn-tails* est né dans un contexte francophone et repose sur une culture scientifique exigeante.  
Il est développé par un **professeur de mathématiques agrégé**, **ingénieur diplômé de l’ISAE-Supaero**, dans une logique de transmission, de rigueur et de souveraineté informatique.

Le dépôt s’inscrit ainsi dans une approche francophone de la sécurité informatique :  
transparence, pédagogie, auditabilité et indépendance vis-à-vis d’acteurs privés.

---

## 👥 Publics visés

*kofn-tails* a été conçu pour répondre aux besoins concrets de plusieurs catégories d’utilisateurs :

### • Journalistes, ONG, lanceurs d’alerte
Protéger une information sensible ou une clé de déchiffrement sans qu’une personne seule ne puisse compromettre l’ensemble.  
Le schéma k-sur-n permet de distribuer la responsabilité et de limiter les risques de compromission ou de pression ciblée.

### • PME, professions libérales, petites structures
Sécuriser une clé serveur, un accès critique ou un mot de passe maître **sans dépendre d’un cloud, d’un HSM ou d’un prestataire externe**.  
Le mécanisme k-sur-n protège à la fois contre les pertes accidentelles et contre certains abus internes.

### • Enseignants, étudiants, formations techniques
C’est l’un des axes majeurs du projet.  
*kofn-tails* fournit :

- un **cas réel** d’application du schéma de Shamir,
- une **explication mathématique structurée** (corps finis, interpolation, sécurité informationnelle),
- des scripts courts et lisibles pouvant servir de support de TP, de TIPE, de projet de cryptographie appliquée ou de cours de cybersécurité.

L’objectif pédagogique est de rendre les concepts **manipulables, démontrables et compréhensibles**.

### • Chercheurs et passionnés de cryptographie
Le dépôt, intégralement open source, offre un matériau auditable pour tester, adapter ou comparer différents modèles de sécurité.  
La simplicité volontaire du code favorise la relecture et l’expérimentation.

### • Particuliers exigeants
Préparer un testament numérique, partager un accès critique, protéger des sauvegardes ou des coffres familiaux :  
*kofn-tails* permet de répartir la confiance sans exposer ses données brutes à un tiers.

---

## 🔐 Principes : accessibilité, rigueur, autonomie

### 1. Auditabilité complète

Les fichiers clés du dépôt sont :

- `procedure_kofn_tails_v1.html`
- `procedure_kofn_tails_v1.html.sig`
- `maths_kofn_tails.tex`
- `maths_kofn_tails.pdf`
- `philipperackette-pgp-public.asc`
- le répertoire `Scripts/` (scripts shell / Python associés)

### 2. Fonctionnement hors ligne (Tails)

La procédure est pensée pour tourner sous **Tails**, en session éphémère et non persistante, sans réseau.  
Ce contexte réduit fortement la surface d’attaque pendant la cérémonie.

### 3. Autonomie

Aucune plateforme externe, aucun compte, aucun cloud :  
seulement des briques libres et standard (Tails, GnuPG, primitives classiques).

---

## 📂 Contenu du dépôt

- `procedure_kofn_tails_v1.html`  
- `procedure_kofn_tails_v1.html.sig`  
- `philipperackette-pgp-public.asc`  
- `maths_kofn_tails.tex`  
- `maths_kofn_tails.pdf`  
- `Scripts/`

---

## 🚀 Utilisation (vue d’ensemble)

1. Démarrer Tails hors ligne.  
2. Copier dans la session Tails au minimum :
   - `procedure_kofn_tails_v1.html`
   - `procedure_kofn_tails_v1.html.sig`
   - `philipperackette-pgp-public.asc`
3. Importer la clé PGP :

   ```bash
   gpg --import philipperackette-pgp-public.asc
   ```

4. Vérifier la signature de la procédure :

   ```bash
   gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
   ```

5. Ouvrir `procedure_kofn_tails_v1.html` dans le navigateur de Tails (toujours hors ligne) et suivre les étapes décrites pour :
   - générer le secret maître,
   - le partager en n parts (schéma k-sur-n),
   - répartir physiquement les parts,
   - documenter la politique de recombinaison.

---

## 🎯 Publics cibles (résumé)

- PME / équipes sécurité  
- Enseignants, agrégatifs, étudiants (CPGE, TIPE, université, écoles d’ingénieurs)  
- Communauté crypto / sécurité pour audit et améliorations  
- Journalistes, ONG, lanceurs d’alerte  
- Particuliers soucieux de protéger des secrets à forte valeur

---

## 🤝 Contributions

Les contributions sont les bienvenues, en particulier :

- améliorations pédagogiques (exemples, exercices, commentaires),
- relectures mathématiques,
- audits cryptographiques,
- retours d’expérience concrets (cérémonies organisées, usages pédagogiques).

Les propositions doivent respecter la philosophie du projet :  
**simplicité, rigueur, autonomie, transparence.**
