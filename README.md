# Solution en code source ouvert de partage de secret (Shamir) sur Tails

Ce dépôt contient une solution de partage de secret **k-sur-n** (schéma de Shamir) fonctionnant sous **Tails**, avec :

- une **procédure HTML autonome** sous Tails pour organiser une cérémonie de partage de secret (génération, protection et distribution d’un secret maître : RSA 4096, Ed25519, AES-GCM) ;
- un **document LaTeX/PDF** expliquant les fondements mathématiques du protocole (corps finis, Shamir, HKDF, PBKDF2, Ed25519, RSA-OAEP, AES-GCM) ;
- des **scripts** dans [`Scripts/`](Scripts/) pour automatiser certaines étapes ;
- la **clé PGP publique** utilisée pour signer la procédure.

**Exemple d’application concrète :**

> Il faut **3 personnes de confiance parmi 5** pour pouvoir accéder à un téléphone protégé par un code à six chiffres.

Version actuelle de la procédure : **v1** (`procedure_kofn_tails_v1.html`).  

---

## 🧭 Philosophie du projet *kofn-tails*

*kofn-tails* repose sur une idée directrice :

> Les techniques cryptographiques sérieuses — partage de secrets k-sur-n, cérémonies de clés, durcissement hors ligne — ne doivent pas être réservées aux grandes organisations dotées d’HSM, de PKI et d’équipes spécialisées.

Le projet propose une méthode **libre**, **reproductible** et **transparente** pour organiser une cérémonie sécurisée sous Tails, avec des moyens modestes, en gardant l’utilisateur au centre :

- environnement **strictement hors ligne** pendant la cérémonie ;
- scripts **simples et auditables** ;
- justification **mathématique rigoureuse** documentée dans le PDF ;
- **aucune dépendance** à une plateforme ou un cloud propriétaire.

### 🇫🇷 Une démarche francophone, scientifique et souveraine

Le projet *kofn-tails* est né dans un contexte francophone et s’inscrit dans une culture scientifique exigeante.  
Il est développé par un **professeur de mathématiques agrégé**, **ingénieur diplômé de l’ISAE-Supaero**, dans une logique de transmission, de rigueur et de souveraineté informatique.

Le dépôt reflète une approche francophone de la sécurité informatique :  
**transparence, pédagogie, auditabilité, indépendance** vis-à-vis d’acteurs privés.

Pour aller plus loin dans cette culture de la sécurité et du libre, on pourra par exemple consulter :
- les ressources de l’ANSSI sur les bonnes pratiques de sécurité numérique ;
- les contenus de l’APRIL autour du logiciel libre et de la souveraineté numérique.

---

## 👥 Publics visés

*kofn-tails* a été conçu pour répondre aux besoins concrets de plusieurs catégories d’utilisateurs.

### • Journalistes, ONG, lanceurs d’alerte

Protéger une information sensible ou une clé de déchiffrement sans qu’une personne seule ne puisse compromettre l’ensemble.  
Le schéma k-sur-n permet de **distribuer la responsabilité** et de limiter les risques de compromission ou de pression ciblée.

### • PME, professions libérales, petites structures

Sécuriser une clé serveur, un accès critique ou un mot de passe maître **sans dépendre d’un cloud, d’un HSM ou d’un prestataire externe**.  
Le mécanisme k-sur-n protège à la fois contre les **pertes accidentelles** et contre certains **abus internes**.

### • Enseignants, étudiants, formations techniques (après-bac)

*kofn-tails* a été pensé pour un usage direct dans l’enseignement supérieur et les formations post‑bac :  
CPGE scientifiques, BTS/BUT, IUT, licences, masters, écoles d’ingénieurs.

Il fournit :

- un **cas réel et complet** d’application du schéma de Shamir (partage de secret k-sur-n) facilement transposable en TD, TP ou projet ;
- une **présentation mathématique structurée** (corps finis, polynômes, interpolation, sécurité informationnelle) en cohérence avec les attendus des enseignements de mathématiques et d’informatique au niveau post‑bac ;
- des **scripts courts, commentés et auditables** pouvant servir de support de TP, de TIPE, de projets de cryptographie appliquée, de modules de cybersécurité ou de projets de fin d’études.

L’objectif pédagogique est de proposer un exemple où la cryptographie n’est pas seulement « vue en théorie », mais devient :

- **manipulable par les étudiants** (scripts, expérimentations, variantes) ;
- **démontrable au tableau** (mathématiques des corps finis, interpolation, arguments de sécurité informationnelle) ;
- **réutilisable** dans des évaluations, projets longs, TIPE ou mémoires.

### • Chercheurs et passionnés de cryptographie

Le dépôt, intégralement open source, offre un matériau **auditable** pour tester, adapter ou comparer différents modèles de sécurité.  
La **simplicité volontaire** du code favorise la relecture, l’expérimentation et les forks (tests de variantes de schémas, de paramètres, de primitives, etc.).

### • Particuliers exigeants

Préparer un **testament numérique**, partager un accès critique, protéger des sauvegardes ou des coffres familiaux :  
*kofn-tails* permet de **répartir la confiance** sans exposer ses données brutes à un tiers et sans confier ses secrets à un service en ligne opaque.

---

## 🔧 Pré-requis

Pour utiliser ce dépôt dans de bonnes conditions, il est recommandé de maîtriser au moins :

- les concepts de base de la **ligne de commande** (copie de fichiers, exécution de scripts) ;
- les notions élémentaires de **cryptographie symétrique / asymétrique** (clé publique / clé privée, chiffrement, signature) ;
- pour l’exploitation pédagogique : un niveau de **mathématiques** au moins équivalent à un premier cycle universitaire (polynômes, interpolation, arithmétique modulaire).

Sur le plan technique :

- système : **Tails** (session éphémère, hors ligne) ;
- outils : **GnuPG** (présent par défaut dans Tails), navigateur intégré à Tails.

---

## 🔐 Principes : accessibilité, rigueur, autonomie

### 1. Auditabilité complète

Les fichiers du dépôt sont :

- [`procedure_kofn_tails_v1.html`](procedure_kofn_tails_v1.html)  
  *Procédure HTML principale pour conduire la cérémonie, à ouvrir localement sous Tails (hors ligne).*  
- [`procedure_kofn_tails_v1.html.sig`](procedure_kofn_tails_v1.html.sig)  
  *Signature PGP de la procédure HTML, pour vérifier l’intégrité et l’authenticité du fichier.*  
- [`maths_kofn_tails.tex`](maths_kofn_tails.tex)  
  *Source LaTeX du document mathématique, pour audit, adaptation ou traduction.*  
- [`maths_kofn_tails.pdf`](maths_kofn_tails.pdf)  
  *Version PDF prête à lire, décrivant les fondements mathématiques et les choix cryptographiques.*  
- [`philipperackette-pgp-public.asc`](philipperackette-pgp-public.asc)  
  *Clé PGP publique utilisée pour signer la procédure.*  
- [`Scripts/`](Scripts/)  
  *Scripts shell / Python associés.*

L’objectif est que **tout soit vérifiable** : depuis les scripts jusqu’au texte mathématique.

### 2. Fonctionnement hors ligne (Tails)

La procédure est pensée pour tourner sous **Tails**, en session éphémère et non persistante, **sans réseau**.  

Ce contexte réduit fortement la surface d’attaque pendant la cérémonie (pas de fuite accidentelle via le réseau, pas de dépendance à un service distant, pas de stockage durable non contrôlé).

### 3. Autonomie

Aucune plateforme externe, aucun compte, aucun cloud :  

> seulement des briques libres et standard (Tails, GnuPG, primitives classiques).

L’utilisateur conserve la **maîtrise complète** de son environnement et de ses secrets.

---

## 🚀 Utilisation (vue d’ensemble)

1. **Démarrer Tails hors ligne.**  

2. **Copier dans la session Tails au minimum :**
   - [`procedure_kofn_tails_v1.html`](procedure_kofn_tails_v1.html)  
   - [`procedure_kofn_tails_v1.html.sig`](procedure_kofn_tails_v1.html.sig)  
   - [`philipperackette-pgp-public.asc`](philipperackette-pgp-public.asc)  

3. **Importer la clé PGP :**

   ```bash
   gpg --import philipperackette-pgp-public.asc
   ```

4. **Vérifier la signature de la procédure :**

   ```bash
   gpg --verify procedure_kofn_tails_v1.html.sig procedure_kofn_tails_v1.html
   ```

   Si la signature est valide et que l’empreinte de la clé correspond à celle attendue, vous pouvez poursuivre.

5. **Ouvrir la procédure HTML sous Tails (hors ligne) :**

   - Ouvrir `procedure_kofn_tails_v1.html` dans le navigateur de Tails.  
   - Suivre les étapes décrites pour :
     - générer le secret maître ;
     - le partager en *n* parts (schéma k-sur-n) ;
     - répartir physiquement les parts (enveloppes, coffres, personnes de confiance) ;
     - formaliser la **politique de recombinaison** (qui, combien de parts, dans quelles conditions).



---

## ⚠️ Limites et avertissement

*kofn-tails* est conçu avec sérieux et rigueur, mais :

- il est avant tout un **projet pédagogique et d’outillage libre** ;
- il ne prétend pas couvrir **tous les modèles de menace possibles**, ni remplacer un audit complet pour des systèmes étatiques ou des infrastructures critiques ;
- pour tout usage **à très forte criticité** (infrastructures vitales, secrets étatiques, etc.), il est recommandé de solliciter un **audit par des équipes spécialisées**.

En revanche, pour des besoins **d’enseignement**, de **sensibilisation**, de **projets étudiants** ou de **sécurisation raisonnable** de secrets sensibles, il fournit une base claire, lisible et auditée.

---

## 🤝 Contributions

Les contributions sont les bienvenues, en particulier :

- **améliorations pédagogiques** (exemples, exercices, variantes de protocoles, commentaires dans les scripts) ;
- **relectures mathématiques** du document LaTeX et propositions d’extensions ;
- **audits cryptographiques**, remarques sur les choix de paramètres ou les implémentations ;
- **retours d’expérience concrets** (cérémonies organisées, usages en cours, en TP, en projets ou en TIPE).

Merci de privilégier :

1. l’ouverture d’une **issue GitHub** pour décrire le contexte et la proposition ;
2. ensuite, le cas échéant, une **pull request** ciblée et argumentée.

Les propositions doivent respecter la philosophie du projet :  
**simplicité, rigueur, autonomie, transparence.**
