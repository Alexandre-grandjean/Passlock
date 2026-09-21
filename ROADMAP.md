# Feuille de route de Passlock

> **Ce document fait autorité.** Toute autre mention d'une phase dans le dépôt doit
> lui être conforme. Si un autre document énonce un contenu de phase différent,
> **c'est ce document qui a raison**, et l'autre doit être corrigé.
>
> Ce document répond à **quoi**, **quand**, **dans quel ordre** et **où l'on en est**.
> Il ne traite pas des risques : ceux-ci appartiennent à `SECURITY.md`, qui les
> présente **par phase** sans les redéfinir.
>
> Le périmètre d'une phase est **fermé**. Ce qui n'y figure pas est hors périmètre,
> même si cela paraît utile ou proche : une phase qui s'élargit en cours de route est
> une phase qui ne se termine pas.

## Répartition des responsabilités documentaires

| Document | Ce qu'il possède | Ce qu'il ne possède **pas** |
|---|---|---|
| **`ROADMAP.md`** *(ce document)* | le contenu des phases, leur ordre, leurs dépendances, leur état | les risques, les points d'insertion techniques |
| `SECURITY.md` | les propriétés de sécurité, les limites, les **risques introduits par phase** | le contenu ni l'ordre des phases |
| `docs/ARCHITECTURE.md` | les invariants, les décisions structurelles, les **points d'insertion** des extensions | l'état d'avancement |
| `docs/DECISIONS.md` | les ADR : pourquoi une décision a été prise | l'état d'avancement |
| `README.md` | ce que le logiciel fait **aujourd'hui**, en une page | la feuille de route détaillée |

Un seul document définit le contenu d'une phase : celui-ci. Les autres s'y réfèrent.

---

## Vue d'ensemble

| Phase | Intitulé | État |
|---|---|---|
| **0** | Documents de conception | **Terminée** |
| **1** | Moteur cryptographique et conteneur | **Terminée et gelée** |
| **2** | Modèle de données et cœur de stockage | **Terminée et gelée** |
| **3** | Générateur de secrets et TOTP | **Terminée et approuvée** |
| **4** | Pièces jointes, sauvegardes, récupération, import/export, presse-papiers | **Terminée** — 4 étapes livrées ; étape 5 (presse-papiers) **abandonnée** par le gate E.0 |
| **5** | Centre de sécurité et analyse d'URL | **Terminée et gelée** — étapes 5.1 à 5.4 livrées |
| **6** | Interface graphique | **Abandonnée** — gate E.1/E.2 |
| **7** | Durcissement, audit et livrables de release | **Non commencée** |

---

## Phase 0 — Documents de conception

**Objectif.** Décider avant d'écrire. Établir le modèle de menace, comparer les
architectures, et fixer les invariants que les phases suivantes ne remettront pas en
cause.

**Fonctionnalités incluses**

- `THREAT_MODEL.md` : actifs, adversaires (Ad1–Ad5), 32 menaces (T1–T32), chacun avec
  sa contre-mesure, son état de vérification et sa phase de livraison.
- Comparaison d'architectures et choix du format de coffre.
- `docs/CRYPTO.md` : primitives, paramètres, mesures.
- `docs/VAULT_FORMAT.md` : le conteneur, octet par octet.
- `docs/ARCHITECTURE.md` : invariants (I1–I6) et points d'insertion.
- ADR-001 à ADR-019.

**Hors périmètre**

- Tout code. Aucun artefact exécutable n'est produit par cette phase.

**Dépendances**

- Aucune.

**État**

- **Terminée.** Les documents existent et ont été révisés à chaque phase suivante
  plutôt que réécrits.

---

## Phase 1 — Moteur cryptographique et conteneur

**Objectif.** Une base cryptographique que le reste du produit ne remet jamais en
cause, et un format de fichier qui puisse survivre à des années d'évolutions.

**Fonctionnalités incluses**

- Dérivation Argon2id — **256 Mio, t=3, p=4** par défaut.
- Chiffrement authentifié **XChaCha20-Poly1305**, header en AAD.
- Hiérarchie de clés **MK → KEK → DEK → `K_records` / `K_attachments` / `K_index`**,
  HKDF à étiquettes de domaine distinctes.
- Conteneur à deux slots de clé (mot de passe, seconde enveloppe), header à offsets
  fixes, **sans parseur**.
- Écriture atomique (`O_TMPFILE`/`O_EXCL` + `fsync` + `renameat`, 0600).
- Verrouillage inter-processus (`flock`).
- Sentinelle anti-retour-en-arrière (HMAC sur `K_index`).
- Durcissement mémoire : `mlock`/`VirtualLock`, `prctl`, `RLIMIT_CORE`, `panic = "abort"`.
- Interface en ligne de commande **headless**.

**Hors périmètre**

- Modèle de données, générateur, TOTP, presse-papiers, sauvegardes, import/export,
  interface graphique.
- **Dénégation plausible**, **résistance à la coercition**, sécurité contre un poste
  entièrement contrôlé — `SECURITY.md` §9 les écarte explicitement.

**Dépendances**

- Phase 0.

**État**

- **Terminée et gelée.**
- 8 défauts réels corrigés dont 3 graves, aucun cryptographique (`docs/AUDIT_PHASE1.md`).
- Passe ciblée de corrections V9–V12 (liens symboliques intermédiaires, arithmétique
  d'offsets, vérification Windows, pression mémoire, sanitizers).
- Paramètres cryptographiques **inchangés** depuis.

---

## Phase 2 — Modèle de données et cœur de stockage

**Objectif.** Stocker des entrées typées à l'intérieur du payload, **sans jamais
toucher au conteneur**. C'est la séparation conteneur/schéma qui doit permettre de
faire évoluer le produit sans casser une seule sauvegarde.

**Fonctionnalités incluses**

- Modèle : `Entry`, `Field`, `Folder`, `Tag`, `Revision`, `AttachmentMeta`,
  `AuditEvent`, identifiants aléatoires de 128 bits.
- Format d'archive **borné, déterministe et vérifié** — aucune allocation dimensionnée
  par une valeur non vérifiée.
- CRUD complet, atomicité « valider puis appliquer ».
- Historique versionné, rétention **50 révisions ou 90 jours**, purge explicite.
- Corbeille, restauration, suppression définitive.
- Dossiers (profondeur ≤ 8), tags, favoris, archivage, champs personnalisés.
- Recherche littérale (insensible à la casse et aux accents latins), filtres, tri.
- Migration de schéma, appliquée en mémoire, **rien n'est écrit si elle échoue**.
- Journal de sécurité à types fermés.

**Hors périmètre**

- **Pièces jointes** : le format les accueille (section présente et bornée), mais
  l'implémentation appartient à la **phase 4**.
- **Import/export** : garde-fous documentés, implémentation en **phase 4**.
- Interface graphique, réseau, générateur, TOTP.

**Dépendances**

- Phase 1 — en particulier l'enveloppe de payload et les sous-clés.

**État**

- **Terminée et gelée.**
- 6 défauts réels corrigés, dont une régression que mes propres corrections avaient
  introduite (`docs/AUDIT_PHASE2.md`).
- **SQLite abandonné** au profit d'un magasin purement Rust : la limite **L6**
  (cache de pages ineffaçable) disparaît, et le cœur n'a plus **aucune dépendance C**.
- Audit sémantique indépendant : 9 500 séquences d'opérations aléatoires, 18
  invariants **VÉRIFIÉS**.

---

## Phase 3 — Générateur de secrets et TOTP

**Objectif.** Produire des secrets, et produire des codes TOTP — sans jamais élargir
la surface d'aléa ni la surface d'analyse au-delà de ce que les phases 1 et 2 ont
établi.

**Fonctionnalités incluses**

- Génération de **mots de passe** : longueur, classes de caractères, exclusions,
  retrait des caractères ambigus, minimums par classe satisfaits par **rejet de
  chaîne entière** (jamais par remplacement de caractère).
- Génération de **phrases de passe** : listes EFF (anglais) et française intégrées,
  liste personnalisée, nombre de mots, séparateur.
- Génération de **secrets arbitraires** : `hex`, `base32`, `base64url`,
  `alphanumérique`, regroupement.
- **Entropie calculée** (jamais estimée), coût des contraintes affiché explicitement,
  bandes qualitatives. **Aucune estimation en durée de cassage.**
- **HOTP** (RFC 4226) et **TOTP** (RFC 6238), SHA-1/SHA-256/SHA-512, 6 ou 8 chiffres.
- Analyse et sérialisation des URI **`otpauth://`**.
- Stockage du secret TOTP comme `Field` de type `Totp` — **aucun changement de format**.
- Décalage d'horloge manuel par coffre, temps **injecté** dans le cœur.
- Commandes : `generate`, `passphrase`, `secret`, `totp`, `entry totp set|new`,
  `entry gen`.

**Hors périmètre**

- **Presse-papiers** : analysé (`docs/TOTP.md` §8), mécanisme en **phase 4**.
- Cache de codes entre invocations, secret TOTP dans le trousseau système,
  « déverrouillage TOTP », coffre TOTP séparé.
- Vérification de l'heure en ligne (NTP) — romprait l'absence de réseau, propriété de
  sécurité de la phase 1.
- QR code d'enrôlement — appartenait à la **phase 6**, **abandonnée** (gate E.1/E.2) ;
  **non livré**.
- Estimateur de robustesse de mots de passe humains.
- Tout secret passé en argument de commande.

**Dépendances**

- Phase 1 — `rng`, `secret`, HMAC/SHA.
- Phase 2 — `Field`, `FieldKind::Totp` et le sac de réglages, **déjà présents**.

**État**

- **Terminée et approuvée** — approbation formelle prononcée.
- 35 vecteurs officiels (10 RFC 4226 + 18 RFC 6238 + 7 RFC 4648) comme preuve de
  conformité ; campagne adversarial sur l'analyse d'URI et le générateur.
- **Une seule dépendance ajoutée** : `sha1 0.11` (RustCrypto).
- Fuzzing exécuté pour la première fois sur ce projet.

---

## Phase 4 — Pièces jointes, sauvegardes, récupération, import/export, presse-papiers

**Objectif.** Faire en sorte que les données **ne soient pas perdues**, qu'elles
puissent **sortir** du produit, et que les fichiers volumineux n'imposent plus de
réécrire le coffre entier.

**Fonctionnalités incluses**

Cette phase regroupe cinq chantiers, volontairement traités ensemble parce qu'ils
partagent la même propriété : **ce sont les seuls endroits où des données traversent
la frontière du coffre** — vers un fichier de sauvegarde, vers un autre format, vers
le presse-papiers, ou vers un blob séparé.

1. **Pièces jointes.** Blobs chiffrés séparés du conteneur, sous `SubKeys::attachments`
   déjà dérivée. Chiffrement par morceaux, nom de blob dérivé par HMAC d'un
   identifiant aléatoire, ramasse-miettes explicite. Le format les accueille depuis la
   phase 2 ; seule l'implémentation manque.
2. **Sauvegardes**, avec **test de restauration** effectif — une sauvegarde jamais
   restaurée n'est pas une sauvegarde.
3. **Récupération** — deux mécanismes, un seul chemin de code :
   - **clé de récupération** de 256 bits, rangée hors machine, encodée en base32
     Crockford, enregistrée comme enveloppe supplémentaire ;
   - **clé matérielle** : même mécanisme, la KEK provenant du support. **Confirmée
     dans cette phase** : elle fait partie des mécanismes de récupération, pas d'une
     extension distincte.

   Les deux passent par `derive_master_kek` ; `unlock_with_kek` est réutilisé tel
   quel. Le **slot de clé label 2 est réservé depuis la phase 1** pour cet usage.
4. **Import/export.** Export chiffré et export **en clair** — désactivé par défaut,
   réauthentification, phrase de confirmation, permissions restrictives. Import CSV
   borné, prévisualisé, transactionnel.
5. **Presse-papiers.** Copie avec durée courte, effacement après délai, **vérification
   avant écrasement**, avertissement à la première utilisation par session.

**Hors périmètre**

- Récupération à distance, question de sécurité, récupération par courriel —
  **structurellement impossibles** dans un produit sans serveur, et refusés comme tels.
- Synchronisation entre machines.
- Importateurs par fournisseur (un seul format d'import, le CSV) : chaque importateur
  supplémentaire est un parseur de plus à fuzzzer.

**Dépendances**

- Phase 1 — `derive_master_kek`, slot de clé label 2 déjà réservé, `SubKeys::attachments`.
- Phase 2 — archive, CRUD, atomicité.
- Phase 3 — l'analyse des risques du presse-papiers (`docs/TOTP.md` §8).

**État**

- **Terminée.** Quatre étapes livrées, chacune close par un audit adversarial séparé.
  La **cinquième — presse-papiers — est abandonnée** par le gate E.0
  (`docs/AUDIT_PHASE4_5_CLIPBOARD.md`) : la bibliothèque retenue (`arboard 3.6.1`)
  aurait exigé d'**élargir** la liste de licences de `deny.toml` et d'**affaiblir**
  `multiple-versions`, c'est-à-dire un renforcement de la chaîne d'approvisionnement
  refusé. Le presse-papiers **n'est pas** une fonctionnalité de Passlock.
- **Étape 1 — récupération : close et auditée**
  (`docs/AUDIT_PHASE4_1_RECUPERATION.md`). Livrés : clé de récupération de 256 bits en
  Crockford Base32 avec total de contrôle, **fichier-clé** sur support amovible par le
  même chemin de code, slots supplémentaires (installation, remplacement, révocation),
  et le socle transverse de création exclusive et de durabilité des fichiers sensibles.
  **Aucun changement de format** : le rôle de slot 2 était réservé depuis la phase 1.
- **Étape 2 — pièces jointes : close et auditée**
  (`docs/AUDIT_PHASE4_2_PIECES_JOINTES.md`). Livrés : blobs chiffrés séparés du conteneur
  (`docs/ATTACHMENT_FORMAT.md`), domaines de clés séparés — `K_blob_name` pour le nom,
  `K_blob_aead` pour le contenu, la racine `K_attachments` étant **détruite** après
  usage —, commandes `attach add|list|get|verify|rm|gc`, et un ramasse-miettes qui
  distingue orphelins, fichiers étrangers et absences. **Aucun changement de format de
  coffre** : la section des pièces jointes existait depuis la phase 2.
- **Étape 3 — sauvegardes : close et auditée** (`docs/AUDIT_PHASE4_3_SAUVEGARDES.md`,
  procédure dans `docs/BACKUP.md`). Livrés : sauvegarde en **couple de chemins** — le
  fichier de coffre et son répertoire de blobs, **sans format nouveau** —, copie sous
  **verrou exclusif** de l'ensemble, vérification **immédiate** de la copie, et un test de
  restauration **effectif** qui rejoue la procédure documentée et relit une pièce jointe
  **octet pour octet**. **Aucune atomicité de destination revendiquée** : une interruption
  brutale laisse une destination partielle, qui **échoue** au test.
- **Étape 4 — import/export : close et auditée** (`docs/AUDIT_PHASE4_4_IMPORT_EXPORT.md`,
  format dans `docs/IMPORT_EXPORT.md`). Livrés : un **format CSV canonique** — une ligne
  par entrée, en-tête fixe de 12 colonnes —, **sans identifiants internes**, sans
  pièces jointes, sans historique, sans corbeille ni réglages ; un échappement
  **contextuel** strict (`%25` partout, `%2F` en dossier, `%7C` en tag, majuscules
  seules, NUL interdit) ; une colonne `fields` en **structure canonique** (JSON à clés
  fixes, champs ordonnés, une seule écriture par valeur). Le tri porte sur les 11
  colonnes exportables, `entry_ref` étant attribué **après** tri : `export → import →
  export` est **identique octet pour octet**, indépendamment des identifiants et de
  l'ordre d'origine. L'**import** valide **tout** avant d'écrire, puis n'enregistre
  qu'une fois — un CSV refusé ne laisse **aucune** modification. Commandes `export`
  (`--output`/`--stdout`, jamais par défaut) et `import` (`--input`).
- **Étape 5 — presse-papiers : abandonnée par le gate E.0**
  (`docs/AUDIT_PHASE4_5_CLIPBOARD.md`). Le gate de chaîne d'approvisionnement a conclu
  **P3** : `arboard 3.6.1` (avec `default-features = false` et
  `wayland-data-control`) ferait échouer `cargo deny check` — **licences** hors de la
  liste blanche (`Zlib` et `Unicode-3.0` sous Unix, `BSL-1.0` sous Windows) et
  **versions multiples** (`hashbrown` sous Unix, `windows-sys` sous Windows). Le faire
  passer aurait exigé d'**élargir** la liste de licences et d'ajouter des contournements
  de versions — un affaiblissement du contrôle **refusé**. **Aucune dépendance clipboard
  n'a été ajoutée**, aucun contrôle `cargo-deny` n'a été désactivé, et **aucun code de
  presse-papiers n'existe** dans le projet. Les prérequis réels n'ont pas pu être
  satisfaits proprement ; le mécanisme est donc écarté, et non reporté.
- **Phase 4 close et gelée.**

---

## Phase 5 — Centre de sécurité et analyse d'URL

**Objectif.** Rendre visible, **entièrement hors ligne**, l'état de sécurité des
secrets déjà stockés — et signaler les sites trompeurs.

Cette phase n'ajoute **aucun** secret et **aucune** primitive. Elle ne fait que
**recalculer** ce qui est déjà dans le coffre et le présenter.

### Fonctionnalités incluses

### 5.1 — Centre de sécurité

Un état des lieux, calculé à la demande sur le coffre déverrouillé :

| Indicateur | Ce qu'il calcule |
|---|---|
| **Réutilisation de mots de passe** | les secrets identiques employés sur plusieurs entrées. Comparaison sur une empreinte dérivée d'une clé du coffre, **jamais sur le secret lui-même**, afin qu'aucune table de correspondance ne subsiste |
| **Ancienneté** | le délai depuis la dernière modification de chaque secret, à partir de `updated_at` **déjà présent** |
| **Entropie recalculée** | l'entropie de chaque secret **recalculée à la demande** (phase 3). Aucun score n'est stocké : `docs/DATA_MODEL.md` a tranché qu'un score figé se périme |
| **Entrées faibles** | les secrets sous un seuil d'entropie, ou de longueur manifestement insuffisante |
| **Absence de TOTP** | les entrées qui gagneraient à porter un second facteur et n'en portent pas |
| **Secrets expirés** | trois états — **expiré**, **bientôt expiré**, **valide** — calculés à partir de `expires_at`, une date **explicitement fournie par l'utilisateur** (voir ci-dessous) |

### 5.2 — Analyse d'URL locale

Signalement des sites trompeurs, **sur la seule chaîne de l'URL**, sans jamais la
résoudre ni la contacter :

- **eTLD+1** : regroupement des entrées par domaine enregistré, via la **liste des
  suffixes publics**. Une entrée `login.exemple.co.uk` et une entrée `exemple.co.uk`
  doivent être reconnues comme le même site — et `exemple.co.uk.evil.com` comme un
  site **différent**, malgré l'apparence.
- **Homoglyphes** : détection des caractères visuellement confondants (`l`/`I`/`1`,
  `rn`/`m`, `0`/`O`, cyrillique `а` contre latin `a`).
- **IDN mixtes** : détection des noms de domaine **mêlant plusieurs écritures** dans un
  même label — la technique du *homograph attack*. Une URL dont le domaine mélange
  latin et cyrillique est signalée comme suspecte, quelle que soit son apparence.
- Sous-domaines trompeurs, nombre excessif de labels, tirets encadrant une marque
  connue.

### 5.3 — `expires_at` : une donnée fournie, jamais devinée

**Décision tranchée.**

- `expires_at` est une date **explicitement saisie par l'utilisateur**. Aucune durée
  d'expiration n'est **déduite** ni **inventée** — ni à partir de l'ancienneté, ni
  d'une politique par type d'entrée, ni d'une valeur par défaut implicite. Une entrée
  sans `expires_at` **n'expire pas** : l'absence de donnée n'est pas une donnée.
- **Aucun schéma dédié n'est créé.** `expires_at` est un `Field` clé-valeur ordinaire
  du modèle de la phase 2, de type date. Le format d'archive **ne change pas**.
- Le centre de sécurité **lit** cette donnée et la classe en **trois états** :

  | État | Condition |
  |---|---|
  | **expiré** | la date est dans le passé |
  | **bientôt expiré** | la date tombe dans la fenêtre d'alerte |
  | **valide** | la date est au-delà de la fenêtre |

**Point laissé ouvert, et signalé comme tel.** La **fenêtre d'alerte** de « bientôt
expiré » est un paramètre, pas une constante cachée. Sa valeur doit être **explicite et
affichée**, et **reste à fixer** : l'inventer ici serait exactement ce que la décision
interdit. Elle sera arbitrée avant l'implémentation de la phase 5.

`expires_at` est le **seul** élément de la phase 5 qui **écrit** dans les entrées :
tout le reste du centre de sécurité et l'analyse d'URL sont en lecture seule.

### 5.4 — Liste des suffixes publics : source, embarquement, mise à jour

L'eTLD+1 exige une liste des suffixes publics. Le choix est tranché, et il suit le
**motif déjà établi pour les listes de mots** (`crates/passlock-core/data/wordlists/`)
plutôt qu'un crate supplémentaire.

| | |
|---|---|
| **Source** | Public Suffix List, `https://publicsuffix.org/list/public_suffix_list.dat` |
| **Dépôt** | `https://github.com/publicsuffix/list` |
| **Licence** | **MPL-2.0** — vérifiée le 2026-09-16 en lisant le fichier `LICENSE` du dépôt (HTTP 200), et non supposée |
| **Mode d'intégration** | fichier **embarqué verbatim** dans le binaire (`include_str!`), comme les deux listes de mots |
| **Emplacement** | `crates/passlock-core/data/public-suffix-list/`, avec son `ATTRIBUTION.md` |
| **Versionnement** | épinglé au **commit SHA** du dépôt amont, consigné dans `ATTRIBUTION.md` |
| **Somme de contrôle** | SHA-256 épingle dans un test d'intégrité, comme `wordlist_integrity.rs` |
| **Réseau** | **aucun**, ni au moment du build, ni à l'exécution |
| **Résolution** | locale uniquement |

**Pourquoi un fichier embarqué et non un crate.** Ajouter un crate comme `publicsuffix`
ferait entrer sa licence dans l'arbre des **dépendances**, où `deny.toml` l'examinerait
au même titre que le code exécuté. L'embarquement maintient la liste des dépendances
inchangée et place le contenu tiers là où le projet a déjà l'habitude de le traiter :
**hors du graphe de crates, sous contrôle manuel documenté**.

**Fait à assumer, et non à dissimuler.** `cargo deny` **ne couvre pas** les données
embarquées — il vérifie les crates. La conformité de la licence de la PSL repose donc
sur `ATTRIBUTION.md` et sur une vérification manuelle, exactement comme pour les listes
de mots. De plus, **MPL-2.0 est une licence nouvelle pour ce projet** : elle ne figure
pas dans la liste blanche actuelle de `deny.toml` (MIT, Apache-2.0, BSD-3-Clause).
Comme le fichier est distribué **non modifié** et accompagné de son attribution, le
fichier conserve sa licence d'origine et la licence du projet reste MIT. **Cette
appréciation est technique, pas juridique** — elle doit être consignée comme telle.

**Stratégie de mise à jour, explicite.** La liste amont évolue : nouveaux TLD,
nouveaux suffixes privés. La stratégie retenue est le **ré-embarquement délibéré** :

1. **Aucune mise à jour automatique, à aucun moment.** Pas de téléchargement au build,
   pas de vérification à l'exécution, pas de rafraîchissement périodique. La propriété
   « aucun réseau » de la phase 1 est **constitutive**, pas configurable.
2. La liste est **ré-embarquée par un commit revu**, qui met à jour le commit SHA
   amont, la date de récupération, l'empreinte SHA-256 et la taille dans
   `ATTRIBUTION.md`. Le test d'intégrité échoue tant que l'empreinte n'a pas suivi.
3. **L'âge de la liste est une donnée publique** : la date de récupération est
   consignée dans `ATTRIBUTION.md` et affichée par le centre de sécurité. Un
   utilisateur doit pouvoir savoir sur quelle liste un verdict a été rendu.
4. **La conséquence d'une liste périmée est documentée** : un suffixe inconnu de la
   liste ne peut pas être regroupé correctement, et le résultat doit alors être
   présenté comme **incertain** plutôt que comme un verdict ferme. La politique de
   repli exacte relève de la spécification de la phase 5.

### Contraintes impératives

Ces trois contraintes sont **constitutives** de la phase, pas des préférences.

1. **Le centre de sécurité n'envoie aucune donnée à un service distant.** Aucune
   requête réseau, sous aucune forme, y compris pour « vérifier » un mot de passe
   contre une base de fuites. Un produit hors ligne qui interroge un service est un
   produit qui n'est plus hors ligne — et l'interrogation révélerait précisément ce
   qu'il prétend protéger.
2. **L'analyse d'URL reste pure** : sans accès au coffre, sans entrée/sortie, sans
   réseau, sans horloge. Elle prend une chaîne, rend un verdict. Elle est donc
   testable sans déverrouiller quoi que ce soit.
3. **Aucune donnée du coffre ne sort.** Les indicateurs sont affichés, jamais
   exportés automatiquement, jamais journalisés en clair.

### Hors périmètre

- Vérification contre une base de fuites en ligne (HIBP ou équivalent) — viole la
  contrainte 1.
- Résolution DNS, `whois`, certificats, réputation, âge du domaine.
- Toute forme de notation globale unique (« score de sécurité 87/100 ») : un chiffre
  composite masque ce qui compte et se compare mal d'un coffre à l'autre.
- Modification automatique des secrets signalés — la phase **signale**, elle ne
  corrige pas à la place de l'utilisateur.

**Dépendances**

- Phase 2 — les entrées, `updated_at`, les champs clé-valeur.
- Phase 3 — le calcul d'entropie, réutilisé tel quel.
- **Liste des suffixes publics** : décision prise en §5.4 — **données embarquées**,
  pas une dépendance de crate. Le graphe de crates du cœur reste donc **inchangé**.

**État**

- **Étape 1 — centre de sécurité (lecture) : livrée et auditée**
  (`docs/AUDIT_PHASE5_1_CENTRE_SECURITE.md`). Livrés : les **six** indicateurs
  (réutilisation, ancienneté, estimation de robustesse, entrées faibles, absence de
  TOTP, expiration) dans `passlock-core/src/security.rs`, en **lecture seule**, sans
  horloge (l'instant UTC est fourni), sans score global, sans exposer aucune valeur ni
  empreinte. L'empreinte de réutilisation est un **quatrième usage HMAC de `K_index`**
  séparé par étiquette (`I-KEYDOMAIN`). L'estimation de robustesse est **nommée comme
  une heuristique** — jamais une entropie — et son faux négatif est testé. Le format
  d'archive ne change **pas**.
- **Étape 2 — analyse d'URL et PSL : livrée et auditée**
  (`docs/AUDIT_PHASE5_2_ANALYSE_URL.md`). Livrés : une analyse **pure**
  (`url::analyze`), **explicable par motifs**, **sans score numérique global** ;
  l'**eTLD+1** via la **PSL embarquée** (`crates/passlock-core/data/public-suffix-list/`,
  verbatim, commit et SHA-256 épinglés, sections **ICANN et PRIVATE**) ; un codec
  **Punycode** écrit à la main (RFC 3492) ; les IDN sont **converties, pas validées**
  (un label non-ASCII ne peut **jamais** produire un verdict `Clean`). **Aucune
  dépendance nouvelle** — la PSL est une donnée embarquée, pas un crate. Deux défauts
  corrigés : règles U-label non normalisées, et refus compté comme `Clean`. Le motif
  « sous-domaine trompeur » est **retiré** faute de référence de marque fiable.
- **Étape 3 — `expires_at` : livrée et auditée.** Livrés : l'écriture de la date
  d'expiration via `passlock entry expires`, qui passe par **`update_entry`** — donc
  validation métier, **révision d'historique** et **aucun** chemin direct vers
  l'archive. La date est validée **avant toute mutation** ; un champ existant est
  **remplacé**, et **plusieurs** champs préexistants font **refuser** l'opération
  plutôt que d'en choisir un — rien n'est supprimé en silence. **Aucun schéma, aucun
  champ, aucun mécanisme d'historique** nouveau : `expires_at` reste un `Field`
  clé-valeur ordinaire.
- **Étape 4 — présentation CLI du centre de sécurité : livrée et auditée**
  (`docs/AUDIT_PHASE5_4_SECURITY_CLI.md`). Livré : `passlock security`, **couche de
  présentation** au-dessus de `passlock-core::security`, **strictement en lecture
  seule** (`read_only` imposé, aucun `save()`). **Aucun score global**, aucun
  pourcentage, aucun classement ; **aucune valeur de champ** ni **aucune empreinte** de
  réutilisation n'est affichée ; `Unknown`/`Indeterminate` sont rendus **comme tels**,
  jamais comme « valide » ou « fort ».
- **Phase 5 close et gelée.** Les quatre étapes sont livrées, et la clôture — commit et
  tag `phase-5-complete` — est faite.

---

## Phase 6 — Interface graphique

**Objectif.** Rendre le produit utilisable au quotidien **sans affaiblir le modèle**.
Une interface qui obligerait à relâcher une propriété de sécurité ne serait pas une
avancée.

**Fonctionnalités prévues — aucune n'est livrée**

- Crate `passlock-gui`, consommant `passlock-core` — **aucune logique de sécurité
  dupliquée** dans la couche graphique.
- **Verrouillage automatique** après inactivité — contre-mesure, pas confort.
- **Session déverrouillée en mémoire** : la DEK reste en mémoire le temps de la
  session, ce qui évite une dérivation Argon2id à chaque consultation.
- **Réauthentification avant révélation** pour les entrées marquées `sensitive`.
- Choix du **profil de paramètres de dérivation** à la création, avec avertissements
  mesurés.
- **Détection de pression mémoire** avant une dérivation coûteuse, avec message
  explicite plutôt qu'un échec.
- Avertissements du presse-papiers à la première utilisation par session.
- QR code d'enrôlement TOTP.
- Import/export et gestion des pièces jointes par l'interface.

**Hors périmètre**

- **Tauri 3.0**, en version alpha à la date de rédaction.
- Synchronisation, compte, service distant.
- Toute télémétrie.
- Réimplémentation de la cryptographie côté interface.

**Dépendances**

- Phases 1 à 5.

**État**

- **Abandonnée — gate E.1/E.2.** Aucun des frameworks graphiques évalués n'est
  compatible avec la politique de chaîne d'approvisionnement de `deny.toml` sans
  l'affaiblir de manière significative : **Tauri 2.11.6** (P3) ; les GUI natives
  **`eframe`/`egui` 0.36.2, `iced` 0.14.0, Slint 1.18.1, FLTK 1.5.23** (P3) ; et
  **`egui` minimal sans `eframe`** (P3). **Aucune solution évaluée, dans le cadre et
  les politiques actuels, n'est acceptable pour cette version.**
- **Rien n'a été implémenté** : aucun crate `passlock-gui`, aucun toolkit graphique,
  aucun frontend. **Aucune dépendance graphique n'a été ajoutée**, **aucune licence
  autorisée en plus**, **aucun advisory ignoré**, **aucun assouplissement de
  `multiple-versions`**. `deny.toml` est **inchangé**.
- **Aucune nouvelle surface webview/IPC/CSP** n'est introduite : aucune de ces
  bibliothèques n'entre dans l'arbre.
- **Fonctionnalités prévues et non livrées** : session déverrouillée en mémoire côté
  GUI, verrouillage automatique GUI, réauthentification `sensitive` dans la GUI, création
  de coffre via GUI, QR TOTP GUI, et interface graphique des pièces jointes, de
  l'import/export et du centre de sécurité.
- **Non reportée.** Comme le presse-papiers en phase 4.5, la phase 6 est **écartée, et
  non reportée** : ses prérequis ne peuvent pas être satisfaits proprement sous la
  politique actuelle. Voir `docs/DECISIONS.md` ADR-042 et, pour le précédent,
  `docs/AUDIT_PHASE4_5_CLIPBOARD.md`.
- **Ce qui reste disponible.** Les fonctionnalités **CLI/cœur** correspondantes —
  création de coffre, import/export, pièces jointes, centre de sécurité, code TOTP —
  **restent livrées** en ligne de commande ; c'est la **couche graphique** qui n'existe
  pas.
- **Phase 6 close et gelée.**

---

## Phase 7 — Durcissement, audit et livrables de release

**Objectif.** Transformer un produit **cohérent** en produit **vérifié** et
**reproductible** — et rendre publique la distinction entre ce qui a été vérifié par
un tiers et ce qui ne l'a pas été.

**Cette phase ne peut pas être entièrement produite par l'agent.** La séparation est
donc explicite et fait partie de la définition de la phase.

### 7.1 — Produit par l'agent

| Élément | Contenu |
|---|---|
| **Durcissement final** | reprise de toutes les limites encore ouvertes : **L9/L12** (`SECURITY.md`), **NV5**, les chemins Windows, les paramètres de durcissement partiels |
| **Audit interne** | campagne adversariale complète sur l'ensemble du produit, sur le modèle des audits de phases 1 et 2 : fonctionnalités livrées / tests réellement exécutés / défauts trouvés / défauts corrigés / limites non vérifiées / risques résiduels |
| **SBOM** | nomenclature logicielle complète, exhaustive et versionnée, générée depuis le `Cargo.lock` |
| **Build reproductible** | installation des conditions d'une construction reproductible et **mesure** de la reproductibilité atteinte |
| **Lockfile figé** | `Cargo.lock` verrouillé et vérifié en intégration continue |
| **Résolution des limites restantes** | chaque limite de `SECURITY.md` est soit **corrigée**, soit **confirmée comme limite assumée** avec sa justification réécrite |
| **Documentation finale** | `README`, `SECURITY`, `THREAT_MODEL`, `ARCHITECTURE`, `ROADMAP` relus et figés ; procédures de restauration et de récupération testées |
| **Livrables de release** | archive source, sommes de contrôle publiées, notes de version, licence, instructions de vérification |

### 7.2 — Exige un tiers externe, **et ne peut pas être produit ici**

| Élément | Pourquoi l'agent ne peut pas le produire |
|---|---|
| **Audit de sécurité externe** | c'est la définition même de la phase 7 dans le cahier des charges initial. Un audit mené par l'auteur du code partage par construction ses angles morts. **`SECURITY.md` affirme depuis la phase 1 que le logiciel n'a pas été audité par un tiers ; cette affirmation ne peut disparaître que par un audit réel** |
| **Vérification indépendante de la reproductibilité** | la reproductibilité se prouve par un **second** constructeur qui reconstruit et compare. Que je reconstruise mon propre artefact ne prouve rien sur le processus, seulement sur ma machine |
| **Signature de release avec une clé de confiance** | la clé doit appartenir au responsable du projet et être détenue hors de portée de l'agent |

**Règle de non-revendication, absolue.** La phase 7 **ne doit jamais** déclarer un
audit externe comme réalisé tant qu'un tiers ne l'a pas **effectivement** effectué.
Aucune formulation ne doit laisser croire à un audit qui n'a pas eu lieu : ni
« audit effectué », ni « audité », ni « vérifié par un tiers », ni une case cochée.
L'agent qui rédige cette phase **ne peut pas** en être la source de vérité, puisque
c'est précisément l'absence de cette source qui motive l'audit.

La même règle s'applique à la **vérification indépendante de la reproductibilité** :
que je reconstruise mon propre artefact ne la prouve pas.

**Conséquence à assumer.** Si aucun tiers n'intervient, la phase 7 se termine avec un
**audit externe non réalisé**, et `SECURITY.md` doit continuer de l'écrire. Une phase 7
« terminée » sans audit externe n'est pas une phase 7 terminée — c'est une phase 7 dont
un livrable est manquant, et le document doit le dire dans ces termes. Le tableau de
l'état final devra porter la mention **« non réalisé »** à sa place, jamais une case
vide ni un tiret.

**Hors périmètre**

- Certification, conformité réglementaire, label de sécurité.
- Publication sur un magasin d'applications.
- Rotation de clés de signature, infrastructure de distribution.

**Dépendances**

- Phases 1 à 6 — durcir suppose que tout existe.

**État**

- **Non commencée.**

---

## Ce que cette feuille de route ne promet pas

- **Une phase terminée ne signifie pas « sûre ».** Elle signifie que son périmètre est
  livré, ses tests exécutés et ses limites écrites. Les audits de phases 1 et 2 ont
  chacun trouvé des défauts réels dans du code pourtant vert.
- **L'ordre est une contrainte, pas une préférence.** Les phases 4 à 7 dépendent des
  précédentes ; les intervertir ferait porter à une phase des responsabilités qu'une
  autre n'a pas encore posées.
- **Les phases 5, 6 et 7 ne sont pas détaillées au même niveau que 1 à 4.** Celles-ci
  ont été spécifiées puis réalisées ; celles-là seront précisées au moment de les
  aborder, à partir de cette définition, et cette définition ne changera pas sans que
  ce document soit modifié.
