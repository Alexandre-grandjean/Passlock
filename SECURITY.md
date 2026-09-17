# Sécurité de Passlock

> Ce document décrit l'architecture de sécurité, les garanties **réellement**
> apportées, et les limites connues. Il se lit avec `THREAT_MODEL.md` (contre quoi
> on protège) et `docs/CRYPTO.md` (détail des primitives).

## Statut du projet

**Phases 0 à 3 terminées et approuvées. Phase 4 en cours — étape 1 sur 5 close.**

Ce qui existe et est testé : dérivation de clés, chiffrement authentifié, hiérarchie
de clés, conteneur et son format, écriture atomique, verrouillage, sentinelle
anti-retour-en-arrière ; modèle de données complet — entrées, dossiers, tags,
historique, corbeille, recherche, migration ; générateur de mots de passe, de phrases
de passe et de secrets arbitraires ; HOTP et TOTP avec analyse des URI
`otpauth://` ; interface en ligne de commande headless.

Ce qui n'existe **pas encore** : pièces jointes, sauvegardes, test de restauration,
import/export, presse-papiers *(phase 4, étapes 2 à 5)* ; centre de sécurité et analyse
d'URL *(phase 5)* ; interface graphique *(phase 6)* ; audit externe, SBOM, build
reproductible *(phase 7)*.

**Le contenu, l'ordre, les dépendances et l'état des phases font autorité dans
[`ROADMAP.md`](ROADMAP.md).** Ce document-ci ne les redéfinit pas : il énonce les
propriétés de sécurité, les limites, et les **risques introduits par chaque phase**.

**Ce logiciel n'a pas été audité par un tiers.** Il est cohérent avec les références
publiques citées, mais une conception cohérente n'est pas une conception auditée.

## 1. Architecture en une page

```
                    ┌─────────────────────────────────────────┐
   mot de passe     │  Argon2id (sel et paramètres du header)  │
   maître ─────────►│  256 Mio, t=3, p=4 par défaut            │
                    └────────────────────┬────────────────────┘
                                         ▼  MK (jamais persistée)
                    HKDF-SHA256, info="passlock/v1/kek" ───► KEK
                                         │
                    slot du header ──────┤ XChaCha20-Poly1305
                    (DEK enveloppée)     ▼
                                        DEK  (32 octets aléatoires, créée une fois)
                                         │
                    HKDF-SHA256, une étiquette par usage
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
               K_records           K_attachments         K_index
                    │
                    ▼  XChaCha20-Poly1305, AAD = tout le header
                 coffre.plk
```

**Isolation des responsabilités, par crate :**

| Crate | Rôle | `unsafe` |
|---|---|---|
| `passlock-core` | cryptographie, format, coffre. **Aucun réseau, aucune interface.** | interdit (`#![forbid(unsafe_code)]`) |
| `passlock-platform` | primitives système (mémoire, fichiers, terminal) | **seul** crate autorisé |
| `passlock-cli` | interface en ligne de commande | interdit |

Le crate cœur ne dépend d'aucune bibliothèque réseau : il est donc **structurellement
incapable** d'exfiltrer quoi que ce soit, y compris par accident. Cette propriété est
vérifiable par `cargo tree -p passlock-core`.

## 2. Garanties apportées

Formulées avec leur portée. Aucune n'est absolue.

| Garantie | Contre quel adversaire | Sous quelles hypothèses |
|---|---|---|
| Le contenu du coffre n'est pas lisible sans le mot de passe maître | quiconque possède le fichier | le mot de passe maître a une entropie suffisante |
| Toute modification du fichier est détectée | quiconque peut écrire le fichier | — |
| Un abaissement des paramètres de dérivation est détecté | quiconque peut écrire le fichier | — |
| Le nombre de tentatives de déverrouillage n'est pas limité par le système | — | *(c'est une absence de garantie, listée par honnêteté)* |
| Deux processus ne peuvent pas écrire le même coffre simultanément | autres processus locaux | le système de fichiers gère les verrous |
| Les fichiers créés ne sont lisibles que par leur propriétaire | autres comptes locaux | système de fichiers gérant les permissions (pas FAT32/exFAT) |
| Aucune donnée ne quitte la machine | tout adversaire réseau | — (le crate cœur n'a aucune dépendance réseau) |
| Un fichier malformé ne provoque jamais de panique | quiconque fournit un fichier | fuzzing en appui |
| Un secret ne peut pas être journalisé par accident | un défaut de programmation | types secrets à `Debug` rédacteur |

## 3. Décisions de conception structurantes

### 3.1 Architecture monolithique — et pourquoi

Le coffre déverrouillé vit dans une base SQLite **en mémoire**. À l'enregistrement, le
contenu est sérialisé puis chiffré en **un seul bloc AEAD**, et le fichier est
remplacé atomiquement.

L'alternative courante — chiffrement page par page du fichier de base (type
SQLCipher) — a été écartée :

| Critère | Monolithique (retenu) | Page à page |
|---|---|---|
| Code cryptographique | **~400 lignes** | ~900 |
| Fuite de structure | **aucune** (taille totale seule) | nombre de lignes, schéma, taille des enregistrements, motifs d'accès |
| Contrôle du cycle de vie du clair | **total** | le cache de pages nous échappe |
| Complexité des nonces | **1 nonce aléatoire par écriture** | 1 nonce par page — invariant délicat |
| Intégrité globale | **un tag couvre tout** | tag par page, pas d'intégrité globale |
| Sauvegarde | **une copie de fichier** | copie + cohérence WAL |

Le facteur décisif n'est pas la performance, c'est **la quantité de code
cryptographique qu'on peut se tromper à écrire**. Réutiliser un nonce entre deux
pages sous la même clé est une erreur fatale silencieuse en AES-GCM ; le nonce de
192 bits de XChaCha supprime la classe entière de bugs. De même, l'intégrité globale
par construction évite d'avoir à concevoir un arbre de hachage — donc d'y laisser un
trou.

**Coût assumé :** tout le coffre est en RAM quand il est déverrouillé, et une
écriture est proportionnelle à sa taille. C'est inévitable pour le premier point
(déchiffrer une entrée la met en mémoire), et négligeable pour le second sur des
données de quelques mégaoctets.

### 3.2 Le header entre dans l'AAD du payload

Conséquence directe : **il n'existe aucune donnée non authentifiée dans le fichier**.
Une attaque par abaissement des paramètres Argon2id est structurellement impossible.

Conséquence secondaire, assumée : changer un slot de clé invalide le tag et impose de
re-chiffrer le payload. C'est peu coûteux — un passage d'AEAD, avec la même clé, sans
nouvelle dérivation — mais ce n'est pas O(1). Le bénéfice de la DEK se manifeste
ailleurs : les blobs de pièces jointes, chiffrés sous `K_attachments`, ne sont pas
touchés du tout.

### 3.3 Layout binaire plutôt qu'un format auto-descriptif

Le header est **la seule donnée non fiable traitée avant toute authentification**. À
ce stade, on ne sait pas si l'utilisateur connaît le mot de passe : on ne peut faire
confiance à rien.

Un format auto-descriptif (CBOR, JSON) exige un parseur générique : structures
imbriquées, longueurs déclarées, encodages variables. Chacune de ces
fonctionnalités est une classe de vulnérabilité connue. Un layout à offsets fixes
**supprime le parseur** : il ne reste que des lectures bornées, dont le nombre est
proportionnel au nombre de champs, chacune testable.

Coût : ajouter un champ exige d'incrémenter la version du format. Accepté sciemment —
tout ce qui évolue vite (types d'entrée, dossiers, index) vit dans le payload
chiffré, dont le schéma est indépendant du conteneur.

### 3.4 Aucune macro procédurale dans le crate cryptographique

`thiserror` et la feature `derive` de `zeroize` sont écartés ; le header n'utilise
aucune bibliothèque de sérialisation. Résultat mesuré : `syn`, `quote`,
`proc-macro2`, `serde`, `zerobytes`, `half` et `ciborium` sont **absents de l'arbre
de dépendances de `passlock-core`**, qui se réduit à RustCrypto plus `libc`.

Justification : les macros procédurales s'exécutent **à la compilation, avec les
privilèges du build**, et sont statistiquement la partie de l'écosystème la plus
exposée aux compromissions de chaîne d'approvisionnement. Les écarter du chemin
critique est un gain concret, pas de la pureté.

## 4. Limites connues

Liste exhaustive de ce que le projet **ne fait pas** ou **ne peut pas** faire, avec
un suivi explicite.

| # | Limite | Conséquence | Suivi |
|---|---|---|---|
| L1 | ~~Composants intermédiaires non protégés~~ → **CORRIGÉ** : marche composant par composant, chaque répertoire ouvert avec `O_NOFOLLOW` **depuis le descripteur du précédent** | un composant symbolique n'importe où dans le chemin est refusé, avec un message nommant le composant et indiquant le remède | reste : chaque composant est ouvert en lecture, donc un répertoire traversable mais non lisible est refusé ; et `..` reste accepté (entrée de répertoire ordinaire) |
| L2 | **Vérification des permissions non implémentée sur Windows**, et la **pose** d'une DACL n'a jamais été observée. Depuis l'étape 1 de la phase 4, les fichiers sensibles **neufs** (fichier-clé, puis blobs, exports et sauvegardes) sont créés par un appel qui **vise** à poser une DACL restrictive **dans l'appel de création** — code **compilé et vérifié statiquement**, **jamais exécuté**. Le **coffre lui-même** continue de reposer sur les ACL héritées de son profil, et rien ne les vérifie | pour le coffre : créer ou déplacer un fichier hors du profil utilisateur (dossier partagé, racine d'un disque) le rendrait accessible à d'autres comptes sans avertissement. Pour les fichiers neufs : la DACL visée est **correcte par construction**, mais **NON VÉRIFIÉE** — sa composition réelle après création n'a pas été constatée | à corriger (`GetNamedSecurityInfoW` + parcours d'ACL), et à **exécuter** sur un Windows réel. Le code de pose **échoue fermé** : une DACL non constructible fait échouer la création, jamais une écriture en permissions héritées (ADR-016, §4.8) |
| L3 | Vidages mémoire et restriction de `ptrace` non appliqués sur Windows | un vidage peut contenir des secrets | à corriger (WER, filtre d'exception) |
| L4 | `MADV_DONTDUMP` sans équivalent Windows utilisable sans privilèges | — | limitation acceptée |
| L5 | Effacement mémoire non garanti | copies possibles dans les registres, la pile et les blocs recyclés par l'allocateur | limitation acceptée, documentée. **La mention du cache SQLite a été retirée en phase 2** : SQLite a été abandonné, ce cache n'existe plus |
| L6 | ~~Le cache de pages SQLite n'est pas sous notre contrôle~~ → **CORRIGÉ en phase 2** : SQLite a été abandonné, il n'existe plus de cache de pages opaque | — | le magasin est en Rust pur : tout buffer déchiffré est un buffer que nous possédons et savons effacer |
| L7 | Aucune limitation du nombre de **tentatives** de déverrouillage | déni de service local par consommation CPU | à traiter côté interface ; ce n'est pas le même sujet que la concurrence (§4.3) |
| L8 | Sentinelle anti-retour-en-arrière **partielle** : le HMAC empêche de forger mais pas de restaurer, et **la suppression de la sentinelle désactive la détection** en rétablissant la référence à la génération de l'attaquant | un rollback peut passer inaperçu | aucune correction locale possible (TPM, support en ajout seul ou journal distant : hors périmètre) |
| L9 | **Le backend Windows compile désormais, mais ne s'exécute pas dans cet environnement** | les signatures FFI et les types sont validés ; le comportement à l'exécution (ACL, déplacement atomique, verrou) reste **non observé** | un job Windows est configuré dans `.github/workflows/ci.yml` ; tant qu'il n'a pas tourné, ne rien affirmer sur le comportement Windows |
| L10 | Aucun audit externe | — | à organiser |
| L11 | L'alerte de retour en arrière est **persistante et non acquittable** | après une restauration légitime, l'utilisateur voit l'alerte à chaque ouverture tant qu'il n'a rien enregistré | voir §4.1 |
| L12 | **Deux cibles de fuzzing sur six ont réellement été exécutées** : `parse_otpauth` (4 816 302 exécutions) et `decode_base32` (3 579 680), sans plantage. Les quatre cibles des phases 1 et 2 **n'ont toujours pas tourné** | la couverture guidée reste inexploitée sur le format et le conteneur | `cargo-fuzz 0.13.2` installé et utilisé en phase 3 ; les cibles des phases 1–2 restent **non vérifiées** |
| L13 | Les états internes de `chacha20poly1305`, `hmac` et `hkdf` ne sont pas effacés (features `zeroize` non activées) | copies de dérivés de clés dans le tas libéré | assumé : exploiter ces copies exige un accès mémoire privilégié, qui lit de toute façon la DEK directement |
| L14 | **MSan et UBSan n'ont jamais été exécutés** ; Miri ne couvre qu'un sous-ensemble | détection absente des lectures de mémoire non initialisée et du comportement indéfini hors de la portée de Miri | ASan, TSan et Miri **ont été exécutés** aux phases 2 et 3. Détail et portée exacte en §4.4 |
| L15 | La concurrence des dérivations n'est bornée que **dans le processus** | plusieurs instances distinctes ne sont pas plafonnées | assumé : un limiteur inter-processus serait contournable, et un attaquant peut allouer la mémoire sans passer par Passlock (§4.2) |
| L16 | **Une horloge système fausse produit des codes TOTP faux, et Passlock ne peut pas le détecter** | l'utilisateur voit un code refusé et croit à une erreur du site | aucune correction hors ligne possible : la RFC 6238 §6 confie la resynchronisation au **validateur**, et Passlock est le **prouveur**. Remède : corriger l'horloge, ou renseigner `totp_offset_seconds` |
| L17 | **L'entropie annoncée suppose un CSPRNG du noyau uniforme et non compromis** | si `getrandom` est instrumenté, tout l'aléa est connu de l'attaquant et les bits annoncés ne valent plus rien | hypothèse **de conception**, jamais mesurée ; rappelée à chaque affichage. Aucune bibliothèque ne peut s'en défendre depuis l'espace utilisateur |
| L18 | **La valeur d'un champ est un `String`, qui ne s'efface pas de façon fiable** | des fragments d'un secret peuvent subsister dans le tas après une réallocation | **limite héritée de la phase 2**, non corrigée ici : la corriger changerait le modèle de données. Documentée plutôt que passée sous silence |
| L19 | **Un secret engendré ne protège que s'il est stocké ailleurs que dans un carnet** | un mot de passe de 128 bits noté à la main vaut 0 bit | hors de portée du logiciel. Le générateur ne maîtrise pas ce qui suit sa sortie |
| L20 | **Un site qui tronque, journalise ou impose un format faible annule la génération** | la robustesse réelle peut être bien inférieure à l'entropie annoncée | Passlock ne peut pas le savoir sans réseau, et n'en fera pas. La contrainte imposée est **mesurée et affichée**, jamais contournée |
| L21 | **Les listes de mots sont vérifiées sur leur compte, leur format, leur unicité et leur empreinte — pas sur leur qualité linguistique** | un mot difficile à orthographier reste dans la liste | vérification impossible depuis ce projet ; les empreintes upstream sont épinglées pour que la provenance soit auditable |
| L22 | **Le presse-papiers est un canal public** | sous X11, toute application lit la sélection sans permission ni journal | mécanisme reporté en phase 4 ; l'analyse complète figure dans `docs/TOTP.md` §8 |
| L23 | Le secret TOTP transite par un `String` lors de l'analyse de l'URI | même limite que L18 | assumé, hérité du modèle de champs |
| L24 | **`cargo deny` ne couvre pas les données tierces embarquées** — il vérifie les licences des *crates*, pas des fichiers livrés. Les listes de mots (CC-BY 3.0) et la future liste des suffixes publics (MPL-2.0) échappent donc à la vérification automatique | une licence de donnée embarquée pourrait changer à l'insu du projet | contrôlée **manuellement** par `ATTRIBUTION.md`, avec empreinte épinglée et test d'intégrité. **MPL-2.0 n'est pas dans la liste blanche de `deny.toml`** : elle n'y entrera pas, un fichier de données n'étant pas une dépendance de crate. Précisé en §6.3 |
| L25 | **La liste des suffixes publics vieillit**, et rien ne le corrige automatiquement (aucun réseau, par conception) | un suffixe récent peut ne pas être reconnu : le regroupement eTLD+1 est alors **incertain** et doit être présenté comme tel | ré-embarquement délibéré, commit revu, âge de la liste **affiché** par le centre de sécurité. Stratégie en `ROADMAP.md` §5.4 |
| L26 | **Un fichier-clé est un fichier : il se copie.** Ce n'est donc pas un facteur de possession inviolable, contrairement à un jeton matériel qui ne peut pas être dupliqué | une copie du fichier clé ouvre le coffre depuis n'importe quelle machine, et rien ne permet de le détecter | dit à l'utilisateur à chaque installation, et repris dans `ROADMAP.md` §4 : le support doit être **physiquement distinct** du coffre et des sauvegardes, et présent seulement pendant l'ouverture. Un vrai facteur matériel (FIDO2 `hmac-secret`) est **repoussé et dit comme tel** — il exigerait `hidapi`/`libusb`, donc du C, et sortirait de la politique de dépendances (ADR-032) |
| L27 | **La durabilité de l'entrée de répertoire n'est pas revendiquée sous Windows.** `make_durable` y retourne `FileOnly` : le contenu est synchronisé, pas le nom | après une coupure d'alimentation, une pièce jointe peut manquer alors que le coffre la référence — une **promesse non tenue** | le niveau est **rendu** par la primitive (`Durability`, `#[must_use]`) et **rapporté à l'ouverture** du coffre, jamais tu. L'absence est détectée par `attach verify` (étape 2). Reprise en phase 7 avec un exécuteur Windows réel |

### 4.1 L'alerte de retour en arrière est persistante — et c'est délibéré

Après une restauration de sauvegarde légitime, l'alerte se déclenche à **chaque**
ouverture tant qu'aucun enregistrement n'a fait avancer la génération. Le remède
attendu est donc d'effectuer une modification puis d'enregistrer.

**Pourquoi il n'existe pas de commande « accepter cette référence ».** Un tel ordre
serait précisément le contournement qu'un attaquant chercherait à invoquer : exécuter
une commande unique pour faire taire la seule détection de retour en arrière
reviendrait à la désactiver sur demande. Le coût de cette absence est un
désagrément ; le coût de sa présence serait la perte de la détection.

**Risque induit, reconnu.** Une alerte qui ne peut pas être éteinte devient du bruit,
et un utilisateur apprend à ignorer le bruit. C'est un anti-modèle de sécurité connu.
La mesure d'atténuation actuelle est que le message reste **détaillé et explicite**
sur les conséquences concrètes. Une meilleure réponse resterait à concevoir :
consigner l'acquittement dans un journal inviolable, ou comparer avec une copie
distante de la sentinelle. Non implémenté.

### 4.2 Concurrence des dérivations : plafonnée dans le processus, pas entre processus

Argon2id alloue sa zone de travail — 256 Mio au profil par défaut — pour **toute la
durée** de la dérivation. La campagne `scripts/measure-memory-pressure.sh` mesure le
pic agrégé sur une machine à 7,7 Gio de RAM :

| Dérivations simultanées | Pic agrégé | Durée unitaire | Part de la RAM |
|---|---|---|---|
| 1 | 258 Mio | 682 ms | 3 % |
| 2 | 517 Mio | 823 ms | 6 % |
| 4 | 1 034 Mio | 1 264 ms | 13 % |
| 8 | 2 068 Mio | 2 709 ms | 26 % |
| 16 | **4 135 Mio** | 5 220 ms | **53 %** |

La croissance est **strictement linéaire**, et le mode de défaillance est le point
important : **un dépassement de la mémoire disponible ne produit pas d'erreur franche
sur Linux.** Le noyau échange, ce qui fait passer la durée de 0,7 s à plusieurs
dizaines de secondes et dégrade la machine entière, y compris les autres
applications de l'utilisateur.

**Ce qui a été fait.** Un limiteur de concurrence **dans le processus**, à une
dérivation par défaut, relevable par `kdf::set_max_concurrent_derivations`. Un
déverrouillage est une action humaine : personne n'ouvre seize coffres dans la même
seconde, donc sérialiser ne coûte rien en pratique et plafonne le pic à 258 Mio au
lieu de le laisser croître sans borne.

**Ce qui n'a pas été fait, et pourquoi.** Le limiteur ne borne pas la concurrence
**entre processus** — chaque instance a le sien. Un plafond inter-processus
demanderait un sémaphore nommé ou un verrou partagé, et surtout il serait
**contournable** : un attaquant local qui veut consommer 256 Mio peut les allouer
directement, sans passer par Passlock. Le limiteur protège donc l'utilisateur de
**notre propre comportement**, pas d'un adversaire. C'est la bonne portée, et elle
est explicitement documentée comme telle plutôt que présentée comme une défense.

### 4.3 Le backend Windows

L'environnement de développement est WSL2. Le code Windows (`MoveFileExW`,
`LockFileEx`, `VirtualLock`, `SetConsoleMode`) est écrit d'après la documentation
Microsoft. La surface FFI a été volontairement réduite à quatre appels pour limiter le
risque.

**État exact, en deux temps — la distinction est essentielle :**

| | |
|---|---|
| **Compilation** | **VÉRIFIÉE.** `cargo check --target x86_64-pc-windows-msvc --workspace --all-targets` passe, y compris pour les tests. Les signatures FFI et les types sont donc validés par le compilateur |
| **Exécution** | **NON OBSERVÉE.** Aucun binaire Windows n'a été lié ni lancé : ni Wine, ni MinGW, ni linker MSVC dans l'environnement. Le comportement à l'exécution — ACL, déplacement atomique, verrouillage, `VirtualLock` — reste **entièrement non vérifié** |

Une version antérieure de cette section affirmait que le code Windows « n'a jamais été
compilé ». **C'était faux**, et contredisait la limite L9. La compilation et
l'exécution sont deux niveaux de confiance très différents, et les confondre dans un
sens ou dans l'autre induit en erreur.

**Aucune affirmation d'ordre fonctionnel ne doit être faite sur Windows** avant qu'un
job de CI n'exécute réellement cette partie. Un tel job est configuré dans
`.github/workflows/ci.yml` ; tant qu'il n'a pas tourné, le comportement Windows reste
non vérifié.

### 4.4 Sanitizers : ce qui a tourné, ce qui n'a pas tourné

Corrige une affirmation antérieure (« aucun test sous sanitizers exécuté ») qui était
**fausse** : ASan, TSan et Miri ont été exécutés aux phases 2 et 3.

| Outil | Exécuté | Portée réelle | Ce que cela ne couvre **pas** |
|---|---|---|---|
| **ASan** | **oui** | espace de travail entier, tous les tests | les fautes qui ne se manifestent pas sur les chemins exercés par les tests |
| **TSan** | **oui** | tests unitaires du cœur, dont le limiteur de dérivation | le code non atteint par ces tests |
| **Miri** | **oui, partiellement** | modules **purs** : `bytes`, `header`, `payload`, `model`, `query`, `migrate`, et une partie d'`archive` | tout ce qui appelle `mlock` ou `getrandom`, que Miri ne sait pas exécuter. La couverture n'est donc **pas** exhaustive |
| **MSan** | **non** | — | les lectures de mémoire non initialisée. **Non exécuté, non disponible** |
| **UBSan** | **non** | — | comportement indéfini hors de la portée de Miri. **Non exécuté, non disponible** |

**Formulation autorisée :** « ASan et TSan ont été exécutés sur l'ensemble des tests,
Miri sur les modules purs. » **Formulation interdite :** « testé sous sanitizers »,
qui laisserait croire à une couverture complète.

Les commandes réellement employées figurent en §12.

### 4.5 Ce que la phase 2 a ajouté comme surface

L'archive du corps est un **analyseur de données non fiables** de plus, et d'une
taille bien supérieure à celle du header. Elle est traitée avec la même rigueur :

| Surface | Nature | Traitement |
|---|---|---|
| Décodeur d'archive | données authentifiées mais possiblement mal formées — autre implémentation, version future, ou défaut de notre propre encodeur | comptes bornés **avant** allocation, UTF-8 validé, profondeur bornée, fuzzing |
| Structure récursive (révision contenant une entrée) | épuisement de pile | invariant « l'historique d'un instantané est vide », **refusé** au décodage |
| Comptes de section | allocation massive | `count × taille_minimale ≤ octets_restants`, testé aux frontières |
| Historique | conserve des secrets que l'utilisateur croit supprimés | rétention bornée (50 / 90 jours), purge explicite, limites énoncées |
| Requête de recherche | coût CPU, injection | sous-chaîne **littérale**, aucun langage de requête, termes bornés |
| Journal d'audit | pourrait contenir un secret | `AuditKind` est un ensemble fermé, le sujet est un identifiant aléatoire |
| Migration de schéma | un défaut détruit les données | en mémoire, rien n'est écrit si elle échoue, version validée avant tout raccourci |
| Références croisées | incohérence exploitable | résolues après décodage, référence invalide = **erreur**, jamais un vide silencieux |

**Le point le plus important de cette liste est l'historique** : c'est le seul où la
fonctionnalité demandée **crée** un risque que l'utilisateur ne perçoit pas
spontanément. La réponse est la transparence — la politique est affichée, la purge est
explicite, et ses limites sont énoncées — jamais la dissimulation.

### 4.6 Ce que la phase 3 a ajouté comme surface

La phase 3 introduit le générateur et le TOTP. Les surfaces nouvelles sont
**bornées et énumérées**, comme aux phases précédentes :

| Surface | Nature | Traitement |
|---|---|---|
| Analyse d'URI `otpauth://` | **nouveau parseur** sur du texte authentifié mais non valide par construction | bornes fermées, échec fermé, 20 000 entrées aléatoires + toutes les troncatures, cible `cargo-fuzz` |
| Décodage Base32 / Base64url | nouveau décodeur | longueur de sortie bornée **avant** allocation, alphabet strict, **bits de remplissage non nuls refusés** (deux encodages pour les mêmes octets seraient un vecteur de malléabilité) |
| Décodage des séquences `%XX` | nouveau parseur | strict : un `%` mal formé est une erreur, jamais un caractère littéral |
| **Injection de séquences d'échappement ANSI** | **réelle et nouvelle** | caractères de contrôle **refusés à l'analyse** du libellé et de l'émetteur — voir ci-dessous |
| Fichier de liste de mots fourni par l'utilisateur | donnée tierce non fiable | lecture bornée **avant** chargement, validation fermée (format, longueur, unicité, caractères de contrôle), échec fermé |
| Concentration de l'usage de l'aléa | un bug y serait **silencieux et catastrophique** | aucune primitive d'aléa nouvelle ; les sélections passent par `rng::below`, dont la plage de rejet est désormais **testable** (voir 4.7) |
| Sortie de secrets sur stdout | historique du terminal, journal de session | stdout redirigeable, rapport sur stderr, `entry gen` sans affichage |
| Dépendance à l'horloge système | nouvelle dépendance à un état non maîtrisé | temps **injecté** dans le calcul, décalage manuel borné, limite écrite — voir `docs/TOTP.md` §6 |
| Listes de mots tierces | contenu tiers embarqué | provenance, licence CC-BY, **empreintes SHA-256 épinglées**, validation stricte |
| **Surévaluation de l'entropie** | **surface de revendication, la plus dangereuse** | aucune estimation en durée ; entropie **calculée** ; coût des contraintes compté ; taille de liste mesurée |

#### L'injection termininale, le point le plus sous-estimé

Un libellé TOTP peut contenir une séquence d'échappement ANSI. Imprimée telle quelle,
elle **réécrit le tampon de l'écran** : `\x1b[2K\x1b[G` efface la ligne et permet
d'afficher un **code qui n'est pas celui qui a été produit**. Un attaquant contrôlant
le libellé d'une entrée importée contrôlerait donc ce que l'utilisateur croit lire.

Le refus a lieu **à l'analyse**, pas à l'affichage. Échapper au moment de l'affichage
serait une défense au point d'usage, qu'un futur site d'affichage oublierait ;
refuser à l'entrée protège tous les usages présents et futurs. Même logique que la
phase 2 : *le lieu d'une vérification est lui-même une propriété de sécurité*.

### 4.7 Une modification du cœur en phase 3, signalée

La phase 3 a modifié **une seule** chose dans le cœur existant : la réduction
d'échantillonnage de `rng::below` a été extraite en une fonction pure `reduce`.

**Motif.** Elle était auparavant noyée dans une boucle qui appelle le générateur en
interne, donc **invérifiable** : le projet interdit tout générateur injectable, et un
test statistique ne peut pas la valider — sur une source 64 bits et une petite borne,
le biais modulo vaut environ 2⁻⁶³, indétectable à l'exécution tout en restant un défaut
réel si la fonction était un jour réécrite sur une source tronquée.

**Ce qui garantit que la factorisation est neutre.** Les cinq tests existants de
`rng.rs` passent **sans modification**, et la suite de valeurs produites est bit à bit
identique. Quatre tests nouveaux vérifient la propriété qui compte : *le nombre de
tirages acceptés est un multiple exact de la borne*, ce qui est la condition de
l'absence de biais modulo.

**Ce qui n'a pas changé** : aucune constante cryptographique, aucun paramètre de
dérivation, aucun octet de format.

### 4.8 Ce que la phase 4, étape 1, a ajouté comme surface

Deux mécanismes d'ouverture supplémentaires et un socle d'écriture de fichiers. Les
surfaces nouvelles sont **bornées et énumérées**, comme aux phases précédentes.

| Surface | Nature | Traitement |
|---|---|---|
| **Encodage Crockford Base32** *(nouveau décodeur)* | texte recopié à la main par l'utilisateur | alphabet fermé (32 symboles, `U` refusé), casse ignorée, `I`/`L`→`1` et `O`→`0`, séparateurs non significatifs, longueur exacte exigée, **bits de remplissage nuls exigés** — donc **une seule chaîne par clé** |
| **Total de contrôle de 40 bits** | détecte une faute de recopie | `SHA-256` tronqué, sur un domaine étiqueté, vérifié en **temps constant**. Refuse **avant** toute dérivation : une clé mal recopiée ne coûte pas un Argon2id |
| **Slots supplémentaires** | un chemin d'entrée de plus, donc une surface d'accès de plus | `install_slot` et `replace_slot` **refusent le rôle maître** : `change_password` reste le seul chemin, et il exige le mot de passe actuel. Un slot déplacé vers un autre coffre ne s'ouvre pas (son AAD contient l'identifiant du coffre) |
| **Fichier-clé** | 32 octets aléatoires, écrits sur un support choisi par l'utilisateur | création **exclusive** (`O_EXCL`/`CREATE_NEW`), permissions restrictives posées à la création, `fsync` puis `fsync` du répertoire, **nettoyage restreint à ce qui a été créé**. **Unix : exécuté et testé. Windows : compilé, jamais exécuté — NON VÉRIFIÉ** |
| **Durabilité dépendante de la plateforme** | la garantie n'est pas la même partout | `Durability` est **rendue** par la primitive, `#[must_use]`, et **rapportée à l'ouverture** du coffre. Une capacité absente n'est pas une erreur, et elle n'est pas tue. **Unix : mesuré. Windows : déclaré par `platform_durability`, NON VÉRIFIÉ** (L27) |
| **Deux options globales d'ouverture** (`--recovery-key-stdin`, `--key-file`) | propagées à toutes les commandes | `open_store` est le **seul** point qui choisit le chemin d'ouverture : aucun chemin n'échappe aux diagnostics. **Aucun secret en argument de commande** |
| **Clé de récupération affichée sur stdout** | un secret quitte le processus par un canal redirigeable | assumé et dit : c'est le seul moyen de la remettre à l'utilisateur. Affichée **une seule fois**, jamais journalisée, jamais recopiée sur la sortie d'erreur |

**Note de correction.** Une version antérieure de `SECURITY.md` §8 affirmait, à propos
des slots, que « l'ajout et la révocation sont en O(1) ». **C'était faux** pour le
fichier de coffre : le header entier entre dans l'AAD du payload, donc ajouter un slot
**ré-écrit tout le payload** au prochain enregistrement. Le §3.2 de ce même document le
disait correctement, et la contradiction a été corrigée dans le §8.

## 5. Journalisation

Règle : **aucun journal ne contient de secret.**

Mécanismes, et non simples consignes :

1. Les types de secret n'implémentent pas `Display` et ont un `Debug` qui affiche
   `[EXPURGÉ]`. Un `{:?}` accidentel ne peut pas fuiter.
2. Le type d'erreur ne porte **aucune** donnée issue du coffre : toutes ses charges
   utiles sont des `&'static str` choisies dans le code. Un message d'erreur peut
   donc être journalisé sans précaution.
3. Le message d'échec de déverrouillage ne désigne jamais la cause interne — un test
   le vérifie mot par mot.
4. `Debug` de `ParsedVault` et de `Vault` n'affiche que des tailles, jamais de
   contenu.

**Ce que la mécanique ne couvre pas :** un `println!("{}", x)` sur une `String` non
typée. Le typage protège tant que les secrets restent dans les types prévus à cet
effet. La couche d'affichage est le seul endroit où un secret devient une `String`,
et cette conversion doit rester visible en relecture.

## 6. Chaîne d'approvisionnement

| Mesure | État |
|---|---|
| `Cargo.lock` versionné (le projet produit des binaires) | **fait** |
| `rust-toolchain.toml` épinglé sur `1.98.0` | **fait** |
| `cargo deny check` — avis de sécurité, licences, bans, sources | **exécuté : les 4 catégories passent** |
| Liste blanche de licences **minimale** (3 entrées, `unused-allowed-license = "deny"`) | **fait et vérifié** |
| Refus explicite d'`openssl`, `openssl-sys`, `native-tls`, `ring` | **fait et vérifié** |
| Refus des registres et dépôts Git non approuvés | **fait et vérifié** |
| Arbre de dépendances du cœur réduit à RustCrypto + `libc` | **fait, mesuré** (`cargo tree`) |
| `cargo deny check` en intégration continue | à mettre en place |
| `cargo audit` (recoupement avec une seconde base d'avis) | à mettre en place |
| SBOM CycloneDX | à produire |
| Builds reproductibles | à valider |
| Signatures des binaires publiés | à mettre en place |

### 6.1 Résultat de l'audit de dépendances

Exécuté le 2026-09-16 avec `cargo-deny` 0.20.2 sur la cible
`x86_64-unknown-linux-gnu`, toutes fonctionnalités activées :

```
advisories ok, bans ok, licenses ok, sources ok
```

Ce que cela établit, précisément :

* **aucun avis de sécurité connu** (base RustSec) ne concerne une crate de l'arbre ;
* aucune crate n'est *yanked* ;
* **aucune version n'est dupliquée** pour une même crate ;
* toutes les licences sont dans la liste blanche, et cette liste est **exactement**
  celle qui est utilisée : trois entrées (MIT, Apache-2.0, BSD-3-Clause). Les entrées
  « au cas où » sont interdites par `unused-allowed-license = "deny"`, ce qui empêche
  l'autorisation silencieuse d'une dépendance future jamais examinée ;
* aucune dépendance ne provient d'un registre ou d'un dépôt Git non approuvé ;
* aucun des paquets explicitement bannis n'est présent.

**Ce que cela n'établit pas.** Un audit de dépendances vérifie des **déclarations
publiées**, pas le contenu du code. Il ne détecte ni une vulnérabilité non encore
consignée, ni une compromission de compte de publication, ni un défaut introduit
volontairement dans une version signée par son mainteneur. `cargo audit`, qui
consulte une seconde base avec un recoupement partiel, reste à mettre en place.

### 6.2 Surface de dépendances, mesurée

Arbre du moteur cryptographique (`cargo tree -p passlock-core --depth 1`) :

```
argon2 0.6.0 · chacha20poly1305 0.11.0 · getrandom 0.4.3 · hkdf 0.13.0
hmac 0.13.0 · sha2 0.11.0 · subtle 2.6.1 · zeroize 1.9.0
```

Huit dépendances directes, toutes des primitives RustCrypto ou des utilitaires
minuscules. **Aucune macro procédurale, aucune bibliothèque de sérialisation, aucune
dépendance réseau** — propriété vérifiée par recherche textuelle dans la sortie de
`cargo tree`.

### 6.3 Données tierces embarquées : le trou que `cargo deny` ne bouche pas

**`cargo deny` vérifie les licences des crates. Il ne voit pas les fichiers livrés
avec le binaire.** Les listes de mots en sont déjà un exemple, et la liste des suffixes
publics (phase 5) en sera un second. Ces contenus exigent donc un contrôle **manuel**,
et c'est la raison d'être des fichiers `ATTRIBUTION.md`.

| Contenu embarqué | Origine | Licence | Contrôle |
|---|---|---|---|
| `eff_large_wordlist.txt` | Electronic Frontier Foundation | CC BY | `data/wordlists/ATTRIBUTION.md`, SHA-256 épinglé |
| `diceware-fr-5-jets.txt` | C.‑M. Duquesne | CC-BY-3.0 | idem |
| `public_suffix_list.dat` *(phase 5)* | publicsuffix.org | **MPL-2.0** | `data/public-suffix-list/ATTRIBUTION.md`, SHA-256 épinglé |

**MPL-2.0 est une licence nouvelle pour ce projet.** Elle ne figure pas dans la liste
blanche de `deny.toml` (MIT, Apache-2.0, BSD-3-Clause) et **n'y entrera pas** : la
liste des suffixes publics est intégrée comme **donnée embarquée verbatim**, non comme
dépendance de crate, donc le graphe de crates du cœur reste inchangé et sa liste
blanche reste exacte.

**Ce que cela implique, énoncé sans détour.** Cette conformité repose sur une
vérification manuelle, pas sur un outil. Un `ATTRIBUTION.md` peut être faux sans que
rien ne le signale — c'est précisément le défaut que la limite **L24** consigne. Le
fichier distribué conservant sa licence d'origine, la licence du projet reste MIT.
**Cette appréciation est technique, pas juridique**, et ne doit pas être présentée
autrement.

## 7. Privilèges

Le programme **ne demande aucun privilège**. Il n'appelle jamais `sudo`, ne
s'installe pas en service, ne touche pas au registre Windows, et n'écrit que dans le
répertoire du coffre et dans le répertoire de configuration de l'utilisateur.

Deux conséquences directes, toutes deux assumées et documentées plutôt que
contournées :

* sur Windows, l'absence de privilèges empêche de configurer la suppression des
  vidages mémoire (L3) et la vérification des ACL (L2). La solution retenue est de
  **signaler** l'absence de protection, pas de demander l'élévation ;
* la sentinelle anti-retour-en-arrière ne peut pas utiliser de compteur matériel, ce
  qui la rend contournable (L8).

## 8. Réponse à incident et récupération

**Il n'existe aucun mécanisme de récupération à distance, et c'est délibéré.**

* Pas de courriel de réinitialisation : aucun serveur n'existe.
* Pas de question de sécurité : faible entropie, souvent publiquement devinable, et
  elle créerait un **second chemin attaquable** affaiblissant le coffre.
* Pas de « réinitialisation » qui perdrait les données en silence.

La récupération est conçue comme un **slot de clé supplémentaire**, et livrée à
l'étape 1 de la phase 4 :

* clé de récupération de 256 bits tirée au hasard, encodée en base32 Crockford avec
  total de contrôle ;
* enveloppe la **même** DEK, donc aucun rechiffrement du contenu ;
* ajout et révocation **sans toucher aux autres slots**, qui restent valides tels quels.

**NOTE DE CORRECTION — le coût réel, dit sans l'embellir.** Une version antérieure de ce
paragraphe affirmait que l'ajout et la révocation sont « en O(1) ». **C'était faux pour le
fichier de coffre.** Le header entier entre dans l'AAD du payload (`ADR-005`) : ajouter
un slot **ré-écrit tout le payload** au prochain enregistrement, parce que son tag doit
couvrir le nouveau header. Le coût est donc proportionnel à la taille du **payload** —
et non à celle des pièces jointes, qui vivent hors du conteneur et ne sont effectivement
pas touchées. C'est là que le bénéfice O(1) est réel, et c'est ce que dit §3.2 depuis la
phase 1. Les deux affirmations ne pouvaient pas être vraies ensemble ; c'est celle-ci qui
a été corrigée.

**La clé matérielle est un fichier.** Livrée par le même chemin de code que la clé de
récupération, elle n'est pas un facteur de possession inviolable : un fichier se copie.
Voir la limite **L26**.

**Compromis assumé, à énoncer clairement à l'utilisateur :** chaque slot est un
chemin d'entrée supplémentaire. Récupérabilité et résistance au vol varient en sens
inverse. L'atténuation est que la clé de récupération, à 256 bits, n'est **pas**
attaquable par force brute — le risque n'est donc pas cryptographique mais
**physique**. Conséquence pratique : la clé de récupération **et le fichier-clé**
doivent être rangés dans un lieu **physiquement distinct des sauvegardes**. Une clé
rangée à côté du disque de sauvegarde ne réduit aucun risque et en ajoute un. Le
programme le rappelle à chaque installation.

## 9. Ce que ce logiciel ne peut pas garantir

Reporté de `THREAT_MODEL.md` §7, car c'est l'information la plus importante de ce
document :

1. un malware avec contrôle total du système lit le coffre déverrouillé ;
2. un keylogger capture le mot de passe maître à la frappe ;
3. un système déjà compromis invalide toutes les garanties ;
4. une attaque privilégiée sur la mémoire lit les secrets ;
5. un écran observé physiquement n'est protégé par rien sur Linux ;
6. **l'effacement mémoire n'est pas garanti** ;
7. **la suppression n'est pas physique** (SSD, TRIM, systèmes de fichiers à copie
   sur écriture) ;
8. **une entrée supprimée subsiste dans les sauvegardes déjà écrites** ;
9. la dénégation est impossible ;
10. la résistance à la coercition est nulle ;
11. **une horloge système fausse produit des codes TOTP faux, et Passlock ne peut pas
    le détecter.** TOTP est un protocole à secret partagé où le serveur est la seule
    référence temporelle ; la RFC 6238 §6 confie la resynchronisation au **validateur**,
    et Passlock est le **prouveur**. Aucune vérification en ligne n'est faite, par
    choix : le cœur n'a aucune dépendance réseau ;
12. **l'entropie annoncée suppose un CSPRNG du noyau uniforme et non compromis.**
    C'est une **hypothèse de conception**, jamais mesurée. Si `getrandom` est
    instrumenté, tout l'aléa est connu de l'attaquant ;
13. **un secret engendré ne protège que s'il est stocké ailleurs que dans un carnet.**
    Le générateur ne maîtrise pas ce qui suit sa sortie ;
14. **un site qui tronque, journalise ou impose un format faible annule la
    génération**, et Passlock ne peut pas le savoir sans réseau ;
15. **la valeur d'un champ est un `String`, qui ne s'efface pas de façon fiable** :
    ses réallocations peuvent laisser des fragments dans le tas. Limite héritée de la
    phase 2, documentée plutôt que corrigée ;
16. **les listes de mots sont vérifiées sur leur compte, leur format, leur unicité et
    leur empreinte — pas sur leur qualité linguistique ni sur l'absence de biais dans
    leur construction d'origine.**

**Le mot « sécurisé » n'est jamais employé sans qualifier l'adversaire et les
conditions.**

## 10. Divulgation de vulnérabilité

Un défaut dans un gestionnaire de secrets peut compromettre l'ensemble des comptes
d'un utilisateur. En conséquence :

* **n'ouvrez pas de rapport public** avant qu'un correctif ne soit disponible ;
* décrivez le problème, la version, la plateforme, et un scénario de reproduction
  minimal ;
* précisez s'il s'agit d'une **faille de conception** (le format ou l'architecture
  est en cause) ou d'un **défaut d'implémentation** — la première est bien plus
  grave, car elle peut ne pas être corrigeable sans rupture de format.

Aucun canal dédié n'existe encore. En attendant, la procédure doit passer par un
canal privé du dépôt.

## 11. Risques introduits par phase

**Le contenu, l'ordre, les dépendances et l'état des phases ne sont pas définis ici.**
Ils font autorité dans [`ROADMAP.md`](ROADMAP.md). Une version antérieure de cette
section dupliquait le contenu des phases, ce qui a effectivement produit une
divergence documentaire ; elle a été supprimée au profit d'un renvoi.

Ce que ce document possède, et que `ROADMAP.md` ne possède pas : le **risque
principal** que chaque phase introduit, et où il est traité.

| Phase | Risque principal introduit | Où il est traité |
|---|---|---|
| 0 | aucun (pas de code) | — |
| 1 | surface de traitement de fichiers non fiables avant authentification | §4.5, `docs/VAULT_FORMAT.md` |
| 2 | historique conservant des secrets que l'utilisateur croit supprimés ; injection de requête *(écartée en abandonnant SQLite)* | §4.5, L22 |
| 3 | faiblesse du générateur ; **revendication d'entropie trop généreuse** ; injection de séquences d'échappement par un libellé TOTP ; **le TOTP rangé dans le même coffre n'apporte aucune protection contre la compromission de ce coffre** ; horloge fausse indétectable | §4.6, §4.7, L16–L21, L23 |
| 4 | **export en clair — fuite massive et délibérée** ; parseurs d'import à fuzzzer ; **presse-papiers comme canal public** ; ramasse-miettes de pièces jointes supprimant des fichiers | L22, T32, `docs/TOTP.md` §8 |
| 4 *(étape 1, livrée)* | **un slot supplémentaire est un chemin d'entrée de plus** — récupérabilité et résistance au vol varient en sens inverse ; **le fichier-clé n'est pas un facteur matériel** (L26) ; **la durabilité réduite sous Windows** peut laisser une promesse non tenue après coupure (L27) ; un secret affiché sur stdout est redirigeable | §4.8, §8, L26, L27, `docs/AUDIT_PHASE4_1_RECUPERATION.md` |
| 5 | **faux sentiment de protection** — un centre de sécurité qui rassure sans rien garantir ; regroupement de domaines par eTLD+1 erroné dans certains cas, notamment sur un suffixe absent d'une liste vieillissante (L25) ; `expires_at` est le **seul** élément de la phase qui écrit dans les entrées, et il écrit une donnée fournie par l'utilisateur | à traiter **en phase 5** ; décisions déjà tranchées en `ROADMAP.md` §5.3 et §5.4 |
| 6 | webview ; IPC ; CSP ; **extension de la durée de vie de la clé en mémoire** par la session déverrouillée | à traiter **en phase 6**, et à documenter ici |
| 7 | **un audit externe non réalisé alors que le produit se présente comme vérifié** | §Statut, L10 |

**Les deux risques les plus élevés de cette table ne sont pas techniques.** Le
« faux sentiment de protection » de la phase 5 et l'absence d'audit externe de la
phase 7 sont des risques de **revendication** : ils ne cassent rien, ils font croire.
C'est aussi la raison pour laquelle la phase 7 distingue explicitement, dans
`ROADMAP.md`, ce qui peut être produit par l'agent et ce qui exige un tiers.

## 12. Vérifier soi-même

Commandes qui étayent les affirmations de ce document :

```sh
# Aucun `unsafe` dans le moteur cryptographique. Les commentaires sont exclus : le
# mot y apparaît dans les explications, jamais comme code.
grep -rn "unsafe" crates/passlock-core/src \
  | grep -vE "^[^:]+:[0-9]+:\s*(//|///|//!)" \
  | grep -v "forbid(unsafe_code)"

# Le magasin : format d'archive, bornes, migration
cargo test -p passlock-core --test adversarial_archive
cargo test -p passlock-core --test store
cargo test -p passlock-core --test semantic_model    # ~9 500 opérations vs modèle

# Conformité TOTP et Base32 : les vecteurs OFFICIELS des RFC, pas les nôtres
cargo test -p passlock-core --test rfc_vectors       # 10 RFC 4226 + 18 RFC 6238 + 7 RFC 4648
cargo test -p passlock-core --test otpauth_adversarial
cargo test -p passlock-core --test secret_inventory
cargo test -p passlock-core --test wordlist_integrity # empreintes SHA-256 upstream

# Le générateur, à la main : le rapport va sur stderr, le secret sur stdout.
passlock generate --length 20 --charset luds
passlock secret --bytes 32 --format base64url
passlock passphrase --words 6 --language fr

# Le TOTP de bout en bout, contre un vecteur officiel de la RFC 6238.
# (le mot de passe maître est lu AVANT le secret sur l'entrée standard)
printf '%s\nGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' "$MOT_DE_PASSE" \
  | passlock entry totp set COFFRE "$ID" --password-stdin --digits 8
MOT_DE_PASSE="$MOT_DE_PASSE" passlock totp COFFRE "$ID" --at 59
# → doit afficher 94287082

# Sanitizers : commandes réellement exécutées (nightly requis)
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -Zbuild-std \
  --target x86_64-unknown-linux-gnu --workspace
RUSTFLAGS="-Zsanitizer=thread"  cargo +nightly test -Zbuild-std \
  --target x86_64-unknown-linux-gnu -p passlock-core --lib
cargo +nightly miri test -p passlock-core --lib bytes::
cargo +nightly miri test -p passlock-core --lib header::
cargo +nightly miri test -p passlock-core --lib payload::
cargo +nightly miri test -p passlock-core --lib query::
cargo +nightly miri test -p passlock-core --lib model::
cargo +nightly miri test -p passlock-core --lib migrate::

# Campagne de pression mémoire (aucun paramètre cryptographique modifié)
scripts/measure-memory-pressure.sh

# Compilation Windows réelle : signatures FFI et types
cargo check --target x86_64-pc-windows-msvc --workspace --all-targets

# Le cœur n'a ni dépendance réseau, ni macro procédurale, ni bibliothèque de
# sérialisation (les trois commandes doivent être vides)
cargo tree -p passlock-core | grep -Ei "reqwest|hyper|tokio|tls|ureq"
cargo tree -p passlock-core | grep -Ei "proc-macro|syn v|quote|proc-macro2"
cargo tree -p passlock-core | grep -Ei "serde|zerocopy|ciborium"

# Audit de dépendances : avis de sécurité, licences, bans, sources
cargo deny check

# Permissions du coffre après création (attendu : 600)
stat -c '%a %n' coffre.plk

# Latence de déverrouillage réellement mesurée sur cette machine
passlock calibrate --budget 5
```
