# Audit adversarial — phase 4, étape 1 : récupération

> Rapport **séparé**, comme pour les phases 1 à 3. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés
> écrites tiennent ; les propriétés non écrites ne sont pas couvertes.

Cette étape ouvre la phase 4. Elle livre **le socle transverse** (création exclusive
de fichiers, durabilité dépendante de la plateforme) et le **premier des cinq
chantiers** : la récupération.

---

## 1. Ce qui a été livré

### 1.1 Cœur — `passlock-core`

| Fichier | Contenu |
|---|---|
| `src/recovery.rs` *(nouveau)* | Crockford Base32, total de contrôle de 40 bits, `RecoveryKey` |
| `src/vault.rs` | `derive_slot_kek`, `unlock_with_kek(.., label)`, `unlock_with_slot_label`, `Credentials`, `Vault::open_with`, `install_slot` / `replace_slot` / `revoke_slot` / `slot_labels` |
| `src/store.rs` | `VaultStore::open_with` |
| `src/lib.rs` | déclaration `pub mod recovery` |

**Aucune modification de format.** Aucune clé dérivée n'est persistée, aucun octet du
conteneur ou de l'archive ne change, aucune migration n'est nécessaire. Le slot de
rôle `Recovery` (label 2) était **déjà** réservé depuis la phase 1 et déjà décodable.

**Modifications de signatures, exhaustives.** `derive_master_kek(header, password)` →
`derive_slot_kek(header, label, secret)` et `unlock_with_kek(bytes, kek)` →
`unlock_with_kek(bytes, kek, label)`. Ces deux fonctions n'avaient **aucun appelant
hors de `vault.rs`** (production et tests unitaires) : la vérification a été faite par
recherche textuelle avant de changer la signature. Les 6 sites de test internes ont été
mis à jour ; **aucun test d'intégration n'était concerné**.

### 1.2 Crate plateforme — le socle transverse (§9 du plan)

| Fonction | Unix | Windows |
|---|---|---|
| `create_private_file` | marche sans lien symbolique + `O_CREAT\|O_EXCL\|O_NOFOLLOW`, 0600 | `ensure_no_symlink_components` + `CreateFileW(CREATE_NEW)` + DACL |
| `make_durable` → `Durability` | `fsync(fichier)` **puis** `fsync(répertoire)` | `FlushFileBuffers(fichier)` seul |
| `platform_durability` | `DirectoryEntrySynced` | `FileOnly` |
| `create_dir_private` | `mkdirat(0700)` + `fsync(parent)` | `CreateDirectoryW` + DACL |
| `remove_file` / `remove_dir` | `unlinkat` (avec/sans `AT_REMOVEDIR`) | `DeleteFileW` / `RemoveDirectoryW` |
| `list_dir` | `fdopendir`/`readdir` sur le descripteur vérifié | `FindFirstFileW`/`FindNextFileW` |
| `read_file` / `open_read` | lecture bornée, refus des non-fichiers | idem |
| `path_exists` | `fstatat(AT_SYMLINK_NOFOLLOW)` | `GetFileAttributesW` |

`sync_file` et `sync_dir` existent mais sont **privées** : elles sont un détail
d'implémentation de `make_durable`, ce qui rend le scénario « `sync_dir` rend
`Unsupported`, l'appelant l'ignore » **structurellement impossible**.

### 1.3 Interface en ligne de commande

| Commande | Effet |
|---|---|
| `recovery new [--force]` | crée et installe une clé de 256 bits, l'affiche **une fois** sur stdout |
| `recovery test` | déverrouille réellement avec la clé — le seul moyen de savoir qu'elle marche |
| `recovery remove --confirm <ID>` | révoque le slot |
| `keyfile new --key-file <CHEMIN>` | écrit un fichier de 32 octets et installe le slot matériel |
| `keyfile test --key-file <CHEMIN>` | déverrouille avec le fichier |
| `keyfile remove --confirm <ID>` | révoque le slot |

Deux options **globales** : `--recovery-key-stdin` et `--key-file <CHEMIN>`, mutuellement
exclusives. `open_store` devient le **seul** point qui choisit le chemin d'ouverture.
`GlobalOptions` est passé par référence (il n'est plus `Copy`), ce qui a demandé un
remaniement mécanique de 19 signatures et 12 sites d'appel.

Le **niveau de durabilité** est rapporté à l'ouverture du coffre, aux côtés des
avertissements de durcissement : sous Unix, aucune ligne (niveau nominal) ; ailleurs,
une ligne explicite.

---

## 2. Ce qui a été **réellement exécuté**

| Outil | Portée | Résultat |
|---|---|---|
| `cargo fmt --all -- --check` | espace de travail | **propre** |
| `cargo clippy --workspace --all-targets` | Linux, tous les tests | **0 avertissement** |
| `cargo clippy --target x86_64-pc-windows-msvc --workspace --all-targets` | Windows | **0 avertissement** |
| `cargo test --workspace` | espace de travail | **528 tests, 0 échec** |
| `cargo check --target x86_64-pc-windows-msvc --workspace --all-targets` | Windows | **passe** |
| `cargo deny check` | advisories, bans, licences, sources | **4/4 ok** |
| `cargo +nightly fuzz run parse_recovery_key` | 60 s | **518 711 exécutions, 0 plantage** |
| `grep "unsafe" crates/passlock-core/src` | hors commentaires | **vide** |
| `cargo tree -p passlock-core \| grep proc-macro…` | arbre du cœur | **vide** (`I12` intact) |

**Ligne de base.** P1 a été exécuté **avant** toute modification fonctionnelle :
473 tests, 0 échec, `deny` 4/4 — exactement ce qu'annonçait `AUDIT_PHASE3.md` §2.1. Le
dépôt est sous contrôle de version depuis P0, commit de référence `730dc42`, tagué
`phase-3-geled`.

**Essai de bout en bout, sur des fichiers réels.** Effectué à la main, avec un coffre
créé par le binaire :

```
$ passlock recovery new --password-stdin coffre.plk > cle.txt
$ cat cle.txt
WMKTK-1A140-XNDK7-K3DP3-WV98J-41Z7S-XGVQ4-GV9R4-HNND5-SE60H-20PB2-5YC4C

$ passlock recovery test --password-stdin coffre.plk        # clé sur stdin
Clé de récupération valide : le coffre 121923d5… s'ouvre (génération 2).

$ passlock --recovery-key-stdin entry list coffre.plk
Aucune entrée.

$ passlock keyfile new --password-stdin coffre.plk --key-file cle.bin
$ stat -c '%a %n' cle.bin coffre.plk
600 cle.bin
600 coffre.plk

$ passlock info coffre.plk | grep -E "Slots|Slot "
Slots de clé     : 3
  Slot 0 — mot de passe maître
  Slot 1 — clé de récupération
  Slot 2 — clé matérielle
```

Trois contrôles qui comptent, et qui ont été observés :

* la clé est **seule** sur stdout — le fichier `cle.txt` fait **exactement 72 octets** :
  60 caractères significatifs, 11 séparateurs, un saut de ligne ;
* une clé **mal recopiée** est refusée par le **total de contrôle**, avant toute
  tentative de dérivation : `erreur : demande refusée : total de contrôle de la clé de
  récupération invalide`. Aucun Argon2id n'est lancé ;
* `recovery new` **exécuté avec une clé de récupération** échoue sur « mot de passe
  incorrect » : la clé ne peut pas installer de slot.

---

## 3. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **L'exécution Windows** — DACL, `CreateFileW`, `sync_file`, `platform_durability` | La cible compile et clippy passe, mais aucun binaire Windows n'est lié ni lancé. Limite **L9**, étendue à la DACL des fichiers sensibles (**L2**) |
| NV2 | **La DACL obtenue contient bien une seule ACE** | Exigerait `GetNamedSecurityInfoW` **et** une exécution. `mark_windows_acl_as_not_verified` vérifie seulement que la création réussit ou échoue franchement |
| NV3 | **La durabilité de l'entrée de répertoire sous Windows** | `platform_durability` y retourne `FileOnly` : c'est une déclaration, pas une mesure |
| NV4 | **Miri** sur les chemins nouveaux | `RecoveryKey` et `Credentials` construisent des `Key<N>`, donc un `SecretVec`, donc un `mlock` que Miri ne supporte pas (NV5 de la phase 3). Les modules purs restent couverts ; les nouveaux ne le sont pas |
| NV5 | **ASan et TSan** sur cette étape | **Non relancés** dans cette session. Ils l'avaient été aux phases 2 et 3 |
| NV6 | **La robustesse du corpus de fuzzing** | 518 711 exécutions réduisent la probabilité d'un défaut, elles ne la ramènent pas à zéro |
| NV7 | **La résistance du total de contrôle** | 40 bits : une erreur de recopie est détectée avec probabilité $1 - 2^{-40}$. Ce n'est **pas** une protection contre un adversaire qui fabrique une clé, et ce n'est pas ce qu'on lui demande |

---

## 4. Défauts trouvés et corrigés

### D1 — **Le nettoyage d'un fichier-clé détruisait le fichier préexistant de l'utilisateur** *(gravité : élevée ; catégorie : perte de données)*

**Comment il a été trouvé.** Par le test `a_key_file_is_never_overwritten`, écrit pour
vérifier une propriété simple : un fichier-clé préexistant n'est jamais écrasé.

**Le défaut.** `write_key_file` enveloppait toute la séquence dans une closure et, en
cas d'échec, appelait `remove_file(path)`. Or l'échec le plus courant est précisément
« la cible existe déjà » : la fonction **refusait d'écraser** le fichier de
l'utilisateur, puis **le supprimait**. Le test a observé un `NotFound` là où il
attendait le contenu d'origine intact.

**Pourquoi c'est grave.** Un fichier-clé peut être le **seul exemplaire** d'une clé
encore installée dans un autre coffre. Le détruire au moment où l'on refuse de
l'écraser transforme un refus poli en perte définitive — et l'utilisateur n'a aucun
moyen de le savoir, puisqu'il a vu un message d'erreur.

**Correction.** Le nettoyage n'est atteignable **qu'après** une création réussie :
`create_private_file` sort par `?` sans rien supprimer, et le `remove_file` n'existe que
sur le chemin « le fichier est le nôtre » (écriture ou synchronisation en échec).

**Ce que la correction dit du plan.** Le plan prescrivait « retirer ce qu'il a créé, et
rien d'autre ». Le défaut est exactement l'écart entre cette phrase et le code. Une
consigne de sûreté qui n'est pas **rendue structurellement impossible** finit par être
mal appliquée : ici, la seule garantie solide est que le chemin de suppression ne soit
pas atteignable quand rien n'a été créé.

### D2 — **Documentation fausse dans `passlock-platform/src/fs.rs`** *(gravité : moyenne ; catégorie : documentation fausse sur une propriété de sécurité)*

**Le défaut.** L'en-tête du module affirmait que les composants **intermédiaires** du
chemin n'étaient pas protégés, et que « seule une marche composant par composant ou
`openat2` répondrait complètement — non implémenté ». **C'était faux depuis la passe
V9–V12 de la phase 1** : `open_dir_no_symlinks` implémente exactement cette marche, et
`SECURITY.md` limite L1 est marquée **CORRIGÉE**.

**Pourquoi c'est un défaut.** Il fait passer une protection **réelle** pour absente,
ce qui fausse le jugement du lecteur — exactement l'inverse du défaut habituel, et tout
aussi trompeur. C'est la même catégorie que les défauts D4 et D5 de la phase 3.

**Correction.** Note de correction en place, renvoyant à la limite L1 et au §5.3 de
`THREAT_MODEL.md`.

### D3 — **Documentation fausse dans `passlock-platform/src/windows.rs`** *(gravité : faible ; catégorie : documentation fausse)*

**Le défaut.** L'en-tête affirmait que le fichier « n'a pas pu être compilé ni testé »,
et un commentaire justifiait une surface FFI réduite à deux appels par cette
impossibilité. La cible Windows est installée, `cargo check` passe, et cette compilation
avait même déjà révélé deux erreurs réelles.

**Correction.** L'en-tête distingue désormais explicitement **compilation VÉRIFIÉE** et
**exécution NON OBSERVÉE**, et la justification périmée de la surface réduite est
remplacée par la justification réelle de son élargissement : une DACL explicite vaut
mieux qu'une garantie héritée du profil, qui disparaît dès que le fichier est créé
hors du profil.

### D4 — **Deux tests que j'avais écrits étaient faux** *(gravité : moyenne ; catégorie : défaut de harnais)*

Voir §5. Consignés séparément parce qu'un oracle faux valide n'importe quoi.

### D5 — **`#[must_use]` redondant refusé par clippy** *(gravité : très faible)*

`Durability` est `#[must_use]` ; l'attribut posé sur `platform_durability` est
redondant, et clippy le refuse (lint `double_must_use`). Retiré.

---

## 5. Défauts de mon **harnais**, corrigés pendant le développement

| # | Défaut | Comment il s'est manifesté |
|---|---|---|
| H1 | `the_final_payload_character_carries_only_one_bit` supposait que le bit résiduel occupait la position **basse** du dernier caractère, donc une valeur de 0 ou 1 | Échec : « pas 16 ». Le bit occupe la position **haute**, donc la valeur est 0 ou 16, et l'assertion correcte est `valeur & 0b1111 == 0` |
| H2 | `a_wrong_length_is_refused` croyait tester 61 caractères en faisant `.take(61)` sur une chaîne de 60 | Échec : `take` ne rallonge pas. Le cas « trop long » est désormais construit en ajoutant un caractère |
| H3 | `a_vault_without_its_password_is_recovered_by_the_recovery_key_alone` ne relâchait pas le coffre ouvert avant de tester une clé étrangère | Échec : le message attendu était `UnlockFailed`, obtenu `AlreadyLocked`. **Le code avait raison, le test avait tort** — et c'est le verrou qui l'a dit |
| H4 | `Zeroizing<String>` n'implémente pas `Display` | Erreur de compilation, à deux endroits (CLI et cible de fuzzing). Le type **refuse délibérément** d'être formaté : c'est une protection, pas une gêne |

**Leçon, la même qu'en phase 3.** Trois des quatre défauts de harnais ont été trouvés
par une **exécution**, pas par relecture. H1 et H2 étaient des attentes fausses sur un
code juste ; H3 était un test qui mesurait autre chose que ce qu'il annonçait.

---

## 6. Points de conception, et leur verdict

| # | Point | Verdict |
|---|---|---|
| 1 | Crockford Base32 | **Livré** — alphabet fermé, `U` refusé, `I`/`L`→`1` et `O`→`0` normalisés, casse ignorée, séparateurs non significatifs |
| 2 | Total de contrôle | **Livré** — 40 bits de `SHA-256(domaine ‖ clé)`, vérifiés en **temps constant**. Détecte la faute de recopie **avant** toute dérivation |
| 3 | Canonicité | **Livré** — bits de remplissage nuls exigés : une seule chaîne par clé. Vérifié par `every_single_character_substitution_is_refused` (60 positions × 31 remplacements) |
| 4 | Un seul chemin d'ouverture | **Livré** — `Credentials` + `derive_slot_kek` + `unlock_with_kek(label)`. Le rôle ne change que le slot visé et le secret présenté |
| 5 | Coût d'un ajout de slot | **Dit sans l'embellir** — ce n'est **pas** O(1) sur le fichier : le header entre dans l'AAD, donc le prochain enregistrement ré-écrit le payload. Le bénéfice O(1) porte sur les **blobs**, pas sur l'archive |
| 6 | Ré-authentification | **Livré** — `install_slot` et `replace_slot` refusent le rôle maître ; `change_password` reste le seul chemin, et il exige le mot de passe actuel. Observé de bout en bout |
| 7 | Un slot ne se transpose pas | **Livré et éprouvé** — `a_recovery_slot_transplanted_into_another_vault_does_not_open` greffe **les octets** d'un slot dans un autre coffre : le header reste décodable, le désenveloppement échoue |
| 8 | Unicité des rôles | **Imposée à l'API**, pas au décodage (`I14`). Le corpus existant ne construit jamais deux slots de même rôle — **observé**, cf. P2 |
| 9 | Observation P2 n° 2 | **Vérifiée** — un header portant un slot `Recovery` se décode, ne perturbe pas l'ouverture par mot de passe, et n'ouvre rien sans sa clé |
| 10 | `write_atomic` non utilisé pour les fichiers neufs | **Respecté** — sa sémantique de **remplacement** le rend inadapté aux destinations qui doivent être neuves |
| 11 | Le nettoyage ne retire que ce qu'on a créé | **Corrigé après D1** — et rendu structurellement impossible sur le chemin « rien n'a été créé » |
| 12 | Durabilité rendue, non subie | **Livré** — `Durability` est `#[must_use]`, `platform_durability` est déclaré par plateforme, et un test interdit aux deux de diverger |
| 13 | Aucun secret en argument | **Respecté** — la clé de récupération vient d'une invite masquée ou de l'entrée standard ; le fichier-clé vient d'un **chemin**, qui n'est pas un secret |

---

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **La DACL Windows n'est pas observée**, et le repli est fermé : un bogue dans ce code rendrait les écritures sensibles impossibles sous Windows | Assumé et **annoncé**. L'alternative — écrire avec les ACL héritées — serait une garantie silencieusement absente. Reprise en phase 7 avec un exécuteur Windows réel |
| R2 | **La durabilité réduite sous Windows** peut laisser une métadonnée sans son blob après une coupure | Détectée par `attach verify` (étape 3). Le niveau est **rapporté à l'ouverture** |
| R3 | **Le total de contrôle n'est pas un mécanisme d'authentification** | Une clé fabriquée par un adversaire est bien formée. Ce n'est pas la propriété recherchée : la clé est **aléatoire sur 256 bits**, et c'est elle qui protège |
| R4 | **`recovery new` affiche la clé sur stdout**, donc redirigeable vers un fichier, un pipe ou un journal de session | Documenté et voulu : c'est le seul moyen de la remettre à l'utilisateur. Le rapport rappelle qu'elle n'est affichée qu'une fois |
| R5 | **Un slot est un chemin d'entrée de plus** | Dit à l'utilisateur à chaque installation, dans le rapport. Récupérabilité et résistance au vol varient en sens inverse |
| R6 | **`Credentials` emprunte** le matériel : si un appelant conservait la valeur au-delà de la durée de vie du matériel, le compilateur l'en empêcherait — mais un `unsafe` futur le pourrait | `passlock-cli` n'a pas d'`unsafe`, et le cœur non plus |

---

## 8. Verdict

**Livré et vérifié.** Socle transverse (§9) et chantier « récupération » :
528 tests, clippy à zéro sur **deux** cibles, `cargo deny` 4/4, `I12` intact, et
518 711 exécutions de fuzzing sans plantage.

**Un défaut réel de gravité élevée a été trouvé et corrigé** (D1) : le nettoyage
détruisait le fichier-clé préexistant de l'utilisateur. Il a été trouvé par un **test**
écrit pour vérifier la propriété inverse — « on ne l'écrase pas » — ce qui confirme
qu'une propriété de sûreté doit être vérifiée **par observation**, pas par relecture de
l'intention.

**Deux documentations fausses** (D2, D3) ont été corrigées : elles faisaient passer une
protection réelle pour absente, ce qui trompe autant qu'une protection absente.

**Quatre défauts de harnais** (H1–H4), dont deux attentes fausses sur un code juste et
un test qui mesurait autre chose que ce qu'il annonçait.

**Ce qui reste non vérifié** est au §3, et ne doit pas être présenté comme acquis — au
premier rang desquels **Windows**, dont le code est **compilé et vérifié statiquement**
(les signatures FFI et les types sont validés par le compilateur, clippy à zéro sur la
cible), mais dont **l'exécution réelle n'a jamais eu lieu**. En particulier, la **DACL
posée sur les fichiers sensibles ne peut pas être observée** ici, et la **durabilité
réduite** (`FileOnly`) est une **déclaration**, pas une mesure : ces trois propriétés
restent **NON VÉRIFIÉES** tant qu'un environnement Windows réel ne les exécute pas.
S'y ajoute **la couverture Miri**, que les nouveaux chemins ne peuvent pas atteindre
(`mlock`).

**Formulation à ne pas employer.** « L'exécution Windows couvre la DACL » est **faux** :
aucun binaire Windows n'a été lié ni lancé. Ce qui est établi est plus étroit, et doit
s'écrire ainsi : *le code Windows compile, ses signatures sont vérifiées
statiquement*. La distinction entre compiler et exécuter est celle qui rend la limite
**L9** exacte, et elle a déjà été confondue une fois dans ce projet — c'est pourquoi
elle est répétée ici.

**Étape close.** Les étapes 2 à 5 de la phase 4 ne sont pas commencées.
