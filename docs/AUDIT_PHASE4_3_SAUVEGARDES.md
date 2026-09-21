# Audit adversarial — phase 4, étape 3 : sauvegardes et test de restauration

> Rapport **séparé**, comme pour les étapes précédentes. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui reste
> **non vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés écrites
> tiennent ; les propriétés non écrites ne sont pas couvertes.

---

## 1. Ce qui a été livré

### 1.1 `VaultConfig::require_exclusive_lock` — `vault.rs`

Une ouverture en lecture seule ne prenait **aucun** verrou. C'est correct pour **un**
fichier : l'écriture du conteneur est atomique, un lecteur voit toujours un état complet.

Ce ne l'est plus pour un **ensemble**. Une sauvegarde copie le coffre **et** ses blobs ;
entre les deux lectures, un écrivain concurrent peut ajouter une pièce jointe, et la copie
contiendrait un coffre référençant un blob absent.

Le champ ajoute le verrou sans jamais retirer une garantie : `read_only` reste
`read_only`.

### 1.2 `backup.rs` *(nouveau)*

| Élément | Rôle |
|---|---|
| `BackupPlan` / `BackupMember` | énumère ce qui doit être copié, **sous verrou**, avant toute copie |
| `create` | copie en flux, rend durable, **puis vérifie**, et retire ce qu'il a créé en cas d'échec |
| `verify` | ouvre la copie en **lecture seule imposée**, décode l'archive, déchiffre chaque pièce jointe |
| `Integrity` / `Age` / `RestoreReport` | deux verdicts **séparés** |
| `Created` | trace ce qui a été **réellement créé**, pour que le nettoyage ne retire que cela |

**Aucun format nouveau.** Le fichier de sauvegarde *est* un coffre.

### 1.3 Interface en ligne de commande — `backup`

`backup create <COFFRE> <DESTINATION>`, `backup verify <SAUVEGARDE>`.

**Aucune commande de restauration**, délibérément : la procédure est documentée
(`docs/BACKUP.md`) et rappelée par `backup verify` avec les deux chemins exacts.

---

## 2. Ce qui a été **réellement exécuté**

| Outil | Portée | Résultat |
|---|---|---|
| `cargo fmt --all -- --check` | espace de travail | **propre** |
| `cargo clippy --workspace --all-targets` | Linux | **0 avertissement** |
| `cargo clippy --target x86_64-pc-windows-msvc …` | Windows | **0 avertissement** |
| `cargo test --workspace` | espace de travail | **569 tests, 0 échec** |
| `cargo check --target x86_64-pc-windows-msvc --workspace --all-targets` | Windows | **passe** |
| `cargo deny check` | advisories, bans, licences, sources | **4/4 ok** |
| `cargo +nightly fuzz build` | **les 7 cibles** | **compilent** |
| fuzzing — 4 cibles | voir §3 | **aucun plantage** |

**Tests d'intégration ajoutés : 13** (`tests/backup.rs`).

**Essais réels de bout en bout** sur un coffre contenant une pièce jointe de 2,5 Mio :

* `backup create` → couple produit, **vérifié avant d'être annoncé** ;
* `backup verify` → intègre, et **aucun fichier créé** dans le répertoire de destination ;
* destination existante → refus, **occupant intact** ;
* répertoire parent absent → refus, message explicite ;
* coffre ayant avancé → **intégrité saine** *et* **ancienneté signalée** ;
* copie tronquée → **refus** (code de retour 1) ;
* pièce jointe absente ou corrompue dans la copie → **défauts d'intégrité**, code retour 1 ;
* la sauvegarde s'ouvre par les commandes ordinaires (`info`, `attach verify`).

---

## 3. Fuzzing : ce qui a été fait, et pourquoi ce n'est **pas** une nouvelle cible

**L'étape 3 n'ajoute aucun parseur.** `backup verify` exécute exactement les parseurs déjà
couverts — le conteneur (`vault_parse`), le header (`header_decode`), l'enveloppe
(`payload_decode`), le header de blob (`parse_attachment_blob`).

Inventer une cible « backup » aurait donc re-fuzzé les mêmes analyseurs sous un nom
nouveau, en donnant l'impression d'une couverture supplémentaire. **Ce qui manquait
réellement, c'était l'exécution des cibles déjà déclarées** — dont `SECURITY.md` (L12)
disait qu'elles n'avaient jamais tourné.

### 3.1 Exécutions

| Cible | Exécutions | Plantage |
|---|---|---|
| `vault_parse` | 38 118 006 | **aucun** |
| `header_decode` | 32 468 492 | **aucun** |
| `payload_decode` | 38 911 196 | **aucun** *(après correction — voir D3)* |
| `parse_attachment_blob` | 40 464 719 | **aucun** *(étape 2)* |

**Total : plus de 149 millions d'exécutions**, et **une cible déclarée qui ne compilait
pas** (§4, D3).

### 3.2 Effet sur L12

**L12 est partiellement levée** : `vault_parse`, `header_decode` et `payload_decode` ne
sont plus dans la catégorie « jamais exécutées ». `parse_otpauth` et `decode_base32`
restent non exécutées **dans cette session**, mais sont construites par la garde
`cargo +nightly fuzz build` ajoutée à l'intégration continue.

---

## 4. Défauts trouvés et corrigés

### D3 — **La cible de fuzzing `payload_decode` ne compilait pas, et portait donc une couverture nulle depuis la phase 2** *(gravité : moyenne ; catégorie : instrumentation morte)*

**Comment il a été trouvé.** En **exécutant** les cibles déclarées, à l'étape 3. Le
compilateur a refusé :

```
error[E0308]: mismatched types
  --> fuzz_targets/payload_decode.rs:35:18
35 |         encoded, data,
   |                  ^^^^ expected `Zeroizing<Vec<u8>>`, found `&[u8]`
```

**Le défaut.** `Payload::encode` rend `Zeroizing<Vec<u8>>` depuis le passage au
zéroïsage ; la cible comparait cette valeur à `&[u8]`. Elle **n'a donc jamais pu
s'exécuter**, tout en figurant :

* au manifeste `fuzz/Cargo.toml` ;
* **et** dans `.github/workflows/ci.yml`.

**Pourquoi c'est un défaut, et pas une simple erreur de compilation.** Une cible de
fuzzing qui ne compile pas est une **couverture nulle qui se présente comme une
couverture**. Elle figure dans les inventaires, elle est citée dans les audits, et elle ne
protège rien. C'est la même classe que le défaut D1 de l'étape 2 — un **oracle faux** — en
version instrumentale.

**Ce que cela dit de plus grave.** Le fichier d'intégration continue **listait** cette
cible. Un lecteur du dépôt pouvait donc légitimement croire qu'elle tournait. Or
l'intégration continue **n'a jamais été exécutée sur ce dépôt** : personne n'a jamais su
si elle passait. **Déclarer n'est pas exécuter**, et un fichier de configuration n'est pas
une preuve d'exécution.

**Correction, en deux parties.**

1. La comparaison est faite sur `&encoded[..]`.
2. Une garde `cargo +nightly fuzz build` est ajoutée **en tête** du job d'intégration
   continue : elle construit **toutes** les cibles d'un coup, de sorte qu'une cible qui ne
   compile pas échoue en quelques secondes au lieu de porter silencieusement une couverture
   nulle.

### D4 — **`backup create` pouvait supprimer un répertoire qu'il n'avait pas créé** *(gravité : moyenne ; catégorie : destruction de données d'autrui ; trouvé par relecture, avant tout test)*

**Le défaut.** La première rédaction nettoyait d'après le **plan** : elle retirait
`blob_dir` dès qu'il y figurait, sans savoir si la session l'avait créé. Un répertoire
`<DESTINATION>.attachments/` **préexistant et vide** — celui d'une sauvegarde antérieure,
par exemple — aurait donc été **supprimé** par un `backup create` échouant avant même de
l'utiliser.

**Pourquoi la relecture l'a trouvé avant les tests.** Le contrat demandé était
« nettoie **uniquement** ce qu'il a créé ». Le code nettoyait d'après une **intention**
(le plan) et non d'après un **fait** (une création réussie). L'écart était visible dans la
structure, pas dans le comportement observable des cas nominaux.

**Correction.** Le nettoyage s'appuie sur `Created`, qui n'enregistre que les créations
**effectivement réussies**. Un `AlreadyExists` du `mkdirat` signifie que le répertoire
existait **déjà** : il n'est donc pas enregistré, et jamais retiré.

**Test associé.** `a_failed_copy_removes_only_what_it_created` occupe le chemin du
répertoire de blobs par un **fichier** : la copie échoue, le fichier de coffre déjà copié
est **retiré**, et l'occupant est **intact**.

### D5 — **Les messages d'échec de création n'étaient pas exploitables** *(gravité : faible ; catégorie : ergonomie trompeuse)*

Un répertoire de destination absent produisait « erreur d'entrée/sortie : No such file or
directory », sans dire **quel** chemin. Une destination existante produisait « File exists
(os error 17) », sans dire que c'était **délibéré**.

**Correction.** Le motif de l'échec est nommé — « le répertoire de destination n'existe
pas », « la destination existe déjà ; elle n'est jamais écrasée ».

**Ce qui n'a pas été fait.** Aucun `path_exists` préalable n'a été ajouté : ce serait
rouvrir la fenêtre que `O_EXCL` ferme. Le contrôle reste **la création elle-même** ; seul
le message est amélioré.

---

## 5. Les exigences contractuelles, et où elles sont tenues

| Exigence | Où |
|---|---|
| sauvegarde = `(<DESTINATION>, <DESTINATION>.attachments/)` | `blob_dir_for` — règle **unique**, partagée avec le coffre vivant |
| verrou exclusif pendant la copie | `require_exclusive_lock` ; `a_backup_holds_the_lock_and_a_second_writer_is_refused` |
| copie du coffre **et** des blobs référencés | `BackupPlan`, énuméré sous verrou |
| vérification complète après copie | `create` appelle `verify` **avant** de réussir |
| échec contrôlé ⇒ nettoie **uniquement** ce qu'il a créé | `Created` ; `a_failed_copy_removes_only_what_it_created` |
| **aucune** atomicité de destination revendiquée | `docs/BACKUP.md` §2, dit explicitement |
| interruption brutale ⇒ destination partielle qui **échoue** à `verify` | `a_truncated_backup_fails_to_verify`, sur 7 longueurs de troncature |
| `backup verify` **strictement** sans effet persistant | config écrasée dans `verify` ; `verifying_a_backup_leaves_no_trace` |
| intégrité et ancienneté = **deux** verdicts | `Integrity` / `Age` ; `integrity_and_age_are_reported_separately` |
| procédure de restauration documentée | `docs/BACKUP.md` §4, et rappelée par `backup verify` |
| **test de restauration effectif**, pièces jointes comprises | `a_backup_restores_a_usable_vault_including_its_attachments` |
| durabilité via `make_durable`, Windows **non** rendu indisponible | `Durability` le plus faible des deux ; un `FileOnly` **avertit**, il ne bloque pas |
| pas de nouveau format de sauvegarde | le fichier produit est un coffre |

### 5.1 Le test de restauration effectif

**Vérifier n'est pas restaurer.** `backup verify` prouve qu'une copie est lisible ; il ne
prouve pas que la procédure écrite pour l'utilisateur produit un coffre utilisable.

Le test exécute donc la procédure **telle qu'elle est documentée** :

```sh
cp <sauvegarde> <coffre>
cp -a <sauvegarde>.attachments <coffre>.attachments
```

et il la recopie **à la main**, sans la factoriser dans un utilitaire : le test doit
éprouver la procédure écrite pour l'utilisateur, pas une variante commode qui pourrait
diverger d'elle. Puis :

1. le coffre restauré s'ouvre par le **chemin ordinaire** ;
2. l'entrée et la métadonnée de la pièce jointe sont présentes ;
3. le contenu de la pièce jointe est relu et comparé **octet pour octet** à l'original
   (2 400 000 octets, trois morceaux) ;
4. le coffre d'origine est **intact**.

Le point 3 est celui qui compte : sans la **seconde** copie, la métadonnée existerait et
le blob serait introuvable — exactement le mode de défaillance que la documentation
annonce, et que `a_backup_missing_its_blob_directory_is_not_sound` couvre de son côté.

---

## 6. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **L'exécution Windows** de `backup create` | Le code **compile** et passe l'analyse statique ; il n'a **jamais été exécuté**. `publish_no_replace` et la DACL restent dans ce cas |
| NV2 | **L'intégration continue n'a jamais tourné** sur ce dépôt | Elle liste sept cibles et trois cibles de fuzzing supplémentaires ; **rien ne prouve** qu'elle passe. C'est précisément ce qui a laissé D3 en place |
| NV3 | **Interruption brutale réelle** (coupure d'alimentation, `SIGKILL` au milieu d'une copie) | La troncature est **simulée** par réécriture du fichier. La conclusion — « une copie partielle échoue au test » — est établie ; le **comportement du système de fichiers** à l'instant de la coupure ne l'est pas |
| NV4 | **`backup create` sur un coffre de plusieurs gigaoctets** | La copie est en flux, donc bornée en mémoire ; la durée et le comportement à l'échelle n'ont pas été mesurés |
| NV5 | **Deux sauvegardes concurrentes du même coffre** | La deuxième est refusée par le verrou — testé pour un écrivain, pas pour une seconde sauvegarde |
| NV6 | **Restauration par-dessus un coffre vivant** | Aucune commande ne le fait, et le test restaure vers un emplacement neuf. Le cas « remplacer un coffre existant » n'est pas éprouvé, et c'est **délibéré** : il n'est pas outillé |
| NV7 | **Migration d'une sauvegarde de schéma antérieur** | Le rapport porte le champ ; le chemin de migration d'une sauvegarde n'a pas été exercé de bout en bout |
| NV8 | **Miri, ASan, TSan** sur cette étape | Non relancés |

---

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Une destination partielle occupe le chemin** : une nouvelle tentative échoue | Dit dans `docs/BACKUP.md` §2. Le reliquat doit être supprimé **explicitement** : écraser silencieusement serait pire |
| R2 | **La sauvegarde n'est pas atomique** sur le couple | Assumé et documenté. Ce qui est garanti est la **détection** : une copie incohérente échoue au test |
| R3 | **Le verrou ne protège pas d'un accès hors de Passlock** | Un tiers peut lire le fichier pendant la copie. Le conteneur reste chiffré ; le verrou protège la **cohérence**, pas la confidentialité |
| R4 | **`state_dir` n'est pas sauvegardé** | Une restauration fait réapparaître une génération ancienne et déclenche l'alerte de retour en arrière — comportement voulu, documenté §4 |
| R5 | **Une cible de fuzzing peut redevenir morte sans que rien ne le signale** | La garde `cargo +nightly fuzz build` couvre la classe « ne compile pas » ; elle ne couvre **pas** une cible qui compile sans rien exercer |

---

## 8. Verdict

**Livré et vérifié.** Sauvegarde en couple, verrou exclusif de l'ensemble, vérification
immédiate de la copie, nettoyage limité aux créations effectives, test de restauration
**effectif** incluant les pièces jointes — 569 tests, clippy à zéro sur **deux** cibles,
`cargo deny` 4/4, plus de **149 millions** d'exécutions de fuzzing sans plantage.

**Deux défauts trouvés, tous deux hors du chemin nominal** :

* **D4**, trouvé par **relecture** : le nettoyage retirait un répertoire d'après le plan,
  non d'après une création réussie — il pouvait donc supprimer un répertoire **d'autrui**.
* **D3**, trouvé en **exécutant enfin** les cibles déclarées : `payload_decode` ne
  compilait pas depuis la phase 2, et portait donc une **couverture nulle qui se présentait
  comme une couverture**. Sa leçon dépasse le fichier : il figurait **aussi** dans le
  fichier d'intégration continue, qui n'a jamais tourné. **Déclarer n'est pas exécuter.**

**Ce qui reste non vérifié** est au §6, au premier rang desquels **l'exécution Windows** et
**l'intégration continue**, qui n'a jamais été lancée sur ce dépôt.

**Étape close.** Les étapes 4 et 5 de la phase 4 ne sont pas commencées.
