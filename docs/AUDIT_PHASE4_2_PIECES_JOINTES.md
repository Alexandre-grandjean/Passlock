# Audit adversarial — phase 4, étape 2 : pièces jointes

> Rapport **séparé**, comme pour les phases 1 à 3. Il distingue ce qui a été **livré**, ce
> qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui reste **non
> vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés écrites
> tiennent ; les propriétés non écrites ne sont pas couvertes.

---

## 1. Ce qui a été livré

### 1.1 Domaines cryptographiques — `keys.rs`

`K_attachments` **n'existe plus après `subkeys()`** : elle est dérivée, employée pour
produire `K_blob_name` (HMAC) et `K_blob_aead` (AEAD), puis **détruite**. Les appelants
n'obtiennent que les deux clés de travail.

| Élément | Contenu |
|---|---|
| `INFO_BLOB_NAME` / `INFO_BLOB_AEAD` | `passlock/v1/blob-name`, `passlock/v1/blob-aead` |
| `SubKeys::blob_name()` / `blob_aead()` | seuls accès aux clés du domaine « pièces jointes » |
| `K_index` | **inchangée** : trois usages d'une même primitive, séparés par étiquette de message |

**Écart assumé par rapport au plan.** Celui-ci prévoyait que `K_attachments` devienne un
champ **privé** de `SubKeys`. Le compilateur a signalé un champ jamais lu, ce qui a montré
qu'il n'avait **aucune raison d'être conservé** : la racine est maintenant détruite après
usage. `I-KEYDOMAIN` est donc **structurellement** impossible à enfreindre, et non
seulement déconseillé.

### 1.2 Format de pièce jointe — `attachment.rs` *(nouveau)*

Spécification complète dans **`docs/ATTACHMENT_FORMAT.md`**. En résumé : magic `ATB1`,
header de 40 octets à offsets fixes **sans parseur**, morceaux de 1 Mio, AAD
`header_octets ‖ vault_id ‖ index`, `content_mac` lié au coffre, au blob et à la taille.

| Fonction | Rôle |
|---|---|
| `seal_blob` | chiffre un flux vers un blob, rend le header et le MAC de contenu |
| `AttachmentReader` | lit un blob, et **ne rend son verdict qu'en fin de flux** |
| `verify_blob` | lit jusqu'au bout, sans écrire le clair ailleurs qu'en mémoire bornée |
| `sweep_blobs` | rend **trois** constats séparés : orphelins, fichiers étrangers, absences |
| `blob_dir_for` / `blob_file_name` / `is_blob_name` | emplacement et nommage, **règle unique** |

### 1.3 Magasin — `store.rs`

`add_attachment`, `remove_attachment`, `purge_blob`, `delete_blob_by_name`,
`attachments_of`, `attachment`, `attachment_dir`, `blob_path`.

**Aucun `AuditKind` ajouté.** Le type est un ensemble **fermé** à valeurs d'octets fixes :
une variante nouvelle rendrait tout coffre écrit par ce binaire **illisible par l'ancien**,
donc exigerait une montée de version de format (ADR-025). Un ajout ou un retrait de pièce
jointe est consigné comme **`EntryUpdated`** — ce qui est exact : l'entrée a changé.

### 1.4 Crate plateforme — `publish_no_replace`

Nouvelle primitive : publie un temporaire sous son nom définitif **sans écraser**.
`linkat` + `unlinkat` sous Unix (le lien refuse une cible existante, et sa pose est
atomique) ; `MoveFileExW` **sans** `MOVEFILE_REPLACE_EXISTING` sous Windows.

### 1.5 Interface en ligne de commande — `attach`

`add`, `list`, `get`, `verify`, `rm`, `gc`.

---

## 2. Ce qui a été **réellement exécuté**

| Outil | Portée | Résultat |
|---|---|---|
| `cargo fmt --all -- --check` | espace de travail | **propre** |
| `cargo clippy --workspace --all-targets` | Linux | **0 avertissement** |
| `cargo clippy --target x86_64-pc-windows-msvc …` | Windows | **0 avertissement** |
| `cargo test --workspace` | espace de travail | **556 tests, 0 échec** |
| `cargo check --target x86_64-pc-windows-msvc --workspace --all-targets` | Windows | **passe** |
| `cargo deny check` | advisories, bans, licences, sources | **4/4 ok** |
| `cargo +nightly fuzz run parse_attachment_blob` | 90 s | **40 464 719 exécutions, 0 plantage** |
| `cargo +nightly fuzz run parse_recovery_key` | 60 s | 518 711 exécutions, 0 plantage *(étape 1)* |

**Tests d'intégration ajoutés : 24** — 15 pour le format (`attachment_format.rs`), 9 pour le
magasin (`attachment_store.rs`).

**Essai de bout en bout sur des fichiers réels :** pièce jointe de 3 000 000 octets
(3 morceaux), restituée **octet pour octet** ; refus d'écraser une destination existante ;
orphelin supprimé par `gc` ; fichier étranger **préservé** ; blob corrompu **signalé et
préservé**.

---

## 3. Les quatre contrôles demandés en revue, et où ils sont tenus

### 3.1 Collision du nom de blob

Le nom est un HMAC **tronqué à 128 bits**. `O_EXCL` (Unix) / `CREATE_NEW` (Windows) est la
garantie ultime : la création **échoue** plutôt que d'écraser, et `seal_new_blob` tire
alors un **nouvel identifiant** et recalcule le nom, jusqu'à `MAX_BLOB_NAME_ATTEMPTS`.

La collision est détectée **avant** de lire la source : réessayer ne consomme donc pas le
flux.

**Ce que la revue a fait changer.** Ce n'est pas la boucle qui a été testée — provoquer une
collision de HMAC sur 128 bits est hors de portée — mais l'**effet observable** de la
même garantie :
`an_attachment_never_overwrites_an_occupant_of_the_blob_directory` place un occupant bien
formé dans le répertoire, ajoute une pièce jointe, et vérifie que **l'occupant survit
intact**.

Ce qui **n'est pas** vérifié, et qu'il ne faut pas présenter comme acquis : le chemin de
**réessai** lui-même, qui ne s'exécute qu'en cas de collision réelle.

### 3.2 `I-BLOB-ORDER` sur le vrai chemin d'intégration

`the_blob_is_on_disk_before_its_metadata_is_saved` exerce la frontière **`Store` /
`Vault::save`**, en trois temps :

1. après `add_attachment` et **avant** `save`, le blob est sur le disque ;
2. **un second magasin, ouvert en lecture seule, ne voit aucune métadonnée** — c'est la
   preuve observable que l'enregistrement n'a pas encore eu lieu ;
3. après `save`, les deux sont là, et le balayage est cohérent.

Deux tests complètent :

* `an_interruption_before_save_leaves_an_orphan_and_an_openable_vault` — l'incident
  laisse **un orphelin** et un coffre qui s'ouvre ;
* `removal_keeps_the_metadata_first_and_the_file_last` — retrait → le fichier est
  **encore là** ; `save()` → puis suppression physique ; résultat cohérent.

Le test d'ordre **injecté** de l'étape 1 (enregistreur d'appels) reste en place dans
`tests/fs_private.rs` pour la primitive ; celui-ci éprouve le chemin réel.

### 3.3 Séparation stricte entre vérification et ramasse-miettes

| Commande | Ce qu'elle fait |
|---|---|
| `attach verify` | **observe et signale** — ne modifie rien, ne répare rien, ne supprime rien |
| `attach gc` | supprime **uniquement** les orphelins, après confirmation par identifiant du coffre |

Trois propriétés, chacune tenue par construction **et** par test :

* **un blob référencé mais corrompu n'est ni orphelin ni absent** — il est *présent*
  (`a_corrupted_blob_is_reported_by_verify_and_never_deleted_by_gc`). Il n'est donc jamais
  candidat à la suppression, et la corruption ne devient pas une perte de données ;
* **une absence est une erreur d'intégrité, pas un déchet**
  (`a_missing_blob_is_an_integrity_error_not_a_deletion_candidate`) ;
* **un fichier étranger n'est jamais supprimé** — observé en essai réel : `notes.txt` a
  survécu à `gc`, et le message le dit.

`attach verify` a été **volontairement doté d'un code de retour non nul** en présence
d'incohérences : un outil de vérification qui se tait ne sert à rien. Essai réel : après
corruption, `attach verify` sort en erreur en nommant la pièce jointe en défaut.

### 3.4 Garanties de système de fichiers jusqu'à la CLI

Le module `attach` **n'appelle ni `std::fs`, ni `Path::exists`, ni une suppression
directe**. Tout passe par `passlock-platform` :

| Opération | Primitive |
|---|---|
| Lire la source à attacher | `fs::open_read` (marche sans lien symbolique, refus des non-fichiers) |
| Créer un blob | `fs::create_private_file` (`O_EXCL` / `CREATE_NEW`, permissions à la création) |
| Créer le répertoire des blobs | `fs::create_dir_private` (**`mkdirat` est le contrôle** : aucun `path_exists` préalable) |
| Rendre durable | `fs::make_durable` → `Durability`, **vérifié** contre ce que la plateforme déclare |
| Temporaire de `attach get` | `fs::create_private_file`, nom tiré du générateur du système |
| Publier la sortie | `fs::publish_no_replace` — **refuse une cible existante** |
| Supprimer un blob | `fs::remove_file`, après **revalidation** du nom par le magasin |
| Balayer le répertoire | `fs::list_dir`, `fs::path_exists` (énumération seulement) |

**Contrôle associé.** `delete_blob_by_name` **revalide** le nom (`is_blob_name`) avant
toute suppression, et le résout relativement au répertoire des blobs : le
ramasse-miettes ne peut donc pas viser un fichier étranger ni sortir du répertoire, quoi
qu'il reçoive. `deleting_a_blob_by_a_foreign_name_is_refused` le vérifie sur cinq noms,
dont `..` et un nom en majuscules.

**`attach get` ne publie rien s'il échoue.** Essai réel : destination existante → refus,
aucun fichier écrit, **aucun temporaire laissé** ; blob corrompu → refus, aucun fichier
publié, aucun temporaire laissé.

---

## 4. Défauts trouvés et corrigés

### D1 — **Une assertion du harnais de fuzzing affirmait une croyance fausse sur notre propre contrat** *(gravité : moyenne ; catégorie : oracle faux)*

**Comment il a été trouvé.** Par le **fuzzing**, en quelques centaines d'exécutions. La
cible `parse_attachment_blob` exigeait qu'une taille de morceau différente de celle du
format **ne puisse pas** être décodée — au motif qu'« aucune version connue ne la
produit ».

**Le défaut.** C'est faux, et délibérément : le décodeur **tolère** une autre taille de
morceau **dans la borne** de `MAX_DECODED_CHUNK_SIZE`, précisément pour qu'un fichier écrit
par une version future — ou par une autre implémentation du format — reste lisible. La
garde du décodeur est bornée, et c'est la borne qui compte.

**Pourquoi c'est un défaut, et pas une simple erreur de test.** Une assertion qui décrit
une règle que le code n'applique pas est un **oracle faux** : elle aurait « validé » un
durcissement futur qui aurait cassé la compatibilité de lecture, en le présentant comme une
correction.

**Correction.** L'assertion est retirée au profit de la borne réelle — `1 ≤ chunk_size ≤
64 Mio` — avec le motif écrit dans la cible.

### D2 — **Le commentaire du modèle sur `content_mac` était sous-spécifié** *(gravité : faible ; catégorie : documentation imprécise sur une valeur de sécurité)*

`model/mod.rs` documentait `content_mac` comme `HMAC(K_index, contenu en clair)`. La
définition réelle — et désormais écrite — lie **le coffre, le blob et la taille** :

```
HMAC(K_index, "passlock/v1/attachment-content-mac" ‖ vault_id ‖ blob_id ‖ taille ‖ clair)
```

Un commentaire « un HMAC du contenu » laissait ouverte la question de ce qui est
authentifié. La valeur est maintenant **auto-descriptive**, et l'écart est consigné dans le
code lui-même.

---

## 5. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **Le chemin de réessai en cas de collision de nom** | Provoquer une collision de HMAC sur 128 bits est hors de portée. Ce qui est vérifié est l'**effet** de la même garantie : rien n'est jamais écrasé |
| NV2 | **Le lecteur de blob sous fuzzing** | Il exige un fichier ; ses contrôles de structure sont couverts par les tests d'intégration, pas par la cible de fuzzing. La cible couvre le **décodage du header**, qui est la surface d'entrée non fiable |
| NV3 | **L'exécution Windows** — `linkat` n'existe pas, `MoveFileExW` sans remplacement | Code **compilé et vérifié statiquement**, **jamais exécuté**. Limites L9 et L2 |
| NV4 | **`sweep_blobs` sur un répertoire de plusieurs milliers de blobs** | Le parcours est linéaire ; le comportement à grande échelle n'a pas été mesuré |
| NV5 | **Miri** sur les nouveaux chemins | Ils construisent des `Key` et manipulent des fichiers : `mlock` et les E/S excluent Miri |
| NV6 | **ASan et TSan** sur cette étape | Non relancés dans cette session |
| NV7 | **Le comportement d'un système de fichiers sans liens durs** pour `publish_no_replace` | Le refus est explicite, mais il n'a pas été observé sur FAT/exFAT |

---

## 6. Points de conception, et leur verdict

| # | Point | Verdict |
|---|---|---|
| 1 | Domaines de clés séparés | **Livré, et renforcé** — la racine n'est pas conservée, donc la réutilisation est structurellement impossible |
| 2 | Format borné, sans parseur | **Livré** — header à offsets fixes, `chunk_count` recalculé, longueur comparée avant allocation |
| 3 | AAD avec index du morceau | **Livré et discriminant** — `permuting_two_chunks_is_detected` échoue si l'index est absent |
| 4 | Ce que l'AEAD ne couvre pas | **Dit sans l'embellir** — troncature et rejeu sont détectés par les métadonnées et `content_mac`, et les tests le **nomment** |
| 5 | Validité du clair | **Sémantique d'API explicite** — un morceau est authentique, pas validé ; `an_intermediate_chunk_is_not_a_verdict` l'observe |
| 6 | `I-BLOB-ORDER` | **Éprouvé à la frontière réelle** `Store`/`Vault::save`, pas seulement par un ordre injecté |
| 7 | Collision de nom | **`O_EXCL` est la garantie ultime**, et rien n'est jamais écrasé |
| 8 | Vérification et GC séparés | **Séparés par construction** — trois constats, trois décisions ; une corruption n'est jamais un déchet |
| 9 | Garanties de fichiers jusqu'à la CLI | **Respectées** — aucune E/S directe dans le module `attach` |
| 10 | `AuditKind` non étendu | **Respecté** (ADR-025) — `EntryUpdated` décrit exactement ce qui se passe |
| 11 | Aucun changement de format de coffre | **Respecté** — la section `attachments` existait depuis la phase 2, bornée et vide |

---

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Une sauvegarde du seul fichier de coffre ne préserve pas les pièces jointes** | Dit à chaque `attach add`, et documenté dans `ATTACHMENT_FORMAT.md` §1. Le chantier « sauvegardes » (étape 3) doit inclure le répertoire des blobs |
| R2 | **Le chemin de réessai sur collision n'a pas été exécuté** | La garantie qui compte — **rien n'est écrasé** — est vérifiée ; le réessai est du code de secours, borné, et son échec est une erreur franche |
| R3 | **Un blob référencé mais corrompu reste inaccessible**, et `attach verify` ne répare rien | Voulu : la commande **signale**. La réparation appartient à une restauration de sauvegarde, pas à un outil qui supprime |
| R4 | **`publish_no_replace` repose sur les liens durs** sous Unix | Un système de fichiers sans liens durs fait échouer la publication avec un message explicite ; rien n'est publié à moitié |
| R5 | **Le répertoire des blobs n'est pas chiffré** — seuls les contenus le sont | Les **tailles** et le **nombre** de pièces jointes sont observables par le système de fichiers, comme la taille du coffre. Aucun nom d'origine, aucun type |

---

## 8. Verdict

**Livré et vérifié.** Domaines de clés séparés (et rendus structurellement impossibles à
confondre), format de pièce jointe borné et documenté octet par octet, magasin,
commandes `attach` — 556 tests, clippy à zéro sur **deux** cibles, `cargo deny` 4/4, et
**40,5 millions** d'exécutions de fuzzing sans plantage.

**Un défaut réel trouvé et corrigé** (D1) : une assertion du harnais affirmait une règle que
le code n'applique pas — un **oracle faux**, trouvé par le fuzzing et non par relecture. Ce
n'est pas un défaut du produit, mais c'est exactement le genre d'erreur qui aurait
« validé » un durcissement cassant la compatibilité de lecture.

**Deux écarts au plan, assumés et préférables :** la racine `K_attachments` est **détruite**
plutôt que conservée privée (`I-KEYDOMAIN` structurel), et le test « morceau court non
final » est remplacé par celui qui établit la **construction** qui le rend impossible — une
propriété garantie par construction n'a pas besoin d'un test artificiel.

**Ce qui reste non vérifié** est au §5, au premier rang desquels **l'exécution Windows**,
qui couvre maintenant `publish_no_replace` et la DACL, et **le chemin de réessai sur
collision**.

**Étape close.** Les étapes 3 à 5 de la phase 4 ne sont pas commencées.
