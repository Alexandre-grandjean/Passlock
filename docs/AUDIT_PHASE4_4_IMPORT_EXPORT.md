# Audit adversarial — phase 4, étape 4 : import/export CSV

> Rapport **séparé**, comme pour les étapes précédentes. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés
> écrites tiennent ; les propriétés non écrites ne sont pas couvertes.

---

## 1. Ce qui a été livré

### 1.1 `portability.rs` — le format

| Élément | Rôle |
|---|---|
| `export` | projection **textuelle** des entrées, **triée par contenu** (11 colonnes), `entry_ref` attribué **après** tri |
| `stage` | analyse et validation **pures** : structure CSV, colonnes, échappements, structure des champs, types, bornes, invariants d'entrée — **sans toucher au magasin** |
| `import` | `stage` puis **application** : dossiers et tags résolus, entrées ajoutées ; **un seul** `save()` est laissé à l'appelant |
| `Context` | les quatre contextes d'échappement : scalaire, dossier, tag, champs |
| `Cursor` / `decode_fields` | analyseur **strict** de la structure canonique des champs |

**Aucun format nouveau côté coffre.** Le conteneur et l'archive ne changent pas d'un
octet : l'import/export est une couche **au-dessus** de `Archive` (ADR-036).

### 1.2 Interface en ligne de commande — `export` / `import`

`passlock export COFFRE (--output FICHIER | --stdout)`, `passlock import COFFRE --input
FICHIER`. Destination **obligatoire** à l'export, fichier créé en **exclusif** et en
`0600`, **jamais écrasé**. Aucun secret en argument de commande.

### 1.3 Documentation

`docs/IMPORT_EXPORT.md` décrit le format **de façon autonome** : colonnes, échappement
contextuel, grammaire de `fields`, bornes, déterminisme, strictness de l'import. Une
autre implémentation peut s'y conformer sans lire le code.

---

## 2. Ce qui a été **réellement exécuté**

| Outil | Portée | Résultat |
|---|---|---|
| `cargo fmt --all -- --check` | espace de travail | **propre** |
| `cargo build --workspace --all-targets` | espace de travail | **passe** |
| `cargo clippy --workspace --all-targets` | Linux | **0 avertissement** |
| `cargo test --workspace` | espace de travail | **601 tests, 0 échec** |
| `cargo +nightly fuzz build` | **les 8 cibles** | **compilent** |
| `cargo +nightly fuzz run csv_import` | analyseur CSV/JSON | **6 047 823 exécutions, aucun plantage** |

**Tests ajoutés : 32** — 14 tests unitaires dans `portability.rs` (échappement,
structure des champs, analyse CSV) et **18 tests d'intégration** dans
`tests/portability.rs`.

**Essais réels de bout en bout** sur un coffre contenant une entrée avec plusieurs
champs :

* `export --stdout` → CSV canonique ; `import` dans un coffre neuf → **ré-export
  identique octet pour octet** (vérifié par `diff`) ;
* `export --output` → fichier en `0600` ; seconde tentative → **refus**, occupant
  **intact** ;
* `export` **sans destination** → refus ;
* `import` d'un CSV portant une séquence inconnue → **refus**, coffre **inchangé**.

---

## 3. Fuzzing

**Cible nouvelle** : `csv_import`, qui exerce `portability::stage` — la partie **pure**
de l'import. Le contrat de la cible est l'**absence de panique** ; le résultat peut être
une erreur, un import vide, ou une liste d'entrées.

| Cible | Exécutions | Plantage |
|---|---|---|
| `csv_import` | **6 047 823** | **aucun** |

La partie qui **écrit** (dossiers, tags, entrées) n'est pas fuzzée ici : elle exige un
coffre déverrouillé. Son contrat de sûreté — pas d'écriture partielle, invariants du
modèle préservés — est couvert par les tests d'intégration (§4).

---

## 4. Ce qui a été trouvé

**Aucun défaut produit n'a été trouvé.**

### 4.1 Un point de conception, levé **avant** d'écrire du code

Le contrat d'échappement n'admet que `%25`, `%2F` (dossier) et `%7C` (tag), et interdit
toute autre séquence. Une colonne `fields` composite exige **deux séparateurs internes**
(champ↔champ, clé↔valeur) : avec seulement ces trois échappements, il faudrait réutiliser
`/` et `|` dans `fields`, ce qui contredit « `/` uniquement dossier » et « `|` uniquement
tags ». **Le contrat était auto-incohérent pour les champs.** Il a été levé par une
décision explicite — une structure **canonique** dans la cellule (JSON à clés fixes,
`/` et `|` **littéraux** dans `fields`), avec `%25` pour seul échappement — et le format
résultant est resté strictement dans le contrat d'échappement.

Cette levée est le point le plus important de cette étape, parce qu'elle a eu lieu
**avant** la première ligne de code : le format a été figé sur le papier et validé, puis
implémenté. C'est le contraire du défaut D4 de l'étape 3, trouvé par relecture après
coup.

### 4.2 Corrections de harnais, pendant le développement

* Une assertion de test comparait la cellule `fields` **sans** tenir compte du doublage
  des guillemets par le CSV (`""`). C'était le **test** qui était faux, pas le code : le
  CSV produit était correct.
* `clippy` a relevé deux `single_match_else` et un `unnecessary_wraps` — corrigés (le
  nettoyage d'erreur d'une fonction d'analyse infaillible n'avait pas à être un `Result`).

Aucune de ces corrections ne porte sur le comportement observable du produit.

---

## 5. Les exigences contractuelles, et où elles sont tenues

| Exigence | Où |
|---|---|
| une ligne par entrée, CSV déterministe | `export` ; `rows_are_sorted_by_the_eleven_columns_and_ref_is_assigned_after` |
| pas de pièces jointes / historique / corbeille / réglages / journal / ids internes | `export` ne parcourt que les entrées non à la corbeille ; `history_is_never_exported`, `trashed_entries_are_excluded_and_archived_entries_are_kept` |
| échappement `%`→`%25` en premier, `/` dossier, `\|` tag, majuscules, NUL interdit | `push_escaped` / `unescape` ; `escaping_respects_context`, `unescaping_is_strict`, `nul_is_refused_on_import_and_on_export` |
| découpage **avant** déséchappement | `decode_folder` / `decode_tags` (`split` puis `unescape`) ; `the_three_escapes_are_contextual` |
| séquences inconnues / malformées / minuscules **refusées** | `unescape` ; `unknown_malformed_and_lowercase_escapes_are_refused` |
| pas de décodage permissif | `unescape` n'accepte que les trois séquences, en majuscules, dans leur contexte |
| tri par les 11 colonnes hors `entry_ref`, bytewise, ordre des colonnes | `export` (`rows.sort()`) ; `rows_are_sorted_by_the_eleven_columns_and_ref_is_assigned_after` |
| tags triés par nom encodé | `encode_tags` |
| `entry_ref` attribué après tri | `export` ; `rows_are_sorted_by_the_eleven_columns_and_ref_is_assigned_after` |
| `export → import → export` identique | `export_import_export_is_byte_identical`, `unicode_edge_cases_round_trip` ; essai CLI réel |
| indépendance vis-à-vis des ids et de l'ordre d'insertion | `export_is_independent_of_insertion_order_and_ids` |
| structure et nombre de colonnes validés | `stage` / `decode_row` ; `missing_or_extra_columns_are_refused` |
| valeurs invalides refusées | `decode_row` ; `invalid_values_are_refused` |
| aucune écriture partielle si la validation échoue | `stage` **avant** `apply` ; `a_malformed_import_leaves_the_vault_untouched`, `a_read_only_target_cannot_persist_an_import` |
| invariants du modèle préservés | `Field::new`, `Entry::new`, `Entry::validate`, `add_folder`, `add_tag`, `add_entry` ; `imported_entries_respect_model_invariants` |
| coexistence avec les données existantes | `resolve_folder` / `resolve_tag` ; `import_coexists_with_existing_data_and_reuses_names` |
| cas limites Unicode | `unicode_edge_cases_round_trip` ; unités `json_string_is_canonical`, `fields_cell_round_trips` |
| bornes : fichier, ligne, cellule, entrées, champs | `MAX_CSV_*`, `MAX_IMPORT_*` ; refus **avant** allocation |
| `\uXXXX` strict, une seule forme canonique | `u_escape_value` ; `decode_fields_rejects_non_canonical_forms` |
| fuzzing du parseur | cible `csv_import`, §3 |
| format documenté indépendamment | `docs/IMPORT_EXPORT.md` |

---

## 6. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **L'exécution Windows** de `export`/`import` | le code compile et passe l'analyse statique ; il n'a **jamais été exécuté** sous Windows |
| NV2 | **L'intégration continue n'a jamais tourné** sur ce dépôt | elle liste huit cibles de fuzzing ; **rien ne prouve** qu'elle passe sur un exécuteur propre |
| NV3 | **Le chemin d'application du magasin** (`apply`) n'est pas fuzzé | il exige un coffre déverrouillé ; il est couvert par les tests d'intégration |
| NV4 | **Très grands coffres** (centaines de milliers d'entrées) | bornes posées, mais la mémoire et la durée à l'échelle n'ont pas été mesurées |
| NV5 | **Miri, ASan, TSan** sur cette étape | non relancés |
| NV6 | **Test CLI automatisé** | les commandes `export`/`import` ont été exercées **manuellement** de bout en bout, mais aucun test d'intégration du binaire ne les couvre (comme pour les étapes précédentes) |
| NV7 | **`\r` isolé et fins de ligne mixtes** | le `\r\n` est accepté (testé), le `\r` isolé est refusé (testé) ; les combinaisons mixtes à l'échelle d'un fichier ne sont pas éprouvées |

---

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **L'export est en clair.** | C'est sa raison d'être, et sa limite nommée : **L32**. Destination obligatoire, fichier `0600`, jamais écrasé, avertissement affiché. Un export **n'est pas une sauvegarde** |
| R2 | **Un export est incomplet** (ni pièces jointes, ni historique, ni corbeille). | Dit dans `docs/IMPORT_EXPORT.md` §1. L'import **ajoute** des entrées ; il ne restaure pas un coffre |
| R3 | **Un fichier hostile peut être volumineux.** | Bornes **avant** allocation : taille de fichier, de ligne et de cellule. La cible `csv_import` n'a produit aucun plantage sur plus de six millions d'exécutions |
| R4 | **Le comparateur de tri est sensible à l'encodage.** | Le tri porte sur la forme **encodée** ; deux états logiquement égaux produisent la même forme canonique. C'est ce qui fonde le déterminisme |
| R5 | **Une évolution future du format casserait la reproductibilité.** | Le format est **documenté** et sa reproductibilité est **testée**. Un changement de colonne ou d'échappement est un changement de format : il doit être revu comme tel |

---

## 8. Verdict

**Livré et vérifié.** Un CSV canonique déterministe — une ligne par entrée, sans
identifiants internes, pièces jointes, historique, corbeille ni réglages —, un
échappement **contextuel strict** (`%25` partout, `%2F` dossier, `%7C` tag, majuscules
seules, NUL interdit), une colonne `fields` en **structure canonique** à écriture unique.
`export → import → export` est **identique octet pour octet**, indépendamment des
identifiants et de l'ordre d'insertion. L'**import** valide **tout** avant d'écrire :
un CSV refusé ne laisse **aucune** modification.

**Aucun défaut produit trouvé.** Le résultat le plus important est **un point de
conception levé avant le code** : le contrat d'échappement ne permettait pas, à lui
seul, d'encoder une colonne de champs composite ; la contradiction a été nommée, une
décision a été prise, et le format a été figé **sur le papier** avant la première ligne
d'implémentation.

**Ce qui reste non vérifié** est au §6, au premier rang desquels **l'exécution Windows**
et **l'intégration continue**, qui n'a jamais été lancée sur ce dépôt.

**Étape close.** L'étape 5 de la phase 4 (presse-papiers) n'est pas commencée.
