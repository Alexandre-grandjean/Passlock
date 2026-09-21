# Audit adversarial — phase 5, étape 1 : centre de sécurité

> Rapport **séparé**, comme pour les étapes précédentes. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés
> écrites tiennent ; les propriétés non écrites ne sont pas couvertes.

---

## 1. Périmètre de cette étape

**Phase 5.1 — centre de sécurité + `expires_at` (lecture).** Sont **hors** périmètre,
et non commencés : l'analyse d'URL, la liste des suffixes publics, et la commande CLI
qui écrira `expires_at`.

## 2. Ce qui a été livré

Un module `passlock-core/src/security.rs`, **sans dépendance nouvelle**, **sans
écriture**, **sans horloge**.

| Élément | Rôle |
|---|---|
| `CivilDate` | analyse stricte `YYYY-MM-DD`, arithmétique par numéro de jour |
| `expiry_state` / `ExpiryReport` | indicateur 6 : expiré / bientôt / valide / indéterminé |
| `AgeInfo` | indicateur 2 : `updated_at` et `days_since`, **aucune bande** |
| `StrengthEstimate` | indicateur 3 : estimation **heuristique**, jamais une entropie |
| `WeakSecret` | indicateur 4 : `heuristic_bits < 64` **ou** longueur `< 8` |
| `detect_missing_totp` | indicateur 5 : `Login` + `Secret` + aucun `Totp` |
| `ReuseGroup` / `detect_reuse` | indicateur 1 : empreinte HMAC sous `K_index` |
| `SecurityReport` / `run_security_center` | les **six** indicateurs, en lecture seule |

**Aucune valeur de secret et aucune empreinte ne figurent dans les résultats.** Les
groupes de réutilisation ne portent que des identifiants et des références de champ.

## 3. Ce qui a été **réellement exécuté**

| Outil | Portée | Résultat |
|---|---|---|
| `cargo fmt --all -- --check` | espace de travail | **propre** |
| `cargo build --workspace --all-targets` | espace de travail | **passe** |
| `cargo clippy --workspace --all-targets` | Linux | **0 avertissement** |
| `cargo test --workspace` | espace de travail | **648 tests, 0 échec** |
| `cargo +nightly fuzz build` | **les 10 cibles** | **compilent** |
| `cargo +nightly fuzz run parse_civil_date` | analyse/arithmétique de date | **113 829 901 exécutions, aucun plantage** |
| `cargo +nightly fuzz run estimate_strength` | estimation heuristique | **30 319 925 exécutions, aucun plantage** |
| `cargo deny check` | advisories, bans, licences, sources | **4/4 ok** (configuration **inchangée**) |

**Tests ajoutés : 47** — 28 unitaires dans `security.rs`, 19 d'intégration dans
`tests/security.rs`.

## 4. Défauts trouvés et corrigés

### D1 — `CivilDate::from_days` débordait, et pouvait paniquer sur une entrée extrême *(gravité : moyenne ; catégorie : robustesse d'une API publique)*

**Comment il a été trouvé.** Par la **cible de fuzzing** `parse_civil_date`, qui
exerce `from_days` sur des entiers arbitraires. L'entrée reproduite tient en huit
octets : `7f ff ff ff ff ff e9 e9`, soit un entier très proche de `i64::MAX`. Le
calcul `days + 719_468` débordait, et **les contrôles de débordement** activés par la
construction de fuzzing faisaient **avorter** le processus.

**Le défaut.** `from_days` était présentée comme une conversion d'instants plausibles,
mais n'était **pas totale** : elle supposait implicitement que l'entrée restait dans
une plage sûre. Une API publique qui panique sur une entrée légale au sens du type
(`i64`) est un défaut de robustesse.

**Portée réelle, énoncée sans exagération.** L'overflow n'est **pas** atteignable via
`from_unix_seconds` ni `run_security_center` : les secondes étant un `u64`, le nombre
de jours reste borné (`≈ 2,1 × 10¹⁴`) et l'arithmétique ne déborde pas. Il est en
revanche atteignable par **tout appelant direct** de `from_days`, y compris un futur
code du CLI.

**Correction.** L'entrée est **bornée** à un domaine large mais sûr
(`MIN_DAY_NUMBER..=MAX_DAY_NUMBER`), puis le résultat est **ramené** à `1970..=9999`.
La fonction est désormais **totale** : aucune entrée ne peut déborder, et le résultat
est toujours une date valide. Un test unitaire couvre `i64::MIN`, `i64::MAX` et
plusieurs valeurs extrêmes.

## 5. Les décisions verrouillées, et où elles sont tenues

| Décision | Où |
|---|---|
| `expires_at` : `Date`, `YYYY-MM-DD`, année `1970..=9999` | `CivilDate::parse` ; tests de forme, de bornes, de bissextilité |
| bornes `expired < 0`, `soon 0..=30`, `valid > 30`, jour inclusif | `classify_expiry` ; `expiry_boundaries_are_inclusive` |
| motifs `Absent`/`WrongKind`/`Malformed`/`Impossible`/`Ambiguous` | `ExpiryUnknown` ; tests dédiés |
| référence **UTC fournie**, aucune horloge | `run_security_center(now)` ; `the_reference_date_is_utc` |
| candidats `Secret`+`Pin`, `Totp` exclu, aucune déduction par clé | `is_secret_candidate` ; `reuse_crosses_secret_and_pin_and_ignores_totp` |
| empreinte `HMAC-SHA256(K_index, "…/reuse-fingerprint" ‖ valeur)` | `reuse_fingerprint` ; aucune persistance, aucune sortie |
| groupe seulement si ≥ 2 `EntryId` distincts | `detect_reuse` ; `reuse_needs_two_distinct_entries` |
| estimation nommée, jamais une entropie | `StrengthEstimate` ; docs et tests d'exemples |
| seuils `64/80/128`, verdict haut `NoStructuralWeakness` | `band_for` ; `thresholds_follow_the_policy` |
| `run_count`, `Periodic` en O(n), `OutsideKnownClasses` seul | `is_periodic`, `StrengthFlags` ; tests dédiés |
| faible si `bits < 64` **ou** longueur `< 8`, `Indeterminate` non converti | `detect_weak_entries` ; `a_short_secret_is_weak_even_when_indeterminate` |
| ancienneté : `days_since` seul, aucune bande | `AgeInfo` ; `age_is_deterministic_and_uses_the_instant` |
| TOTP : `Login` + `Secret` + aucun `Totp` | `detect_missing_totp` ; `missing_totp_rule` |
| six indicateurs, aucun score global | `SecurityReport` ; `the_report_has_six_indicators_and_no_global_score` |
| corbeille exclue, archivées incluses | `trash_is_excluded_and_archived_is_included` |
| aucune valeur ni empreinte en sortie | `no_value_or_fingerprint_escapes_the_report` |

## 6. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **L'exécution Windows** | le module est pur et portable ; il n'a pas été exécuté sous Windows |
| NV2 | **L'intégration continue** | jamais lancée sur ce dépôt |
| NV3 | **L'écriture `expires_at`** | hors périmètre de cette étape (commande CLI dédiée à venir) |
| NV4 | **Analyse d'URL et PSL** | non commencées |
| NV5 | **Miri, ASan, TSan** | non relancés |
| NV6 | **La pertinence sécurité de l'heuristique** | l'heuristique est **aveugle aux dictionnaires** par construction : c'est une limite, pas un défaut mesurable |

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Faux négatifs de l'estimation** (`Tr0ub4dor&3` n'est pas signalé) | documenté comme limite centrale : l'estimation est **optimiste**, un score haut ne garantit rien. Seul un score **bas** est un signal |
| R2 | **Faux positifs de l'absence de TOTP** (un `Secret` qui n'est pas un mot de passe) | documenté dans `detect_missing_totp` ; règle conservatrice assumée |
| R3 | **L'empreinte de réutilisation est une fonction de la valeur** | jamais persistée, jamais affichée ; la comparaison reste en mémoire |
| R4 | **`expires_at` est fourni par l'utilisateur** | aucune durée n'est déduite ni inventée ; une absence vaut « n'expire pas » |

## 8. Verdict

**Livré et vérifié.** Le centre de sécurité calcule les **six** indicateurs, en lecture
seule, sans score global, sans exposer aucune valeur ni empreinte, avec un ordre
déterministe indépendant de l'insertion. L'estimation de robustesse est **nommée comme
une heuristique** et un test documente explicitement son faux négatif.

**Un défaut trouvé**, par le **fuzzing** : `from_days` n'était pas totale et pouvait
avorter sur une entrée extrême. Corrigé et couvert.

**Ce qui reste non vérifié** est au §6, au premier rang desquels l'exécution Windows et
l'intégration continue.

**Suite.** Analyse d'URL, liste des suffixes publics et commande d'écriture
`expires_at` ne sont **pas** commencées.
