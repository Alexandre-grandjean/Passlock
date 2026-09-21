# Audit adversarial — phase 5, étape 2 : analyse d'URL et PSL

> Rapport **séparé**, comme pour les étapes précédentes. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.

---

## 1. Périmètre

**Phase 5.2 — analyse d'URL locale + liste des suffixes publics.** L'analyse est
**pure** : entrée `&str`, verdict, **aucune** E/S, **aucun** réseau, **aucune**
horloge, **aucun** coffre, **aucun** score numérique global. Le motif
« sous-domaine trompeur » est **retiré** (voir §4) faute de référence fiable.

## 2. Ce qui a été livré

| Élément | Rôle |
|---|---|
| `encoding::punycode_encode` / `punycode_decode` | codec Punycode (RFC 3492), **écrit à la main**, borné |
| `psl::registrable_domain` / `DomainInfo` / `SuffixCertainty` | eTLD+1 selon la sémantique officielle (normale, joker, exception, défaut) |
| `psl::raw_list` | contenu embarqué verbatim, exposé pour le test d'intégrité |
| `url::analyze` / `UrlVerdict` / `Motif` / `Verdict` | analyse pure, bornée, **explicable par motifs** |
| `url::fold_confusables` / `is_confusable_with` | repli confusable exact, pour **comparer** — sans produire de motif seul |
| `data/public-suffix-list/` | PSL **verbatim** + `ATTRIBUTION.md` (commit, date, taille, SHA-256) |

**Aucune dépendance nouvelle.** La PSL est **embarquée** (`include_str!`) : le graphe
de crates du cœur et la liste blanche de `deny.toml` restent **inchangés**.

### 2.1 PSL : provenance

`publicsuffix/lib`, fichier `public_suffix_list.dat`, commit
`645b36c9a51ff0b3718df0ba02f6570aa6921632`, récupéré le **2026-09-20** (UTC),
334 227 octets, 16 481 lignes, SHA-256
`d3fba7b2934b0e1b9c958baf42bef85107b53cd0115ff7e81a7e61c7119a36d0`, licence
**MPL-2.0**. Les **deux** sections (ICANN **et** PRIVATE) sont utilisées : `github.io`
est un suffixe public, donc `a.github.io` et `b.github.io` sont deux sites distincts.

## 3. Ce qui a été **réellement exécuté**

| Outil | Résultat |
|---|---|
| `cargo fmt --all -- --check` | **propre** |
| `cargo build --workspace --all-targets` | **passe** |
| `cargo clippy --workspace --all-targets` | **0 avertissement** |
| `cargo test --workspace` | **708 tests, 0 échec** |
| `cargo +nightly fuzz build` | **les 12 cibles compilent** |
| `cargo +nightly fuzz run analyze_url` | **4 745 965 exécutions, aucun plantage** |
| `cargo +nightly fuzz run punycode` | **6 369 030 exécutions, aucun plantage** |
| `cargo deny check` | **4/4 ok** (configuration **inchangée**) |

**Tests ajoutés : 60** — unitaires (`psl`, `url`, `encoding::punycode`) et
d'intégration (`tests/url_analysis.rs`, `tests/public_suffix_integrity.rs`).

## 4. Décisions verrouillées, et où elles sont tenues

| Décision | Où |
|---|---|
| ICANN + PRIVATE | `psl` ; `a_private_suffix_separates_tenants` |
| sémantique PSL (joker, exception, plus longue, défaut) | `registrable_domain` ; tests dédiés |
| U-label → A-label pour la PSL, A-label → Unicode pour les scripts | `analyze_dns_host` ; `a_unicode_label_and_its_a_label_agree_and_are_indeterminate` |
| **aucune** validation IDNA2008 ; `IdnaNotFullyValidated` ⇒ `Indeterminate` | `Motif::IdnaNotFullyValidated` ; tests |
| `münchen.de` ≡ `xn--mnchen-3ya.de`, **non** `Clean` | test dédié |
| pas de normalisation Unicode silencieuse (NFC ≠ NFD) | `no_silent_normalization_between_nfc_and_nfd` |
| faux `xn--` refusé (décodage + aller-retour) | `an_invalid_punycode_label_is_indeterminate` |
| **`DeceptiveSubdomain` retiré** | aucun variant ; les tests documentent l'absence |
| confusables : repli exposé, **pas** de motif seul | `fold_confusables` ; `confusable_folding_is_exposed` |
| bornes sur la forme **A-label** (label 63, hôte 253), entrée 4096 octets | `analyze_dns_host` ; tests de bornes |
| hôte nu, points, ports, userinfo, IPv4/IPv6 | `parse` ; tests dédiés |
| aucun réseau / E-S / horloge | test **structurel** `the_module_has_no_io_and_no_network` |

## 5. Défauts trouvés et corrigés

### D1 — La PSL contient des règles en **U-label**, et le parseur ne les normalisait pas *(gravité : moyenne ; catégorie : fonctionnalité silencieusement inopérante)*

**Comment il a été trouvé.** En écrivant le test d'intégrité `every_rule_line_is_ascii`,
qui a **échoué** sur `aéroport.ci`. La liste mêle en réalité **459 règles en U-label**
(`aéroport.ci`, `公司.cn`, `个人.hk`…) et le reste en A-label `xn--`.

**Le défaut.** L'hôte est analysé en **A-label** ; un parseur qui laissait les règles
Unicode telles quelles n'aurait **jamais** fait correspondre `xn--aroport-bya.ci`. Le
domaine enregistrable aurait été calculé **sans la règle**, donc faux, sans aucun
signal.

**Correction.** Les règles sont **normalisées en A-label** au chargement
(`normalize_rule` : chaque label non ASCII est encodé en `xn--…`). Un test unitaire
couvre `www.xn--aroport-bya.ci`, et le test d'intégrité vérifie que la source **mêle
bien** les deux formes — pour que la normalisation reste **nécessaire**.

### D2 — Un hôte malformé ou trop long ressortait `Clean` *(gravité : moyenne ; catégorie : verdict trompeur)*

**Comment il a été trouvé.** Par les tests d'intégration de bornes : un label de
64 octets et un hôte de 259 octets produisaient `Clean`.

**Le défaut.** Le verdict ne traitait que les motifs « suspects » et « indéterminés ».
`MalformedHost` et `TooLong` ne relevaient d'aucune des deux catégories, donc le
verdict tombait sur `Clean` — un **refus compté comme un feu vert**.

**Correction.** Un **refus structurel** (`NoHost`, `MalformedHost`, `TooLong`) rend
l'hôte inanalysable : le verdict devient `NotApplicable`, et le nom d'hôte n'est pas
publié. Un label IDN invalide, lui, reste `Indeterminate` (l'hôte est analysable, mais
son nom n'est pas publiable).

## 6. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **Exécution Windows** | module pur et portable ; non exécuté sous Windows |
| NV2 | **Intégration continue** | jamais lancée sur ce dépôt |
| NV3 | **Qualité de la liste amont** | l'empreinte prouve l'identité du fichier, pas sa justesse |
| NV4 | **`DeceptiveSubdomain`, homographes de marque, hyphens autour d'une marque** | **non implémentés** faute de liste de marques ; non « à revoir » mais **écartés** |
| NV5 | **Miri, ASan, TSan** | non relancés |
| NV6 | **Exactitude IDNA** | aucune validation IDNA2008 : c'est une **limite assumée**, pas un défaut mesurable |

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Un IDN légitime n'est jamais `Clean`** | c'est **voulu** : on ne prétend pas valider IDNA. Le verdict est `Indeterminate`, jamais présenté comme un feu vert |
| R2 | **Faux positifs d'`ExcessiveLabels`** (seuil 5) | seuil explicite et affiché ; signalé comme motif, pas comme « phishing » |
| R3 | **Faux négatifs d'usurpation de marque** | `rnicrosoft.com` n'est pas signalé : **assumé**, faute de référence. Le repli confusable est exposé pour une comparaison future |
| R4 | **Liste vieillissante (L25)** | un suffixe absent donne `UnknownSuffix` et un verdict **incertain** ; l'âge est dans `ATTRIBUTION.md` |

## 8. Verdict

**Livré et vérifié.** Analyse d'URL pure, locale et bornée, avec verdict explicable par
motifs, **aucun score global**, et une PSL embarquée épinglée. IDNA **non** revendiqué
comme validé : un label non-ASCII ne peut jamais produire un verdict `Clean`.

**Deux défauts trouvés**, tous deux **corrigés** : une PSL dont les règles U-label
n'étaient pas normalisées (D1), et un verdict `Clean` sur un hôte refusé (D2).

**Ce qui reste non vérifié** est au §6, au premier rang desquels l'exécution Windows et
l'intégration continue.

**Suite.** La commande CLI du centre de sécurité, l'écriture `expires_at`, et la phase 6
ne sont **pas** commencées.
