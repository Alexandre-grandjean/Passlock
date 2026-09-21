# Gate E.0 — presse-papiers : abandon (P3)

> Ce document **n'est pas l'audit d'une fonctionnalité livrée** : c'est le compte rendu
> d'un **gate de chaîne d'approvisionnement** qui a conclu à l'**abandon**. Il dit ce
> qui a été mesuré, pourquoi les variantes P1 et P2 ont été écartées, et ce qui reste
> **non vérifié**.

## 1. Décision

**Phase 4, étape 5 (presse-papiers) : abandonnée par le gate E.0.**

* **Aucune dépendance clipboard n'a été ajoutée** — ni à `passlock-core`, ni à
  `passlock-cli`, ni au moindre `Cargo.toml`.
* **Aucun code de presse-papiers n'existe** dans le dépôt.
* **Aucun contrôle `cargo-deny` n'a été affaibli** : pas d'élargissement de la liste de
  licences, pas de `skip` de versions, pas de désactivation.
* Le presse-papiers **n'est pas** une fonctionnalité de Passlock.

## 2. Contraintes posées avant le gate

La bibliothèque était fixée : `arboard 3.6.1`, `default-features = false`, fonctionnalité
`wayland-data-control`, dépendance cantonnée à `passlock-cli`, jamais dans le cœur.

Trois profils de sortie étaient définis : **P1** (support Unix réellement vérifié), **P2**
(Windows, avec l'exception `windows-sys` étroite et justifiée), **P3** (abandon si les
prérequis ne peuvent pas être satisfaits proprement).

## 3. Méthode

`arboard 3.6.1` a été résolu dans un **crate sonde hors du dépôt** (aucun fichier du
projet modifié), avec les fonctionnalités exactes. L'arbre obtenu a été confronté à la
**politique réelle du projet** (`deny.toml` copié tel quel), via `cargo deny check`, pour
les cibles Linux et Windows.

## 4. Ce qui a été mesuré

`cargo deny check` → **`advisories ok, bans FAILED, licenses FAILED, sources ok`**.

### 4.1 Licences hors de la liste blanche

La liste autorisée est `{MIT, Apache-2.0, BSD-3-Clause}`, avec
`unused-allowed-license = "deny"` :

| Plateforme | Crate | Licence |
|---|---|---|
| Unix | `foldhash 0.1.5` | `Zlib` |
| Unix | `unicode-ident 1.0.26` | `(MIT OR Apache-2.0) AND Unicode-3.0` (le `AND` exige `Unicode-3.0`) |
| Windows | `clipboard-win 5.4.1` | `BSL-1.0` |
| Windows | `error-code 3.4.0` | `BSL-1.0` |

### 4.2 Versions multiples (`multiple-versions = "deny"`)

| Plateforme | Crate | Versions |
|---|---|---|
| Unix | `hashbrown` | `0.15.5` **et** `0.17.1` (par `petgraph → hashbrown` et `petgraph → indexmap → hashbrown`) |
| Windows | `windows-sys` | `0.60.2` (arboard) **et** `0.61.2` (déclaré par `passlock-platform`) |

### 4.3 Dépendance C et macros procédurales

* **Unix non pur Rust** : `wayland-sys` a une build-dependency `pkg-config` (liaison à la
  **libwayland C**) ; `wayland-backend` a une build-dependency `cc`.
* **Macros procédurales** dans l'arbre du binaire : `syn`, `proc-macro2`, `quote`,
  `unicode-ident`, `thiserror-impl`, `wayland-scanner` (proc-macro) — alors que
  `passlock-cli` évite `clap` `derive` **précisément** pour les garder dehors.
* **Données tierces embarquées** : `tree_magic_mini` embarque une base MIME (classe L24).

## 5. Pourquoi P1 et P2 sont écartés

* **P1 (Unix propre) : impossible.** L'Unix seul échoue déjà `licenses` (`Zlib`,
  `Unicode-3.0`) **et** `bans` (`hashbrown`), et tire une bibliothèque C.
* **P2 (exception `windows-sys`) : insuffisant.** Une exception ciblée sur `windows-sys`
  ne couvre ni le doublon `hashbrown` sous Unix, ni les licences des deux plateformes, ni
  la libwayland. Pour rendre `cargo deny` vert, il faudrait **élargir la liste de licences
  de trois entrées** et **ajouter au moins deux contournements de versions** — un
  affaiblissement du contrôle explicitement **exclu**.

**D'où P3 : les prérequis ne peuvent pas être satisfaits proprement.**

## 6. Ce qui reste **non vérifié**

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **L'exécution Windows** de quoi que ce soit lié au presse-papiers | aucune exécution Windows n'a eu lieu ; le doublon `windows-sys` est constaté par **résolution**, pas par exécution |
| NV2 | **L'intégration continue** | elle n'a jamais été lancée sur ce dépôt ; le comportement de `deny.toml` y est identique, mais non observé |
| NV3 | La présence de `libwayland` sur l'exécuteur `ubuntu-latest` | non vérifiée ; le crate sonde a seulement compilé sur la machine de développement |

## 7. Verdict

**Abandon, et non report.** Le résultat du gate n'est pas « à revoir plus tard » : c'est
une décision de conception. Le presse-papiers est un **canal public par conception**
(`docs/TOTP.md` §8) qui n'apporte aucune garantie de sécurité ; l'abandon **retire** un
risque (T32 / L22) au lieu de l'ajouter. La phase 4 est **close** : quatre étapes livrées,
la cinquième écartée par un contrôle de chaîne d'approvisionnement qui n'a pas été
assoupli pour la faire passer.
