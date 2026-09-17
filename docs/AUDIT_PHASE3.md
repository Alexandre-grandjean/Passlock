# Audit adversarial de la phase 3 — générateur et TOTP

> Rapport **séparé**, comme pour les phases 1 et 2. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.
>
> **Un test vert n'est pas une preuve de sécurité.** Il prouve que les propriétés
> écrites tiennent ; les propriétés non écrites ne sont pas couvertes.

---

## 1. Ce qui a été livré

### 1.1 Cœur (`passlock-core`)

| Fichier | Contenu | Lignes de test |
|---|---|---|
| `src/encoding.rs` | Base32 RFC 4648 (avec et sans remplissage), Base64url §5, hexadécimal | 13 |
| `src/entropy.rs` | Entropie exacte, coût des contraintes par programmation dynamique, bandes de politique | 12 |
| `src/totp.rs` | HOTP, TOTP, ensembles fermés de paramètres, analyse et sérialisation `otpauth://` | 24 |
| `src/wordlist.rs` | Deux listes embarquées, validation stricte, liste personnalisée | 13 |
| `src/generator.rs` | Mots de passe, phrases de passe, secrets arbitraires | 31 |
| `data/wordlists/*` | Les deux listes **verbatim** + `ATTRIBUTION.md` | — |

### 1.2 CLI (`passlock-cli`)

`src/generate.rs` et `src/totp.rs` — nouveaux modules, **additifs** dans `main.rs`.

| Commande | Rôle |
|---|---|
| `generate` | Mot de passe, avec contraintes de site et rapport d'entropie |
| `passphrase` | Phrase de passe, liste au choix, entropie sur la taille **réelle** |
| `secret` | Secret arbitraire, quatre formats |
| `totp` | Code d'une entrée, `--list`, `--at`, `--json` |
| `entry totp set` / `new` | Association ou génération d'un secret TOTP |
| `entry gen` | Génération **directement dans le coffre**, sans transit par le shell |

### 1.3 Modifications du code existant — **exhaustives**

| Fichier | Modification |
|---|---|
| `Cargo.toml` (racine + cœur) | `sha1 = "0.11"` — **une** dépendance ajoutée |
| `lib.rs` | 6 déclarations `pub mod` |
| `rng.rs` | Extraction de `reduce` (§4.7 de `SECURITY.md`) |
| `error.rs` | **Une** variante : `InvalidInput { reason: &'static str }` |
| `main.rs` | 2 `mod`, 6 entrées de dispatch, `pub(crate)` sur 8 éléments partagés |
| `deny.toml` | Commentaire de licences corrigé (§3.4) |

**Aucune modification** de `archive.rs`, `container.rs`, `keys.rs`, `kdf.rs`,
`aead.rs`, `header.rs`, `store.rs`, `model/`, `migrate.rs`, `query.rs`, `vault.rs`,
ni de `passlock-platform`.

**Aucun changement de format.** `FieldKind::Totp` et le sac `Archive::settings`
existaient depuis la phase 2 : zéro octet modifié, aucune migration, aucune fenêtre
de compatibilité.

### 1.4 Suites de tests et cibles de fuzzing

| Fichier | Contenu |
|---|---|
| `tests/rfc_vectors.rs` | **35 vecteurs officiels** : 10 RFC 4226 + 18 RFC 6238 + 7 RFC 4648 §10 |
| `tests/otpauth_adversarial.rs` | 20 000 entrées aléatoires, toutes les troncatures, injections terminales |
| `tests/secret_inventory.rs` | Inventaire des copies, absence de secret dans `Debug`/`Display`/erreurs |
| `tests/wordlist_integrity.rs` | Empreintes SHA-256 upstream épinglées |
| `fuzz/fuzz_targets/parse_otpauth.rs` | Cible de fuzzing |
| `fuzz/fuzz_targets/decode_base32.rs` | Cible de fuzzing |

---

## 2. Ce qui a été **réellement exécuté**

### 2.1 Tests

```
cargo test --workspace        →  473 tests, 0 échec
```

| Cible | Tests | Avant la phase 3 |
|---|---|---|
| `passlock-core` (bibliothèque) | **317** | 220 |
| `tests/rfc_vectors.rs` | **6** | — |
| `tests/otpauth_adversarial.rs` | **8** | — |
| `tests/secret_inventory.rs` | **9** | — |
| `tests/wordlist_integrity.rs` | **5** | — |
| `tests/adversarial.rs` | 17 | 17 |
| `tests/adversarial_archive.rs` | 10 | 10 |
| `tests/key_hierarchy.rs` | 11 | 11 |
| `tests/malformed_input.rs` | 7 | 7 |
| `tests/semantic_model.rs` | 20 | 20 |
| `tests/store.rs` | 22 | 22 |
| `passlock-platform` | 41 | 41 |

**125 tests ajoutés** (97 dans la bibliothèque, 28 en intégration). Les 348 tests
antérieurs passent **sans modification**.

### 2.2 Conformité — la preuve extérieure

Les tables sont reproduites **verbatim** depuis les RFC. Elles ne disent pas « ce
code fait ce que son auteur attendait », elles disent « ce code fait ce que la norme
prescrit ».

| Source | Volume | Résultat |
|---|---|---|
| RFC 4226 appendice D (HOTP) | 10 vecteurs, compteurs 0–9 | conformes |
| RFC 6238 appendice B (TOTP) | 18 vecteurs, 3 algorithmes × 6 instants | conformes |
| RFC 4648 §10 (Base32) | 7 vecteurs | conformes |

**Vérification de bout en bout**, sur le chemin réel : le secret de test de la RFC
6238, enregistré dans un **coffre chiffré**, relu, décodé et transmis au calcul,
produit exactement :

```
t=59  → 94287082     t=1234567890  → 89005924
t=1111111109 → 07081804     t=2000000000  → 69279037
t=1111111111 → 14050471     t=20000000000 → 65353130
```

### 2.3 Outils

| Outil | Périmètre | Résultat |
|---|---|---|
| **Clippy** | espace de travail, Linux | **0 avertissement** |
| **Clippy** | cible `x86_64-pc-windows-msvc` | **0 avertissement** |
| **`cargo deny`** | advisories, bans, licences, sources | **4/4 ok** |
| **ASan** | espace de travail entier, 473 tests | **0 erreur mémoire** |
| **TSan** | cœur, 317 tests | **0 course de données** |
| **Miri** | modules purs | **16 tests validés**, puis blocage (§3.3) |
| **Fuzzing** | `parse_otpauth` | **4 816 302 exécutions**, 0 plantage |
| **Fuzzing** | `decode_base32` | **3 579 680 exécutions**, 0 plantage |

### 2.4 Deux points de méthode

**Le fuzzing s'exécute pour la première fois dans ce projet.** Les phases 1 et 2 le
rapportaient comme **jamais exécuté**. `cargo-fuzz` a été installé, les quatre
cibles existantes et les deux nouvelles compilent, et les deux nouvelles ont tourné
60 secondes chacune — environ **8,4 millions d'exécutions** au total, sans plantage.
Les cibles des phases 1 et 2 **n'ont toujours pas été exécutées** : cela reste
**non vérifié**.

**Le défaut le plus grave de cette phase a été trouvé par une exécution de tests
sous ASan**, pas par relecture. Il est décrit au §4.

### 2.5 Ce qui a échoué, et pourquoi

**TSan a d'abord échoué** avec `mixing -Zsanitizer will cause an ABI mismatch`. Ce
n'était pas un défaut du code : les artefacts ASan et TSan partageaient le même
répertoire cible. Relancé avec un `CARGO_TARGET_DIR` distinct, il passe. **Défaut de
mon dispositif de mesure**, pas du logiciel — la distinction est notée parce qu'un
rapport qui confond les deux est inutilisable.

---

## 3. Ce qui n'est **pas** vérifié

À ne pas présenter comme acquis.

### 3.1 Hors de portée, par nature

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **Absence de biais du CSPRNG du noyau** | Ancre de confiance depuis la phase 1. Aucun test depuis l'espace utilisateur ne peut la valider. L'entropie annoncée en **dépend** |
| NV2 | **Détection de dérive d'horloge** | Non revendiquée, et structurellement impossible hors ligne : la RFC 6238 §6 confie la resynchronisation au **validateur** |
| NV3 | **Qualité linguistique des listes de mots** | Seuls le compte, le format, l'unicité et l'empreinte sont vérifiés. L'absence de biais dans leur construction d'origine ne l'est pas |
| NV4 | **Comportement Windows à l'exécution** | Compilation et signatures FFI vérifiées ; les tests ne s'exécutent pas sur cette machine |

### 3.2 Limites d'outillage, avec leur conséquence exacte

| # | Limite | Conséquence |
|---|---|---|
| NV5 | **Miri ne supporte pas `mlock`** | Toute construction d'un `SecretVec` échoue sous Miri. Cela **exclut** du champ de Miri : `base32_decode`, `parse_uri`, HOTP/TOTP, et la plupart des tests du générateur |
| NV6 | **Miri et l'isolation du système de fichiers** | Les tests utilisant `tempfile` sont exclus (`mkdir` indisponible) |
| NV7 | **MSan et UBSan** | Indisponibles sur cette toolchain |
| NV8 | **Cibles de fuzzing des phases 1 et 2** | Toujours jamais exécutées |

**Ce que Miri a réellement couvert** : 16 tests — l'arithmétique d'entropie, la
programmation dynamique des contraintes, et le calcul d'entropie du générateur. Puis
il s'est arrêté sur `mlock`.

**Ce que cela signifie.** La vérification mémoire des **436 autres tests** repose
uniquement sur ASan, qui est un détecteur d'exécution et non un vérificateur
exhaustif. C'est une faiblesse de la couverture, pas du code — mais elle doit être
écrite.

**Une piste non retenue à ce stade.** Un aménagement `#[cfg(miri)]` dans
`passlock-platform::memory`, qui sauterait `mlock` sous Miri, ouvrirait à Miri le
Base32, l'analyse d'URI et le calcul HOTP/TOTP — c'est-à-dire l'essentiel du code
nouveau. Il n'a **pas** été fait : cela modifierait un crate gelé, ce qui n'est pas
de ressort d'une phase de fonctionnalités, et surtout Miri éprouverait alors un
**chemin différent** de celui livré. La décision revient à la **phase 7**
(résolution des limites restantes), où elle sera prise avec l'ensemble des autres.

### 3.3 Ce qui n'est pas couvert par les tests, même verts

- **La justesse du corpus de fuzzing.** 8,4 millions d'exécutions sans plantage
  réduisent la probabilité d'un défaut, elles ne la ramènent pas à zéro.
- **La conformité de `sha1` à SHA-1.** Elle est établie **indirectement**, par les 28
  vecteurs HOTP/TOTP qui passent. La bibliothèque elle-même n'a pas été auditée.
- **La sûreté de la bibliothèque standard Rust** et du noyau.
- **La conservation des listes de mots par leur source.** L'empreinte prouve que le
  fichier embarqué est **celui téléchargé le 2026-09-16**, pas qu'il est complet ou
  de bonne qualité.

---

## 4. Défauts trouvés

### D1 — **Le séparateur de phrase de passe rendait la concaténation ambiguë et l'entropie surestimée** *(gravité : moyenne ; catégorie : revendication fausse)*

**Comment il a été trouvé.** En exécutant la suite de tests sous **ASan** — donc par
hasard, puisque le test passait auparavant. Le message :

```
assertion failed: « implant-blooming-mutilator-mobster-felt-tip-provoke »
  left: 7   right: 6
```

**Le défaut.** Le séparateur par défaut était le tiret. Or la liste EFF contient
`drop-down`, `felt-tip`, `t-shirt` et `yo-yo`, et la liste française contient `-`,
`--`, `---`, `:-(` et `:-)`.

Quand un mot contient le séparateur, la concaténation est **ambiguë** :
`[a-b, c, d]` et `[a, b-c, d]` produisent la même chaîne. Le nombre de sorties
**distinctes** devient donc strictement inférieur à `Wⁿ`, et `n × log₂(W)`
**surestime** l'entropie réelle.

**Pourquoi c'est un défaut et pas une coquetterie.** C'est exactement le type de
surestimation que l'ADR-026 interdit. Un générateur qui annonce 77,5 bits en
produisant un espace plus petit ment sur son unique chiffre.

**Correction.** Séparateur par défaut `.`, **absent des deux listes** (vérifié). Un
séparateur fourni qui apparaît dans un mot est **refusé** avec un message explicite.
Le mode aléatoire **filtre** sa liste de séparateurs, et le nombre retenu entre dans
le calcul des bits.

**Tests de non-régression ajoutés :** `a_separator_appearing_in_a_word_is_refused`,
`the_default_separator_is_absent_from_both_lists`,
`the_random_separator_mode_never_picks_an_ambiguous_character`.

### D2 — **Le test qui a révélé D1 était instable** *(gravité : moyenne ; catégorie : défaut de test)*

**Le défaut.** `a_passphrase_contains_the_requested_number_of_words` découpait la
phrase sur `-` et comparait le nombre de fragments. Il passait **par chance** : un
mot composé n'apparaît qu'une fois sur quelques centaines de tirages. Six
exécutions consécutives après correction confirment la stabilité retrouvée.

**Pourquoi c'est grave.** Un test instable qui passe est **pire** qu'un test absent :
il donne l'illusion d'une vérification, et le défaut qu'il aurait dû attraper
(D1) est resté invisible jusqu'à ce qu'une exécution fortuite le révèle.

**Correction.** Le test dérive désormais du séparateur par défaut, et un test dédié
vérifie que la découpe est **inversible**.

### D3 — **Repli silencieux dans l'encodeur** *(gravité : faible ; catégorie : corruption muette potentielle)*

**Le défaut.** Première version de `encoding.rs` : `alphabet.get(idx).map_or('?', …)`.
Inatteignable en pratique, mais s'il l'était, un `?` serait écrit dans un mot de
passe — une corruption silencieuse.

**Correction.** Index masqués à la largeur exacte de chaque alphabet (`& 0x1F`,
`& 0x3F`, `& 0x0F`), ce qui borne l'accès **par construction**. Aucun repli.

### D4 — **Le commentaire de `deny.toml` annonçait de faux décomptes** *(gravité : faible ; catégorie : documentation fausse)*

**Le défaut, préexistant.** Il annonçait « 33 crates en Apache-2.0, 37 en MIT, 1 en
BSD-3-Clause », soit 71. Le décompte réel, extrait de `cargo metadata`, était de
**43** avant cette phase et **44** après.

**Pourquoi c'est un défaut.** Un commentaire faux dans un fichier de politique de
sécurité donne l'illusion d'une vérification. Il a été remplacé par le décompte réel
par expression de licence.

### D5 — **La documentation de `rng.rs` annonçait la mauvaise erreur** *(gravité : très faible ; préexistant)*

Le commentaire de `fill` annonçait `Error::Io` ; le code renvoie `Error::Internal`.
Sans conséquence à l'exécution, mais un commentaire qui décrit un contrat inexistant
est un piège pour le prochain lecteur. **Signalé, non corrigé** dans cette phase —
la correction relève d'un nettoyage documentaire, pas de la phase 3.

### D6 — **Aucune variante d'erreur pour un paramètre invalide** *(gravité : faible ; catégorie : manque)*

`Error` ne décrivait que des fichiers. Une longueur de mot de passe hors bornes
n'avait pas de variante propre. Ajout de `InvalidInput { reason: &'static str }`,
qui reste **non porteur de données** comme toutes les autres.

### D7 — **Mes notes contenaient une affirmation fausse sur la RFC 6238** *(gravité : moyenne ; catégorie : affirmation non vérifiée)*

Une note antérieure affirmait que « la RFC 6238 fait de SHA-1 le défaut obligatoire
pour l'interopérabilité ». **C'est faux.** La RFC 6238 ne contient aucune phrase de ce
type. La justification de SHA-1 vient de la **RFC 4226 appendice B**, citée verbatim
dans `docs/TOTP.md` §3. L'affirmation a été corrigée avant d'être publiée.

### Défauts du **dispositif de mesure**, pas du logiciel

| # | Défaut | Conséquence |
|---|---|---|
| M1 | TSan lancé dans le répertoire cible d'ASan | conflit d'ABI, exécution invalide. Relancé avec un répertoire distinct |
| M2 | Première alerte sur la liste française prise pour des remplissages | **Infirmée** : les 240 entrées sans lettre sont des éléments Diceware authentiques (chiffres, ponctuation). Le critère « contient une lettre » était faux |
| M3 | Plusieurs erreurs de compilation dans mon propre harnais (§5) | corrigées avant d'en tirer la moindre conclusion |

---

## 5. Défauts de mon **harnais**, corrigés pendant le développement

Consignés parce qu'un oracle faux valide n'importe quoi, et parce qu'ils indiquent
où la vérification était faible.

| # | Défaut | Comment il s'est manifesté |
|---|---|---|
| H1 | Attentes d'entropie fausses (`20 × log₂(94)` écrit 130,99 au lieu de 131,09) | échec de test — **mes attentes**, pas le calcul |
| H2 | Chaîne brute `r#"…"#` refermée par le `"#` du contenu | erreur de compilation |
| H3 | `Display` appelé sur `Zeroizing<String>` | erreur de compilation |
| H4 | `usize::try_from(f64)` inexistant | erreur de compilation |
| H5 | Accolade fermante en trop fermant le module de tests | erreur de compilation |
| H6 | Nommage fautif : `high` était le compteur, pas le code | erreur de compilation |
| H7 | Boucle sans objet dans un test de format | nettoyée |
| H8 | Emprunt multiple de `rng` dans le harnais d'URI | erreur de compilation |
| H9 | Emprunt de `false` en position d'assertion | avertissement clippy |

---

## 6. Points de conception, et leur verdict

| # | Point | Verdict |
|---|---|---|
| 1 | Modèle de sécurité du générateur | **Livré** — `SECURITY.md` §4.6, ADR-026/027 |
| 2 | Source d'aléa | **Livré** — aucune primitive nouvelle ; `rng::below` seule voie, plage de rejet désormais **testable** |
| 3 | Calcul et représentation de l'entropie | **Livré** — exact pour les contraintes par DP, bandes de politique, refus des estimations en durée |
| 4 | Contraintes des sites | **Livré** — rejet de chaîne entière, coût compté et affiché |
| 5 | Phrases de passe | **Livré** — deux listes, entropie sur la taille **réelle** ; D1 corrigé |
| 6 | Secrets arbitraires | **Livré** — 4 formats, puissances de deux sans perte |
| 7 | Modèle TOTP | **Livré** — ensembles fermés, 28 vecteurs officiels |
| 8 | Secret TOTP en mémoire | **Livré et inventorié** — `SecretVec` + `Zeroizing`, aucune `Clone`, `Debug` rédigé |
| 9 | Horodatage et dérive | **Livré, avec limite écrite** — temps injecté, décalage borné, **aucune détection revendiquée** |
| 10 | Format de stockage | **Livré sans changement de format** — URI `otpauth://` dans un `FieldKind::Totp` |
| 11 | Coffre verrouillé | **Livré** — aucun code sans déverrouillage, aucun cache, aucun second chemin d'accès |
| 12 | Génération, copie, affichage | **Livré** — stdout/stderr séparés, `entry gen`, pas de secret en argument ; **presse-papiers reporté** |
| 13 | Tests adversariaux | **Livré** — 125 tests, 35 vecteurs officiels, 4,8 M + 3,6 M exécutions de fuzzing |
| 14 | Risques du presse-papiers | **Analysés et documentés** — mécanisme reporté en phase 4 |
| 15 | Surfaces nouvelles | **Énumérées** — `SECURITY.md` §4.6, injection termininale traitée |

---

## 7. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Horloge fausse → codes faux, indétectable** | Limite structurelle, écrite, **non corrigeable hors ligne** |
| R2 | **L'entropie annoncée dépend d'une hypothèse non mesurée** (NV1) | Rappelée à chaque affichage ; aucune durée de cassage n'est annoncée |
| R3 | **Miri ne couvre que 16 tests sur 473** (NV5) | Limite d'outillage écrite ; piste `cfg(miri)` identifiée mais **non retenue** en phase 3 |
| R4 | Un séparateur personnalisé reste plus lisible avec un mot composé | **Refusé** plutôt qu'accepté avec une entropie approximative ; l'utilisateur choisit un autre séparateur |
| R5 | Le `String` d'un champ n'est pas effaçable de façon fiable | Limite **héritée de la phase 2**, documentée (L18) |
| R6 | Le presse-papiers reste un canal public | Conçu et documenté ; mécanisme en phase 4 |
| R7 | Les cibles de fuzzing des phases 1 et 2 n'ont toujours pas tourné | **Non vérifié**, signalé (NV8) |
| R8 | `Cargo.lock` des cibles de fuzzing | Le crate `fuzz/` a son propre verrou : `deny` ne le couvre pas |

---

## 8. Verdict

**Livré et vérifié.** Générateur (mots de passe, phrases, secrets) et TOTP, avec
125 tests nouveaux, 35 vecteurs officiels de RFC, 8,4 millions d'exécutions de
fuzzing, ASan et TSan propres, clippy à zéro sur les deux plateformes, `cargo deny`
4/4.

**Un défaut réel trouvé et corrigé** (D1) : une **surestimation de l'entropie**
causée par un séparateur ambigu. Il a été trouvé **par une exécution de tests**, pas
par relecture — ce qui confirme que la relecture seule ne suffit pas, et que la
détection doit reposer sur des exécutions répétées, pas sur un test qui passe une
fois.

**Un défaut de méthode aggravant** (D2) : le test qui l'a révélé était **instable**.
La correction inclut la stabilisation.

**Cinq défauts préexistants ou mineurs** (D3–D7), dont une **affirmation fausse de
mes propres notes** sur la RFC 6238, corrigée avant publication.

**Ce qui reste non vérifié** est énuméré au §3 et ne doit pas être présenté comme
acquis — au premier rang desquels **l'absence de biais du CSPRNG du noyau**, dont
dépend l'entropie annoncée, et la **couverture Miri**, limitée à 16 tests sur 473
par une limitation d'outillage.

**La conformité aux vecteurs RFC prouve la conformité à la RFC, pas la sécurité du
produit.**
