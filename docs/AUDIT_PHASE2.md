# Audit adversarial — phase 2

> Revue **indépendante** du cœur de stockage, conduite après coup et avec une posture
> hostile. Elle ne reprend pas l'audit de la phase 1 (`AUDIT_PHASE1.md`), qui reste
> valide pour le moteur cryptographique.
>
> **Ce que cet audit n'est pas.** Une revue par un tiers. Il est conduit par l'auteur
> du code, ce qui borne par construction sa capacité à trouver les défauts de
> conception partagés entre l'implémentation et son auteur.

**Périmètre.** `model/`, `archive.rs`, `query.rs`, `migrate.rs`, `store.rs`, et les
extensions de `vault.rs`, `payload.rs`, `bytes.rs`, plus les commandes de la CLI.

**Méthode.** Lecture du code, construction d'un harnais adversarial nouveau, et
vérification de chaque affirmation de la documentation **une par une** contre le
comportement observé du binaire.

---

## 1. Fonctionnalités réellement livrées

| Élément | État |
|---|---|
| `model/` — `Entry`, `Field`, `Folder`, `Tag`, `Revision`, `AttachmentMeta`, `AuditEvent`, `Archive`, identifiants, effacement | **livré** |
| `archive.rs` — encodage/décodage binaire borné et déterministe | **livré** |
| `query.rs` — recherche littérale, filtres, tri, normalisation sans dépendance | **livré** |
| `migrate.rs` — schéma 1→2, politique de rétention, chaîne de migration | **livré** |
| `store.rs` — `VaultStore` : CRUD, historique, corbeille, dossiers, tags, journal | **livré** |
| `vault.rs` — `take_body`, version de schéma, `set_migrated_from` | **livré** |
| `payload.rs` — suivi de version, `upgrade_schema` explicite | **livré** |
| `bytes.rs` — `Reader`/`Writer` bornés, `count` avec vérification avant allocation | **livré** |
| CLI — `entry add/list/show/rm/restore/purge`, `search`, `history` | **livré** |
| `docs/DATA_MODEL.md`, `docs/STORAGE_FORMAT.md`, ADR-020/021/022 | **livré** |
| Pièces jointes | **conçu, non implémenté** — le format les accueille (section présente, bornée) |
| Import/export | **conçu, non implémenté** — garde-fous documentés |
| Interface graphique | **hors périmètre** |

**Ce qui n'est pas livré ne l'est pas par choix de périmètre**, conforme à la
feuille de route approuvée : la phase 2 est le cœur de stockage seul.

---

## 2. Tests réellement exécutés

```
cargo test --workspace      →  328 tests, 0 échec
```

| Suite | Nombre | Contenu |
|---|---|---|
| `passlock-core` (unitaire) | 220 | modèle, archive, recherche, migration, primitives, plus la phase 1 |
| `passlock-core/tests/store.rs` | 22 | magasin de bout en bout, atomicité, historique, corbeille, journal |
| `passlock-core/tests/adversarial_archive.rs` | 10 | harnais adversarial du codec |
| `passlock-core/tests/adversarial.rs` | 17 | attaques de la phase 1 (non régressées) |
| `passlock-core/tests/key_hierarchy.rs` | 11 | invariants cryptographiques (phase 1) |
| `passlock-core/tests/malformed_input.rs` | 7 | robustesse (phase 1) |
| `passlock-platform` (unitaire + intégration) | 41 | mémoire, fichiers, terminal |

**Résultats quantifiés du harnais adversarial d'archive :**

* **20 000 mutations** d'une archive valide, dont **19 917 modifient réellement les
  octets** ; **1 403 sont acceptées**, et **toutes** se ré-encodent à l'identique.
* **20 000 entrées aléatoires** : aucune panique, aucune acceptation.
* **Toutes** les troncatures (0 → taille complète) : refusées.
* **Six comptes de section** × cinq valeurs absurdes (`u32::MAX`, 2 milliards,
  1 milliard, 1 million, juste au-dessus de ce que les octets permettent) : refusés.

**Analyse dynamique réellement exécutée :**

| Outil | Portée | Résultat |
|---|---|---|
| **Miri** | `bytes` (8), `model` (24), `query` (17), `migrate` (10), 6 tests d'archive ciblés, plus `header` (19) et `payload` (14) de la phase 1 | aucune opération indéfinie |
| **ASan** | espace de travail **entier**, 328 tests | **aucun défaut mémoire** |
| **TSan** | **220 tests unitaires du cœur**, dont le limiteur de dérivation | **aucune course de données** |
| `cargo deny check` | avis, bans, licences, sources | **4/4** |
| `cargo clippy` | Linux et Windows, `-D warnings` | **0 avertissement** |
| `cargo check --target x86_64-pc-windows-msvc --all-targets` | espace de travail | **compile** |

**Ce que Miri ne couvre pas, et pourquoi.** Les tests d'archive **volumineux**
(2000 entrées, parcours exhaustif octet par octet) dépassent le budget pratique de
l'interpréteur : Miri les exécute, mais en plusieurs dizaines de minutes. Six tests
d'archive ciblés — aller-retour, historique, comptes hostiles, entrées dégénérées —
sont exécutés à la place. La propriété de fidélité est en revanche couverte
exhaustivement par les 20 000 mutations, hors Miri.

---

## 3. Défauts découverts

Pas moins de **six défauts réels**, dont un de gravité élevée. Deux d'entre eux ont
été **introduits par mes propres corrections**, et détectés par des tests écrits
avant eux — c'est le résultat le plus instructif de cette phase.

### D1 — Un coffre fraîchement créé était **inouvrable** *(gravité élevée)*

`Vault::create` écrit l'enveloppe au schéma courant avec un corps **vide**, puisqu'il
ne connaît pas le modèle de données. Le magasin appelait ensuite `archive::decode` sur
ce corps vide, qui échouait sur « signature d'archive tronquée ».

Conséquence : **un coffre créé par `VaultStore::create` ne pouvait pas être rouvert**
avant le premier enregistrement. Le défaut ne se voyait pas dans le test de
persistance, qui enregistre avant de rouvrir.

Trouvé par `a_version_one_vault_opens_and_migrates_transparently`, qui ouvre un coffre
créé par l'API de la phase 1.

### D2 — Le correctif de D1 a **contourné la validation de version** *(gravité élevée, régression)*

En ajoutant le cas « corps vide », je l'ai placé **en tête** de `decode_any`. Les
schémas 0 et futurs étaient alors acceptés dès que le corps était vide — c'est-à-dire
que le raccourci contournait exactement le contrôle que les tests de version vérifient.

Trouvé par `version_zero_is_refused` et `a_future_version_is_refused_explicitly`,
écrits en phase 1 et non modifiés. **La leçon est que l'ordre des vérifications est
lui-même une propriété de sécurité** : une validation de format précède toute
interprétation, jamais l'inverse.

### D3 — La propriété de fidélité du payload était rompue *(gravité moyenne, régression)*

`Payload::decode` accepte désormais les schémas 1 et 2, mais `encode` écrivait toujours
la version courante. Un décodage d'enveloppe v1 suivi d'un encodage produisait donc des
octets **différents** — la propriété « tout ce qui est accepté se ré-encode à
l'identique » ne tenait plus, et un test de la phase 1 l'a détectée.

Corrigé en rendant la montée de version **explicite** (`Payload::upgrade_schema`),
appelée par le magasin à l'enregistrement. Effet secondaire bénéfique : la migration
devient un acte délibéré au lieu d'un effet de bord silencieux du décodage.

Trouvé par `payload_decoder_is_robust_to_arbitrary_input`, écrit en phase 1.

### D4 — `entry list --trash` affichait les entrées **actives** *(gravité moyenne)*

Les drapeaux `--trash` et `--archived` étaient passés directement en
`include_trashed` / `include_archived`, ce qui les **ajoutait** au lieu de les
**sélectionner**. L'utilisateur n'avait aucun moyen de consulter la corbeille.

Défaut purement sémantique, invisible à la lecture du code et **invisible aux tests
unitaires de `query.rs`**, qui vérifient la sémantique d'`include_*` — correcte — et
non l'intention de la commande.

Trouvé en **exerçant réellement la commande**, comme l'audit de phase 1 avait trouvé la
limite des liens symboliques en l'exécutant.

### D5 — `MIN_ENCODED_FIELD` était **trop basse** *(gravité moyenne)*

La constante valait 12 alors que le minimum d'un champ **valide** est 13 : une clé vide
est refusée, donc la clé occupe au moins un octet. Une constante **trop basse rend la
borne d'allocation plus permissive** qu'elle ne devrait l'être — c'est le sens
d'erreur dangereux, à l'inverse d'une constante trop haute qui ne ferait que refuser
des corps légitimes.

Trouvé par `the_minimum_encoded_sizes_match_the_encoder`, écrit précisément pour
confronter chaque constante à l'encodage réellement produit.

### D6 — Une fonction de duplication était un bricolage *(gravité faible)*

`clone_entry_via_codec` a été écrite puis immédiatement remplacée : elle passait par un
encodage/décodage complet et contenait du code mort. Remplacée par `Entry::duplicate`,
une méthode explicite et documentée, à sa vraie place.

### Défauts trouvés dans mes **propres tests**

Trois assertions fausses, qu'il faut consigner parce qu'un test faux protège moins
qu'aucun test — il donne l'illusion d'une vérification.

| Test | Ce qu'il affirmait à tort |
|---|---|
| `an_empty_query_returns_every_active_entry` | attendait 3 résultats ; le jeu de données en contient 4 dont **2 actives** (une archivée, une à la corbeille). C'est le filtre qui avait raison |
| `mutations_of_a_valid_archive_never_panic_or_diverge` | exigeait que **chaque** mutation modifie les octets ; une mutation peut être un no-op |
| Le même | affichait le buffer entier dans le message d'échec, ce qui aurait déversé un corps de coffre dans le journal de la CI |

---

## 4. Défauts corrigés

| # | Défaut | Correction | Non-régression |
|---|---|---|---|
| D1 | Corps vide refusé | Un corps vide est une archive vide (`decode_any`) **et** `VaultStore::create` enregistre immédiatement une archive valide | `a_version_one_vault_opens_and_migrates_transparently` |
| D2 | Version validée après le raccourci | Version validée **en premier**, avec le commentaire expliquant pourquoi l'ordre est critique | `version_zero_is_refused`, `a_future_version_is_refused_explicitly` |
| D3 | Montée de version implicite | `Payload::upgrade_schema`, appelée par `Vault::set_body` | `payload_decoder_is_robust_to_arbitrary_input` |
| D4 | Vues de liste cumulatives | `--trash`, `--archived`, `--all` sont **sélectifs** et mutuellement exclusifs | vérification manuelle + `entry list` |
| D5 | Constante de borne trop basse | 13 au lieu de 12, avec la justification du calcul | `the_minimum_encoded_sizes_match_the_encoder` |
| D6 | Duplication par le codec | `Entry::duplicate`, méthode explicite | couvert par les tests du magasin |
| — | Assertions fausses | Corrigées, avec la raison consignée | les tests eux-mêmes |

**Aucun défaut cryptographique.** Le conteneur, la hiérarchie de clés et les
paramètres de dérivation sont inchangés depuis la phase 1, et leurs tests passent.

---

## 5. Ce qui reste réellement non vérifié

Liste exhaustive, sans nuance rassurante.

1. **L'exécution du backend Windows.** Il compile — c'est vérifié à chaque `cargo
   check` — mais aucun binaire Windows n'a été lié ni exécuté : ni Wine, ni MinGW, ni
   linker MSVC dans l'environnement. Le job `windows-latest` de la CI est le seul
   endroit qui l'exécute, et **il n'a pas tourné**.
2. **Le comportement du magasin n'est pas éprouvé sur Windows** : ni les chemins, ni
   les ACL, ni `MoveFileExW`.
3. **Les cibles `cargo-fuzz` n'ont jamais tourné** (`cargo-fuzz` absent). Le harnais
   déterministe couvre une partie de la propriété, mais pas la couverture guidée.
4. **Miri sur les tests d'archive volumineux** : budget dépassé (§2).
5. **MSan et UBSan** : non exécutés, non disponibles.
6. **L'effacement mémoire n'est pas observé.** Il est vérifié par le type (`Drop`,
   `Zeroizing`) et par lecture du code, **jamais par inspection d'un vidage mémoire**.
   Un `impl Drop` oublié sur un type ajouté plus tard ne serait pas détecté
   automatiquement — le risque R1 est réel.
7. **L'historique ne peut pas être purgé des sauvegardes.** Structurel.
8. **Les pièces jointes et l'import/export** : conçus, aucune ligne exécutée.
9. **Aucun audit externe.**

---

## 6. Risques résiduels

### Acceptés, documentés, sans correctif prévu

| # | Risque | Pourquoi il n'est pas corrigé |
|---|---|---|
| R1 | Un `Drop` d'effacement oublié sur un futur type | Aucun mécanisme automatique ne peut garantir qu'un nouveau type est effacé. Parade : revue obligatoire à chaque ajout, et un test par type |
| R2 | L'historique conserve des identifiants révoqués | Choix assumé (50 / 90 jours) ; la purge existe et ses limites sont énoncées |
| R3 | La purge n'atteint pas les sauvegardes | Conséquence inévitable du fait qu'une sauvegarde est une copie de fichier |
| R4 | Le coffre est en clair en mémoire pendant toute la session | Inhérent à toute architecture où l'on affiche une entrée |
| R5 | Les copies internes à l'allocateur et au compilateur subsistent | Limites du langage et du noyau (voir `docs/CRYPTO.md` §7) |
| R6 | La recherche est O(n) par requête | Mesuré acceptable à cette échelle ; un index serait une optimisation, pas une exigence |
| R7 | Le journal ne consigne pas les consultations | Choix délibéré : les consigner rendrait toute ouverture modifiante |

### À traiter, avec une échéance

| # | Risque | Échéance |
|---|---|---|
| R8 | **Backend Windows jamais exécuté** | avant toute annonce de support |
| R9 | Cibles de fuzzing jamais exécutées | intégration continue |
| R10 | Pièces jointes : format conçu mais non éprouvé | phase 4 |
| R11 | Import/export : garde-fous documentés, non implémentés | phase 4 |
| R12 | Aucun audit externe | avant toute diffusion large |

---

## 7. Auto-critique : pourquoi cette phase pourrait être moins solide qu'elle n'en a l'air

**Le harnais adversarial trouve ce qu'il cherche.** Il mute des octets et vérifie la
fidélité. Il ne teste **pas** la sémantique du magasin : qu'une entrée mise à la
corbeille reste trouvable, que l'historique contient le bon instantané, qu'une purge
supprime bien tout. Ces propriétés sont couvertes par les tests de `store.rs`, écrits
par moi — donc avec les mêmes angles morts que le code.

**Les défauts trouvés étaient tous d'un type particulier** : ordre des vérifications,
sémantique d'un drapeau, constante trop basse, cas limite manquant. Aucun n'était une
erreur d'architecture. Cela peut signifier que l'architecture est saine — ou que je ne
sais pas la remettre en cause.

**Le point faible structurel de cette phase est l'effacement du modèle.** Il repose sur
des `impl Drop` écrits à la main, sur une dizaine de types. Le vérificateur d'emprunts
ne dit rien de leur exhaustivité, et aucun test ne peut observer un buffer libéré. Un
type ajouté en phase 3 sans son `Drop` passerait inaperçu. **C'est le risque R1, et il
est réel.**

**Ce que la phase 2 n'a pas encore éprouvé du tout** : tout ce qui touche aux fichiers.
Les pièces jointes ajouteront un format sur disque, un ramasse-miettes qui supprime des
fichiers, et une gestion de chemins. C'est la partie où les gestionnaires de mots de
passe se sont historiquement le plus fait prendre — et elle arrive en phase 4.

**Enfin, cet audit n'est pas un audit.** Les tests verts ne prouvent pas la sécurité :
ils prouvent que les propriétés écrites tiennent. Rien de plus.
