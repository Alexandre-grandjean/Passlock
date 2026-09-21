# Audit adversarial — phase 5, étape 4 : présentation CLI du centre de sécurité

> Rapport **séparé**, comme pour les étapes précédentes. Il distingue ce qui a été
> **livré**, ce qui a été **réellement exécuté**, ce qui a été **trouvé**, et ce qui
> reste **non vérifié**.

---

## 1. Périmètre

Une **couche de présentation** : la commande `passlock security COFFRE`. Elle affiche
les six indicateurs déjà calculés par `passlock_core::security`, sans rien recalculer et
sans rien modifier. Aucun septième indicateur, aucun score global.

## 2. Ce qui a été livré

`crates/passlock-cli/src/security.rs` : `command()` + `cmd_security`, et six
présentateurs (`print_reuse`, `print_age`, `print_strength`, `print_weak`,
`print_missing_totp`, `print_expiry`).

La commande ouvre le coffre en **lecture seule imposée** (`VaultConfig { read_only: true }`),
lit l'instant à la frontière (`now_seconds()`), et appelle `run_security_center` **sans
horloge dans le module pur**. Aucun `save()`.

## 3. Ce qui a été **réellement exécuté**

| Outil | Résultat |
|---|---|
| `cargo test --workspace` | **729 tests, 0 échec** |
| `cargo test -p passlock-cli --test security` | **8 tests, 0 échec** |
| `cargo fmt --all -- --check` | **propre** |
| `cargo clippy --workspace --all-targets` | **0 avertissement** |
| `cargo build --workspace --all-targets` | **passe** |
| `cargo deny check` | **4/4 ok** (configuration **inchangée**) |
| `cargo +nightly fuzz build` | **les 12 cibles compilent** |
| **E2E réel** (coffre de test) | voir §5 |

## 4. L'audit demandé : quatre chemins, et leur fermeture

Le contrat de cette étape se résume à quatre propriétés. Chacune est vérifiée.

### 4.1 Aucun chemin n'imprime un secret

La couche affiche : identifiants, **titres**, **clés de champ** (`password`, `pin`…),
**ordinals**, genres, bits estimés, jours, dates et états. Elle **ne lit jamais** une
`Field::value`. La seule fonction qui touche aux champs (`field_key`) ne renvoie que la
**clé**, jamais le contenu.

`the_report_never_contains_a_secret_or_a_fingerprint` (cœur, étape 5.1) établit déjà
que le **rapport** ne porte aucune valeur. Le test CLI
`seeded_indicators_are_shown_without_leaking_any_value` vérifie la sortie **réelle** :
la valeur partagée n'apparaît pas.

### 4.2 Aucun chemin n'imprime une empreinte

Le type `ReuseGroup` ne contient que des `EntryId` et des `FieldRef` ; l'empreinte reste
une clé de `BTreeMap` interne au calcul, jamais rendue. Un test structurel de la sortie
vérifie qu'**aucun jeton de 64 caractères hexadécimaux** (la forme d'une empreinte
SHA-256) n'y figure.

### 4.3 Aucun chemin ne modifie le coffre

La configuration est **écrasée en lecture seule** par la commande ; aucun `save()`
n'existe dans le module. Le test `the_command_is_read_only_and_deterministic` compare,
avant et après exécution, **les octets du fichier de coffre** et **la liste des fichiers
du répertoire** : identiques. L'exécution est aussi **déterministe** (deux exécutions
produisent la même sortie).

### 4.4 Aucune incertitude n'est transformée en verdict positif

`ExpiryState::Unknown` est rendu par un motif explicite (« aucune date », « date mal
formée », « date impossible », « plusieurs champs `expires_at` »), jamais par
« valide ». `StrengthBand::Indeterminate` affiche « indéterminée (aucune estimation
chiffrée) », jamais un chiffre ni « fort ». Le verdict haut de l'estimation s'appelle
**« aucune faiblesse structurelle détectée »**, jamais « fort » ni « sûr ».

`unknown_and_indeterminate_states_are_shown_as_such` vérifie ces deux affichages, et
`an_empty_vault_shows_the_six_indicators_and_no_global_score` vérifie qu'aucun mot
d'agrégat (`score`, `pourcent`, `global`, `classement`) n'apparaît.

## 5. E2E réel

Coffre de test avec deux entrées actives (une troisième mise à la corbeille) :

```
Centre de sécurité — 2 entrée(s) analysée(s), corbeille exclue.
Fenêtre d'expiration : 30 jour(s). Référence : 2026-09-21 (UTC).

Robustesse estimée (heuristique structurelle — PAS une entropie mesurée)
  af62…  compte ancien — champ « password » (ordinal 0) : indéterminée (aucune estimation chiffrée) [caractères hors des classes connues]
  d7bb…  banque.example — champ « password » (ordinal 0) : 41.4 bits — très faible
  Note : cette estimation compte des plages et des classes de caractères ; elle est aveugle aux mots de dictionnaire. Un résultat élevé ne garantit rien.

Absence de TOTP
  af62…  compte ancien — aucun TOTP détecté

Expiration
  af62…  compte ancien — 1970-01-02 — expirée (il y a 20716 jour(s))
  d7bb…  banque.example — indéterminée (aucune date)

Ces indications sont des **faits**, pas des garanties : l'absence de signal n'est pas une preuve de sécurité.
```

La **corbeille est exclue** (« 2 entrée(s) analysée(s) » alors que 3 existent), et
aucune valeur de mot de passe n'apparaît.

## 6. Défaut de présentation trouvé et corrigé

**Une redondance trompeuse.** La première version affichait, pour une estimation
indéterminée, `estimation indéterminée — indéterminée (caractères hors classes connues)
[caractères hors des classes connues]` : le même fait, trois fois. La ligne dit
désormais `indéterminée (aucune estimation chiffrée) [caractères hors des classes
connues]`. Aucun changement de comportement, mais un affichage qui ne noie plus
l'information utile.

## 7. Ce qui n'est **pas** vérifié

| # | Non vérifié | Motif |
|---|---|---|
| NV1 | **Exécution Windows** | la présentation est portable ; non exécutée sous Windows |
| NV2 | **Intégration continue** | jamais lancée sur ce dépôt |
| NV3 | **Miri / ASan / TSan** | non relancés |
| NV4 | **Lisibilité sur un très grand coffre** | la sortie est linéaire en nombre d'entrées ; un coffre de plusieurs milliers d'entrées produira une sortie longue, non mesurée |
| NV5 | **Correction linguistique des libellés** | vérifiée par lecture, pas par un outil |

## 8. Risques résiduels

| # | Risque | Traitement |
|---|---|---|
| R1 | **Un rapport vide rassure à tort** | une ligne de pied dit explicitement que l'absence de signal n'est **pas** une preuve ; **L37** |
| R2 | **Les titres sont affichés** | c'est la convention CLI existante (`entry list`), et ce ne sont pas des valeurs de champ |
| R3 | **Un IDN légitime apparaît « indéterminé »** | limite **L35** assumée : on ne prétend pas valider IDNA |

## 9. Verdict

**Livré et vérifié.** Une couche de présentation **strictement en lecture seule**,
**déterministe**, sans score global, qui n'expose **ni valeur ni empreinte** et
**n'embellit aucune incertitude**. Les quatre chemins du contrat (secret, empreinte,
écriture, incertitude→positif) sont fermés et testés.

**Un défaut d'affichage** trouvé et corrigé (redondance sur l'estimation indéterminée).

**Ce qui reste non vérifié** est au §7, au premier rang desquels l'exécution Windows et
l'intégration continue.

**Suite.** La phase 6 (interface graphique) n'est pas commencée.
