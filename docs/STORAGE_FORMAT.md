# Format de stockage — archive du corps (schéma 2)

> Complète `VAULT_FORMAT.md`, qui décrit le **conteneur**. Ici : ce que contient le
> corps déchiffré.

## 1. Rappel : deux formats indépendants

```
coffre.plk
├── conteneur            (VAULT_FORMAT.md — inchangé depuis la phase 1)
│   ├── signature, version, drapeaux, longueur
│   ├── header : identifiant, slots de clé, sels, paramètres KDF
│   ├── nonce
│   └── payload chiffré  ──── AEAD, AAD = tout le préfixe + header
│         │
│         ▼  (déchiffré)
└── enveloppe de payload  (phase 1)
    ├── "PAY1"
    ├── schema_version      ─── 1 = corps vide (phase 1), 2 = archive (phase 2)
    ├── génération
    └── corps  ─────────────► ARCHIVE (ce document)
```

Le **conteneur** et le **schéma du corps** évoluent séparément. Ajouter un type
d'entrée, un champ ou un index ne change **jamais** le conteneur : c'est cette
séparation qui permet de faire évoluer le modèle de données pendant des années sans
casser une seule sauvegarde.

## 2. Archive

`ARCHIVE_MAGIC = "ARC2"`, `ARCHIVE_VERSION = 2`.

| Offset | Taille | Champ | Rôle |
|---|---|---|---|
| 0 | 4 | `magic` | `"ARC2"` |
| 4 | 2 | `version` | `u16` = 2 |
| 6 | 2 | *réservé* | doit valoir `0` |
| 8 | 8 | `created_at` | `u64`, secondes epoch |
| 16 | 4 | `folder_count` | nombre de dossiers |
| 20 | 4 | `tag_count` | nombre de tags |
| 24 | 4 | `entry_count` | nombre d'entrées |
| 28 | 4 | `attachment_count` | pièces jointes — section **présente et bornée**, toujours 0 tant que la phase 4 ne les implémente pas |
| 32 | 4 | `audit_count` | événements de journal |
| 36 | 4 | `settings_count` | réglages du coffre |
| 40 | … | sections | dans l'ordre : réglages, dossiers, tags, entrées, journal |

**Les comptes sont en tête.** C'est ce qui permet de les valider **avant** de
parcourir quoi que ce soit, et donc avant toute allocation (§5).

## 3. Enregistrements

Tous les entiers sont en **gros-boutiste**, à taille fixe.

### 3.1 Dossier — minimum 38 octets

`id` (16) · `name_len` (4) + octets UTF-8 · `parent` (16, tout à zéro = aucun) · `ordinal` (2)

### 3.2 Tag — minimum 20 octets

`id` (16) · `name_len` (4) + octets UTF-8

### 3.3 Champ — minimum 13 octets

`key_len` (4) + octets · `kind` (1) · `ordinal` (2) · `flags` (1) · `value_len` (4) + octets

`flags` : bit 0 = masqué à l'affichage. Tout bit inconnu est **refusé**.

### 3.4 Entrée — minimum 82 octets

| Ordre | Champ | Taille |
|---|---|---|
| 1 | `id` | 16 |
| 2 | `kind` | 1 |
| 3 | `flags` | 1 — bit 0 favori, bit 1 archivée, bit 2 sensible |
| 4 | `revision` | 4 |
| 5 | `created_at` | 8 |
| 6 | `updated_at` | 8 |
| 7 | `trashed_at` | 8 — `0` signifie « pas à la corbeille » |
| 8 | `folder` | 16 — tout à zéro signifie « aucun » |
| 9 | `title` | 4 + octets |
| 10 | `subtitle` | 4 + octets |
| 11 | `tags` | 4 + n × 16 |
| 12 | `fields` | 4 + n × Champ |
| 13 | `history` | 4 + n × Révision |

Tout bit de `flags` non défini est **refusé**.

### 3.5 Révision — minimum 12 octets

`at` (8) · `entry_len` (4) · `entry_len` octets d'une **Entrée encodée**

**Invariant structurel** : l'entrée d'un instantané **doit** avoir un historique
vide. Le décodeur refuse le contraire. C'est ce qui borne la profondeur de la
structure à un niveau — sans cette règle, un corps forgé pourrait imbriquer des
révisions à l'infini et épuiser la pile.

### 3.6 Pièce jointe — minimum 92 octets

`id` (16) · `entry` (16) · `name_len` (4) + octets · `size` (8) · `chunk_size` (4) ·
`chunk_count` (4) · `created_at` (8) · `content_mac` (32)

### 3.7 Événement de journal — minimum 25 octets

`at` (8) · `kind` (1) · `subject` (16, tout à zéro = aucun)

## 4. Déterminisme

L'encodage ne comporte **aucune structure associative**. Les sections suivent l'ordre
des `Vec`, les champs leur `ordinal`. Deux archives équivalentes produisent donc des
octets **identiques**, ce qui rend deux choses possibles :

* le format est testable par simple comparaison d'octets ;
* l'AAD du conteneur, qui repose sur l'encodage du header, ne peut pas être ambiguë.

Un test vérifie que deux encodages successifs de la même archive sont identiques.

## 5. Bornes, et l'invariant qui compte

### 5.1 L'invariant

> **Aucune allocation n'est dimensionnée par une valeur lue dans le corps avant que
> cette valeur n'ait été confrontée aux octets réellement disponibles.**

Avant tout `Vec::with_capacity(count)`, on vérifie :

```
count × taille_minimale_d_un_enregistrement  ≤  octets_restants
```

avec `checked_mul`. Un corps déclarant quatre milliards d'entrées dans cent octets
est donc refusé **avant** toute tentative de réservation, et non après un
épuisement mémoire.

Les tailles minimales utilisées sont celles de §3, et un test les confronte à
l'encodage réellement produit — une constante **trop basse** rendrait la borne plus
permissive qu'elle ne devrait l'être.

### 5.2 Bornes

| Borne | Valeur |
|---|---|
| `MAX_ENTRIES` | 1 000 000 |
| `MAX_FOLDERS` / `MAX_TAGS` | 4 096 |
| `MAX_FIELDS_PER_ENTRY` | 256 |
| `MAX_TAGS_PER_ENTRY` | 64 |
| `MAX_HISTORY_PER_ENTRY` | 50 |
| `MAX_AUDIT_EVENTS` | 1 000 |
| `MAX_ATTACHMENTS` | 4 096 |
| `MAX_FOLDER_DEPTH` | 8 |
| `MAX_TITLE_LEN` | 1 Kio |
| `MAX_NAME_LEN` | 256 o |
| `MAX_FIELD_KEY_LEN` | 128 o |
| `MAX_FIELD_VALUE_LEN` | 64 Kio |
| `MAX_ARCHIVE_LEN` | `MAX_VAULT_BYTES / 2` |

### 5.3 Validation à deux niveaux

1. **Le décodeur garantit la forme** : signature, version, zones réservées, bornes,
   comptes compatibles avec les octets restants, UTF-8 valide, absence de récursion.
2. **`Archive::validate` garantit la cohérence** : références croisées (dossier, tags,
   pièce jointe), absence de cycle de dossiers, invariants par entrée.

Les deux sont appelées, dans cet ordre. Une référence invalide est une **erreur**,
jamais un `Option` silencieusement vide : une donnée rattachée à rien disparaîtrait
sans que personne ne s'en aperçoive.

## 6. Recherche

Aucun index n'est stocké. La recherche parcourt l'archive à chaque requête.

**Pourquoi pas d'index.** Trois défauts pour aucun bénéfice à cette échelle : une
désynchronisation possible entre l'index et les données, une double mémoire (l'index
recopie des secrets), et une surface d'injection dès que l'index apporte son propre
langage de requête — exactement ce que FTS5 aurait imposé.

**La requête n'est pas un langage.** Le texte est découpé en termes littéraux ; tous
doivent apparaître. Aucune expression régulière, aucun opérateur. Les métacaractères
sont des caractères comme les autres : il n'y a rien à échapper, donc rien à injecter.

**Bornes** : 16 termes, 64 octets par terme, 1 000 résultats.

## 7. Migration

`schema_version` vit **dans l'enveloppe chiffrée**. Réglé par `migrate.rs` :

| Version | Contenu du corps |
|---|---|
| 1 | **vide** — la phase 1 ne stockait pas de modèle |
| 2 | archive |

**Règles.**

1. La version est validée **avant** tout raccourci d'interprétation.
2. Migration **en mémoire**, de proche en proche, sans saut de version.
3. **Si une migration échoue, rien n'est écrit** : le fichier reste octet pour octet
   identique. C'est la propriété la plus importante du mécanisme, et elle est testée.
4. Un corps **vide** est une archive vide, y compris au schéma courant — `Vault::create`
   écrit l'enveloppe courante sans connaître le modèle. Sans ce cas, un coffre
   fraîchement créé serait inouvrable.
5. La montée de version est un **acte explicite** (`Payload::upgrade_schema`), effectué
   à l'enregistrement. Rendre la montée implicite au décodage ferait perdre la
   fidélité de l'aller-retour décodage/encodage.
6. Une version **supérieure** à celle du binaire est refusée avec un message
   actionnable.

## 8. Ajouter une migration

1. Incrémenter `PAYLOAD_SCHEMA_VERSION` (et `migrate::CURRENT_SCHEMA` suit, un test
   vérifie leur cohérence).
2. Ajouter un bras dans `migrate_step` pour la version précédente.
3. Écrire un test qui part d'un corps de cette version.

Aucune autre modification n'est nécessaire : la chaîne d'appel s'adapte.
