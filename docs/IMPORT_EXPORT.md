# Import et export — format CSV canonique

> Ce document décrit le format **de façon autonome** : une autre implémentation,
> dans un autre langage, doit pouvoir produire un fichier que Passlock accepte, et
> relire un fichier que Passlock produit. Le format est **explicite** et ne dépend
> d'aucun détail interne.

## 1. Ce que le format contient — et ce qu'il ne contient pas

Une projection **textuelle, en clair**, des entrées du coffre.

**Contient** : le type, le titre, le sous-titre, le dossier, les tags, les champs
nommés, les drapeaux `favorite`/`archived`/`sensitive`, et les dates de création et de
modification.

**Ne contient pas** :

* les **pièces jointes** (les blobs chiffrés vivent hors du conteneur) ;
* l'**historique** (une seule version par entrée, la courante) ;
* la **corbeille** (les entrées mises à la corbeille ne sont pas exportées) ;
* les **réglages** du coffre ;
* le **journal** de sécurité ;
* les **identifiants internes** (`EntryId`, `FolderId`, `TagId`, `BlobId`), qui sont
  aléatoires et non exportables.

Un export n'est donc **pas une sauvegarde** : c'est un échange de données. Pour
sauvegarder un coffre, voir `docs/BACKUP.md`.

## 2. Vue d'ensemble

* Encodage : **UTF-8**. Séparateur de champ : `,`. Séparateur de ligne : `\n`. Chaque
  ligne, en-tête comprise, se termine par `\n`.
* À l'**import**, un `\r\n` est accepté et **normalisé** en `\n` (RFC 4180) ; un `\r`
  **isolé hors guillemets** est refusé. Un `\r` **dans** un champ cité est un contenu,
  préservé tel quel. L'**export** n'émet jamais que `\n`.
* Guillemets : **RFC 4180**. Une cellule est entourée de `"` si et seulement si elle
  contient `,`, `"`, `\n` ou `\r`. À l'intérieur, `"` est doublé (`""`).
* Une ligne d'en-tête **fixe**, puis une ligne par entrée.
* **NUL interdit** : aucun octet `0x00` dans le fichier, et aucune représentation
  échappée d'un NUL (voir §4).

```text
entry_ref,kind,title,subtitle,folder,tags,fields,favorite,archived,sensitive,created_at,updated_at
```

| # | Colonne | Contenu | Contexte d'échappement |
|---|---|---|---|
| 1 | `entry_ref` | référence de ligne, `E` + index décimal sur 8 chiffres | — (voir §5) |
| 2 | `kind` | nom canonique du type d'entrée | scalaire |
| 3 | `title` | titre | scalaire |
| 4 | `subtitle` | sous-titre | scalaire |
| 5 | `folder` | chemin de dossier, composants joints par `/` | dossier |
| 6 | `tags` | noms de tags, joints par `\|`, triés | tag |
| 7 | `fields` | structure canonique des champs (voir §4) | champs |
| 8 | `favorite` | `true` ou `false` | scalaire |
| 9 | `archived` | `true` ou `false` | scalaire |
| 10 | `sensitive` | `true` ou `false` | scalaire |
| 11 | `created_at` | date de création, secondes Unix, décimal | scalaire |
| 12 | `updated_at` | date de modification, secondes Unix, décimal | scalaire |

### Types canoniques

| Entrée | `kind` |
|---|---|
| identifiant | `login` |
| note sécurisée | `secure_note` |
| carte bancaire | `credit_card` |
| identité | `identity` |
| clé d'API | `api_key` |
| clé SSH | `ssh_key` |
| réseau Wi-Fi | `wifi` |
| passkey (métadonnées) | `passkey_metadata` |
| personnalisé | `custom` |

| Champ | `kind` (dans `fields`) |
|---|---|
| texte | `text` |
| secret | `secret` |
| url | `url` |
| texte long | `multiline` |
| courriel | `email` |
| totp | `totp` |
| nombre | `number` |
| date | `date` |
| code | `pin` |
| personnalisé | `custom` |

## 3. Échappement, par contexte

L'échappement est **déterministe**, **strict** et **contextuel**. Un `%` introduit par
un `%XX` n'est jamais ré-échappé : **on échappe `%` en premier**.

| Contexte | Cellules | Remplacer |
|---|---|---|
| scalaire | `kind`, `title`, `subtitle`, `favorite`, `archived`, `sensitive`, `created_at`, `updated_at` | `%` → `%25` |
| dossier | chaque **composant** de `folder` | `%` → `%25`, `/` → `%2F` |
| tag | chaque **nom** de `tags` | `%` → `%25`, `\|` → `%7C` |
| champs | chaque **chaîne interne** au JSON de `fields` | `%` → `%25` |

Règles non négociables :

* l'hexadécimal est **toujours en majuscules** : `%2f` est **refusé** ;
* seules les séquences **admises dans le contexte** sont valides : `%2F` n'est valide
  que dans un composant de dossier, `%7C` que dans un tag, `%25` partout ;
* le **découpage précède le déséchappement** : `folder` est découpé sur `/`, `tags`
  sur `|`, **puis** chaque morceau est déséchappé. Un `/` ou un `|` littéral a été
  échappé à l'export (`%2F`, `%7C`), il ne peut donc pas être pris pour un séparateur ;
* toute séquence **inconnue**, **incomplète** ou **minuscule** fait échouer l'import ;
  il n'existe **aucun** décodage « au mieux ».

## 4. La cellule `fields`

### 4.1 Pourquoi une structure

Une entrée porte un nombre variable de champs. Une colonne CSV unique ne peut pas les
accueillir « à plat » sans introduire un séparateur interne — or `/` et `|` sont
réservés à `folder` et `tags`, et aucun autre caractère d'échappement n'est admis. La
cellule contient donc une **structure canonique** : un tableau JSON à clés fixes.

### 4.2 Grammaire

```text
fields_cell = "[]" | "[" field ("," field)* "]"

field       = "{" "\"key\":"   string ","
                  "\"kind\":"  string ","
                  "\"value\":" string ","
                  "\"ordinal\":" uint ","
                  "\"concealed\":" bool "}"

uint        = "0" | chiffre-non-nul chiffre*        ; 0..65535, sans zéro de tête
bool        = "true" | "false"

string      = '"' char* '"'
char        = octet octet UTF-8 sauf  "  \  U+0000..U+001F  %
            | "\""        ; guillemet
            | "\\"        ; barre oblique inverse
            | "\b"        ; U+0008
            | "\f"        ; U+000C
            | "\n"        ; U+000A
            | "\r"        ; U+000D
            | "\t"        ; U+0009
            | "%25"       ; SEUL percent-escape admis ici
            | "\u00XX"    ; voir ci-dessous
```

### 4.3 Canonicalisation

1. **Échappement** : dans `key`, `kind` et `value`, `%` → `%25`. Le `/` et le `|` sont
   **littéraux** : ils n'ont aucun rôle structurel dans `fields`.
2. **Encodage JSON** de la chaîne échappée : `"` → `\"`, `\` → `\\`, et pour les
   caractères de contrôle.
3. **`\u00XX`** n'est admis **que** pour un C0 qui n'a pas de raccourci :
   `01`–`07`, `0B`, `0E`–`1F`. Les cinq caractères `08 09 0A 0C 0D` ont pour **seule**
   forme canonique `\b \t \n \f \r`. **`\u0000` est interdit.** Les chiffres
   hexadécimaux sont **toujours en majuscules** (`\u000b` est refusé). Tout `\u00XX`
   représentant autre chose qu'un C0 autorisé — `\u0041` par exemple — est refusé.
   **Aucune chaîne n'a donc deux écritures possibles.**
4. **Ordre des champs** : par `(ordinal, key, kind, value, concealed)` sous forme
   encodée. Deux listes logiquement égales produisent la même cellule.
5. **Ordre des clés d'objet** : toujours `key`, `kind`, `value`, `ordinal`,
   `concealed` — **aucun espace**, `[]` pour une liste vide.

### 4.4 Exemple

Champs `password`/secret/`Tr0p%S3cr3t`/ordinal 0 et `url`/url/`https://ex.com/a|b`/ordinal 1 :

Cellule (avant guillemets CSV) :

```json
[{"key":"password","kind":"secret","value":"Tr0p%25S3cr3t","ordinal":0,"concealed":true},{"key":"url","kind":"url","value":"https://ex.com/a|b","ordinal":1,"concealed":false}]
```

Dans le CSV, cette cellule contient `,` et `"` : elle est entourée de guillemets et ses
`"` sont doublés.

## 5. Tri et `entry_ref`

* Les entrées sont triées par les **11 colonnes 2 à 12**, comparées **dans l'ordre des
  colonnes**, puis **bytewise UTF-8** sur leur forme **encodée**. Ce tri **ne dépend
  jamais** d'un identifiant interne ni de l'ordre d'insertion.
* Les tags sont triés par **nom encodé** au sein de la colonne 6, et dédupliqués.
* `entry_ref` est attribué **après le tri** : `E` suivi du rang décimal sur 8 chiffres
  (`E00000001`, `E00000002`, …). Il est **ignoré à l'import** (l'import ne l'utilise ni
  comme clé, ni comme ordre) ; à la relecture, il doit simplement avoir cette forme.

**Conséquence** : `export → import → export` produit un fichier **identique octet pour
octet**. Ce qui n'est pas exporté (identifiants, révision, historique, corbeille,
réglages, pièces jointes, `ordinal` de dossier) n'influence ni une cellule ni le
comparateur.

## 6. Bornes, appliquées avant toute allocation

| Borne | Valeur | Où elle s'applique |
|---|---|---|
| Taille du fichier | 512 Mio | refus **avant** lecture |
| Taille d'un enregistrement | 64 Mio | refus **pendant** l'analyse |
| Taille d'une cellule | 64 Mio | refus **pendant** l'analyse |
| Nombre d'entrées | 1 000 000 | aligné sur le modèle |
| Nombre de champs par entrée | 256 | aligné sur le modèle |

Ces bornes dépassent ce que le modèle peut produire : la plus grosse cellule `fields`
possible — 256 champs de 64 Kio, échappés — reste sous 64 Mio.

## 7. Import : strict et transactionnel

L'import **refuse** :

* un en-tête différent ou un nombre de colonnes ≠ 12 ;
* un octet NUL, ou une entrée non-UTF-8 ;
* une séquence d'échappement inconnue, incomplète ou minuscule, ou `%2F`/`%7C` hors de
  leur contexte ;
* un `kind` inconnu, un booléen qui n'est pas `true`/`false`, un horodatage non
  canonique (zéro de tête refusé) ;
* une cellule `fields` non canonique (clés dans le désordre, espace, `\u` non
  canonique, `%` interdit dans une chaîne, structure tronquée) ;
* un composant de dossier vide, une profondeur de dossier au-delà de la limite, un tag
  vide ou répété ;
* toute valeur violant les invariants du modèle (titre ou champ hors bornes, etc.).

L'import **n'écrit rien** tant que tout n'est pas validé : le fichier entier est
analysé et construit en mémoire **d'abord**, puis un **seul** enregistrement du coffre
a lieu. Un CSV refusé laisse le coffre **strictement inchangé** — ni entrée, ni
dossier, ni tag.

Les entrées **s'ajoutent** aux données existantes. Un dossier ou un tag de même nom
(comparaison insensible à la casse) est **réutilisé**, jamais dupliqué. Les
identifiants internes sont **neufs** : l'import ne « restaure » pas un coffre, il y
verse des entrées.

## 8. Ligne de commande

```sh
# Export vers un fichier neuf (jamais écrasé, permissions 0600).
passlock export coffre.plk --output sauvegardes/export.csv

# Export vers la sortie standard (par exemple pour un tube).
passlock export coffre.plk --stdout > export.csv

# Import : ajoute les entrées du fichier au coffre.
passlock import coffre.plk --input export.csv
```

* La destination de l'export est **obligatoire** : rien n'est écrit par défaut.
* Le mot de passe maître est lu par l'invite habituelle, ou sur l'entrée standard avec
  `--password-stdin`. **Aucun secret n'est accepté en argument de commande.**
* L'export ouvre le coffre en **lecture seule** : il ne crée ni verrou ni sentinelle et
  ne modifie rien.

## 9. Ce que le format ne protège pas

* Il est **en clair** : il contient les secrets sans chiffrement. Sa confidentialité
  repose entièrement sur l'endroit où il est rangé.
* Il **ne restaure pas** un coffre : il n'a ni les pièces jointes, ni l'historique, ni
  l'identité du coffre. Un import dans un coffre existant **ajoute** des entrées.
* Les dates exportées proviennent du coffre ; un import les reprend telles quelles.
