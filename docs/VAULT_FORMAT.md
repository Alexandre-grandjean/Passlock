# Format du coffre Passlock — version 1

> Ce document décrit **exactement** ce que le code écrit et lit. Le format est gelé
> à l'issue de la phase 1 : tout coffre créé par une version ultérieure doit rester
> lisible par ce lecteur, ou la version de format doit être incrémentée et un outil
> de migration fourni.

## 1. Principes

1. **Aucun champ n'est non authentifié.** Le header entier entre dans l'AAD du
   payload. Modifier un seul octet — y compris un paramètre de dérivation ou un
   sel — invalide le tag du contenu.
2. **Aucun parseur générique.** Le layout est à offsets fixes. Il n'y a donc ni
   récursion possible, ni longueur imbriquée, ni subtilité d'encodage canonique.
   Le seul traitement d'entrée non fiable effectué **avant** toute
   authentification est une suite de lectures bornées.
3. **Le minimum de métadonnées publiques.** Le header ne contient que ce qui est
   strictement nécessaire au déchiffrement. Il ne contient **ni** nombre d'entrées,
   **ni** titres, **ni** noms de dossiers, **ni** index de recherche, **ni** taille
   du contenu applicatif, **ni** aucune donnée d'entrée du coffre. Tout cela vit
   dans le payload chiffré.
4. **Encodage déterministe.** Deux headers équivalents produisent des octets
   identiques, par construction et non par convention.
5. **Tous les entiers sont en gros-boutiste** (big-endian), taille fixe.

## 2. Layout du fichier

| Offset | Taille | Champ | Contenu |
|---|---|---|---|
| 0 | 8 | `magic` | `"PASSLOCK"` (octets `50 41 53 53 4C 4F 43 4B`) |
| 8 | 2 | `format_version` | `u16` — vaut `1` |
| 10 | 2 | `flags` | `u16` — doit valoir `0` |
| 12 | 4 | `header_len` | `u32` — longueur du header en octets, ≤ 4096 |
| 16 | `H` | `header` | voir §3 |
| 16 + H | 24 | `payload_nonce` | nonce XChaCha20 |
| 40 + H | `P` | `payload_ciphertext` | contenu chiffré, **tag de 16 octets inclus** (postfixe) |

Longueur totale : `40 + H + P`.

`flags` est **refusé s'il est non nul**. Ignorer un drapeau inconnu reviendrait à
deviner sa sémantique : c'est ainsi qu'on introduit une faille en
rétrocompatibilité. Un fichier portant un drapeau que cette version ne comprend pas
est refusé avec un message explicite.

## 3. Header

Partie fixe : 28 octets.

| Offset | Taille | Champ | Contenu |
|---|---|---|---|
| 0 | 16 | `vault_id` | identifiant aléatoire, stable sur toute la vie du coffre |
| 16 | 8 | `created_at` | `u64` — secondes depuis l'époque Unix |
| 24 | 1 | `payload_alg` | `1` = XChaCha20-Poly1305 |
| 25 | 1 | `slot_count` | 1 à 16 |
| 26 | 2 | *réservé* | doit valoir `0` |
| 28 | `122 × slot_count` | `slots` | voir §4 |

**Longueur exigée : exactement `28 + 122 × slot_count`.** Aucun octet
excédentaire n'est toléré. Un désaccord signale soit une corruption, soit une
tentative de faire porter des données non prises en compte par le décodeur.

### 3.1 Rôle de `vault_id`

* corréler une sauvegarde et la sentinelle anti-retour-en-arrière (§7) ;
* lier l'authentification de chaque slot à **ce** coffre précis (§5.1), ce qui
  empêche de déplacer un slot d'un coffre à un autre.

Il est public. Il ne doit jamais être traité comme un secret.

## 4. Slot de clé — 122 octets

| Offset | Taille | Champ | Contenu |
|---|---|---|---|
| 0 | 2 | `slot_id` | `u16`, unique dans le header |
| 2 | 1 | `label` | `1` = mot de passe maître, `2` = récupération, `3` = matériel |
| 3 | 1 | `kdf_alg` | `1` = Argon2id |
| 4 | 1 | `argon2_version` | `0x13` (v1.3) |
| 5 | 1 | *réservé* | doit valoir `0` |
| 6 | 4 | `m_cost_kib` | `u32` — coût mémoire en Kio |
| 10 | 4 | `t_cost` | `u32` — nombre d'itérations |
| 14 | 4 | `p_cost` | `u32` — degré de parallélisme |
| 18 | 32 | `salt` | sel Argon2id |
| 50 | 24 | `wrap_nonce` | nonce XChaCha20 de l'enveloppe |
| 74 | 48 | `wrapped_dek` | DEK chiffrée (32) + tag (16) |

### 4.1 Règles de validation à la lecture

Chaque violation produit une erreur typée, jamais une panique :

* `label` ∈ {1, 2, 3} ; `kdf_alg` = 1 ; `argon2_version` = 0x13 ; champs réservés = 0 ;
* `slot_count` ∈ [1, 16], et les `slot_id` sont **uniques** ;
* `m_cost_kib` ∈ [8192, 2097152], `t_cost` ∈ [1, 16], `p_cost` ∈ [1, 16] ;
* `salt` = 32 octets, `wrap_nonce` = 24, `wrapped_dek` = 48 (garantis par le layout) ;
* taille du header exactement conforme.

**Le plafond de `m_cost_kib` (2 Gio) est une protection contre le déni de service,
pas un choix de sécurité.** Un fichier hostile peut annoncer `m = 4 Gio` : le refus
intervient pendant le décodage du header, donc **avant** toute allocation liée à
ces paramètres. Sans ce plafond, ouvrir un fichier piégé suffirait à épuiser la
mémoire de la machine.

### 4.2 Pourquoi chaque slot a son propre sel et ses propres paramètres

Un slot de récupération porte une clé de 256 bits tirée au hasard, qui n'est pas
attaquable par force brute ; un slot de mot de passe maître protège un secret
d'entropie inconnue. Imposer les mêmes paramètres aux deux serait absurde. Chaque
slot est donc autonome, et **retirer ou ajouter un slot n'affecte aucun autre**.

## 5. Données authentifiées (AAD)

### 5.1 AAD d'un slot

```
"passlock/v1/slot"          (16 octets, ASCII)
‖ vault_id                  (16)
‖ slot_id                   (2, gros-boutiste)
‖ label                     (1)
‖ kdf_alg                   (1)
‖ argon2_version            (1)
‖ m_cost_kib                (4, gros-boutiste)
‖ t_cost                    (4, gros-boutiste)
‖ p_cost                    (4, gros-boutiste)
‖ salt                      (32)
```

`wrapped_dek` est **exclu** : il porte son propre tag, et l'inclure rendrait la
construction circulaire.

**Ce que cette liaison empêche.** Sans elle, un attaquant pourrait déplacer un slot
d'un coffre vers un autre, ou échanger deux slots, et le désenveloppement
réussirait — la KEK correspondrait toujours — en produisant une clé de données qui
n'est pas celle attendue. Avec elle, tout déplacement invalide l'authentification.

### 5.2 AAD du payload

**Les octets `0 .. 16 + header_len`** du fichier, c'est-à-dire la signature, la
version, les drapeaux, la longueur et l'intégralité du header.

C'est ce qui rend **structurellement impossible** une attaque par abaissement des
paramètres : réduire `m_cost` dans le header pour rendre le cassage hors ligne moins
coûteux invalide le tag du contenu.

## 6. Payload déchiffré

Une fois le payload déchiffré et son tag vérifié, on obtient une enveloppe :

| Offset | Taille | Champ | Contenu |
|---|---|---|---|
| 0 | 4 | `magic` | `"PAY1"` |
| 4 | 2 | `schema_version` | `u16` — vaut `1` |
| 6 | 2 | *réservé* | doit valoir `0` |
| 8 | 8 | `generation` | `u64` — compteur monotone |
| 16 | 4 | `body_len` | `u32` |
| 20 | `body_len` | `body` | contenu applicatif |

Longueur totale exigée : exactement `20 + body_len`.

### 6.1 Pourquoi la génération est ici et non dans le header

Le header est lisible **sans la clé**. Un compteur de génération qui y figurerait
pourrait être réécrit par un attaquant pour masquer un retour en arrière. Placé
dans le payload, il est couvert par le tag : le modifier est impossible sans la clé.

### 6.2 Contenu du corps

En phase 1, le corps est **vide** : le moteur cryptographique est livré et testé
avant tout modèle de données.

À partir de la phase 2, le corps contiendra la base SQLite **sérialisée en
mémoire**. Choix assumé :

* la recherche (FTS5) porte sur du clair, ce qui est précisément ce que fait un
  index en mémoire ;
* le fichier du coffre reste une enveloppe opaque : un ajout de type d'entrée, de
  champ ou d'index ne change **ni** le format du conteneur, **ni** celui de cette
  enveloppe. C'est cette séparation qui permet de faire évoluer le modèle de
  données pendant des années sans casser une seule sauvegarde.

### 6.3 Compression

**Aucune en phase 1.** Le champ correspondant n'existe même pas. L'activer
ajouterait une dépendance de décompression **et** une surface d'attaque (bombe de
décompression) pour un gain modeste sur des données majoritairement textuelles.

## 7. Fichiers annexes

### 7.1 Verrou d'écriture — `<coffre>.lock`

Fichier vide, créé en 0600, sur lequel un verrou exclusif non bloquant est posé.

**Pourquoi un fichier séparé et non le coffre lui-même :** l'écriture atomique
**remplace** le fichier par un renommage, donc change l'inode. Un verrou posé sur
le coffre serait silencieusement perdu au premier enregistrement.

Ce fichier peut être supprimé sans risque lorsqu'aucune instance n'est en cours.

### 7.2 Sentinelle anti-retour-en-arrière — `<condensé>.sent`

Emplacement : le répertoire de configuration de l'utilisateur
(`$XDG_CONFIG_HOME/passlock` ou `~/.config/passlock` sur Unix, `%APPDATA%\Passlock`
sur Windows) — **jamais** à côté du coffre. Un attaquant qui peut écrire le coffre
écrirait la sentinelle du même geste si elle s'y trouvait.

Nom de fichier : `hex(HMAC-SHA256(K_index, "passlock/v1/sentinel-name" ‖ vault_id))[0..16]` + `.sent`.

Conséquence : le nom **ne contient pas** le chemin du coffre, et n'est pas
dérivable sans la clé. Un attaquant lisant le répertoire de configuration
n'apprend ni quels coffres existent ni où ils se trouvent. Corollaire assumé : la
sentinelle n'est lisible qu'**après** déverrouillage.

Contenu — 64 octets :

| Offset | Taille | Champ |
|---|---|---|
| 0 | 16 | `vault_id` |
| 16 | 8 | `generation` (`u64`, gros-boutiste) |
| 24 | 8 | `updated_at` (`u64`, gros-boutiste) |
| 32 | 32 | `HMAC-SHA256(K_index, "passlock/v1/sentinel-mac" ‖ octets 0..32)` |

Une sentinelle dont la taille, le tag ou l'identifiant ne correspondent pas est
traitée comme **absente**, et l'appelant doit le signaler.

## 8. Versionnement et compatibilité

| Changement | `format_version` | Compatibilité |
|---|---|---|
| Ajout d'un champ dans le corps du payload | inchangé | compatible |
| Ajout d'un type d'entrée, d'un index | inchangé | compatible |
| Champs ajoutés dans l'enveloppe du payload | inchangé si `schema_version` est géré ; sinon erreur explicite | à traiter |
| Second slot de clé | **inchangé** | compatible — la liste `slots` existait déjà |
| Nouvel algorithme référencé par `payload_alg` | inchangé | compatible si l'implémentation le connaît, sinon erreur explicite |
| Modification du layout du conteneur | **incrémenté** | rupture assumée, outil de migration requis |

## 9. Migration des paramètres de dérivation

Les paramètres sont **toujours lus dans le fichier**, jamais pris dans une
constante du code. Durcir les valeurs par défaut ne rend donc aucun coffre
existant illisible.

Pour migrer un coffre vers des paramètres plus forts :

1. dériver la KEK avec les **anciens** paramètres et obtenir la DEK ;
2. générer un **nouveau sel** ;
3. dériver une nouvelle KEK avec les **nouveaux** paramètres ;
4. ré-envelopper **la même DEK** ;
5. réécrire le header et incrémenter la génération.

La DEK ne change pas, donc le contenu n'est jamais rechiffré sous une clé
différente. Aucune fenêtre de corruption partielle n'existe : l'écriture est
atomique, et l'ancien fichier reste intact en cas d'échec.

> **Note importante sur le coût réel.** Le header entrant dans l'AAD du payload,
> changer un slot invalide le tag et **impose de re-chiffrer le payload**. C'est peu
> coûteux — un passage d'AEAD sur quelques mégaoctets, avec la même clé, sans
> nouvelle dérivation — mais ce n'est pas O(1) sur la taille du coffre. Le bénéfice
> réel de la DEK se manifeste ailleurs : les blobs de pièces jointes, chiffrés sous
> une clé dérivée de la DEK, ne sont pas touchés du tout.

## 10. Exemple de coffre de test

Un coffre minimal, **ne contenant aucun secret réel**, est présent dans
`tests/fixtures/`. Il est ouvert par la suite de tests à chaque exécution : c'est la
garantie qu'aucun changement de code ne casse la lisibilité d'un coffre existant.

## 11. Ce qui n'est pas dans ce format, et pourquoi

| Absent | Raison |
|---|---|
| Compression | Dépendance et bombe de décompression pour un gain marginal (§6.3) |
| Pièces jointes | Blobs chiffrés séparés, sous une clé distincte. Un fichier de 500 Mo ne doit pas être réécrit à chaque changement de titre |
| Deuxième algorithme AEAD | AES-GCM doublerait la surface de test et de maintenance sans bénéfice ici (§`docs/CRYPTO.md`) |
| Horodatage de dernière modification | Lisible sans contexte et sans utilité ; la génération suffit |
| Nombre d'entrées, index | Fuite de métadonnées majeure pour aucun bénéfice |
| Valeur de contrôle de clé | Envisagée puis retirée : aucun de ses usages ne survit à l'examen (voir `docs/DECISIONS.md`) |
