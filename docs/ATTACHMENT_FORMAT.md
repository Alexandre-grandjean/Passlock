# Format de pièce jointe — blobs chiffrés séparés

> Complète `VAULT_FORMAT.md` (le conteneur) et `STORAGE_FORMAT.md` (le corps chiffré).
> Ici : ce qu'est un **fichier de blob**, octet par octet.

## 1. Pourquoi les pièces jointes sont hors du conteneur

Le conteneur est chiffré en **un seul bloc AEAD** (ADR-002). Y loger une pièce jointe de
500 Mio imposerait de réécrire ces 500 Mio à chaque modification d'un titre. Un blob vit
donc dans **son propre fichier**, chiffré sous une clé dédiée, et le conteneur ne porte
que ses métadonnées — qui vivent, elles, dans l'archive du corps (schéma 2, section
`attachment_count`).

**Conséquence à dire, et pas à découvrir.** Une sauvegarde du seul fichier de coffre ne
préserve **pas** les pièces jointes. Elle doit inclure le répertoire des blobs.

## 2. Emplacement et nommage

```
<répertoire du coffre>/<nom du coffre>.attachments/<nom de blob>
```

| | |
|---|---|
| Répertoire | `<nom du coffre>.attachments`, créé en **0700**, ouvert par une marche **sans lien symbolique** |
| Nom de blob | `hex(HMAC-SHA256(K_blob_name, vault_id ‖ blob_id))` **tronqué à 16 octets** (32 caractères hexadécimaux minuscules) |

`K_blob_name` est dérivée de `K_attachments` par HKDF (`passlock/v1/blob-name`). L'étiquette
de domaine vit dans le **HKDF**, pas en préfixe du message : `I-KEYDOMAIN` interdit de
l'écrire deux fois.

**Ce que le nom révèle, et ne révèle pas.** Il n'est pas dérivable sans la clé, donc
l'énumération par un tiers est fermée. En revanche, l'**existence** et la **taille** des
blobs restent observables par le système de fichiers — comme la taille du coffre lui-même.

**Collision de nom.** La troncature à 128 bits rend une collision improbable, jamais
impossible. `O_EXCL` (Unix) et `CREATE_NEW` (Windows) sont la garantie ultime : la
création **échoue** plutôt que d'écraser, et un nouvel identifiant est tiré. Aucun
occupant du répertoire n'est jamais écrasé.

## 3. Structure du fichier

```
offset  taille  champ
0       4       magic "ATB1"
4       2       version (u16, gros-boutiste) = 1
6       2       réservé — doit valoir 0
8       16      blob_id
24      8       plaintext_size (u64)
32      4       chunk_size (u32)
36      4       chunk_count (u32)
40      …       chunk_count enregistrements, dans l'ordre
```

Chaque enregistrement :

```
nonce (24 octets) ‖ XChaCha20-Poly1305(chunk_plaintext) (len + 16)
```

`chunk_size` vaut **1 Mio** à l'écriture. Longueur totale attendue :

```
40 + chunk_count × (24 + 16) + plaintext_size
```

Cette longueur est **recalculée** puis comparée à la taille réelle du fichier **avant
toute allocation** : c'est ce contrôle qui détecte une troncature propre, que l'AEAD seul
laisserait passer.

## 4. Découpage

| | |
|---|---|
| Taille de morceau | 1 Mio (`ATTACHMENT_CHUNK_SIZE`) |
| Nombre de morceaux | `max(1, ceil(plaintext_size / chunk_size))` — un contenu **vide** occupe **un** morceau de zéro octet, car l'archive refuse `chunk_count == 0` |
| Morceau court | **seul le dernier** peut être plus court — par construction, puisque le décodeur recalcule le nombre de morceaux à partir de la taille |

## 5. AAD d'un morceau — et l'invariant

```
aad(i) = header_octets[0..40] ‖ vault_id (16) ‖ i (u32, gros-boutiste)
```

Le header est repris **octet pour octet**, et non reconstruit depuis les champs : c'est la
raison d'`ADR-005`, appliquée ici. Un ré-encodage pourrait diverger, des octets exacts non.

> **`I-BLOB-AAD`.** Chaque morceau est authentifié sous l'identité du coffre, l'identité du
> blob, l'intégralité du header de blob **et sa position**. Aucun morceau ne peut donc être
> réordonné, dupliqué à une autre position, déplacé d'un blob à un autre, ni déplacé d'un
> coffre à un autre sans qu'un tag devienne invalide.

**Pourquoi l'index est indispensable.** Le nonce voyage avec son chiffré. Sans l'index dans
l'AAD, deux enregistrements de même taille seraient **interchangeables** : le
déchiffrement réussirait et le clair serait **réordonné** — une corruption silencieuse,
invisible jusqu'à l'empreinte finale. Une première rédaction de ce format omettait l'index
tout en affirmant le contraire ; c'est la construction qui a été corrigée, pas la
formulation.

### 5.1 Ce que l'AEAD ne protège pas

| Atteinte | Détectée par |
|---|---|
| Morceaux réordonnés, dupliqués, transplantés | **l'AAD** (elle contient l'index, le blob et le coffre) |
| **Fichier tronqué proprement** | `chunk_count` **et la longueur exacte**, venus de l'archive — **pas** par l'AEAD |
| **Rejeu d'une version antérieure du même blob** | `content_mac` |
| Suppression du fichier par un tiers | `attach verify` — une **absence constatée**, jamais un silence |

L'AEAD seul ne suffit donc pas : la validation croise **trois** sources — le tag par
morceau, le header de blob, et les métadonnées de l'archive.

## 6. `content_mac`

```
content_mac = HMAC-SHA256(K_index,
                          "passlock/v1/attachment-content-mac"
                          ‖ vault_id ‖ blob_id ‖ plaintext_size ‖ clair)
```

Stocké dans `AttachmentMeta` (32 octets). Il est calculé **pendant** le chiffrement, jamais
en relisant le clair — relire supposerait de le conserver ou de le déchiffrer deux fois.

La liaison au coffre, au blob et à la taille rend la valeur **non rejouable** d'un blob,
d'un coffre ou d'une taille à un autre. Ce n'est **pas** la correction d'une faille
démontrée — l'AAD des morceaux lie déjà ces valeurs — mais une défense en profondeur, et
surtout une valeur **auto-descriptive** là où le modèle ne documentait qu'« un HMAC du
contenu ».

## 7. Bornes

| Borne | Valeur |
|---|---|
| `ATTACHMENT_CHUNK_SIZE` | 1 Mio |
| `MAX_ATTACHMENT_BYTES` | 512 Mio |
| `MAX_DECODED_CHUNK_SIZE` | 64 Mio — tolérance de décodage, pour qu'un fichier d'une version future reste lisible |
| `MAX_ATTACHMENTS` | 4 096 (archive) |
| `MAX_ATTACHMENT_NAME_LEN` | 512 octets (archive) |

**Invariant d'allocation.** Aucune allocation n'est dimensionnée par une valeur lue dans
le fichier avant que celle-ci n'ait été confrontée aux octets réellement disponibles :
`chunk_count` est **recalculé** depuis la taille, `chunk_size` est borné, et la longueur
totale est comparée à la taille du fichier avant toute lecture de morceau.

## 8. Quand le clair est-il valide ?

Un morceau est **authentifié pour sa position** dès que son tag vérifie ; la pièce jointe
n'est **valide** qu'après les contrôles de fin de flux — nombre de morceaux, taille,
`content_mac`.

**Un morceau intermédiaire est authentique, pas validé.** Les appelants qui écrivent le
clair quelque part doivent donc attendre la fin du flux avant de le considérer comme
complet : `attach get` écrit dans un fichier temporaire et ne le **publie** qu'après le
verdict. Une pièce jointe tronquée ne se présente jamais comme un fichier complet.

## 9. Cycle de vie, et l'ordre qui compte

> **`I-BLOB-ORDER`.** Un blob est écrit, `fsync`é, **et son entrée de répertoire rendue
> durable**, **avant** que sa métadonnée soit enregistrée. En suppression, l'ordre est
> **inverse** : la métadonnée d'abord, le fichier ensuite — ou jamais, s'il devient un
> orphelin.

**Pourquoi.** Une métadonnée sans son fichier est une **promesse non tenue** : le coffre
annonce une pièce jointe que `attach get` ne peut pas restituer. Un fichier sans sa
métadonnée est un **orphelin** : invisible, inoffensif, récupérable par `attach gc`.

**Une interruption brutale ne produit que le second cas.** Le blob est durable avant
l'enregistrement : un incident entre les deux laisse un orphelin.

## 10. Ramasse-miettes

`attach gc` confronte le répertoire aux métadonnées et distingue **trois** constats, qui
n'appellent pas la même décision :

| Constat | Décision |
|---|---|
| **Orphelin** — nom bien formé, aucune métadonnée | **supprimé** |
| **Fichier étranger** — nom qui ne peut pas être un nom de blob | **jamais supprimé** ; signalé |
| **Absence** — métadonnée sans fichier | **rien à supprimer** ; c'est une incohérence d'intégrité |

**Un blob référencé mais corrompu n'est ni orphelin ni absent : il est présent.** Il n'est
donc **jamais** candidat à la suppression. Sans cette propriété, une corruption se
transformerait en perte de données par l'effet d'un outil de maintenance.

Le balayage rend des **noms**, pas des chemins, et le magasin revalide le nom avant toute
suppression : le ramasse-miettes ne peut donc pas viser un fichier hors du répertoire des
blobs, quoi qu'il reçoive.
