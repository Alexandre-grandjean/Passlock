# Modèle de données

> Phase 2. Décrit **ce qui est stocké**, **pourquoi**, et — tout aussi important —
> **ce qui ne l'est pas**.

## 1. Principes

1. **Champs clé-valeur typés, pas de schéma figé par type d'entrée.** Un `Login` et
   une `SecureNote` ne diffèrent que par leurs champs. Ajouter un type d'entrée ou un
   champ personnalisé ne change **ni le format ni le code de sérialisation** — c'est
   ce qui permet de faire évoluer le produit sans casser une seule sauvegarde.
2. **Identifiants aléatoires, jamais dérivés d'un contenu.** Un identifiant dérivé du
   titre permettrait de **confirmer la présence** d'une entrée connue. 128 bits, ce
   qui rend une collision négligeable même à des millions d'entrées.
3. **Tout ce qui est stocké est déchiffré quelque part.** Il n'y a donc pas de champ
   « moins sensible » : la distinction secret/non-secret est une indication
   **d'affichage**, jamais une garantie de stockage.
4. **Rien n'est stocké qui puisse être calculé.**
5. **Aucune structure récursive.** L'instantané d'une révision a un historique
   **obligatoirement vide** : la profondeur est bornée à un niveau, ce qui empêche un
   corps forgé de provoquer un épuisement de pile au décodage.

## 2. Types

```rust
EntryId / FolderId / TagId / BlobId   = 16 octets aléatoires

EntryKind  = Login | SecureNote | CreditCard | Identity | ApiKey
           | SshKey | Wifi | PasskeyMetadata | Custom

FieldKind  = Text | Secret | Url | Multiline | Email | Totp
           | Number | Date | Pin | Custom
```

`EntryKind` et `FieldKind` sont des ensembles **fermés** : un octet inconnu au
décodage produit une erreur, jamais un rangement silencieux dans une catégorie
fourre-tout. Un type ajouté par une version future sera donc signalé explicitement
plutôt que de faire disparaître des données.

### 2.1 Entrée

| Champ | Type | Borne | Rôle |
|---|---|---|---|
| `id` | `EntryId` | — | identifiant aléatoire |
| `kind` | `EntryKind` | — | type d'entrée |
| `title` | texte | 1 Kio | nom affiché |
| `subtitle` | texte | 1 Kio | texte secondaire : nom d'utilisateur, domaine |
| `created_at` | `u64` | — | création, secondes epoch |
| `updated_at` | `u64` | — | dernière modification |
| `trashed_at` | `Option<u64>` | — | mise à la corbeille ; `0` encodé signifie « aucune » |
| `archived` | booléen | — | archivée |
| `favorite` | booléen | — | favorite |
| `sensitive` | booléen | — | marque une entrée sensible. La **réauthentification avant révélation** qui devait l'exploiter appartenait à l'interface graphique, **abandonnée** (gates E.1/E.2, ADR-042) : le marqueur est **stocké, exporté et affiché**, mais **aucune couche n'impose la réauthentification** |
| `folder` | `Option<FolderId>` | — | dossier de rattachement |
| `tags` | `Vec<TagId>` | 64 | tags |
| `fields` | `Vec<Field>` | 256 | contenu |
| `revision` | `u32` | — | numéro de révision |
| `history` | `Vec<Revision>` | 50 | versions antérieures |

### 2.2 Champ

| Champ | Type | Borne | Rôle |
|---|---|---|---|
| `key` | texte | 128 o | `password`, `totp`, `url`… ou clé libre |
| `kind` | `FieldKind` | — | nature de la valeur, pour l'affichage |
| `value` | texte | 64 Kio | contenu |
| `ordinal` | `u16` | — | ordre d'affichage ; rend l'encodage déterministe |
| `concealed` | booléen | — | masquage à l'affichage |

Une clé vide est **refusée** : elle produirait un champ impossible à désigner.

### 2.3 Dossier, tag, pièce jointe, journal

| Type | Champs | Bornes |
|---|---|---|
| `Folder` | `id`, `name`, `parent: Option<FolderId>`, `ordinal` | nom ≤ 256 o, profondeur ≤ 8, pas de cycle |
| `Tag` | `id`, `name` | nom ≤ 256 o |
| `AttachmentMeta` | `id`, `entry`, `name`, `size`, `chunk_size`, `chunk_count`, `created_at`, `content_mac` | nom ≤ 512 o *(phase 4)* |
| `AuditEvent` | `at`, `kind: AuditKind`, `subject: Option<EntryId>` | journal borné à 1 000 événements |

## 3. Ce qui n'est **pas** stocké, et pourquoi

Principe de minimisation appliqué champ par champ.

| Non stocké | Raison |
|---|---|
| Date de dernière consultation d'une entrée | Métadonnée d'usage sans utilité fonctionnelle. **C'est une trace** : la consigner révélerait les habitudes de l'utilisateur sans rien apporter |
| Nombre d'ouvertures, compteur d'usage | idem |
| Index de recherche persistant | Calculé à la volée : pas de désynchronisation possible, pas de double mémoire, pas de secrets recopiés hors des entrées |
| Score de robustesse d'un mot de passe | **Recalculable** : le stocker figerait un jugement qui se périme |
| Domaine enregistrable déduit d'une URL | **Calculable** : le dupliquer créerait une incohérence possible entre les deux valeurs |
| Nom du propriétaire du coffre | Sans usage : le fichier appartient déjà à un compte |
| Identifiant de machine, de session | Aucun besoin fonctionnel, et c'est une donnée d'identification |
| Tout identifiant dérivé d'un contenu | Permettrait de confirmer la présence d'une entrée connue |
| Type MIME d'une pièce jointe | **Sauf** le mime : non déductible de façon fiable. Il sera stocké, contrairement au reste |

## 4. Organisation

* **Dossiers** hiérarchiques, profondeur maximale **8**. La borne évite la récursion
  à l'encodage comme au décodage, et la détection de cycle est bornée par elle.
* **Tags** plats, uniques par nom (comparaison insensible à la casse).
* **Favoris**, **archivage**, **corbeille** : trois états distincts. Une entrée
  *active* est ni archivée ni à la corbeille ; c'est la définition utilisée par la
  recherche.
* **Champs personnalisés** : n'importe quelle clé non reconnue devient un champ
  libre, sans configuration.
* **Historique versionné** : voir §5.

## 5. Historique : ce qui est conservé, et ce que cela implique

**Politique par défaut : 50 révisions au maximum, 90 jours au maximum.** La plus
contraignante des deux bornes l'emporte.

**Ce que l'historique conserve.** Une copie **complète** de l'entrée avant chaque
modification — titre, champs, valeurs comprises. Modifier un mot de passe laisse donc
l'ancien dans le coffre.

**Pourquoi c'est un problème, et comment il est traité.** Le cahier des charges
l'identifiait : un historique conserve des secrets que l'utilisateur croit supprimés.
La réponse est la **transparence**, pas la dissimulation :

* la politique est affichée (`passlock history <id>` la rappelle) ;
* `passlock history <id> --purge` efface l'historique d'une entrée, et le geste est
  consigné au journal ;
* `passlock entry purge <id>` supprime l'entrée **et** son historique.

**Ce que la purge ne fait pas, et qui doit être dit.** Elle n'a **aucun effet sur les
sauvegardes déjà écrites**. Toute copie antérieure du coffre contient toujours les
anciennes versions, et aucune opération depuis cette application ne peut les
atteindre. C'est une conséquence inévitable du fait qu'une sauvegarde est une copie
de fichier.

**Compromis assumé du choix « 50 / 90 jours ».** L'historique illimité garantit de ne
jamais rien perdre, mais conserve indéfiniment des identifiants révoqués — y compris
ceux qu'on a changés **précisément parce qu'ils avaient fuité**. L'historique
désactivé protège de cette rétention mais rend une modification accidentelle
irréversible. La borne est le compromis entre les deux.

## 6. Ce qu'un événement de journal ne contient jamais

`AuditKind` est un ensemble **fermé** de 13 variantes. Un événement porte :

* une date ;
* un type, choisi parmi les variantes ;
* un `EntryId` — un identifiant aléatoire, **pas un contenu**.

Il n'existe donc **aucun chemin** par lequel un titre, une valeur de champ ou une clé
pourrait entrer dans le journal. Un test le vérifie sur des entrées portant des
valeurs reconnaissables.

Le journal est **circulaire** : au-delà de 1 000 événements, les plus anciens sortent.

**Une exception explicite.** Consigner chaque déverrouillage dans le journal permanent
rendrait **toute consultation modifiante**, et forcerait une écriture pour une simple
lecture. `record_without_dirty` existe pour cela : le journal garde les **actions**,
pas les **consultations**. Le compromis est assumé et documenté.

## 7. Recherche

Voir `query.rs` et `docs/STORAGE_FORMAT.md` §6. Points saillants :

* le texte cherché est une **sous-chaîne littérale**, jamais un langage de requête ;
* tous les termes doivent apparaître (**conjonction**) ;
* insensible à la casse et, pour les écritures latines, aux accents ;
* bornes : 16 termes au plus, 64 octets par terme, 1 000 résultats au plus.

**Limite assumée** : une écriture non latine est trouvée en insensible à la casse
mais **pas** en insensible aux accents. Ajouter une crate de normalisation Unicode
pour une fonctionnalité de confort serait disproportionné.
