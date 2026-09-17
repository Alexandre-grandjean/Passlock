# Audit adversarial — phase 1

> Revue indépendante du **code réel** de la phase 1, menée après coup et avec une
> posture hostile : chercher ce qui casse, pas confirmer ce qui a été annoncé.
>
> **Ce que cet audit n'est pas.** Une revue par un tiers. Il a été conduit par
> l'auteur du code, ce qui borne par construction sa capacité à trouver certaines
> classes de défauts — notamment les erreurs de conception partagées par
> l'implémentation et son auteur. La section 10 en tire les conséquences.

Méthode : lecture du code source, recherche systématique des sites à risque
(`grep` sur les clones, conversions, `Drop`, affichages), construction d'un harnais
d'attaques nouveau (`tests/adversarial.rs`), et vérification des affirmations de la
documentation **une par une** contre le comportement observé.

**Résultat en une ligne :** six défauts réels trouvés et corrigés, dont un écart
entre un commentaire et le comportement sur une propriété de sécurité, et une course
TOCTOU. Aucune vulnérabilité cryptographique. Le format et la hiérarchie de clés
tiennent sous les attaques testées.

---

## 1. Audit de la hiérarchie de clés

### 1.1 Tableau complet

| | MK | KEK | DEK | K_records | K_attachments | K_index |
|---|---|---|---|---|---|---|
| **Origine** | Argon2id(mot de passe, sel du slot) | HKDF-SHA256(MK, `passlock/v1/kek`) | 32 octets aléatoires du noyau, générés **une fois** à la création | HKDF(DEK, `…/records`) | HKDF(DEK, `…/attachments`) | HKDF(DEK, `…/index`) |
| **Taille** | 32 o | 32 o | 32 o | 32 o | 32 o | 32 o |
| **Dérivation** | Argon2id, `m`/`t`/`p`/sel lus dans le slot | HKDF-extract + expand, sel `None` | aucune (aléatoire) | HKDF, étiquette dédiée | HKDF, étiquette dédiée | HKDF, étiquette dédiée |
| **Usage exact** | entrée de HKDF uniquement ; **jamais** dans un AEAD | enveloppe / désenveloppe la DEK dans un slot, via XChaCha20-Poly1305 | **jamais utilisée directement** : uniquement entrée de HKDF | AEAD du payload du conteneur | blobs de pièces jointes *(phase 4)* | HMAC du nom de sentinelle et HMAC du contenu de sentinelle |
| **Contexte / séparation** | lié au slot par le sel et les paramètres | AAD = `"passlock/v1/slot" ‖ vault_id ‖ slot_id ‖ label ‖ alg ‖ argon2_version ‖ m ‖ t ‖ p ‖ salt` | — | étiquette `info` distincte | étiquette `info` distincte | étiquette `info` + préfixes `NAME_INFO` / `MAC_INFO` |
| **Durée de vie** | de la dérivation au calcul de la KEK, puis détruite | de la dérivation à la désenveloppe | **toute la session**, tant que `Vault` existe | idem DEK | idem DEK | idem DEK |
| **Emplacement mémoire** | `Key<32>` → `LockedBuffer` (tas, `mlock` best-effort) | idem | idem | idem | idem | idem |
| **Destruction** | `Drop for Key<N>` → `zeroize` (écriture volatile + barrière) | idem | idem | idem | idem | idem |
| **Pourquoi elle existe** | transformer un secret d'entropie inconnue en clé d'entropie pleine | permettre **plusieurs** mécanismes d'ouverture (mot de passe, récupération, matériel) sur **une** clé de données | éviter que changer un mécanisme d'ouverture n'impose de rechiffrer sous une clé différente | séparer les domaines d'usage | idem | idem |

### 1.2 Vérification : aucune réutilisation incompatible

**Résultat : conforme, à une exception près, documentée.**

* **MK** n'est utilisée que comme entrée de HKDF. Vérifié dans `keys.rs::derive_kek`.
* **KEK** n'est utilisée que dans `wrap`/`unwrap`. Jamais dans le payload.
* **DEK** n'apparaît dans **aucun** appel à `aead::seal`/`aead::open` : `.expose()` n'est appelé que dans `wrap` (pour la chiffrer) et dans `expand` (comme entrée HKDF). Vérifié par recherche : les seules utilisations de `dek.0.expose()` sont dans `KeyEncryptionKey::wrap`.
* **K_records**, **K_attachments**, **K_index** proviennent de trois expansions HKDF avec des étiquettes distinctes et versionnées. Un test vérifie qu'elles sont deux à deux différentes.

**L'exception : `K_index` sert à deux choses** — dériver le nom du fichier de sentinelle et authentifier son contenu. C'est le seul cas où un même matériel de clé intervient dans deux contextes. Il est séparé par les préfixes de domaine `NAME_INFO` et `MAC_INFO`, tous deux préfixés au message avant HMAC. Sans eux, une valeur calculée pour l'un pourrait être valide pour l'autre ; comme les longueurs d'entrée diffèrent aujourd'hui, l'ambiguïté n'est pas exploitable — mais s'appuyer sur une différence de longueur serait fragile, d'où le préfixe explicite.

**Verdict : VERIFIED.**

### 1.3 Un point relevé par l'audit : la durée de vie de MK et KEK

Dans `Vault::create` et `change_password`, `MasterKey` et `KeyEncryptionKey` sont explicitement détruites par `drop` **avant** l'écriture sur disque. Dans `Vault::open`, la KEK est détruite après usage. Aucune de ces deux clés ne survit à l'opération qui les a créées.

**En revanche, la DEK et les sous-clés vivent aussi longtemps que l'objet `Vault`.** C'est nécessaire — un changement de mot de passe doit pouvoir ré-envelopper la DEK sans nouvelle dérivation. Conséquence directe : **toute la durée d'utilisation du coffre est une fenêtre d'exposition de la DEK**. C'est la raison d'être de `Vault::lock`, et c'est pourquoi le verrouillage automatique (phase 6) n'est pas un confort mais une contre-mesure.

---

## 2. Audit du format

### 2.1 Layout octet par octet

`A` = authentifié · `S` = secret · `M` = mutable sans casser l'authentification.

| Zone | Offset | Taille | Champ | Valeur | S | A | M | Raison de présence |
|---|---|---|---|---|---|---|---|---|
| Conteneur | 0 | 8 | `magic` | `"PASSLOCK"` | non | oui (AAD) | non | distinguer un coffre d'un autre fichier |
| | 8 | 2 | `format_version` | `1` | non | oui | non | permettre une migration explicite |
| | 10 | 2 | `flags` | `0`, refusé si ≠ 0 | non | oui | non | réserver une évolution sans deviner sa sémantique |
| | 12 | 4 | `header_len` | `28 + 122×n`, ≤ 4096 | non | oui | non | délimiter le header, borne anti-allocation |
| | 16 | `H` | `header` | voir ci-dessous | non | oui | non | — |
| | 16+H | 24 | `payload_nonce` | aléatoire | non | **non** (voir §3.5) | non | nonce AEAD |
| | 40+H | `P` | `payload_ciphertext` | AEAD, tag inclus | oui | oui | non | contenu |
| Header | +0 | 16 | `vault_id` | aléatoire | non | oui | non | lier les slots au coffre, corréler les sauvegardes |
| | +16 | 8 | `created_at` | époque Unix | non | oui | non | affichage ; **non vérifié par `info`** (voir §2.4) |
| | +24 | 1 | `payload_alg` | `1` | non | oui | non | extensibilité |
| | +25 | 1 | `slot_count` | 1..16 | non | oui | non | borner le travail de lecture |
| | +26 | 2 | réservé | `0`, refusé si ≠ 0 | non | oui | non | — |
| Slot | +0 | 2 | `slot_id` | unique | non | oui (AAD slot) | non | identifier un slot |
| | +2 | 1 | `label` | 1..3 | non | oui | non | rôle, affichage, sélection |
| | +3 | 1 | `kdf_alg` | `1` | non | oui | non | extensibilité |
| | +4 | 1 | `argon2_version` | `0x13` | non | oui | non | reproductibilité de la dérivation |
| | +5 | 1 | réservé | `0` | non | oui | non | — |
| | +6 | 4 | `m_cost_kib` | 8192..2097152 | non | oui | non | paramètre lu **depuis le fichier** |
| | +10 | 4 | `t_cost` | 1..16 | non | oui | non | idem |
| | +14 | 4 | `p_cost` | 1..16 | non | oui | non | idem |
| | +18 | 32 | `salt` | aléatoire, unique par slot | non | oui | non | salage Argon2id |
| | +50 | 24 | `wrap_nonce` | aléatoire | non | non | non | nonce de l'enveloppe |
| | +74 | 48 | `wrapped_dek` | AEAD(KEK, DEK) + tag | **oui** (chiffré) | oui (tag propre) | non | porter la DEK |
| Payload (déchiffré) | 0 | 4 | `"PAY1"` | — | non | oui | non | distinguer l'enveloppe d'un corps brut |
| | +4 | 2 | `schema_version` | `1` | non | oui | non | versionner le schéma du corps |
| | +6 | 2 | réservé | `0` | non | oui | non | — |
| | +8 | 8 | `generation` | monotone | non | oui | **oui** | détecter un retour en arrière |
| | +16 | 4 | `body_len` | — | non | oui | oui | délimiter le corps |
| | +20 | `n` | `body` | contenu applicatif | **oui** | oui | oui | — |

**Sur la colonne « mutable ».** Aucun champ portant `M = non` ne peut être modifié
sans invalider l'authentification. Seuls `generation`, `body_len` et `body` changent,
et uniquement lors d'une écriture légitime — ils sont à l'intérieur du chiffré.

### 2.2 Les huit attaques de manipulation, une par une

| Attaque | Mécanisme de défense | Test | Résultat |
|---|---|---|---|
| **Substitution de champ** | tout champ du header est dans l'AAD du payload ; tout champ de slot est dans l'AAD du slot | `changing_the_kdf_parameters_…`, `changing_the_slot_label_…` | refusé |
| **Mélange de deux coffres** | `vault_id` dans l'AAD du slot **et** dans l'AAD du payload | `transplanting_a_whole_slot_…`, `swapping_the_ciphertext_…`, `splicing_two_halves_…` | refusé |
| **Mélange de deux slots** | l'AAD du payload couvre le header entier, donc l'ordre et l'ensemble des slots | `swapping_two_slots_in_the_header_…` | refusé |
| **Confusion de version** | `format_version` dans l'AAD ; `payload_alg` et `argon2_version` vérifiés contre un ensemble fermé ; `schema_version` à l'intérieur du chiffré | `changing_the_format_version_…`, `unknown_*_is_rejected` | refusé |
| **Ambiguïté de parsing** | offsets fixes ; longueur de header **exactement** conforme ; champs réservés refusés ; aucun parseur générique | `trailing_bytes_are_rejected`, `every_truncation_…` | impossible |
| **Allocation excessive** | `header_len ≤ 4096`, `slot_count ≤ 16`, `m_cost ≤ 2 Gio` **vérifié pendant le décodage**, `try_reserve_exact`, lecture de fichier bornée | `absurd_declared_lengths_…`, `a_hostile_memory_cost_…`, `a_huge_file_…` | refusé |
| **Débordement d'entier** | `checked_add` pour composer les longueurs ; offsets des lectures internes bornés par construction | revue de code (voir §2.3) | non atteignable |
| **Troncature ambiguë** | le tag Poly1305 couvre la longueur du chiffré ; toute coupe est détectée | `truncations_at_every_offset_…`, `truncated_ciphertext_…` | refusé |

### 2.3 Débordement d'entier : un risque latent identifié

Les compositions de longueurs dans `container.rs` utilisent `checked_add`, et les
bornes sont vérifiées avant toute allocation. **Mais** les lectures internes de
`header.rs` (`read_u16`, `read_u32`) et de `container.rs` (`read_array`) font
`bytes.get(offset..offset + N)` sans `checked_add`.

Aujourd'hui **ce n'est pas atteignable** : tous les appels utilisent des offsets
constants (0, 2, 3, 4, 5, 6, 10, 14, 18, 50, 74) ou dérivés d'une valeur déjà
bornée (`body_start ≤ 4112`). Une valeur hostile ne peut pas atteindre ces
fonctions.

Le danger est **latent** : si un futur appelant passe un offset calculé depuis une
donnée du fichier, `offset + N` peut déborder — silencieusement en release
(comportement de repli à la retenue), ce qui donnerait une plage d'indices
incohérente. Reclassé en durcissement à faire lors de la phase 2, quand de nouveaux
champs de longueur apparaîtront.

### 2.4 Un écart constaté sur `info`

`passlock info` affiche `created_at` et les paramètres des slots **sans vérifier
l'authenticité**, puisqu'il n'a pas la clé. Ces champs *sont* couverts par le tag du
payload, mais contrôler ce tag exige la clé : un fichier modifié peut donc afficher
une date ou des paramètres différents de ceux d'origine, et la falsification ne sera
détectée qu'au déverrouillage.

Ce n'était pas dit. La sortie de `info` porte maintenant un avertissement explicite.
Ce n'est pas une vulnérabilité — `info` n'a jamais prétendu authentifier — mais
c'était une **confusion possible** pour l'utilisateur, qui voyait « paramètres
Argon2id : 256 Mio » et pouvait croire que cette valeur était garantie.

---

## 3. Audit AEAD

| Point | Constat | Où |
|---|---|---|
| Algorithme | XChaCha20-Poly1305 (RFC 8439 + extension 192 bits) | `aead.rs::cipher_for` |
| Taille de clé | 32 octets, garantie par le type `Key<32>` | `aead.rs::KEY_LEN` |
| Taille de nonce | 24 octets, garantie par `[u8; NONCE_LEN]` | `aead.rs::NONCE_LEN` |
| Génération | `rng::array::<24>()` → `getrandom`, **aucun repli** | `aead.rs::generate_nonce` |
| Unicité | tirage aléatoire à chaque opération ; test de 1 024 tirages sans collision ; test que deux enveloppements de la même DEK diffèrent | `generated_nonces_are_distinct`, `wrapping_the_same_dek_twice_…` |
| AAD | payload : **tous** les octets `0..16+H` ; slot : les métadonnées du slot | `container.rs`, `header.rs::Slot::aad` |
| Ordre des opérations | voir §3.2 | `vault.rs::unlock_with_kek` |
| Échec | erreur typée dédiée `AeadError`, traduite par chaque appelant | `aead.rs` |
| Réutilisation de nonce | impossible par construction (tirage frais), et sans conséquence en XChaCha20 (§3.4) | — |

### 3.1 Ce que l'audit a vérifié, et non supposé

* La clé n'est **jamais** réutilisée entre deux contextes : `K_records` chiffre le
  payload, `K_attachments` (phase 2) chiffrera les blobs, la KEK enveloppe la DEK.
  Trois matériels distincts, aucune intersection.
* `aead::open` refuse explicitement tout chiffré plus court que le tag **avant**
  d'appeler la bibliothèque, donc sur une entrée dégénérée (0 octet) on ne dépend
  pas du comportement exact de la dépendance.
* Les tests parcourent **chaque octet** du chiffré, du tag et de l'AAD, un par un,
  et vérifient que chaque modification est refusée.

### 3.2 Ordre des opérations — et pourquoi il compte

```
1. parse du header                (aucun calcul cryptographique)
2. Argon2id → MK                  (coûteux)
3. HKDF → KEK
4. désenveloppe du slot → DEK     ← PREMIÈRE vérification d'authenticité
5. HKDF → sous-clés
6. déchiffre le payload           ← SECONDE vérification d'authenticité
```

**Aucun octet du payload n'est interprété avant l'étape 6.** Autrement dit, le
format interne du corps (qui contiendra du SQLite en phase 2) n'est jamais exposé à
une donnée non authentifiée. L'étape 1 traite la seule donnée non fiable, et elle ne
fait que des lectures bornées.

### 3.3 Échec

Le module ne renvoie **pas** `crate::error::Error` mais `AeadError`, sans conversion
automatique. C'est délibéré : le compilateur oblige chaque site d'appel à choisir le
message public. Un `From` aurait laissé passer l'erreur générique par défaut, ce qui
rouvrirait la fuite d'information que `error.rs` cherche à fermer.

### 3.4 Réutilisation de nonce

Deux couches de protection :

1. **Par construction** : chaque chiffrement tire un nonce neuf. Il n'existe aucun
   état de compteur à maintenir, donc aucun état à désynchroniser.
2. **Par la marge** : avec un nonce de 192 bits, la probabilité de collision reste de
   l'ordre de 2^-97 après 2^48 messages sous une même clé. Même une collision
   accidentelle resterait sans conséquence pratique.

L'invariant « une clé donnée ne chiffre qu'avec un nonce neuf » est vérifié par
`wrapping_the_same_dek_twice_produces_different_ciphertexts` et
`distinct_nonces_produce_distinct_ciphertexts`. Aucun test ne peut prouver
l'absence de collision future, mais aucun état n'est partagé entre deux
chiffrements, ce qui rend la réutilisation structurellement impossible.

### 3.5 Un point de précision : le nonce n'est pas dans l'AAD

Le nonce du payload **n'est pas** couvert par l'AAD — il vient après elle dans le
fichier. C'est conforme à la construction AEAD, qui traite le nonce comme une entrée
d'initialisation et non comme une donnée authentifiée.

**Est-ce exploitable ?** Non. Modifier le nonce change la clé de flux : le tag
calculé sur le résultat ne correspond plus, et le déchiffrement échoue. Un attaquant
ne peut pas forger par ce chemin, cela exigerait une collision de tag.

C'est néanmoins une subtilité qu'il vaut mieux écrire que laisser deviner : « tous
les octets sont authentifiés » est vrai **au sens où toute modification est
détectée**, mais le nonce l'est *implicitement* (par l'échec du tag) et non
*explicitement* (par l'AAD). Le test `swapping_the_payload_nonce_between_two_vaults_…`
vérifie le comportement.

**Verdict AEAD : VERIFIED.**

---

## 4. Audit Argon2id

### 4.1 Paramètres

| Contexte | `m` (Kio) | RAM | `t` | `p` | Sortie | Sel | Où |
|---|---|---|---|---|---|---|---|
| **Production, défaut** | 262 144 | 256 Mio | 3 | 4 | 32 o | 32 o aléatoires | `KdfParams::standard()`, `VaultConfig::default()` |
| Production, profil bas | 65 536 | 64 Mio | 3 | 2 | 32 o | idem | `KdfParams::low()` |
| Production, profil haut | 1 048 576 | 1 Gio | 4 | 4 | 32 o | idem | `KdfParams::paranoid()` |
| **Tests unitaires et d'intégration** | **8 192** | **8 Mio** | **1** | **1** | 32 o | idem | `test_support::cheap_params()` |
| Test dédié aux paramètres | 16 384 | 16 Mio | 2 | 1 | 32 o | idem | `change_password_can_also_upgrade_kdf_parameters` |
| Plancher absolu accepté | 8 192 | — | 1 | 1 | — | — | `MIN_M_COST_KIB` |
| Plafond absolu accepté | 2 097 152 | 2 Gio | 16 | 16 | — | — | `MAX_*` |

### 4.2 Les tests modifient-ils les propriétés de sécurité du chemin de production ?

**Non. Vérifié, et c'est un point sensible.**

1. `test_support` est déclaré `#[cfg(test)]` : il **n'existe pas** dans un binaire
   compilé hors tests. Il ne peut pas être atteint par du code de production.
2. `KdfParams::default()` retourne `standard()` — le profil **durci** — et non le
   plus léger. `VaultConfig` dérive son `Default`, donc hérite de cette valeur. Un
   appelant qui oublie de spécifier les paramètres obtient le choix sûr.
3. Les tests qui portent **sur la valeur** des paramètres construisent explicitement
   leurs propres valeurs et n'effectuent aucune dérivation
   (`rejects_weak_and_excessive_parameters`, `recommendation_flag_tracks_parameters`).
4. Le chemin de code parcouru est **identique** quelle que soit la valeur : `m`, `t`,
   `p` sont des arguments passés à `Params::new`, pas des branches. Utiliser le
   plancher ne réduit donc aucune couverture.
5. La CLI utilise `KdfParams::standard()` en dur pour `init` et `change-password`.

**Une réserve honnête.** `kdf::calibrate` retourne `KdfParams::low()` si même le
profil le plus léger dépasse le budget demandé. C'est du code de production qui peut
donc *recommander* le profil faible. Il ne l'**applique** jamais : aucune commande
ne consomme le résultat de `calibrate`. La fonctionnalité est donc incomplète plutôt
que dangereuse, et c'est à traiter en phase 6 quand l'interface proposera
effectivement de migrer.

### 4.3 Le sel

32 octets tirés de `getrandom`, **unique par slot**, généré à la création et à
chaque migration. Il est stocké dans le slot et couvert par l'AAD du slot : le
modifier invalide l'authentification. Un test vérifie que deux sels successifs
diffèrent, et qu'un sel différent produit une clé différente.

### 4.4 Implications des paramètres retenus

**Petites machines et machines à mémoire limitée.** 256 Mio est inutilisable sur un
système à 2 Go de RAM ou dans un conteneur limité. Deux protections : le profil bas
(64 Mio) est proposé explicitement, et `derive_into` utilise `try_reserve_exact` —
l'épuisement mémoire devient une **erreur exploitable** au lieu d'un `abort`.

**Mais `try_reserve_exact` ne suffit pas à rendre le cas confortable.** Sur un
système au bord du swap, allouer 256 Mio **fonctionne** tout en écrasant les
performances de la machine entière, parfois pendant plusieurs secondes. Il n'existe
aucun mécanisme qui détecte cette situation et propose spontanément le profil bas :
c'est à l'utilisateur de le choisir. Trou identifié pour la phase 6.

**Ouverture simultanée de plusieurs coffres.** Chaque coffre ouvert coûte `m` octets
uniquement **le temps de la dérivation** — la mémoire Argon2 est libérée et effacée
juste après. Les clés dérivées, elles, ne pèsent que quelques dizaines d'octets.
Ouvrir dix coffres simultanément ne coûte donc pas dix fois 256 Mio de façon
durable. Le pic transitoire, en revanche, est séquentiel par coffre : il n'existe
aucun mécanisme de sérialisation globale, et deux ouvertures en parallèle
demanderaient 512 Mio simultanément. Non mesuré.

**Déni de service local.** Deux chemins :

* **Paramètres annoncés par le fichier** : traités par le plafond à 2 Gio, vérifié
  **pendant le décodage du header**, avant toute allocation. Vérifié par test.
* **Tentatives répétées** : il n'existe **aucune limitation**. Une interface qui
  réessaierait automatiquement en boucle consommerait un temps CPU proportionnel au
  nombre d'essais — 0,78 s par tentative avec le profil par défaut sur la machine de
  mesure. Ce n'est pas une faiblesse cryptographique, le KDF fait exactement son
  travail, mais c'est un levier local réel. **Risque résiduel assumé**, à traiter
  côté interface.

**Verdict Argon2id : VERIFIED** pour les paramètres et la séparation test/production.
**PARTIALLY VERIFIED** pour le comportement sous pression mémoire, qui n'a pas été
mesuré.

---

## 5. Audit du retour en arrière

### 5.1 Matrice des capacités

| Capacité de l'attaquant | Détection | Pourquoi |
|---|---|---|
| Modification du coffre **seulement** | **OUI** | la génération recule, la sentinelle (sur un autre chemin) reste en avance |
| Modification du coffre **+ sentinelle**, valeur recalculée | **NON** | le HMAC exige `K_index`, donc la DEK — mais si l'attaquant peut **lire** la sentinelle courante, la recopier telle quelle suffit : il n'a pas besoin de la **forger**, seulement de la restaurer |
| Accès en écriture au répertoire du coffre | **OUI** | la sentinelle vit dans le répertoire de configuration de l'utilisateur |
| Accès en écriture **au répertoire de configuration** | **NON** | il peut restaurer la sentinelle à l'ancienne valeur, ou la **supprimer** (voir §5.2) |
| Ancienne sauvegarde disponible, sentinelle intacte | **OUI** | cas d'usage nominal de la détection |
| Accès `root` / `Administrator` | **NON** | peut réécrire arbitrairement les deux emplacements |
| Machine entièrement compromise | **NON** | hors de portée de toute défense logicielle |

### 5.2 Le point le plus faible : la suppression de la sentinelle

Un attaquant qui peut écrire dans le répertoire de configuration peut **effacer** la
sentinelle. Le déverrouillage suivant rapporte alors `NoSentinel`, et
l'implémentation **rétablit la référence** à la génération du coffre présenté — donc
à celle de l'attaquant.

Conséquence : effacer un fichier de 64 octets suffit à désactiver définitivement la
détection, et à faire en sorte que le rollback ne soit plus jamais signalé. Un
avertissement est bien affiché au moment du rétablissement, mais c'est un
avertissement, pas un blocage, et rien ne le distingue d'une première ouverture sur
une machine neuve — situation parfaitement banale.

**Ce n'est pas corrigeable dans une architecture entièrement locale.** Toute
solution exige un état que l'attaquant ne peut pas réécrire : un compteur monotone
matériel (TPM), un support en ajout seul, ou un journal distant. Les trois sortent du
périmètre fixé.

**Ce qui a été fait à la place :** la limite est documentée, la formulation « détection
de rollback » a été remplacée partout par « détection **partielle** », et la matrice
ci-dessus est publiée.

### 5.3 Corrections de formulation

Trois affirmations trop fortes ont été corrigées :

| Avant | Après |
|---|---|
| « détection de rollback » | « détection **partielle** de rollback » (elle dépend d'un fichier que l'attaquant peut réécrire) |
| « un attaquant écrivant aux deux emplacements l'annule » — présenté comme le seul cas | le cas de la **suppression** est désormais explicite, et c'est le plus accessible |
| « la sentinelle est authentifiée par HMAC » — laissait entendre qu'elle était infalsifiable | l'authentification empêche de **forger** une valeur, pas de **restaurer** une valeur antérieure valide |

Ce troisième point est le plus important : le HMAC protège contre la création d'une
sentinelle arbitraire, pas contre la remise en place d'une sentinelle authentique
d'une époque antérieure. C'est une distinction facile à confondre.

**Verdict : PARTIALLY VERIFIED.** La détection fonctionne contre l'attaquant
périphérique (modification du coffre seul, restauration de sauvegarde) et échoue
contre un attaquant ayant accès aux deux emplacements ou aux privilèges
administrateur. Conforme à ce que la documentation corrigée annonce désormais.

---

## 6. Audit mémoire

Recherche systématique des sites où un secret peut exister en plus de son
emplacement légitime.

### 6.1 Défauts trouvés et corrigés

| # | Défaut | Gravité | Correction |
|---|---|---|---|
| **M1** | `rng::key` passait par un tableau de pile `[u8; N]` intermédiaire, jamais effacé : la DEK laissait une copie complète dans une zone de pile recyclée | élevée | remplissage direct dans le buffer de la clé, via `expose_mut()` |
| **M2** | `Payload::decode` faisait `to_vec()` sur le corps : **seconde copie intégrale du coffre en clair**, la première n'étant jamais effacée | **critique** | `Payload::decode_owned` prend possession du `Zeroizing<Vec<u8>>` et transfère le corps par `split_off`, sans copie |
| **M3** | `container::decrypt` renvoyait un `Vec<u8>` nu : le contenu déchiffré était libéré sans effacement, y compris sur les chemins d'erreur | **critique** | le type de retour est `Zeroizing<Vec<u8>>` |
| **M4** | `Payload` **n'avait aucun `Drop`**, alors que le commentaire de `Vault::lock` affirmait le contraire : tout le contenu déchiffré restait dans le tas libéré | **critique** | `impl Drop for Payload` effaçant le corps ; commentaire corrigé |
| **M5** | `Vault::set_body` remplaçait le corps par une affectation de champ : l'ancien contenu tombait sans passer par le `Drop` | élevée | `Payload::replace_body` efface explicitement l'ancien |
| **M6** | `Payload::encode` renvoyait un `Vec<u8>` contenant le corps en clair | élevée | retourne `Zeroizing<Vec<u8>>` |
| **M7** | `Payload` dérivait `Clone` : duplication accidentelle possible du coffre entier | moyenne | dérive retirée |

**Le défaut M4 est le plus instructif : ce n'était pas une erreur de code contre
laquelle un test protège, mais un écart entre un commentaire et le comportement.**
Le commentaire affirmait « Drop sur … Payload libère et efface ce qui peut l'être »
alors que `Payload` n'implémentait pas `Drop`. Une relecture attentive l'aurait vu ;
un test ne pouvait pas le voir, faute d'observabilité sur un buffer libéré. Il a été
trouvé en cherchant systématiquement les `impl Drop` du code et en les comparant aux
affirmations de la documentation.

### 6.2 Sites de copie qui subsistent — inventaire exhaustif

Ce qui suit **n'est pas corrigeable** au niveau de cette application.

| # | Site | Nature | Peut-on l'éviter ? |
|---|---|---|---|
| C1 | `XChaCha20Poly1305::new_from_slice` copie la clé dans l'état du chiffreur | interne à la bibliothèque | non, sauf à réécrire l'AEAD — exclu |
| C2 | `HmacSha256::new_from_slice` copie la clé dans l'état HMAC (ipad/opad) | idem | non ; la feature `zeroize` de `hmac` n'est pas activée |
| C3 | `Hkdf::new` conserve une copie de l'IKM (la DEK) pendant l'expansion | idem | non ; idem |
| C4 | Argon2 hache le mot de passe avec Blake2b dans un tampon interne | idem | non — mais la zone de travail principale **est** effacée par nos soins |
| C5 | `std::io::stdin().read_line` peut réallouer le tampon du mot de passe | std | **partiellement** : la capacité est désormais réservée à l'avance, ce qui supprime les réallocations |
| C6 | `String::from_utf8_lossy` / conversions côté affichage | application | oui, éviter les conversions ; aucune n'est faite sur un secret |
| C7 | Migration de page, swap, vidage mémoire | noyau | non — `mlock` est best-effort et ne couvre pas tout |
| C8 | Registres et pile pendant les appels de fonction | compilateur | non |

**La liste C1 à C4 est le point le plus important de cette section.** Les trois
bibliothèques RustCrypto que nous utilisons (`chacha20poly1305`, `hmac`, `hkdf`)
**n'effacent pas leurs états internes** : les features `zeroize` correspondantes
existent mais ne sont pas activées.

Est-ce un défaut ? **Non, et il faut être précis sur pourquoi :** ces copies
contiennent des dérivés de nos clés (`K_records` pour C1, la KEK ou la DEK pour C2
et C3), pas les clés elles-mêmes. Leur exploitation exigerait un accès privilégié à
la mémoire du processus — auquel cas l'attaquant lit directement la DEK dans le
`LockedBuffer`. Cela n'augmente donc pas réellement la surface.

Il serait en revanche **malhonnête de ne pas le mentionner** : un futur lecteur
pourrait croire que `zeroize` couvre l'ensemble du cycle de vie des clés. C'est
maintenant écrit dans `docs/CRYPTO.md`.

### 6.3 Conversions, affichages, erreurs

| Recherche | Résultat |
|---|---|
| `format!` sur un secret | **aucun** — `Key` et `SecretVec` n'implémentent pas `Display` |
| `{:?}` sur un secret | impossible : `Debug` affiche `[EXPURGÉ]`, vérifié par test sur `Key`, `SecretVec`, `MasterKey`, `KeyEncryptionKey`, `DataEncryptionKey`, `WrappedKey`, `LockedBuffer`, `Payload`, `Vault` |
| erreurs contenant des données du coffre | **aucune** : toutes les charges utiles sont des `&'static str` |
| `println!` / `eprintln!` dans le cœur | **aucun** — la sortie n'existe que dans la CLI |
| `panic!` dans le code de production | **aucun** dans le cœur ; `unwrap`/`expect` interdits par lint (`deny`) et absents hors tests |
| `Debug` affichant un contenu | `Vault` et `ParsedVault` affichent des **tailles**, jamais un contenu — couvert par test |

### 6.4 Ce qui n'est toujours pas garanti

**L'effacement mémoire n'est pas garanti, et ne le sera pas.** Après les corrections
ci-dessus, ce que nous contrôlons est effacé : les buffers que nous allouons et
dont nous connaissons la durée de vie. Ce qui échappe reste :

* les copies C1 à C4, internes aux bibliothèques ;
* les valeurs que le compilateur place dans des registres ou sur la pile ;
* les blocs recyclés par l'allocateur système ;
* les pages écrites dans l'espace d'échange, quand `mlock` a échoué — cas normal,
  pas exception, sur un système où `RLIMIT_MEMLOCK` est bas ;
* ce que le noyau et le matériel conservent.

**Sur une machine de mesure, `mlock` a réussi** (aucun avertissement émis par la
CLI). Ce n'est pas une propriété générale : sur un système à `RLIMIT_MEMLOCK` bas, la
protection anti-swap est absente et l'application le signale.

**Verdict : PARTIALLY VERIFIED**, avec sept défauts corrigés. La formulation
« effacement garanti » n'est employée nulle part dans la documentation.

---

## 7. Audit du système de fichiers

| Attaque | Protection | Constat |
|---|---|---|
| Lien symbolique sur le **dernier** composant du répertoire | `O_DIRECTORY\|O_NOFOLLOW` | **protégé**, testé |
| Lien symbolique sur le nom du fichier temporaire | `O_CREAT\|O_EXCL\|O_NOFOLLOW` + nom aléatoire | **protégé**, testé |
| Lien symbolique sur le coffre lui-même | le renommage substitue l'entrée du lien, pas sa cible | **protégé**, testé (`replacing_a_symlink_…`) |
| **Lien symbolique sur un composant intermédiaire** | **aucune** *(état au moment de l'audit)* | **NON PROTÉGÉ — démontré par test** (§7.1) → **corrigé depuis, voir §11.1** |
| TOCTOU sur le contrôle d'existence | verrou pris **avant** le contrôle | **corrigé** (§7.2) |
| Permissions trop ouvertes | mode 0600 **à la création**, relu après correction | **protégé**, testé |
| Permissions d'un système de fichiers sans mode | relecture après écriture, erreur si le mode n'a pas changé | **protégé** — échec explicite plutôt que fausse assurance |
| Remplacement atomique | `renameat` + `fsync` du fichier puis du répertoire | **protégé**, testé |
| Corruption partielle | aucun état intermédiaire observable | **protégé**, testé (`interrupted_writes_…`) |
| Fichiers temporaires résiduels | nom aléatoire, 0600, supprimés sur échec | **protégé**, testé |
| Concurrence entre instances | `flock` exclusif non bloquant sur `<coffre>.lock` | **protégé**, testé |

### 7.1 La limite non corrigée, démontrée

`O_NOFOLLOW` ne s'applique qu'au **dernier** composant d'un chemin. Un composant
intermédiaire symbolique est suivi normalement par le noyau.

Le test `a_symlinked_intermediate_parent_is_not_refused_known_limitation` le
**démontre** : avec `a` → `attaquant/`, écrire dans `a/b/coffre.plk` écrit bien dans
`attaquant/b/coffre.plk`. Le test réussit quand la limite existe ; il échouera si
elle est un jour corrigée, ce qui forcera la mise à jour de la documentation.

**Est-ce une vulnérabilité ?** Nuancé. L'utilisateur choisit lui-même le chemin du
coffre ; suivre les liens symboliques est le comportement normal d'un système de
fichiers. Le scénario défavorable est celui où un attaquant peut **créer** un lien
dans un répertoire parent après que l'utilisateur a fixé le chemin — par exemple un
dossier partagé en écriture. Cela exige déjà un accès en écriture à un répertoire que
l'utilisateur contrôle mal.

**Correctif identifié** : marcher composant par composant, ou utiliser
`openat2(RESOLVE_NO_SYMLINKS)` (Linux ≥ 5.6). Non implémenté ; aucune échéance
fixée.

### 7.2 L'audit a trouvé une course TOCTOU réelle

`Vault::create` testait `path.exists()` **puis** acquérait le verrou. Deux créations
concurrentes franchissaient donc toutes les deux le contrôle, se sérialisaient sur le
verrou, et la seconde **écrasait silencieusement** le coffre de la première : perte
de données sans aucun message.

C'est exactement la classe de bug que le verrou était censé fermer — il était pris
trop tard pour servir à quoi que ce soit.

**Correction** : verrou d'abord, contrôle ensuite. **Non-régression** :
`concurrent_creations_never_silently_overwrite_each_other` lance les deux créations
en parallèle douze fois et exige exactement un succès à chaque essai, plus la
vérification que le coffre survivant est ouvrable avec exactement un des deux mots de
passe.

**Verdict filesystem : PARTIALLY VERIFIED** — une course corrigée, une limite
connue démontrée.

---

## 8. Attaques négatives

Nouveau fichier `crates/passlock-core/tests/adversarial.rs`, **17 tests**, dont 12
n'existaient pas avant cet audit.

| # | Attaque demandée | Test | Résultat |
|---|---|---|---|
| 1 | header tronqué | `every_truncation_is_rejected_without_panic` (existant) + `header_decoder_rejects_every_truncation_…` | refusé |
| 2 | longueur énorme | `absurd_declared_lengths_never_cause_an_allocation` | refusé, sans allocation |
| 3 | longueur incohérente | idem + `trailing_bytes_are_rejected` | refusé |
| 4 | version inconnue | `changing_the_format_version_is_refused_explicitly` | refusé |
| 5 | mauvais ordre de champs | `swapping_two_slots_in_the_header_invalidates_the_payload` | refusé |
| 6 | slot du mauvais coffre | `transplanting_a_whole_slot_from_another_vault_is_refused` | refusé par les deux mots de passe |
| 7 | chiffré d'un autre coffre | `swapping_the_ciphertext_between_two_vaults_is_refused` | `Corrupted` |
| 8 | nonce d'un autre coffre | `swapping_the_payload_nonce_between_two_vaults_is_refused` | `Corrupted` |
| 9 | AAD modifiée | `modified_aad_is_rejected` + `every_header_bit_flip_breaks_the_payload_tag` | refusé |
| 10 | clé enveloppée remplacée | `swapping_the_ciphertext_…` + `tampering_with_the_slot_…` | `UnlockFailed` |
| 11 | deux fichiers mélangés | `splicing_two_halves_of_different_vaults_is_refused` | refusé |
| 12 | sauvegarde ancienne | `restoring_a_copy_is_reported_but_never_blocks_opening` | signalé, non bloqué |
| 13 | fichier partiellement écrit | `interrupted_writes_never_leave_a_partial_vault` | coffre intact |
| 14 | chemin avec symlink parent | `a_symlinked_immediate_parent_is_refused` **et** `…_intermediate_parent_is_not_refused_known_limitation` | refusé / **limite démontrée** |
| 15 | concurrence ouverture/écriture | `a_second_writer_is_refused_and_the_vault_stays_readable` + `concurrent_creations_…` | refusé, coffre intact |
| 16 | **(ajouté)** paramètres KDF altérés | `changing_the_kdf_parameters_preserves_structure_but_fails_authentication` | `UnlockFailed` |
| 17 | **(ajouté)** `vault_id` altéré | `changing_the_vault_id_invalidates_every_slot` | `UnlockFailed` |

### 8.1 Deux de mes propres tests étaient faux

Il faut le consigner, parce que c'est le résultat le plus instructif de cet exercice.

* `changing_the_vault_id…` modifiait l'**octet 0**, qui appartient à la signature
  `"PASSLOCK"`. Le refus obtenu était `NotAVault` — correct, mais sans rapport avec
  ce que le test prétendait vérifier. Le `vault_id` commence à l'offset 16.
* `changing_the_slot_label…` attendait `UnlockFailed`. Le comportement réel est
  `InvalidHeader` : transformer le seul slot en « récupération » laisse un coffre
  **sans slot maître**, violation structurelle détectée avant toute dérivation.

Dans les deux cas j'ai vérifié le comportement réel avec le binaire avant de conclure,
et **c'est le test qui a été corrigé, pas le code**. Le second cas a néanmoins révélé
une imprécision réelle de la documentation (voir §3 et §9), qui a été corrigée.

---

## 9. Vérification indépendante : invariants de sécurité

Checklist construite **indépendamment** des tests existants, en partant des
propriétés qu'un gestionnaire de secrets doit respecter.

| # | Invariant | Preuve dans le code | Test | Résultat |
|---|---|---|---|---|
| I1 | Aucun octet du fichier n'échappe à l'authentification | AAD = `0..16+H` ; nonce protégé implicitement | `mutations_of_a_valid_vault_never_panic` : 6 519 mutations, **toute** mutation détectée | **VERIFIED** |
| I2 | L'encodage du header est déterministe | layout à offsets fixes, aucun tri ni forme canonique | `encoding_is_deterministic` | **VERIFIED** |
| I3 | Aucun message d'erreur ne dépend de la valeur du mot de passe | toutes les charges utiles sont `&'static str` | `unlock_failure_message_is_cause_agnostic`, `changing_the_slot_label_…` | **VERIFIED** |
| I4 | Aucune allocation dimensionnée par une valeur non bornée du fichier | bornes vérifiées pendant le décodage ; `try_reserve_exact` ; lecture bornée ; **arithmétique d'offsets vérifiée** | `a_hostile_memory_cost_…`, `a_huge_file_…`, `absurd_declared_lengths_…`, tests `bytes::` | **VERIFIED** |
| I5 | La DEK est rigoureusement identique après un changement de mot de passe | ré-enveloppe de `self.dek` | `changing_the_password_preserves_the_payload_and_the_vault_identity` | **VERIFIED** |
| I6 | Un slot ne peut pas changer de coffre | `vault_id` dans l'AAD du slot | `transplanting_a_whole_slot_…` | **VERIFIED** |
| I7 | Le contenu déchiffré est effacé à la destruction | `Drop for Payload`, `Drop for Key`, `Zeroizing` | `the_type_system_enforces_the_effacement_contract` + preuve de type | **PARTIALLY VERIFIED** — les copies C1–C4 échappent |
| I8 | Aucun secret n'est affichable | pas de `Display` ; `Debug` rédacteur | 8 tests de rédaction | **VERIFIED** |
| I9 | Deux processus ne peuvent pas écrire simultanément | `flock` exclusif non bloquant | `exclusive_lock_is_refused_…`, `concurrent_creations_…` | **VERIFIED** |
| I10 | Une écriture interrompue ne laisse pas de coffre partiel | temporaire + `fsync` + `renameat` | `interrupted_writes_…` | **VERIFIED** |
| I11 | Les fichiers créés sont inaccessibles aux autres comptes | mode 0600 à la création | `new_file_is_created_with_owner_only_permissions` | **VERIFIED sur Unix** · **NOT VERIFIED sur Windows** (compile, mais la sémantique des ACL n'est pas observable ici — §11.3) |
| I12 | Un fichier malformé ne provoque jamais de panique | lecture bornée, aucun `unwrap` en production | 20 000 mutations + 20 000 entrées aléatoires + toutes les troncatures | **VERIFIED** |
| I13 | Le cœur n'a aucune dépendance réseau | `cargo tree` | vérification manuelle | **VERIFIED** |
| I14 | Le retour en arrière est détecté | génération + sentinelle HMAC | `rollback_of_the_vault_file_is_detected`, `restoring_a_copy_…` | **PARTIALLY VERIFIED** — §5 |
| I15 | Aucun débordement d'entier sur les longueurs | `checked_add` **dans toutes** les lectures du format (`bytes.rs`) | `an_offset_that_would_overflow_is_refused_not_wrapped`, `the_last_valid_offset_is_accepted` | **VERIFIED** (passe ciblée §11.2) |
| I16 | Les paramètres de test ne fuient pas en production | `#[cfg(test)]`, `Default` durci | revue de code | **VERIFIED** |
| I17 | Le commit est reproductible | `Cargo.lock`, `rust-toolchain.toml` | — | **PARTIALLY VERIFIED** — build non testé en environnement vierge |
| I19 | Aucun composant de chemin n'est un lien symbolique | `open_dir_no_symlinks` : marche avec descripteurs tenus | 6 tests dans `atomic_write.rs`, 1 dans `adversarial.rs` | **VERIFIED sur Unix** · **PARTIALLY sur Windows** (vérification préalable, course résiduelle) |
| I20 | La concurrence des dérivations est plafonnée | sémaphore global, 1 place par défaut | `the_semaphore_serialises_…`, `a_derivation_cannot_finish_…`, `concurrent_derivations_never_exceed_…` | **VERIFIED** dans le processus · **OUT OF SCOPE** entre processus |
| I18 | Aucune vulnérabilité connue dans les dépendances | `deny.toml` | `cargo deny check` | **VERIFIED** au 2026-09-16 |

---

## 10. Verdict de phase 1

### 10.1 Classement

| Domaine | Verdict | Justification |
|---|---|---|
| Hiérarchie de clés | **VERIFIED** | aucune réutilisation incompatible ; `K_index` à double usage, séparé par domaines |
| Séparation des clés (HKDF) | **VERIFIED** | étiquettes distinctes et versionnées, test d'unicité |
| Format — structure et authentification | **VERIFIED** | 8 classes d'attaques repoussées, layout sans parseur |
| Format — arithmétique des longueurs | **PARTIALLY VERIFIED** | `offset + N` non vérifié ; non atteignable aujourd'hui |
| Format — `info` sans clé | **PARTIALLY VERIFIED** | métadonnées affichées non authentifiées ; avertissement ajouté, comportement inchangé |
| AEAD | **VERIFIED** | algorithme, tailles, nonces, AAD, ordre, échecs — tous vérifiés |
| Argon2id | **VERIFIED** | paramètres, sel, séparation test/production |
| Argon2id sous pression mémoire | **NOT VERIFIED** | non mesuré ; pas de détection de swap → **mesuré depuis, voir §11.4** |
| Retour en arrière | **PARTIALLY VERIFIED** | efficace contre l'attaquant périphérique ; neutralisé par la suppression de la sentinelle |
| Mémoire | **PARTIALLY VERIFIED** | 7 défauts corrigés ; copies internes aux bibliothèques hors de portée |
| Système de fichiers — Unix | **PARTIALLY VERIFIED** | TOCTOU corrigée ; composants intermédiaires non protégés → **corrigé depuis, voir §11.1** |

> **Ce tableau est daté.** Il reflète l'état **au moment de l'audit**. La passe ciblée
> décrite en §11 a depuis corrigé plusieurs de ces points : les lignes concernées
> portent un renvoi. Le tableau de revérification fait foi pour l'état courant — §11.6.

| Système de fichiers — Windows | **NOT VERIFIED** | **jamais compilé** *(état au moment de l'audit)* — ACL, vidages, `ptrace` → **compile depuis, exécution toujours non observée, voir §11.3** |
| Robustesse aux entrées malformées | **VERIFIED** | 40 000 cas + fuzzing déterministe |
| Fuzzing guidé par couverture | **NOT VERIFIED** | cibles écrites, **jamais exécutées** (nightly absent) |
| Chaîne d'approvisionnement | **VERIFIED** | `cargo deny` : 4 catégories |
| Verrouillage automatique, TOTP, presse-papiers, sauvegardes, import/export, interface | **OUT OF SCOPE** | phases 2 à 6 |

### 10.2 Vulnérabilités réelles découvertes

Par ordre de gravité décroissante.

| # | Défaut | Gravité | Exploitation |
|---|---|---|---|
| **V1** | `Payload` sans `Drop` **et** commentaire affirmant le contraire : tout le coffre déchiffré restait en clair dans le tas libéré au verrouillage ou à la destruction | **élevée** | lecture de mémoire non privilégiée après verrouillage ; un vidage mémoire capturé après `lock()` exposait le contenu |
| **V2** | `container::decrypt` renvoyait un `Vec<u8>` nu, libéré sans effacement, **y compris sur les chemins d'erreur** | **élevée** | idem V1, pendant toute la session |
| **V3** | `Payload::decode` créait une **seconde copie intégrale** du coffre en clair, dont aucune n'était effacée | **élevée** | double la fenêtre d'exposition de V2 |
| **V4** | Course TOCTOU dans `Vault::create` : `exists()` avant le verrou | **moyenne** | deux créations concurrentes → écrasement silencieux, perte de données |
| **V5** | `rng::key` laissait la DEK dans un tableau de pile non effacé | **moyenne** | copie permanente de la clé de données dans une zone recyclée |
| **V6** | `Vault::set_body` remplaçait le corps sans effacer l'ancien | **faible** | fenêtre réduite |
| **V7** | Lecture du fichier entier avant le contrôle de taille | **faible** | déni de service local par fichier volumineux |
| **V8** | Tampon CLI non borné et réalloué à chaque frappe | **faible** | copies partielles du mot de passe dans le tas ; déni de service par tube sans fin de ligne |

**Aucun de ces défauts n'est cryptographique.** Le chiffrement, la dérivation, la
gestion des nonces et l'authentification sont corrects. Les défauts trouvés portent
tous sur le **cycle de vie des secrets en mémoire** et sur le **système de
fichiers** — deux domaines où le code est plus difficile à relire et où les tests
observent peu de choses.

### 10.3 Corrections appliquées

| Défaut | Correction | Fichier |
|---|---|---|
| V1 | `impl Drop for Payload` effaçant le corps ; commentaire de `Vault::lock` corrigé | `payload.rs`, `vault.rs` |
| V2 | `container::decrypt` retourne `Zeroizing<Vec<u8>>` | `container.rs` |
| V3 | `Payload::decode_owned` transfère le corps par `split_off`, sans copie | `payload.rs` |
| V4 | verrou acquis **avant** le contrôle d'existence | `vault.rs` |
| V5 | remplissage direct dans le buffer de la clé | `rng.rs` |
| V6 | `Payload::replace_body` efface l'ancien contenu | `payload.rs` |
| V7 | `read_vault_file` avec lecture bornée par `Take` | `vault.rs` |
| V8 | capacité réservée à l'avance, lecture bornée, refus explicite au-delà de 1024 octets | `passlock-cli/src/main.rs` |
| — | `Payload` ne dérive plus `Clone` ni `PartialEq` | `payload.rs` |
| — | avertissement ajouté à la sortie de `info` | `passlock-cli/src/main.rs` |
| — | règle exacte des erreurs documentée (format vs `UnlockFailed`) | `error.rs`, `docs/CRYPTO.md` |
| — | `deny.toml` : clé obsolète, liste blanche resserrée à 3 entrées, faux positif des jokers | `deny.toml` |

### 10.4 Tests de non-régression

| Défaut | Test ajouté |
|---|---|
| V1 | `the_type_system_enforces_the_effacement_contract` (borne `T: Drop` vérifiée à la compilation) |
| V2, V3 | `owned_decoding_transfers_the_body_without_copying` |
| V1, V3 | `owned_decoding_of_a_corrupted_envelope_fails_cleanly` |
| V4 | `concurrent_creations_never_silently_overwrite_each_other` (12 essais parallèles) |
| V7 | `a_huge_file_is_refused_without_being_loaded` |
| §8 | 12 attaques de manipulation supplémentaires |
| Doc | `changing_the_kdf_parameters_preserves_structure_but_fails_authentication` |
| Limite | `a_symlinked_intermediate_parent_is_not_refused_known_limitation` |

**Total : 168 tests avant l'audit, 188 après** — mesuré avec
`cargo test --workspace` : 132 unitaires du cœur, 17 adversariaux, 11 d'intégration,
7 de robustesse sur entrées malformées, 6 unitaires de la plateforme, 15 d'intégration
de la plateforme.

### 10.5 Risques résiduels

Classés par ce qu'ils exigent de l'attaquant.

**Acceptés, documentés, sans correctif prévu :**

| # | Risque | Pourquoi il n'est pas corrigé |
|---|---|---|
| R1 | Copie du mot de passe maître par un keylogger | hors de portée d'une application |
| R2 | Lecture de la DEK par un attaquant privilégié | `mlock` et `PR_SET_DUMPABLE` ne protègent que du non-privilégié |
| R3 | Effacement mémoire non garanti (copies C1–C4, registres, swap) | limites du langage, des bibliothèques et du noyau |
| R4 | Déni de service par tentatives répétées de déverrouillage | à traiter côté interface ; le KDF fait son travail |
| R5 | Le mot de passe maître reste le point de défaillance | aucune décision d'architecture ne compense un secret devinable |
| R6 | ~~Composants intermédiaires de chemin non protégés~~ | **corrigé** (§11.1) : marche composant par composant, `openat2` écarté pour cause de portabilité. Le risque résiduel est déplacé sur Windows (vérification préalable, sujette à une course) |
| R7 | Sauvegardes antérieures : une entrée supprimée y subsiste | conséquence inévitable d'une sauvegarde |
| R8 | Sentinelle supprimable si l'attaquant écrit dans le répertoire de configuration | exige un état inviolable (TPM, distant) |

**À traiter, avec une échéance :**

| # | Risque | Échéance |
|---|---|---|
| R9 | **Backend Windows jamais compilé** — ACL non vérifiées, vidages non désactivés, `ptrace` non restreint | **avant toute annonce de support Windows** |
| R10 | Cibles `cargo-fuzz` jamais exécutées | intégration continue, phase 2 |
| R11 | `offset + N` non vérifié dans les lectures internes | phase 2, quand de nouveaux champs de longueur apparaîtront |
| R12 | `calibrate` produit une recommandation que rien ne consomme | phase 6 |
| R13 | Aucune détection de pression mémoire proposant le profil bas | phase 6 |
| R14 | Aucun audit externe | avant toute diffusion large |

### 10.6 Conditions nécessaires pour commencer la phase 2

**Rempli :**

1. ✅ Aucune vulnérabilité cryptographique.
2. ✅ Les huit défauts trouvés sont corrigés et couverts par un test de non-régression.
3. ✅ Le format est figé, documenté octet par octet et vérifié par un test de layout.
4. ✅ La distinction test/production des paramètres de dérivation est vérifiée.
5. ✅ `cargo deny check` passe sur les quatre catégories.
6. ✅ Chaque affirmation de sécurité de la documentation est soit vérifiée, soit
   explicitement marquée comme non vérifiée.
7. ✅ 188 tests verts, `clippy` sans avertissement, formatage conforme.

**Non rempli — et qui ne bloque pas la phase 2, mais doit être fait avant toute
diffusion :**

1. ❌ **Compilation et exécution du backend Windows.** La phase 2 ajoute du code
   portable ; elle n'aggrave pas cette lacune, mais elle ne la comble pas non plus.
2. ❌ **Exécution des cibles de fuzzing** en intégration continue.
3. ❌ **Audit par un tiers.**

**Recommandation : commencer la phase 2**, en y intégrant dès le départ les deux
exigences que cet audit a montrées comme déterminantes :

* **tout `Vec<u8>` contenant du contenu déchiffré doit être `Zeroizing`** — les
  défauts V1 à V3 venaient tous de l'absence de cette règle appliquée
  systématiquement ;
* **toute affirmation dans un commentaire doit être vérifiable** — le défaut le plus
  grave (V1) n'était pas une erreur de code mais un commentaire qui décrivait un
  comportement inexistant.

---

## Annexe — ce que cet audit ne couvre pas

Énoncé explicitement, pour éviter l'impression de complétude.

* **Ce n'est pas un audit externe.** L'auteur du code a conduit la revue. Les
  erreurs de conception partagées entre l'implémentation et son auteur — celles qui
  paraissent évidentes à celui qui a écrit le code — sont par construction les moins
  susceptibles d'être trouvées ici.
* **La cryptographie n'a pas été auditée mathématiquement.** L'audit porte sur
  l'**usage** des primitives, pas sur leur correction. H1 et H2 de
  `THREAT_MODEL.md` restent des hypothèses.
* **Aucun test dynamique sous sanitizers n'a été mené** (ASan, MSan, Miri). Ils
  auraient pu détecter des lectures de mémoire non initialisée que la revue ne voit
  pas. Non disponibles dans l'environnement actuel.
* **Aucun test d'analyse de mémoire réelle n'a été mené.** L'effacement est vérifié
  par le type et par la lecture du code, pas par inspection d'un vidage mémoire.
  C'est une conséquence assumée de la conception, mais cela signifie que
  l'affirmation « le contenu est effacé » repose sur `zeroize` et sur la lecture de
  `Drop`, pas sur une observation.
* **La phase 1 n'a aucune interface graphique** : les surfaces liées à l'affichage,
  au presse-papiers et à la webview sont hors périmètre par construction.

---

## 11. Passe ciblée post-audit

Cinq points traités après l'audit initial, avant gel de la phase 1.

### 11.1 Liens symboliques sur les composants intermédiaires

**Approches comparées avant de choisir.**

| Approche | Sécurité | Portabilité | Complexité |
|---|---|---|---|
| `openat2(RESOLVE_NO_SYMLINKS)` | maximale, résolution atomique par le noyau | **Linux ≥ 5.6 uniquement** ; numéro d'appel par architecture ; absent de `libc` | faible, mais FFI brute et détection de disponibilité |
| vérification `lstat` préalable | **faible** : TOCTOU entre la vérification et l'ouverture | totale | faible |
| refus global de tout lien | élevée | totale | faible, mais casse les dispositions légitimes (`/tmp` sur macOS, `/home` sur certaines distributions) |
| **marche avec descripteurs tenus** ← retenue | élevée : chaque composant est vérifié **et retenu** | POSIX, avec un analogue Windows (`FILE_FLAG_OPEN_REPARSE_POINT`) | moyenne |

**Pourquoi la marche.** C'est la seule approche à la fois sûre — les descripteurs
ouverts garantissent qu'aucun composant ne peut être remplacé après vérification, ce
qu'une vérification préalable ne garantit pas — et transposable à Windows, où
`openat2` n'existe pas. `openat2` serait plus élégant mais enferme la solution dans un
noyau récent et une architecture, pour un appel unique.

**Mise en œuvre.** `open_dir_no_symlinks` part d'un ancrage explicite (la racine pour
un chemin absolu, le répertoire courant sinon) puis ouvre chaque composant avec
`O_DIRECTORY | O_NOFOLLOW` **depuis le descripteur du précédent**. `write_atomic`
utilise le descripteur obtenu comme base de `openat` et `renameat`.

**Trade-off assumé et documenté.** Chaque composant est ouvert en lecture, ce qui
exige le droit de lecture sur chaque répertoire traversé : un répertoire traversable
mais non lisible (mode `--x`) est refusé. Le message d'erreur nomme le composant
fautif et indique le remède (passer le chemin résolu).

**Windows.** Pas de famille `*at` : la vérification est faite en amont par
`ensure_no_symlink_components`, qui lit l'attribut `FILE_ATTRIBUTE_REPARSE_POINT`
— `FileType::is_symlink` seul ne reconnaît ni les points de jonction ni certains
points d'analyse. La **course résiduelle est documentée**, et la fonction n'est pas
présentée comme équivalente à la marche Unix.

**Tests de non-régression** — 7 ajoutés : composant symbolique au deuxième niveau,
au troisième, dans un chemin absolu, `..` toujours accepté, chemin profond légitime
toujours accepté, nommage du composant dans le message, et le cas acceptant de la
vérification portable.

**Le test qui documentait la limite a échoué dès la correction** — c'était sa
fonction : il avait été écrit pour forcer la mise à jour de la documentation si la
limite disparaissait un jour. Il a été inversé en test de non-régression.

### 11.2 Arithmétique des offsets

**Défaut visé.** Les lectures internes faisaient `bytes.get(offset..offset + N)`. Un
`offset` hostile proche de `usize::MAX` fait **déborder** l'addition : en release, le
résultat est silencieusement ramené modulo la taille du type, et la plage obtenue
peut être incohérente. L'audit initial avait classé ce risque **latent** — non
atteignable, tous les appels utilisant des offsets constants ou déjà bornés.

**Correction.** Un module `bytes.rs` centralise **toutes** les lectures du format, avec
un invariant explicite appliqué dans cet ordre : `checked_add` contre le débordement,
puis `get` contre la borne, et **aucune allocation avant ces deux vérifications**.
`header.rs`, `container.rs` et `payload.rs` y passent intégralement ; les helpers
locaux qui faisaient le calcul non vérifié ont été supprimés.

Le calcul d'offset des slots (`HEADER_FIXED_LEN + index * SLOT_LEN`) est lui aussi
passé en `checked_mul`/`checked_add`, pour que l'invariant soit local plutôt que
dépendant d'un raisonnement sur les bornes appliquées ailleurs.

**Pourquoi maintenant.** Corriger avant que la phase 2 n'introduise de nouveaux champs
de longueur coûte quelques dizaines de lignes ; après coup, cela coûterait une
relecture complète du format.

**Tests aux frontières** — 8 ajoutés : dernier offset valide accepté et suivant
refusé, offsets `usize::MAX`, `usize::MAX-1`, `usize::MAX-7`, longueurs nulles, buffer
vide, longueur exacte contre longueur minimale, et **toutes** les troncatures de 0 à
8 octets pour chaque type d'entier.

**Le test décisif** est `an_offset_that_would_overflow_is_refused_not_wrapped` : sans
`checked_add`, il échoue. C'est la non-régression qui protège la propriété.

### 11.3 Windows : d'« état prévu » à « vérification réelle »

**Ce qui a été fait.** La cible `x86_64-pc-windows-msvc` a été installée, et
l'intégralité de l'espace de travail — **cibles de test incluses** — compile avec
`-D warnings`.

**Deux erreurs de compilation réelles ont été trouvées immédiatement** :

1. un import `io` dupliqué dans `windows.rs` (module entier puis `self` dans une
   seconde liste) ;
2. une implémentation manuelle de `Debug` référençant un champ renommé, devenue une
   erreur de type.

Elles auraient été livrées sans que rien ne les signale : aucune relecture ne les
attrape, et l'audit initial — qui relevait pourtant que « ce code n'a jamais été
compilé » — n'avait pas pu les voir non plus. **C'est le résultat le plus concret de
cette passe.**

**Ce qui est donc désormais vérifié** : signatures FFI, types, noms de fonctions et
constantes de `windows-sys`, cohérence des `cfg`, et le fait que `windows-sys` 0.61
avec la liste de fonctionnalités choisie suffit.

**Ce qui reste non vérifié, précisément.** L'environnement ne dispose ni de Wine, ni
de MinGW, ni du linker MSVC — vérifié, pas supposé. Donc **aucun binaire Windows n'a
été lié ni exécuté**. Restent non observés : le comportement réel de `MoveFileExW` sur
un remplacement, la sémantique de conflit de `LockFileEx`, la confidentialité
effective reposant sur les ACL, le refus effectif des points d'analyse, les chemins
longs et UNC, et les noms réservés.

**Ce qui a été mis en place pour combler l'écart** : un job `windows-latest` dans
`.github/workflows/ci.yml` qui exécute `cargo test --workspace` — c'est-à-dire la
seule étape qui **exécute** le backend Windows. Et un nouveau fichier de tests
`fs_portable.rs` (13 tests) sans aucun `cfg(unix)`, conçu pour tourner sur Windows :
il constitue la seule preuve d'exécution réelle de cette couche.

**Aucun résultat Windows n'est affirmé.** Tant que le job n'a pas tourné, la
formulation reste « compile, comportement non observé ».

### 11.4 Pression mémoire sous Argon2id

**Campagne** : `scripts/measure-memory-pressure.sh`, N coffres **distincts** ouverts
simultanément, échantillonnage du pic agrégé à ~200 Hz.

| N | Pic agrégé | Par processus | Durée unitaire | Part de la RAM |
|---|---|---|---|---|
| 1 | 258 Mio | 258 Mio | 682 ms | 3 % |
| 2 | 517 Mio | 258 Mio | 823 ms | 6 % |
| 4 | 1 034 Mio | 258 Mio | 1 264 ms | 13 % |
| 8 | 2 068 Mio | 258 Mio | 2 709 ms | 26 % |
| 16 | **4 135 Mio** | 258 Mio | 5 220 ms | **53 %** |

Croissance **strictement linéaire**. Le mode de défaillance est le point important :
sur Linux, le dépassement de la mémoire disponible **ne produit pas d'erreur franche**
— le noyau échange, la durée passe de 0,7 s à plusieurs dizaines de secondes, et la
machine entière est dégradée.

**Une limitation de concurrence était donc nécessaire.** Implémentée : sémaphore
global, **une dérivation par défaut**, relevable par
`kdf::set_max_concurrent_derivations`. Un déverrouillage est une action humaine : la
sérialisation ne coûte rien en pratique et plafonne le pic à 258 Mio.

**Correction de méthode, consignée parce qu'elle est instructive.** Une première
version de la campagne ouvrait N fois le **même** coffre. Le verrou exclusif en
refusait N-1, et la mesure retournait un pic plat de 258 Mio quelle que soit la valeur
de N : elle mesurait la sérialisation par le verrou, et non la pression mémoire. Le
chiffre n'était pas faux, il ne répondait pas à la question. Le dispositif a été
corrigé (N coffres distincts) avant toute conclusion.

**Portée, sans ambiguïté** : le limiteur borne la concurrence **dans le processus**.
Chaque instance a le sien ; N instances lancées séparément ne sont pas plafonnées. Un
plafond inter-processus serait **contournable** — un attaquant local qui veut
consommer 256 Mio peut les allouer directement, sans passer par ce programme. Le
limiteur protège donc l'utilisateur de **notre propre comportement**, pas d'un
adversaire. C'est la bonne portée, et elle est écrite comme telle.

**Aucun paramètre cryptographique n'a été modifié.** Le profil mesuré est celui qui
est livré : 256 Mio, t=3, p=4.

### 11.5 Sanitizers

Ce qui a **réellement tourné**, et rien de plus :

| Outil | Portée exécutée | Résultat |
|---|---|---|
| **ASan** (`-Zsanitizer=address`, `-Zbuild-std`) | espace de travail entier, **225 tests** | aucun défaut mémoire |
| **TSan** (`-Zsanitizer=thread`) | **149 tests unitaires du cœur**, dont le limiteur | **aucune course de données** |
| **Miri** | **41 tests** : `bytes` (8), `header` (19), `payload` (14) | aucune opération indéfinie |
| MSan | — | **non exécuté** : exige que toutes les dépendances soient instrumentées |
| UBSan | — | **non disponible** pour Rust |

**Pourquoi Miri ne couvre pas tout** : les modules `secret`, `aead`, `container`,
`rollback`, `kdf` et `vault` passent par `mlock` et `getrandom`, que Miri refuse
d'appeler — il échoue avec « can't call foreign function `mlock` ». C'est une
**limitation d'environnement**, pas un défaut détecté. Les trois modules couverts sont
précisément ceux qui décodent des données non fiables, là où la couverture vaut le
plus.

### 11.6 Revérification des 18 invariants

| Invariant | Avant cette passe | Après |
|---|---|---|
| I1 — tout octet est authentifié | VERIFIED | **VERIFIED** |
| I2 — encodage déterministe | VERIFIED | **VERIFIED** |
| I3 — aucun message ne dépend du mot de passe | VERIFIED | **VERIFIED** |
| I4 — aucune allocation non bornée | VERIFIED | **VERIFIED** (renforcé par `bytes.rs`) |
| I5 — DEK conservée | VERIFIED | **VERIFIED** |
| I6 — slot non transposable | VERIFIED | **VERIFIED** |
| I7 — effacement du contenu | PARTIALLY | **PARTIALLY** (inchangé : copies internes aux bibliothèques) |
| I8 — aucun secret affichable | VERIFIED | **VERIFIED** |
| I9 — verrou d'écriture exclusif | VERIFIED | **VERIFIED** |
| I10 — pas de coffre partiel | VERIFIED | **VERIFIED** |
| I11 — permissions restrictives | Unix VERIFIED / Windows NOT | **Unix VERIFIED** / Windows : compile, comportement non observé |
| I12 — aucune panique sur entrée malformée | VERIFIED | **VERIFIED** |
| I13 — aucune dépendance réseau | VERIFIED | **VERIFIED** |
| I14 — retour en arrière détecté | PARTIALLY | **PARTIALLY** (limites §5 inchangées) |
| I15 — aucun débordement d'entier | **PARTIALLY** | **VERIFIED** |
| I16 — paramètres de test non fuyants | VERIFIED | **VERIFIED** |
| I17 — build reproductible | PARTIALLY | **PARTIALLY** (inchangé) |
| I18 — aucune vulnérabilité connue | VERIFIED | **VERIFIED** |
| **I19 — aucun composant symbolique** *(nouveau)* | — | **Unix VERIFIED** / Windows PARTIALLY |
| **I20 — concurrence plafonnée** *(nouveau)* | — | **VERIFIED** dans le processus |

**Résultat : un invariant passe de PARTIALLY à VERIFIED (I15), deux sont ajoutés, aucun
ne régresse.**

### 11.7 Défauts trouvés pendant cette passe

| # | Défaut | Gravité | Statut |
|---|---|---|---|
| **V9** | Deux erreurs de compilation dans le backend Windows (import dupliqué, `Debug` obsolète) — livrables sans être détectées | **moyenne** | **corrigé**, la cible Windows est désormais compilée |
| **V10** | Débordement d'entier latent sur `offset + N` dans les lectures du format | **moyenne** (non atteignable) | **corrigé**, invariant centralisé et testé aux frontières |
| **V11** | Concurrence des dérivations non bornée : 16 ouvertures simultanées consommaient 4,1 Gio, sans échec franc | **moyenne** | **corrigé**, limiteur à une dérivation par défaut |
| **V12** | Composants intermédiaires symboliques suivis — limite démontrée en §7.1 | **moyenne** | **corrigé** sur Unix, partiellement sur Windows |

Et deux défauts **dans le dispositif de mesure lui-même** : la campagne mémoire
mesurait la sérialisation par le verrou au lieu de la concurrence, et deux tests du
limiteur étaient instables parce qu'ils assertaient sur un état global partagé par
des tests parallèles. Les deux sont corrigés, et la cause est consignée plutôt que
dissimulée derrière un ajustement.

### 11.8 Ce qui reste réellement non vérifié

Liste exhaustive, sans nuance rassurante :

1. **L'exécution du backend Windows.** Compile, mais aucun binaire Windows n'a été lié
   ni exécuté : ni Wine, ni MinGW, ni linker MSVC dans l'environnement. Comportement
   des ACL, de `MoveFileExW`, de `LockFileEx` : **non observés**.
2. **Les cibles `cargo-fuzz`.** Écrites, un job CI les exécute, mais elles n'ont
   **jamais tourné** ici (`cargo-fuzz` absent). Le harnais déterministe (40 000 cas)
   couvre localement une partie de la propriété.
3. **MSan et UBSan.** Non exécutés : le premier exige des dépendances instrumentées,
   le second n'existe pas pour Rust.
4. **Miri au-delà de 41 tests.** Bloqué par `mlock` et `getrandom`.
5. **Le comportement sous pression mémoire réelle.** La campagne mesure le pic
   linéaire, mais **n'a pas provoqué** de saturation : il aurait fallu faire échanger
   la machine, ce qui aurait perturbé l'environnement de mesure.
6. **La concurrence entre processus.** Non bornée par conception, assumé et justifié.
7. **L'effacement mémoire réel.** Vérifié par le type (`Drop`, `Zeroizing`) et par
   lecture du code, **jamais par inspection d'un vidage mémoire**. Les copies internes
   à `chacha20poly1305`, `hmac` et `hkdf` subsistent.
8. **La sentinelle anti-retour-en-arrière.** Contournable ou supprimable (§5) : aucune
   correction locale possible.
9. **Aucun audit externe, aucun test sous sanitizer pour le backend Windows.**
10. **La latence sur d'autres machines.** Les mesures valent pour cette machine.

### 11.9 Gel de la phase 1

**Conditions de sortie remplies** :

- ✅ corrections documentées (§11.1 à §11.5, plus `docs/CRYPTO.md` §3.5 et §7.1) ;
- ✅ tests de non-régression ajoutés — **37 nouveaux tests** dans cette passe (188 → 225) ;
- ✅ `AUDIT_PHASE1.md` mis à jour ;
- ✅ ce qui reste non vérifié est listé en §11.8 ;
- ✅ **aucun paramètre cryptographique modifié** : le profil livré reste
  256 Mio / t=3 / p=4, et la campagne mémoire l'a mesuré tel quel.

**État final** : 225 tests verts, `clippy` sans avertissement, formatage conforme,
`cargo deny check` à 4/4 sur les catégories, compilation Windows vérifiée, ASan et
TSan passés, Miri passé sur les décodeurs.

**La phase 1 est gelée.**
