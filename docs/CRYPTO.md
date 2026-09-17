# Cryptographie de Passlock

> Toutes les valeurs de ce document sont soit des **paramètres** (définis dans le
> code), soit des **mesures**. Les mesures sont explicitement étiquetées, avec leur
> machine et leur version de binaire. Aucune n'est extrapolée ni reprise d'une
> source externe.

## 1. Primitives

| Rôle | Primitive | Mise en œuvre | Version |
|---|---|---|---|
| Dérivation depuis le mot de passe maître | **Argon2id** | crate `argon2` (RustCrypto) | 0.6.0 |
| Chiffrement authentifié | **XChaCha20-Poly1305** | crate `chacha20poly1305` (RustCrypto) | 0.11.0 |
| Séparation de clés | **HKDF-SHA256** (RFC 5869) | crate `hkdf` | 0.13 |
| Hachage / HMAC | **SHA-256** | crate `sha2` | 0.11 |
| Index aveugles, sentinelle | **HMAC-SHA256** | crate `hmac` | 0.13 |
| Aléa | **générateur du noyau** | crate `getrandom` | 0.4 |
| Effacement mémoire | — | crate `zeroize` | 1.9 |
| Comparaison en temps constant | — | crate `subtle` | 2.6 |

**Aucune primitive n'est écrite à la main.** Aucun algorithme n'est inventé. Aucun
protocole cryptographique n'est inventé : la construction décrite en §3 est un
assemblage standard (enveloppe de clé + AEAD + dérivation par étiquettes), dont
chaque brique est un standard publié.

### Pourquoi Argon2id

Vainqueur du Password Hashing Competition (2015), normalisé dans la RFC 9106. La
variante `id` est hybride : la première passe se comporte comme `i` (résistante aux
attaques par canal auxiliaire) et les suivantes comme `d` (résistante au calcul
parallèle sur GPU/ASIC). Le paramètre de coût **mémoire** est le levier décisif :
chaque cœur d'attaque doit disposer de la totalité de `m`, ce qui plafonne son
parallélisme par la mémoire disponible et non par sa puissance de calcul.

### Pourquoi XChaCha20-Poly1305 et non AES-256-GCM

**Le critère décisif est la taille du nonce.**

| | XChaCha20-Poly1305 | AES-256-GCM |
|---|---|---|
| Nonce | **192 bits** | 96 bits |
| Collision de nonce à 2^32 messages | probabilité ~2^-97 | probabilité ~2^-33 |
| Conséquence d'une collision de nonce | — | confidentialité **et** intégrité rompues, silencieusement |
| Constante en temps | oui, par conception (ARX) | dépend d'AES-NI ; tables S-box logicielles vulnérables au cache-timing |
| Performance | bonne (AVX2) | excellente (AES-NI) |

Avec un nonce aléatoire de 96 bits, la borne du paradoxe des anniversaires est
atteinte bien plus tôt qu'on ne l'imagine, et y parvenir casse **à la fois** la
confidentialité (récupération du XOR des deux messages) et l'intégrité
(falsification possible du tag). C'est une défaillance silencieuse : rien ne la
signale à l'exécution.

Le nonce de 192 bits de XChaCha supprime la classe entière de bugs. On accepte un
écart de performance réel pour éliminer un mode de défaillance catastrophique.

AES-256-GCM n'est **pas** proposé en option. Exposer deux algorithmes doublerait la
surface de test et de maintenance sans bénéfice.

> **SHA-1 dans le TOTP.** Le TOTP (RFC 6238) utilise HMAC-SHA-1 dans son profil de
> compatibilité. Ce n'est **pas** une violation de la règle interdisant SHA-1 : les
> attaques sur SHA-1 sont des attaques par collision, inapplicables à HMAC, et
> RFC 6238 impose ce choix pour l'interopérabilité. Le SHA-1 reste interdit partout
> ailleurs. Ce point est consigné ici pour qu'aucun contributeur ne « corrige » à
> tort un comportement conforme.

## 2. Hiérarchie de clés

```
        mot de passe maître  (entrée utilisateur, entropie inconnue)
                 │
                 │  Argon2id(sel ⊂ slot, paramètres ⊂ slot)
                 ▼
                MK   clé maître        32 octets — JAMAIS persistée
                 │
                 │  HKDF-SHA256, info = "passlock/v1/kek"
                 ▼
               KEK   clé de chiffrement de clé
                 │
                 │  XChaCha20-Poly1305 : désenveloppe le slot du header
                 │  (échec ⇒ « mot de passe incorrect ou coffre corrompu »)
                 ▼
               DEK   clé de données   32 octets aléatoires, créée UNE fois
                 │
                 │  HKDF-SHA256, une étiquette par usage
                 ├──────────────► K_records     "passlock/v1/records"      payload
                 ├──────────────► K_attachments "passlock/v1/attachments"  pièces jointes
                 └──────────────► K_index       "passlock/v1/index"        index aveugles,
                                                                          sentinelle
```

### 2.1 Pourquoi une DEK distincte

Le raccourci naïf — chiffrer directement avec la clé dérivée du mot de passe —
rend toute modification du mécanisme d'authentification **solidaire du chiffrement
de toutes les données**.

| Opération | Sans DEK | Avec DEK |
|---|---|---|
| Changer le mot de passe maître | rechiffrer tout le coffre | réécrire 122 octets dans le header |
| Durcir les paramètres Argon2id | rechiffrer tout le coffre | idem |
| Ajouter une clé de récupération | impossible proprement | ajouter un slot |
| Révoquer une clé de récupération | impossible proprement | supprimer un slot |

La DEK sépare donc deux préoccupations indépendantes : **comment on déverrouille**
et **comment on chiffre**.

> **Correction d'une formulation initiale trop optimiste.** On lit souvent qu'une
> DEK rend le changement de mot de passe O(1). C'est faux dans cette architecture,
> et il vaut mieux le dire : le header entre dans l'AAD du payload (c'est ce qui
> rend l'attaque par abaissement des paramètres impossible), donc changer un slot
> invalide le tag et **impose de re-chiffrer le payload**. Le coût est faible — un
> passage d'AEAD sur quelques mégaoctets, avec la même clé, sans nouvelle
> dérivation — mais il est proportionnel à la taille du payload.
>
> Le bénéfice réel de la DEK se manifeste ailleurs : les **blobs de pièces
> jointes**, chiffrés sous `K_attachments`, ne sont pas touchés du tout. Pour des
> données qui peuvent peser des centaines de mégaoctets, l'opération est bien O(1).

### 2.2 Pourquoi la DEK brute n'est jamais utilisée directement

Chaque contexte cryptographique reçoit une sous-clé distincte via HKDF avec une
étiquette `info` propre et versionnée. Utiliser le même matériel de clé dans deux
contextes différents est une erreur classique : une faiblesse ou un oracle obtenu
dans un contexte peut se propager à l'autre. Le coût de HKDF est nul, la protection
est structurelle.

Les étiquettes sont préfixées par `/v1/` : un futur changement de format produira
des sous-clés différentes à partir de la même DEK, ce qui permettra de faire
cohabiter deux versions sans collision de domaine.

### 2.3 Absence de valeur de contrôle de clé

Une « valeur de contrôle de clé » (`HKDF(DEK, "…/keycheck")` tronquée) figurait dans
la conception initiale. Elle a été **retirée** : aucun de ses usages envisagés ne
survit à l'examen. Vérifier qu'une clé de récupération correspond au coffre est déjà
fait par le succès du désenveloppement ; vérifier qu'une sauvegarde vient du même
coffre est fait par `vault_id`, qui est public. La conserver aurait publié une valeur
dérivée de la DEK permettant de tester une DEK candidate — oracle inexploitable en
pratique, mais oracle inutile.

## 3. Paramètres Argon2id

### 3.1 Valeurs

| Profil | `m` (Kio) | RAM | `t` | `p` | Usage |
|---|---|---|---|---|---|
| Bas | 65 536 | 64 Mio | 3 | 2 | machines à mémoire limitée |
| **Standard (défaut)** | **262 144** | **256 Mio** | **3** | **4** | desktop |
| Paranoid | 1 048 576 | 1 Gio | 4 | 4 | utilisateurs avertis |

* sortie : **32 octets** ;
* sel : **32 octets aléatoires**, unique par slot, issus du générateur du noyau ;
* version Argon2 : `0x13` (v1.3), stockée dans le header ;
* plancher absolu accepté à la lecture : 8 Mio ;
* plafond absolu accepté à la lecture : 2 Gio (anti-déni-de-service, §3.4).

`p` est inclus dans `m` : en Argon2, `m` désigne la mémoire **totale** répartie
entre les voies. 256 Mio avec `p = 4` signifie 64 Mio par voie et 256 Mio en tout.

### 3.2 Justification, référence par référence

Références effectivement consultées :

* **OWASP Password Storage Cheat Sheet** — Argon2id minimum `m = 19 Mio`, `t = 2`,
  `p = 1` ; variantes équivalentes jusqu'à `m = 46 Mio`, `t = 1`, `p = 1`.
* **RFC 9106** — Argon2id `t = 1`, `m = 2 Gio` (premier choix) ; `t = 3`,
  `m = 64 Mio` (second choix, environnements contraints).
* **Bitwarden** (documentation officielle) — défaut Argon2id 64 Mio, 3 itérations,
  4 threads, présentés comme au-dessus des recommandations OWASP.

**Pourquoi les minima OWASP ne sont pas repris tels quels.** Ces minima visent une
**authentification serveur**, où le coût est payé à chaque connexion pour des
millions d'utilisateurs et où le hachage stocké protège un mot de passe parmi des
milliards. Ici :

* le KDF est payé **une fois par session de déverrouillage**, sur un seul coffre,
  pour un seul utilisateur ;
* le fichier est un objet unique et isolé : le budget de calcul de l'attaquant est
  dédié, non mutualisé ;
* le budget de latence disponible est bien plus large : 0,78 s de déverrouillage
  sont acceptables, 0,78 s par requête HTTP ne le seraient pas.

Le raisonnement impose donc d'être **au-dessus** des minima serveur. C'est aussi la
conclusion de Bitwarden.

### 3.3 Mesures

Machine : WSL2, noyau Linux 5.15, x86_64, 16 cœurs visibles.
Binaire : profil `release` (`opt-level = 3`, `lto = true`, `codegen-units = 1`).
Méthode : `passlock calibrate`, une dérivation complète par profil, horloge
monotone.

| Profil | Paramètres | Durée mesurée |
|---|---|---|
| Bas | 64 Mio, t=3, p=2 | **0,18 s** |
| Standard | 256 Mio, t=3, p=4 | **0,78 s** |
| Paranoid | 1 Gio, t=4, p=4 | **4,42 s** |

En profil `dev` (non optimisé), la même dérivation en 64 Mio t=3 p=2 a été mesurée à
**~3,3 s**, soit un facteur d'environ **21** par rapport au release. Argon2id est
purement calculatoire : c'est le comportement attendu, mais cela signifie qu'un
binaire de développement ne donne **aucune** indication utilisable sur la latence
réelle.

**Ce que ces chiffres ne disent pas.** Ils ne bornent en rien le coût pour un
attaquant disposant de matériel dédié. Ils disent seulement ce que coûte *le
déverrouillage légitime sur cette machine*. La calibration répond à une question de
confort, pas de sécurité.

### 3.4 Deux risques liés aux paramètres

**Déni de service par paramètres hostiles.** Un fichier de coffre peut annoncer
`m = 4 Gio`. Les paramètres sont donc validés pendant le décodage du header, **avant
toute allocation** liée à ces valeurs. Sans ce plafond, ouvrir un fichier piégé
suffirait à épuiser la mémoire de la machine.

**Échec d'allocation sur machine faible.** Une allocation qui échoue en Rust
déclenche un `abort`, pas une erreur. La dérivation utilise donc
`try_reserve_exact` : l'épuisement mémoire devient une erreur exploitable, ce qui
permet de proposer le profil réduit au lieu de tuer le processus.

### 3.5 Pression mémoire et concurrence

Argon2id alloue sa zone de travail — 256 Mio au profil standard — pour **toute la
durée** de la dérivation, pas seulement à l'instant du hachage. La campagne
`scripts/measure-memory-pressure.sh` mesure le pic agrégé lorsque N coffres
**distincts** sont ouverts simultanément.

Machine : WSL2, 7 754 Mio de RAM, 16 cœurs visibles, binaire release.

| Dérivations simultanées | Pic agrégé | Par processus | Durée unitaire | Part de la RAM |
|---|---|---|---|---|
| 1 | 258 Mio | 258 Mio | 682 ms | 3 % |
| 2 | 517 Mio | 258 Mio | 823 ms | 6 % |
| 4 | 1 034 Mio | 258 Mio | 1 264 ms | 13 % |
| 8 | 2 068 Mio | 258 Mio | 2 709 ms | 26 % |
| 16 | **4 135 Mio** | 258 Mio | 5 220 ms | **53 %** |

**Le pic croît strictement linéairement**, à 258 Mio par dérivation. Extrapolé, 30
dérivations simultanées dépasseraient la mémoire de cette machine.

**Le mode de défaillance est le point important.** Sur Linux, un dépassement de la
mémoire disponible **ne produit pas d'erreur franche** : le noyau échange, ce qui
fait passer la durée unitaire de 0,7 s à plusieurs dizaines de secondes et dégrade la
machine entière, y compris les autres applications de l'utilisateur. Une erreur serait
préférable à une dégradation silencieuse.

**Correction appliquée.** Un limiteur de concurrence **dans le processus**, à **une
dérivation par défaut**, relevable par `kdf::set_max_concurrent_derivations`. Un
déverrouillage est une action humaine : personne n'ouvre seize coffres dans la même
seconde, donc sérialiser ne coûte rien en pratique et plafonne le pic à 258 Mio.

**Correction de méthode, à consigner.** Une première version de la campagne ouvrait N
fois le **même** coffre : le verrou exclusif en refusait N-1, et la mesure retournait
un pic plat de 258 Mio quelle que soit la valeur de N. Elle mesurait la sérialisation
par le verrou, pas la pression mémoire. Le chiffre n'était pas faux — il ne répondait
pas à la question posée.

**Portée, énoncée sans ambiguïté.** Le limiteur borne la concurrence **dans le
processus**. Chaque instance a le sien : N instances de Passlock lancées séparément
ne sont **pas** plafonnées. Un plafond inter-processus demanderait un sémaphore nommé
ou un verrou partagé, et surtout il serait **contournable** — un attaquant local qui
veut consommer 256 Mio peut les allouer directement, sans passer par ce programme.
Le limiteur protège donc l'utilisateur de **notre propre comportement**, pas d'un
adversaire.

### 3.6 Stratégie d'évolution

Les paramètres sont **lus dans le fichier**, jamais pris dans une constante du code.
Durcir les valeurs par défaut ne rend donc aucun coffre existant illisible. Un coffre
dont les paramètres sont plus faibles que le profil par défaut courant reçoit un
avertissement, et `passlock change-password` effectue la migration (nouveau sel,
nouveaux paramètres, **même DEK**, réécriture du header, incrémentation de la
génération).

L'intervalle de `KdfParams::is_below_recommendation()` est dérivé du profil par
défaut courant et non d'une constante externe : durcir le défaut fait
automatiquement apparaître l'avertissement sur les coffres plus anciens.

## 4. Générateur aléatoire

Un seul point d'entrée, `rng::fill`, qui appelle `getrandom`. Aucun générateur en
espace utilisateur, aucun générateur injectable, aucun repli sur une horloge ou un
compteur.

**Pourquoi une règle aussi stricte.** Un générateur non cryptographique ne se
distingue pas d'un bon générateur à l'usage : le programme fonctionne, les tests
passent, et le défaut ne se révèle que lorsque les clés sont cassées. En n'exposant
qu'un point d'entrée unique et non substituable, l'erreur devient structurellement
impossible à commettre dans ce projet.

**Pas de repli.** Si `getrandom` échoue, l'opération échoue. Un repli produirait des
clés prédictibles, ce qui est strictement pire que refuser de fonctionner :
l'utilisateur croirait son coffre protégé.

Le tirage d'un entier dans un intervalle utilise un **rejet** et non un modulo : le
modulo n'est pas uniforme, les premières valeurs de l'intervalle étant plus
probables. Sur un sel ou un nonce, ce biais réduirait l'espace effectif.

## 5. Gestion des nonces

| Usage | Taille | Génération | Risque de réutilisation |
|---|---|---|---|
| Payload du conteneur | 24 o | aléatoire, à chaque écriture | négligeable (2^-97 à 2^48 écritures) |
| Enveloppe d'un slot | 24 o | aléatoire, à chaque enveloppement | négligeable |
| Pièces jointes (phase 4) | 24 o | aléatoire, par blob | négligeable |

Aucun compteur persistant n'est nécessaire : c'est précisément l'intérêt du nonce
de 192 bits. Un compteur serait un état supplémentaire à maintenir correctement,
donc une source de bugs silencieusement dangereux.

Un test vérifie que deux enveloppements successifs de la même DEK produisent des
nonces et des chiffrés distincts, et qu'un test de 1 024 générations ne produit
aucune collision.

## 6. Authentification et intégrité

* Le tag Poly1305 (16 octets, postfixe) authentifie le contenu du payload **et son
  AAD**.
* L'AAD du payload est l'intégralité des octets `0 .. 16 + header_len`, soit la
  signature, la version, les drapeaux, la longueur et tout le header.
* L'AAD d'un slot lie son identité, son rôle, ses paramètres et son sel à
  l'identifiant du coffre.

Conséquences vérifiées par les tests :

* modifier un octet du payload ⇒ `Corrupted` ;
* modifier un octet du header ⇒ le tag du payload devient invalide ;
* modifier un octet de la clé enveloppée ⇒ `UnlockFailed`, indiscernable d'un mot de
  passe faux ;
* déplacer un slot entre coffres ⇒ `UnlockFailed` ;
* abaisser `m_cost` dans le header ⇒ tag invalide ;
* tronquer le fichier ⇒ détecté, jamais de panique.

## 7. L'effacement mémoire n'est pas garanti

`zeroize` efface ce que nous contrôlons : les buffers alloués sur le tas, avec une
écriture volatile et une barrière mémoire qui empêchent l'optimiseur de supprimer
l'effacement. Cela **ne couvre pas** :

* les copies que le compilateur a pu faire dans des registres ou sur la pile au
  cours d'un appel ;
* les copies internes de SQLite, dont le cache de pages n'est pas sous notre
  contrôle (limite assumée de l'architecture retenue) ;
* les pages écrites dans l'espace d'échange, si `mlock` a échoué — ce qui est un cas
  de fonctionnement normal, pas une exception ;
* ce que le matériel ou le noyau conservent.

**Aucune garantie d'effacement total ne doit être annoncée à l'utilisateur.**

Mesure appliquée en complément :

| Mesure | Linux | Windows |
|---|---|---|
| Verrouillage des zones de clés | `mlock` | `VirtualLock` |
| Exclusion des vidages mémoire | `MADV_DONTDUMP` | non supporté sans privilèges |
| Vidages mémoire désactivés | `RLIMIT_CORE = 0` | non supporté sans privilèges |
| Restriction de `ptrace` | `PR_SET_DUMPABLE = 0` | non supporté sans privilèges |

Le durcissement du processus est appliqué au point d'entrée du binaire, jamais à
l'initialisation de la bibliothèque : une bibliothèque ne doit pas modifier l'état
global d'un processus hôte à son insu. Chaque mesure non appliquée est **signalée à
l'utilisateur** plutôt que tue.

### Un point positif souvent manqué

Argon2 0.6 expose `hash_password_into_with_memory`, qui laisse l'appelant fournir
les blocs de travail. Nous nous en servons pour **effacer explicitement** les `m`
Kio d'état intermédiaire après la dérivation. Cet état est un dérivé direct du mot
de passe maître : le laisser traîner reviendrait à conserver une version
« à mi-parcours » du secret. Cette zone n'est **pas** verrouillée avec `mlock` :
256 Mio dépasseraient systématiquement `RLIMIT_MEMLOCK` et feraient échouer la
protection pour toutes les autres clés. Le compromis est explicite — on efface sans
verrouiller.

### 7.1 Outils d'analyse dynamique : ce qui a réellement tourné

Aucun de ces résultats n'est extrapolé : ce qui n'a pas tourné est listé comme tel.

| Outil | Portée réellement exécutée | Résultat |
|---|---|---|
| **ASan** (`-Zsanitizer=address`, `-Zbuild-std`) | **l'espace de travail entier**, 225 tests | aucun défaut mémoire détecté |
| **TSan** (`-Zsanitizer=thread`) | **les 149 tests unitaires du cœur**, dont le limiteur de concurrence | **aucune course de données détectée** |
| **Miri** | **41 tests** : modules `bytes` (8), `header` (19), `payload` (14) | aucune opération indéfinie détectée |
| MSan | — | **non exécuté** : exige que toutes les dépendances soient instrumentées, ce qui n'est pas réalisable ici |
| UBSan | — | **non disponible** pour Rust |

**Pourquoi Miri ne couvre pas tout.** Les modules `secret`, `aead`, `container`,
`rollback`, `kdf` et `vault` sont hors de portée : Miri refuse d'appeler une fonction
étrangère, et ces modules passent par `mlock` (via `passlock-platform`) et
`getrandom`. Ce n'est pas un défaut détecté, c'est une **limitation d'environnement**.
Les trois modules couverts sont précisément ceux qui décodent des données non fiables
— c'est là que la couverture vaut le plus.

Les commandes correspondantes sont consignées dans `SECURITY.md` §12.

## 8. Absence d'oracle au déverrouillage

Deux causes d'échec doivent être indiscernables pour un attaquant qui ne connaît pas
le mot de passe :

1. le mot de passe est faux ;
2. le slot ou le header a été altéré.

Les deux produisent `Error::UnlockFailed`, avec un **message strictement
identique** : « déverrouillage impossible : mot de passe incorrect ou coffre
corrompu ». Un test vérifie que ce message ne désigne aucune cause interne (aucune
occurrence de « slot », « tag », « header », « payload », « Argon2 »…).

### La nuance, assumée

Une fois le déverrouillage réussi — donc le mot de passe connu — la distinction
devient légitime et utile :

* l'ouverture du **slot** échoue → `UnlockFailed`, cause ambiguë ;
* le slot s'ouvre mais le **payload** échoue → `Corrupted`, car le mot de passe
  était juste.

Pour atteindre la seconde branche, il faut **déjà la clé** : aucune information
exploitable ne fuit. Refuser cette distinction rendrait le diagnostic impossible
pour l'utilisateur légitime sans rien apporter en sécurité. Les deux comportements
sont couverts par des tests dédiés.

### La règle exacte, après audit adversarial

Une première version de cette documentation affirmait que « toute altération de slot
produit `UnlockFailed` ». L'audit de la phase 1 a montré que c'était faux :

| Altération | Erreur | Dépend du mot de passe ? |
|---|---|---|
| viole un invariant structurel | erreur de format explicite | **non** |
| préserve la structure | `UnlockFailed` | **non** |
| slot ouvert, payload altéré | `Corrupted` | oui — la clé est requise |

Ce qui protège n'est pas l'uniformité des messages, c'est que **aucun message ne
dépende de la valeur du mot de passe**. Un fichier que l'attaquant a lui-même
modifié peut bien signaler une incohérence structurelle : cela ne lui apprend rien
sur le secret.

### Ce qui n'est pas protégé

Il n'existe **aucune limitation du nombre de tentatives de déverrouillage**. Une
application qui réessaierait automatiquement en boucle consommerait un temps CPU
proportionnel au nombre d'essais. Ce n'est pas une faiblesse cryptographique — le
KDF fait exactement son travail — mais c'est un levier de déni de service local, à
traiter côté interface. Consigné comme risque résiduel.

## 9. Sources

* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
* [RFC 8439 — ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
* [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
* [Bitwarden — Encryption Key Derivation](https://bitwarden.com/help/kdf-algorithms/)
