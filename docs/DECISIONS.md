# Journal des décisions

Chaque décision structurante est consignée avec le raisonnement qui l'a motivée et,
lorsqu'elle a été **annulée en cours de route**, la raison de l'annulation. Les
décisions revues sont signalées **[RÉVISÉE]** : une conception qui ne montre que ses
conclusions cache précisément ce qui a été appris.

Gabarit, repris de la règle de conception du projet : *quel problème · quelle menace
réduite · quelle complexité ajoutée · quel compromis · quelle alternative plus
simple · quelle conséquence si mal implémenté*.

---

## ADR-001 — Rust comme langage du cœur

**Statut :** accepté

**Problème.** Il faut un langage où l'effacement du matériel de clé soit réellement
exprimable, où le cycle de vie des buffers soit vérifiable à la compilation, et où le
binaire soit distribuable sans chaîne d'exécution lourde.

**Menace réduite.** T16 (lecture de mémoire), T20 (fuites par les journaux), T22
(fichiers temporaires). Surtout : la classe entière des erreurs de gestion mémoire,
qui est la première cause de vulnérabilités graves dans un logiciel de sécurité.

**Complexité ajoutée.** Courbe d'apprentissage, temps de compilation, nécessité
d'isoler le code système dans un crate séparé.

**Compromis.** On accepte un développement plus lent contre des garanties de
compilation.

**Alternatives.** Go : le ramasse-miettes rend l'effacement non fiable et les chaînes
sont immuables, ce qui contredit directement une exigence centrale du projet. C# :
`SecureString` est déconseillé par Microsoft lui-même ; la distribution du runtime
est lourde. Python et PHP : aucune garantie de cycle de vie mémoire, distribution
difficile.

**Si mal implémenté.** Le risque principal serait de croire que « Rust » suffit. Il
ne suffit pas : `zeroize` reste nécessaire, `unsafe` doit être isolé, et
`#![forbid(unsafe_code)]` doit être posé sur le crate concerné — ce qui est fait.

---

## ADR-002 — Architecture monolithique plutôt que chiffrement page par page

**Statut :** accepté

**Problème.** Où vit le coffre déverrouillé, et comment est-il écrit ?

**Menace réduite.** T3 (accès disque), T8 (modification), T9 (corruption), T29
(corruption de base). Mais la motivation principale est la **réduction du code
cryptographique** : ~400 lignes contre ~900, et un seul nonce par écriture contre un
nonce par page.

**Complexité ajoutée.** Une écriture est proportionnelle à la taille du coffre ; les
pièces jointes doivent être sorties du conteneur.

**Compromis.** On paye un coût d'écriture négligeable sur quelques mégaoctets pour
supprimer une classe de bugs silencieusement catastrophiques (réutilisation de nonce
en AES-GCM).

**Alternatives.** Chiffrement page à page (SQLCipher) : fuite de structure (nombre de
lignes, schéma, motifs d'accès), perte de contrôle du cycle de vie du clair, arbre de
hachage à concevoir. Conteneur segmenté avec journal : ~1 500 lignes de code
cryptographique.

**Si mal implémenté.** Le risque propre à ce choix est la perte du contenu entier en
cas de corruption. Il est traité par l'écriture atomique et par l'exigence de
sauvegardes testées (phase 4).

---

## ADR-003 — DEK distincte et enveloppe de clé à plusieurs slots

**Statut :** accepté, **justification révisée**

**Problème.** Comment changer le mot de passe maître, durcir les paramètres de
dérivation, ou ajouter un second facteur d'accès sans toucher aux données ?

**Menace réduite.** Réduit le risque opérationnel des migrations, et permet
(T31, récupération) sans créer de porte dérobée.

**Compromis.** Un niveau d'indirection supplémentaire : MK → KEK → DEK → sous-clés.

**Alternative plus simple.** Chiffrer directement avec la clé dérivée du mot de
passe. Rejetée : toute modification du mécanisme d'authentification deviendrait
solidaire du chiffrement de toutes les données.

**[RÉVISÉE] Une justification initiale était trop optimiste.** La conception
affirmait qu'une DEK rend le changement de mot de passe O(1). C'est **faux** dans
cette architecture, et l'implémentation l'a mis en évidence : le header entre dans
l'AAD du payload (ADR-005), donc changer un slot invalide le tag et **impose de
re-chiffrer le payload**. Le coût reste faible — un passage d'AEAD avec la même clé,
sans nouvelle dérivation — mais il est proportionnel à la taille du payload.

**Où le bénéfice est réel.** Les blobs de pièces jointes, chiffrés sous une clé
dérivée de la DEK, ne sont pas touchés du tout. Pour des données pouvant peser des
centaines de mégaoctets, l'opération est bien O(1). C'est là que la DEK paie.

**Leçon.** Une affirmation d'architecture non vérifiée par un test peut survivre
longtemps. L'invariant « la DEK est rigoureusement identique après un changement de
mot de passe » est désormais **testé**, et c'est le test qui a permis de repérer le
décalage entre la promesse et le comportement.

---

## ADR-004 — Aucune macro procédurale et aucune bibliothèque de sérialisation dans le cœur

**Statut :** accepté, **étendu en cours de route**

**Problème.** Comment minimiser la surface de chaîne d'approvisionnement du crate qui
manipule les clés ?

**Menace réduite.** Ad8 (compromission de dépendance). Les macros procédurales
s'exécutent **à la compilation, avec les privilèges du build**, et sont
statistiquement la partie la plus exposée de l'écosystème.

**Décisions prises, et mesures associées :**

| Écarté | Remplacé par | Effet |
|---|---|---|
| `thiserror` | `Display` et `Error` écrits à la main | retire un proc-macro |
| feature `derive` de `zeroize` | `Zeroizing<T>` et `Drop` manuels | retire un proc-macro |
| `ciborium` + `serde` | layout binaire à offsets fixes | retire 9 crates dont 2 proc-macros |

**[RÉVISÉE] `ciborium` a été retiré après avoir été retenu.** La conception initiale
prévoyait du CBOR pour le header, avec l'argument que RustCrypto et une bibliothèque
éprouvée valaient mieux qu'un format maison. L'examen des dépendances a montré que
`ciborium` entraînait `serde`, `serde_derive`, `syn`, `quote`, `proc-macro2`,
`half`, `zerocopy` et `zerocopy-derive`.

Le raisonnement décisif n'est pas le nombre de dépendances, c'est que **le header est
la seule donnée non fiable traitée avant toute authentification**. Un format à
offsets fixes supprime le parseur : plus de bombe de récurrence, plus de subtilité
d'encodage canonique, plus de parseur à fuzzer. On élimine la classe entière de bugs
sur le chemin le plus exposé du programme.

**Résultat mesuré** (`cargo tree -p passlock-core`) : `syn`, `quote`, `proc-macro2`,
`serde`, `zerocopy`, `half` et `ciborium` sont **absents** de l'arbre du cœur, qui se
réduit à RustCrypto plus `libc`.

**Complexité ajoutée.** Ajouter un champ au header exige d'incrémenter la version de
format. Accepté : tout ce qui évolue vite vit dans le payload chiffré.

**Compromis.** `clap` est utilisé **sans** sa feature `derive` dans la CLI, pour la
même raison. C'est un peu plus verbeux.

---

## ADR-005 — Le header entier entre dans l'AAD du payload

**Statut :** accepté

**Problème.** Comment rendre impossible l'abaissement des paramètres de dérivation
dans un fichier volé ?

**Menace réduite.** T4, T6 et T11 : un attaquant qui réduit `m_cost` dans le header
pour rendre le cassage hors ligne moins coûteux.

**Décision.** L'AAD du payload est l'intégralité des octets `0 .. 16 + header_len`.
Il n'existe donc **aucune donnée non authentifiée** dans le fichier.

**Compromis.** Toute modification d'un slot impose de re-chiffrer le payload (voir
ADR-003).

**Alternative plus simple.** Limiter l'AAD à la partie immuable du header. Rejetée :
elle laisserait un attaquant **supprimer un slot** — donc la voie de récupération de
l'utilisateur — sans que le tag s'en aperçoive. Chaque slot est bien authentifié par
son propre tag, mais l'ensemble ne l'était plus.

**Si mal implémenté.** Si l'AAD était calculé sur une reconstruction du header plutôt
que sur ses octets exacts, une différence d'encodage rendrait tout coffre
indéchiffrable. C'est pourquoi l'encodage est **déterministe par construction**, et
un test vérifie que deux encodages du même header sont identiques octet pour octet.

---

## ADR-006 — XChaCha20-Poly1305 plutôt qu'AES-256-GCM

**Statut :** accepté

**Problème.** Quel AEAD pour un format qui doit rester sûr pendant des années ?

**Menace réduite.** La réutilisation de nonce — défaillance **silencieuse** qui casse
simultanément la confidentialité et l'intégrité sous AES-GCM.

**Décision.** Nonce de 192 bits, tiré au hasard à chaque chiffrement. La probabilité
de collision reste de l'ordre de 2^-97 après 2^48 écritures sous la même clé, ce qui
supprime le besoin d'un compteur persistant — donc d'un état supplémentaire à
maintenir correctement.

**Compromis.** Performance inférieure là où AES-NI est disponible. Écart réel, sans
conséquence pour quelques écritures par minute.

**Alternative.** AES-256-GCM avec nonce aléatoire de 96 bits : utilisable, mais la
borne du paradoxe des anniversaires (2^32 messages) est atteinte bien plus tôt qu'on
ne l'imagine, et y parvenir casse tout silencieusement.

**Décision secondaire :** AES-GCM n'est **pas** proposé en option. Exposer deux
algorithmes doublerait la surface de test et de maintenance sans bénéfice. Le champ
`payload_alg` existe pour permettre un ajout futur, mais l'ajouter sans besoin est du
coût pur.

---

## ADR-007 — Argon2id au-dessus des minima OWASP

**Statut :** accepté

**Problème.** Quels paramètres de dérivation ?

**Décision.** Profil standard : **256 Mio, t=3, p=4**. Les minima OWASP (19 Mio,
t=2, p=1) sont pour une **authentification serveur**, où le coût est payé à chaque
connexion pour des millions d'utilisateurs. Ici le coût est payé une fois par session,
sur un seul coffre : le budget de latence disponible est sans commune mesure. Mesure
réelle sur la machine de développement : **0,78 s** en binaire release.

*(La justification complète, référence par référence, et les mesures des trois
profils sont dans `docs/CRYPTO.md` §3.)*

**Compromis.** Un déverrouillage de 0,78 s au lieu de ~0,05 s. Accepté.

**Si mal implémenté.** Deux pièges, tous deux traités :

* le fichier peut annoncer des paramètres hostiles (4 Gio) pour provoquer un déni de
  service → plafond absolu vérifié **avant toute allocation** ;
* une allocation qui échoue en Rust déclenche un `abort` → utilisation de
  `try_reserve_exact` pour obtenir une erreur exploitable.

---

## ADR-008 — Sentinelle anti-retour-en-arrière : alerte, jamais blocage

**Statut :** accepté, **avec limites explicitement reconnues**

**Problème.** Détecter qu'un coffre a reculé par rapport au dernier état connu, sans
transformer une restauration légitime en perte de données.

**Menace réduite.** T10, T11.

**Décision.** Un compteur de génération **à l'intérieur du payload chiffré** (donc
inforgeable sans la clé), comparé à une sentinelle HMAC conservée dans le répertoire
de configuration — **délibérément pas à côté du coffre**, sinon un attaquant écrivant
le coffre écrirait la sentinelle du même geste. Une régression déclenche une alerte
détaillée ; on n'empêche jamais l'ouverture.

**Limite, reconnue et documentée.** Contournable par un attaquant qui écrit dans les
deux emplacements. La seule protection complète exigerait un compteur monotone
matériel (TPM) ou un journal en ajout seul sur un support distinct. **Ni l'un ni
l'autre n'est implémenté.** L'interface doit donc dire « détection **partielle** ».

**Pourquoi ne pas bloquer.** Un blocage dur sur une restauration après sinistre
détruirait la seule copie exploitable. On alerte, on explique les conséquences
concrètes (des entrées supprimées peuvent réapparaître, un ancien mot de passe peut
redevenir valide), l'utilisateur décide en connaissance de cause.

**Le nom du fichier ne contient pas celui du coffre** : il est dérivé par HMAC de
l'identifiant du coffre avec `K_index`, donc non dérivable sans la clé. Corollaire
assumé : la détection a lieu **après** le déverrouillage.

---

## ADR-009 — **[RETIRÉE]** Valeur de contrôle de clé

**Statut :** retirée avant implémentation complète

**Décision initiale.** Publier `HKDF(DEK, "passlock/v1/keycheck")` tronquée à 8
octets, pour permettre de vérifier qu'une clé de récupération correspond bien à **ce**
coffre.

**Pourquoi elle a été retirée.** Aucun de ses usages envisagés ne survit à l'examen :

| Usage envisagé | Déjà couvert par |
|---|---|
| Vérifier qu'une clé de récupération correspond au coffre | le succès du désenveloppement du slot |
| Vérifier qu'une sauvegarde vient du même coffre | `vault_id`, qui est public |
| Vérifier qu'un changement de mot de passe a conservé la DEK | comparaison directe des DEK en mémoire |

La conserver aurait publié une valeur dérivée de la DEK permettant de tester une DEK
candidate. Cet oracle est inexploitable en pratique — la DEK est aléatoire sur
256 bits, un attaquant ne peut pas en produire une candidate — mais **un oracle
inutile reste un oracle inutile**, et la surface n'a aucune raison de le contenir.

**Leçon.** Une fonctionnalité prévue dans une conception doit être justifiée au
moment où on l'implémente, pas au moment où on la conçoit. Ici, l'examen a montré
qu'elle ne servait à rien.

---

## ADR-010 — **[REJETÉE]** Vérification des fuites par API réseau

**Statut :** rejetée

**Demande.** Vérifier si les mots de passe stockés apparaissent dans des fuites
connues, via l'API k-anonymat d'un service public (envoi des 5 premiers caractères
hexadécimaux du SHA-1).

**Pourquoi rejetée.**

* L'API reçoit 20 bits d'un condensé du mot de passe, ainsi que l'adresse IP et
  l'horodatage. Ce n'est pas une révélation directe, mais **c'est une fuite** : la
  séquence des préfixes interrogés, corrélée dans le temps, révèle quels mots de
  passe vous détenez et à quel rythme.
* Cela casse la propriété « aucune donnée ne quitte la machine » pour un gain
  modeste : la vérification ne détecte que les fuites **déjà connues** du tiers.
* **Décision :** fonctionnalité **absente**, pas seulement désactivée. Une
  fonctionnalité désactivée peut être réactivée par un utilisateur n'ayant pas lu
  l'avertissement ; une fonctionnalité absente ne le peut pas.

**Alternative retenue.** Import d'une liste de fuites téléchargée manuellement
**hors de l'application**, et vérification 100 % locale sur des index aveugles.
Meilleure confidentialité, coût disque élevé. Option avancée, hors du chemin par
défaut.

---

## ADR-011 — **[REJETÉE]** Coffre leurre

**Statut :** rejetée

**Demande.** Un second coffre « leurre », pour offrir une dénégation plausible sous
contrainte.

**Pourquoi rejetée.**

1. **Elle ne protège pas contre la coercition.** Qui peut vous forcer à révéler une
   phrase de passe peut vous forcer à révéler la seconde. La dénégation ne
   fonctionne que si l'existence du vrai coffre est indétectable — impossible : le
   header contient un nombre de slots **authentifié**, et la taille du payload est
   observable.
2. **Elle est dangereuse pour l'utilisateur.** Présentée comme une protection, elle
   encourage à placer de vrais secrets dans un conteneur qui n'est pas conçu pour
   résister à l'analyse.
3. **Coût élevé** : deux jeux de données, deux ensembles de slots, surface de test
   doublée.

**Alternative honnête retenue.** La **compartimentation réelle** : deux coffres
distincts avec deux phrases de passe distinctes. L'existence du second n'est pas
niée, mais le vol d'une phrase de passe ne donne pas accès à tout. C'est un bénéfice
de sécurité réel, sans illusion — et cela ne demande **aucun code spécifique**, un
coffre étant déjà un fichier indépendant.

---

## ADR-012 — **[REJETÉE]** Intégration navigateur et remplissage automatique

**Statut :** rejetée pour la phase 1

**Pourquoi.** C'est la fonctionnalité la plus demandée et la plus dangereuse :

* elle expose une interface de remplissage à l'environnement **le moins fiable** du
  système (extensions, pages, cadres imbriqués) ;
* elle exige un canal de communication qui devient la **nouvelle surface réseau** du
  coffre et casse la propriété « le coffre n'écoute nulle part » ;
* le remplissage sur le mauvais domaine est un vecteur d'hameçonnage direct.

**Conséquence.** Hors périmètre, consignée dans `THREAT_MODEL.md` §6 (« scénarios
hors périmètre »). C'est un choix, pas un oubli.

---

## ADR-013 — **[REJETÉE]** Téléchargement de favicons

**Statut :** rejetée

**Pourquoi.** Télécharger une icône signifie émettre une requête vers le domaine (ou
vers un service tiers) pour **chaque** entrée du coffre. Effet net : publication de
la liste complète de vos comptes à votre fournisseur DNS, à tout observateur réseau,
et éventuellement au tiers. Fuite de métadonnées majeure pour un gain purement
cosmétique.

**Alternative retenue.** Jeux d'icônes locaux, choix manuel par l'utilisateur, ou
icône dérivée du domaine sans aucun accès réseau.

---

## ADR-014 — **[REJETÉE]** Compression du payload

**Statut :** rejetée pour la version 1 du format

**Pourquoi.** Ajoute une dépendance de décompression **et** une surface d'attaque
(bombe de décompression) pour un gain modeste sur des données majoritairement
textuelles. Aucun champ de compression n'existe dans le format : ce qui n'est pas
implémenté ne peut pas être mal configuré.

---

## ADR-015 — Paramètres de test au plancher de validation

**Statut :** accepté, après un problème mesuré

**Problème.** La suite de tests a été mesurée à **685 secondes**. Diagnostic établi
par la mesure, pas par intuition :

1. le profil `dev` (non optimisé) rend Argon2id **~21 fois plus lent** qu'en release
   — mesuré : ~3,3 s contre ~0,155 s pour une dérivation à 64 Mio, t=3, p=2 ;
2. deux tests appelaient `Vault::open` **une fois par octet muté**, soit environ 468
   dérivations complètes.

**Ce qui n'a PAS été fait.** Les paramètres **livrés** n'ont pas été affaiblis. Le
défaut reste `standard()` (256 Mio, t=3, p=4). Une instruction explicite interdisait
de toucher aux paramètres cryptographiques pour accélérer les tests, et cette
instruction est respectée : `KdfParams::default()` retourne toujours le profil durci.

**Ce qui a été fait.**

* Les tests utilisent le **plancher de validation** (8 Mio, t=1, p=1). Les paramètres
  de dérivation sont des **entrées** de fonction, pas des branches : le chemin de
  code parcouru est rigoureusement identique. Aucune couverture n'est perdue, et les
  tests qui portent **spécifiquement** sur la valeur des paramètres construisent
  explicitement leurs propres valeurs sans effectuer de dérivation.
* La dérivation est **sortie des boucles** de mutation. Argon2id est une fonction
  pure de `(mot de passe, sel, paramètres)` : la recalculer ne teste rien de plus sur
  l'octet muté. Ce changement a nécessité d'extraire `derive_master_kek` et
  `unlock_with_kek` — une séparation qui a de la valeur en soi, puisqu'elle marque la
  frontière entre « obtenir une clé » et « ouvrir avec elle », et servira de point
  d'insertion aux futurs mécanismes d'ouverture (clé de récupération, clé matérielle).

**Résultat mesuré : 685 s → 2,41 s** (facteur ≈ 270), sans modification d'un seul
paramètre livré.

**Leçon.** Un test lent est un test qui sera désactivé. Mais la réponse correcte était
de corriger la **stratégie de test**, pas les valeurs de sécurité — et il a fallu
mesurer pour savoir laquelle des deux causes dominait.

---

## ADR-016 — Divergences assumées entre Unix et Windows

**Statut :** accepté, **avec une limite majeure reconnue**

**Problème.** Plusieurs primitives de durcissement n'ont pas d'équivalent Windows
utilisable sans privilèges.

| Mesure | Unix | Windows |
|---|---|---|
| Verrouillage mémoire | `mlock` | `VirtualLock` |
| Exclusion des vidages | `MADV_DONTDUMP` | **non supporté** (passe par WER, donc par le registre) |
| Vidages désactivés | `RLIMIT_CORE = 0` | **non supporté** sans privilèges |
| Restriction de `ptrace` | `PR_SET_DUMPABLE = 0` | **non supporté** (régit par la DACL) |
| Permissions | mode `0600` | **vérification non implémentée** (DACL) |

**Décision.** Ne pas demander de privilèges pour autant (le projet n'en demande
aucun), et **signaler chaque mesure non appliquée** à l'utilisateur plutôt que de la
taire. Une protection silencieusement absente est pire qu'une protection absente
annoncée : elle fausse le jugement de l'utilisateur sur son propre risque.

**Limite majeure.** Le backend Windows **n'a jamais été compilé ni exécuté** :
l'environnement de développement est WSL2 sans cible Windows installée. La surface
FFI a été volontairement réduite à quatre appels pour limiter le risque d'y
introduire une erreur silencieuse, mais elle reste **non vérifiée**. Consigné comme
limite L9 dans `SECURITY.md`.

> **Mise à jour postérieure à cet ADR.** La cible `x86_64-pc-windows-msvc` est
> désormais installée, et l'espace de travail **compile** pour Windows, cibles de test
> comprises. Cette compilation a immédiatement révélé **deux erreurs réelles** qui
> auraient été livrées : un import `io` dupliqué et une implémentation de `Debug`
> référençant un champ renommé. En revanche, **l'exécution reste non observée** — ni
> Wine, ni MinGW, ni linker MSVC dans l'environnement. La distinction entre compiler
> et exécuter doit être maintenue : c'est elle qui rend la limite L9 exacte. Détail
> dans `SECURITY.md` §4.3.

---

## ADR-018 — Liste blanche de licences minimale, et faux positif des jokers

**Statut :** accepté, après exécution réelle de l'outil

**Problème.** `deny.toml` avait été écrit, mais `cargo-deny` n'était pas installé :
la politique de chaîne d'approvisionnement était donc **affirmée sans être
vérifiée**. Après installation et première exécution, deux problèmes réels sont
apparus — plus un résultat positif.

**Ce que la première exécution a révélé.**

1. `severity-threshold` est une clé supprimée dans cargo-deny 0.20 : la
   configuration entière était refusée. Sans exécution, le fichier aurait été cru
   fonctionnel.
2. **Cinq licences de la liste blanche n'étaient utilisées par aucune dépendance**
   (ISC, Unicode-3.0, Zlib, CC0-1.0, BSD-2-Clause, Apache-2.0 WITH
   LLVM-exception). Elles y étaient « au cas où ».
3. Les dépendances de l'espace de travail écrites `{ workspace = true }` étaient
   signalées comme des **jokers**, alors que ce sont des dépendances de chemin
   internes au dépôt.

**Décision.**

* La liste blanche est ramenée aux **trois licences réellement présentes** : MIT,
  Apache-2.0, BSD-3-Clause. `unused-allowed-license = "deny"` garantit qu'elle le
  reste.
* `allow-wildcard-paths = true` lève le faux positif sur les dépendances de chemin.

**Pourquoi la liste minimale est la bonne politique.** Une liste d'autorisation qui
contient des entrées « au cas où » autorise **silencieusement** des dépendances
futures qui n'ont jamais été examinées. Rendre l'ajout d'une licence obligatoire
transforme un effet de bord en décision consciente — ce qui est exactement le but
d'une politique de chaîne d'approvisionnement.

**Compromis assumé.** Ajouter une dépendance sous une nouvelle licence fera échouer
la vérification jusqu'à ce que la liste soit modifiée. C'est le comportement voulu,
mais cela demande une modification de fichier là où d'autres projets préfèrent la
souplesse.

**Résultat après correction :** `advisories ok, bans ok, licenses ok, sources ok`.

**Leçon.** Une configuration jamais exécutée est une configuration supposée. Les
trois problèmes ci-dessus étaient invisibles à la relecture : deux n'apparaissent
que lorsque l'outil tourne, et le troisième inverse une conclusion intuitive (on
croit qu'une liste de licences large est prudente ; elle est en réalité permissive).

---

## ADR-019 — Licence MIT plutôt que double MIT/Apache-2.0

**Statut :** accepté, après revue

**Décision initiale.** Double licence MIT OR Apache-2.0, convention de l'écosystème
Rust.

**Pourquoi changée.** Je ne peux pas reproduire fidèlement le texte complet de la
licence Apache-2.0 sans risque d'erreur, et un texte de licence inexact est **pire
qu'une licence unique correcte** : il créerait une ambiguïté juridique sur un projet
dont l'objet même est la confiance. Le choix retenu est donc MIT **seul**, avec un
texte complet et exact.

**Conséquence.** Perte de la clause de brevets d'Apache-2.0. À reconsidérer si le
projet est un jour distribué largement : la solution serait alors de récupérer le
texte officiel depuis une source faisant autorité plutôt que de l'écrire de mémoire.

---

## ADR-020 — Abandon de SQLite au profit d'un magasin purement Rust

**Statut :** accepté, **révise l'ADR-002**

**Décision antérieure.** La phase 1 actait « SQLite en mémoire, sérialisé dans le
payload », justifié par la recherche FTS5 et les transactions.

**Ce que l'examen de la phase 2 a montré.** Aucune des quatre raisons ne tient dans
*ce* système :

| Ce que SQLite apporte | Notre situation |
|---|---|
| Transactions | L'écriture du conteneur est **déjà** tout-ou-rien ; la granularité « un `save()` » suffit |
| Concurrence multi-processus | Mono-processus sous verrou exclusif, base en mémoire |
| Planificateur de requêtes | Moins de 10 000 entrées : un parcours linéaire est instantané |
| Intégrité | Le tag AEAD couvre l'intégralité du payload |
| Recherche FTS5 | **Abandonnée comme choix de sécurité** (voir ci-dessous) |
| Durabilité | Assurée par l'écriture atomique du conteneur |

**Ce que SQLite coûtait.**

1. **Un cache de pages opaque, ineffaçable** — c'était la limite **L6** de
   `SECURITY.md`, documentée en phase 1 comme un défaut d'hygiène mémoire assumé.
   L'abandon **fait disparaître L6** : tout buffer déchiffré redevient un buffer que
   nous possédons et savons effacer. C'est le gain de sécurité principal de cette
   décision.
2. **La dernière dépendance C du projet.** `passlock-core` est désormais du Rust pur :
   plus de `libsqlite3-sys`, plus de code C compilé à la construction.
3. **Une surface d'injection** : l'opérateur `MATCH` de FTS5 a sa propre syntaxe, et
   l'audit de phase 1 avait consigné qu'un utilisateur tapant `"` ou `NEAR(` casserait
   la requête. La recherche en Rust supprime la question — il n'y a plus de langage de
   requête du tout.

**Compromis assumé.** Plus de code de sérialisation à écrire, à borner et à fuzzer.
C'est un coût réel, mais **borné et testable**, contrairement au cache de pages d'une
bibliothèque C.

**Ce qui a été fait pour maîtriser ce coût.** Un module `bytes.rs` centralise toutes
les lectures, avec l'invariant « aucune allocation dimensionnée par une valeur non
vérifiée ». Un harnais adversarial dédié (10 tests, 20 000 mutations) vérifie que tout
ce qui est accepté est ré-encodé à l'identique.

**Gain annexe, mesuré.** Les nouveaux modules étant en Rust pur et sans FFI, **Miri
les couvre** : il échouait en phase 1 sur `mlock` et `getrandom`. La couverture Miri
passe de 41 tests à 100, dont les décodeurs qui traitent des données non fiables.

---

## ADR-021 — Rétention de l'historique : 50 révisions ou 90 jours

**Statut :** accepté

**Problème.** Un historique versionné conserve des secrets que l'utilisateur croit
supprimés. Le cahier des charges l'avait identifié explicitement.

**Pourquoi ne pas conserver indéfiniment.** L'historique illimité garantit de ne rien
perdre, mais conserve **indéfiniment des identifiants révoqués** — y compris ceux
qu'on a changés précisément parce qu'ils avaient fuité. C'est le cas où la
fonctionnalité de confort devient le vecteur de rétention.

**Pourquoi ne pas désactiver par défaut.** Une modification accidentelle deviendrait
irréversible, et l'utilisateur n'a aucun moyen de la rattraper.

**Décision.** 50 révisions ou 90 jours, la plus contraignante l'emportant. Assez pour
rattraper une erreur récente, borné pour ne pas conserver indéfiniment.

**Ce qui accompagne la décision, et qui compte davantage que le chiffre.** La
politique est **affichée**, la purge est **explicite** et consignée au journal, et ses
limites sont énoncées : purger n'a **aucun effet sur les sauvegardes déjà écrites**.
Un utilisateur qui croit avoir supprimé un secret doit savoir où il subsiste.

---

## ADR-022 — Recherche sans index persistant

**Statut :** accepté

**Décision.** Aucun index n'est stocké : chaque requête parcourt l'archive déchiffrée.

**Pourquoi.** Un index persistant introduirait trois défauts pour aucun bénéfice à
cette échelle : une **désynchronisation** possible entre l'index et les données, une
**double mémoire** (l'index recopie des secrets hors des entrées), et une **surface
d'injection** dès que l'index apporte son propre langage de requête.

**Conséquence directe : la requête n'est pas un langage.** Le texte est une
sous-chaîne littérale, découpée en termes dont **tous** doivent apparaître. Les
métacaractères sont des caractères comme les autres — il n'y a rien à échapper, donc
rien à injecter. Un test vérifie que `".*"`, `"\"`, `"\" OR 1=1 --"`, `"NEAR("` et
`U+202E` sont traités comme du texte.

**Compromis.** Un parcours linéaire est O(n) par requête. Mesuré : quelques milliers
d'entrées restent instantanées. Un index serait une **optimisation**, à ajouter si un
coffre réel le justifiait — pas une exigence de conception.

---

## ADR-023 — Quelles opérations sont idempotentes, et pourquoi

**Statut :** accepté, tranché par l'audit sémantique

**Problème.** La répétition d'une opération doit-elle converger ou produire un effet
cumulatif ? La question n'avait jamais été posée explicitement : le comportement
résultait de l'implémentation plutôt que d'une décision.

**Ce qui doit converger.** `trash_entry`, `restore_entry`, `purge_history`,
`empty_trash` : elles mènent à un **état**, et le répéter ne change rien. C'est ce qui
rend une reprise après incident possible — réémettre une opération interrompue doit
être sûr.

**Ce qui ne doit pas converger.** `update_entry` : deux appels sont **deux
modifications**, donc deux révisions. Rendre l'opération idempotente perdrait une
modification légitime. `add_*` : chaque appel crée un objet neuf.

**L'asymétrie `trash` / `purge`, délibérée.** `purge_entry` sur une entrée **absente**
échoue, alors que `trash_entry` sur une entrée déjà à la corbeille réussit.
Justification : `trash` est réversible, `purge` ne l'est pas. Signaler que la cible
n'existe pas indique qu'aucune suppression n'a eu lieu, donc que l'identifiant visé
n'était probablement pas le bon.

**Alternative examinée et écartée.** Faire réussir `purge` sur une cible absente
simplifierait la reprise automatique, au prix de masquer une erreur de cible sur une
opération **irréversible**. Le compromis a été tranché en faveur du signal, et il est
désormais écrit plutôt que subi.

---

## ADR-024 — TOTP sur `hmac` + `sha1`/`sha2`, plutôt que `totp-rs`

**Statut :** accepté

**Problème.** Faut-il dépendre d'une bibliothèque TOTP, ou implémenter HOTP et TOTP
sur les primitives déjà présentes ?

**Décision.** Implémenter sur `hmac` + `sha1`/`sha2`.

**Motif.** `hmac` et `sha2` étaient **déjà** des dépendances du cœur pour la
sentinnelle anti-rollback. La RFC 4226/6238 est un **assemblage** sur HMAC, pas une
primitive cryptographique : quarante lignes entièrement déterminées par des vecteurs
de test officiels. `totp-rs` apporterait `url`, `percent-encoding`, `base32`,
`qrcodegen` et `rand`, dont une fraction serait utilisée, et dont l'arbre devrait être
audité.

**Ce qui rend la décision défendable.** L'implémentation n'est pas « faite maison » au
sens où elle échapperait à la vérification : les **10 vecteurs de la RFC 4226
appendice D** et les **18 vecteurs de la RFC 6238 appendice B** sont reproduits
verbatim et exécutés. C'est une preuve plus forte qu'un test écrit à partir de la même
compréhension que le code.

**Coût.** Une dépendance ajoutée : `sha1 0.11.0` (RustCrypto, `MIT OR Apache-2.0`),
qui partage `digest 0.11.3` déjà présent dans l'arbre — aucune dépendance transitive
nouvelle.

**Ce que cela n'autorise pas.** Une construction cryptographique *nouvelle* devrait
être refusée. HOTP et TOTP ne sont pas nouvelles : elles sont normalisées, et leurs
vecteurs sont publics.

---

## ADR-025 — L'URI `otpauth://` comme format de stockage

**Statut :** accepté

**Problème.** Comment stocker un secret TOTP sans modifier le format de coffre ?

**Décision.** La valeur d'un `Field` de type `FieldKind::Totp` contient l'URI
`otpauth://` complète.

**Motif.** `FieldKind::Totp` existe depuis la phase 2 (`to_u8 = 6`, masqué par
défaut, `concealed` imposé par `Field::new`). **Aucun octet de format n'est modifié**,
donc aucune montée de version, aucune migration, aucune fenêtre de compatibilité.

L'URI est le format d'échange de fait, ce qui rend l'export (phase 4) trivial. Ses
paramètres voyagent avec le secret : les séparer risquerait de les désynchroniser.

**Coût assumé.** Le libellé et l'émetteur sont dupliqués entre le titre de l'entrée et
l'URI. Redondance mineure, préférée à un format non standard.

**Autre décision liée :** **aucune variante d'`AuditKind` n'est ajoutée**. `from_u8`
rejette tout octet inconnu, donc une variante nouvelle rendrait tout coffre écrit par
ce binaire illisible par l'ancien, ce qui exigerait une montée de version. Le gain
d'un journal « code TOTP consulté » est faible : un attaquant disposant d'un coffre
déverrouillé a déjà tout.

---

## ADR-026 — L'entropie est calculée, jamais estimée

**Statut :** accepté

**Problème.** Comment annoncer la robustesse d'un secret engendré ?

**Décision.** Calculer `log₂(|espace|)` exactement. **Refuser** toute estimation en
durée de cassage.

**Motif — pourquoi pas d'estimateur de robustesse.** Les estimateurs du type zxcvbn
sont calibrés sur des mots de passe **choisis par des humains** : leurs modèles
détectent des motifs, des mots de dictionnaire, des dates. Une sortie uniforme n'en
contient aucun par construction, et leur score ne décrit donc pas la bonne chose.
Pire, il **masquerait** le seul chiffre exact : un estimateur répondant « excellent »
à un mot de passe de 12 bits imposerait une confiance injustifiée.

**Motif — pourquoi aucune durée.** Une estimation en temps exige des hypothèses sur le
matériel de l'attaquant : nombre d'essais par seconde, coût, parallélisation. Ce projet
ne peut pas les vérifier. Un chiffre inventé dans un gestionnaire de mots de passe est
un mensonge aux conséquences réelles. Le projet rend un **fait arithmétique** et une
**politique assumée** ; la conversion en temps n'est pas faite et ne le sera pas.

**Représentation.** Trois éléments ensemble : le nombre de bits (arrondi **vers le
bas**, jamais vers le haut), le nombre de possibilités sous forme `2^n`, et une bande
qualitative dont les seuils (< 64, 64–79, 80–127, ≥ 128 bits) sont **une politique**,
pas une mesure.

**Réserve obligatoire.** `H = longueur × log₂(|alphabet|)` n'est vraie que si le tirage
est uniforme, ce qui suppose un CSPRNG non compromis. Le chiffre est donc une propriété
**de conception**, et l'hypothèse est rappelée **à chaque affichage** — un nombre de
bits présenté sans son hypothèse se lit comme une garantie.

---

## ADR-027 — Contraintes par rejet de chaîne entière

**Statut :** accepté

**Problème.** Un site exige « au moins un chiffre et un symbole ». Comment satisfaire
la contrainte sans réduire l'entropie au-delà du nécessaire ?

**Décision.** Tirer uniformément sur l'alphabet complet, et **rejeter la chaîne
entière** si elle ne satisfait pas la contrainte.

**Méthode écartée, et pourquoi.** L'implémentation courante consiste à générer puis à
**remplacer** un caractère au hasard pour satisfaire la contrainte. Elle est
**doublement fautive** : elle réduit la taille de l'espace réel, et elle rend la
position du caractère substituté légèrement plus probable, donc partiellement
devinable. Elle est répandue parce qu'elle est simple à écrire.

**Ce que la méthode retenue garantit.** Le résultat est uniforme sur l'ensemble des
chaînes satisfaisantes — pas « à peu près », exactement — et aucun caractère n'a de
position privilégiée.

**Le coût est compté, pas caché.** Il est calculé exactement par une programmation
dynamique sur des probabilités (compteurs écrêtés au minimum requis), ce qui évite
tout débordement : `94^1024 ≈ 10^2019`. Le terme `log₂(P)` est négatif et **affiché**.

**Refus.** Au-delà d'un budget de tirages, la génération **échoue** avec un message
explicite plutôt que de boucler. Une contrainte insatisfaisable est refusée **avant**
toute tentative.

**Ce qui n'est pas supporté.** Les contraintes de *forme* (« ne doit pas commencer par
un chiffre », « pas plus de deux caractères identiques ») : leur comptage exact n'est
pas fermé, et une entropie **approximative** est pire qu'une entropie **absente**. Le
générateur refuse la contrainte au lieu de surestimer.

---

## ADR-028 — Pas de casse aléatoire, pas de chiffres aléatoires dans les phrases

**Statut :** accepté

**Problème.** Faut-il « renforcer » une phrase de passe en capitalisant un mot au
hasard ou en insérant un chiffre ?

**Décision.** Non. Ces transformations sont refusées.

**Motif.** Le gain d'entropie est faible au regard d'un mot supplémentaire, et surtout
elles rendent l'entropie annoncée **inexacte**. La casse d'un mot est ambiguë : une
liste contenant `chat` et `Chat` produit un espace dont le décompte dépend du schéma
de capitalisation appliqué, ce qui n'est plus `W^n`. Un mot de plus vaut mieux, et se
calcule exactement.

**Séparateur.** Par défaut, une constante publique, qui n'apporte **aucun** bit — et
la sortie le dit explicitement. `--random-separator` est offert, et alors
`log₂(nombre de séparateurs)` est **ajouté** au total.

#### Défaut trouvé après coup : le séparateur doit être absent des mots

Le séparateur traditionnel est le tiret (`-`), et c'était le premier choix. Il est
**faux pour ces listes**, et le défaut a été trouvé en exécutant la suite de tests :
une phrase engendrée contenait `felt-tip` et se découpait en **sept** fragments au
lieu de six.

La liste EFF contient `drop-down`, `felt-tip`, `t-shirt` et `yo-yo` ; la liste
française contient `-`, `--`, `---`, `:-(` et `:-)`.

**Pourquoi c'est un défaut et pas une coquetterie.** Avec un séparateur présent dans
les mots, la concaténation est **ambiguë** : `[a-b, c, d]` et `[a, b-c, d]` produisent
la même chaîne. Le nombre de sorties **distinctes** devient donc strictement inférieur
à `Wⁿ`, et `n × log₂(W)` **surestime** l'entropie réelle. C'est exactement le type de
surestimation que l'ADR-026 interdit.

**Correction.** Le séparateur par défaut devient `.`, **absent des deux listes
embarquées**, ce qui rend la découpe inversible et l'entropie exacte. Un séparateur
fourni qui apparaîtrait dans un mot est **refusé** avec un message explicite, jamais
accepté avec une entropie approximative. Le mode aléatoire **filtre** la liste de
séparateurs dans le même but, et le nombre retenu entre dans le calcul des bits.

**Leçon retenue.** Le défaut était invisible à la lecture : il ne se manifeste qu'une
fois sur quelques centaines de tirages, quand un mot composé est tiré. Deux tests ont
été ajoutés — le refus d'un séparateur ambigu, et l'absence du séparateur par défaut
dans les deux listes — ainsi qu'une vérification que le test d'origine ne dépend plus
du hasard.

**Tirage avec remise, conservé.** Un mot peut apparaître deux fois. Ce n'est pas un
oubli : l'ensemble des tirages **avec** remise compte `W^n` éléments, alors que
l'exclure donnerait `W × (W−1) × …`, **strictement plus petit**. Refuser les doublons
**réduirait** l'entropie, pour un gain purement esthétique.

---

## ADR-029 — Aucune vérification d'horloge en ligne

**Statut :** accepté

**Problème.** TOTP dépend de l'horloge. Faut-il la vérifier par le réseau ?

**Décision.** Non. Aucun appel réseau, aucun repli. Le décalage se corrige par un
réglage manuel borné, et le diagnostic par `--at`.

**Motif.** Le cœur n'a **aucune** dépendance réseau, et c'est une propriété de sécurité
établie en phase 1, pas une commodité. Une horloge réseau introduirait trois problèmes :
une fuite d'information (l'adresse du serveur consulté), une dépendance à un tiers, et
une **surface de falsification** — un serveur NTP menteur décalerait tous les codes.
Vérifier l'heure en ligne dans un gestionnaire hors ligne est une contradiction.

**Ce qui n'est pas revendiqué.** **Aucune détection de dérive n'est annoncée.** Un CLI
vit quelques millisecondes : comparer `Instant` et `SystemTime` sur cette durée ne
détecte rien d'utile. La comparaison a du sens dans une application longue (phase 6) et
sera conçue là.

**Limite écrite.** Si l'horloge système est fausse, les codes sont faux, et Passlock ne
peut pas le détecter. C'est une conséquence du rôle de **prouveur** : la RFC 6238 §6
confie la resynchronisation au **validateur**.

---

## ADR-030 — Refus du cache de codes, du trousseau système et du « déverrouillage TOTP »

**Statut :** accepté

**Problème.** Un code TOTP change toutes les 30 secondes, ce qui impose un
déverrouillage fréquent. Peut-on alléger cette contrainte ?

**Décision.** Non, sur trois points.

| Refus | Motif |
|---|---|
| **Cache de codes** entre invocations | Un code mis en cache est un secret qui survit à l'extinction du processus, dans un fichier que rien ne protège |
| **Secret TOTP dans le trousseau du système** | Placer le secret hors du coffre crée un **second chemin d'accès**, non protégé par le mot de passe maître : le coffre vaudrait alors son maillon le plus faible |
| **« Déverrouillage TOTP »** — produire un code sans mot de passe maître | Ferait du second facteur un moyen d'ouvrir le premier. Contradiction directe avec l'objet du produit |
| **Coffre TOTP séparé**, à chiffrement plus faible | Même raison, sous une autre forme |
| **Mode démon** gardant la DEK en mémoire | Élargit la fenêtre d'exposition de la clé maîtresse à la durée de vie de la machine, pour un confort marginal |

**Conséquence assumée.** Aucun code n'est produisible sans déverrouillage. Pour un site
demandant un code toutes les 30 s, cela impose un déverrouillage toutes les 30 s :
inconfortable, et correct. La lenteur d'Argon2id (256 Mio, ~0,78 s mesuré) est
précisément ce qui protège le coffre.

**Voie retenue pour le confort.** L'interface graphique (phase 6) maintiendra une
session déverrouillée en mémoire avec verrouillage automatique — et non un affaiblissement
du modèle.
