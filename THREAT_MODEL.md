# Modèle de menace — Passlock

> Ce document décrit **contre quoi** Passlock protège, **dans quelles conditions** et
> **avec quelles hypothèses**. Il décrit aussi ce contre quoi il ne protège pas.
>
> Toute affirmation de sécurité dans ce projet doit être lue avec ce document. Une
> phrase comme « c'est chiffré » n'a pas de sens sans préciser l'adversaire, le
> scénario et les hypothèses.

## 1. Actifs protégés

Par ordre de sensibilité décroissante.

| # | Actif | Où il vit | Persisté ? |
|---|---|---|---|
| A1 | Mot de passe maître | mémoire seule | **jamais** |
| A2 | DEK (clé de données) | mémoire + enveloppée dans le header | enveloppée |
| A3 | Secrets des entrées (mots de passe, TOTP, clés SSH, cartes) | payload chiffré | oui, chiffrés |
| A4 | Contenu des notes sécurisées | payload chiffré | oui, chiffré |
| A5 | Pièces jointes | blobs chiffrés séparés *(phase 4)* | oui, chiffrés |
| A6 | Métadonnées (titres, URLs, dossiers, dates d'entrée) | payload chiffré *(phase 2)* | oui, chiffrées |
| A7 | Fichier de coffre et sauvegardes | disque / support externe | oui, chiffré |
| A8 | Clé de récupération | **hors machine**, support physique | non (utilisateur) |
| A9 | Sentinelle anti-retour-en-arrière | répertoire de configuration | oui, authentifiée |
| A10 | Journal de sécurité | payload chiffré *(phase 2)* | oui, chiffré |

**Ce que le fichier de coffre révèle à qui le possède sans la clé**, exhaustivement :
la signature, la version de format, le nombre de slots, leurs rôles, leurs paramètres
de dérivation, leurs sels, la date de création, l'identifiant du coffre, et la taille
totale. **Rien d'autre.** Voir `VAULT_FORMAT.md`.

## 2. Adversaires

| # | Adversaire | Capacités supposées | Dans le périmètre ? |
|---|---|---|---|
| Ad1 | Voleur opportuniste de fichier | lit un fichier trouvé (partage, cloud, clé USB) | **oui** |
| Ad2 | Attaquant hors ligne sur GPU/ASIC | le fichier + un budget de calcul loué | **oui** |
| Ad3 | Malware local non privilégié | lit fichiers, surveille le presse-papiers, hooke les entrées | **partiellement** |
| Ad4 | Malware local privilégié / `root` / `Administrator` | tout, y compris `ptrace` et les vidages mémoire | **non** |
| Ad5 | Attaquant réseau | observe et altère le trafic | **sans objet** (aucun réseau) |
| Ad6 | Attaquant physique | accès au périphérique, durée variable | **partiellement** |
| Ad7 | Site ou annonce malveillant | contrôle une page, trompe l'utilisateur | **partiellement** (assistance) |
| Ad8 | Attaquant de chaîne d'approvisionnement | compromet une dépendance ou le build | **partiellement** (réduction) |
| Ad9 | Autre utilisateur local du même poste | lit les fichiers d'un autre compte | **oui** |
| Ad10 | L'utilisateur lui-même (erreur) | exporte en clair, copie au mauvais endroit, ignore une alerte | **oui** |

**Ad4 est hors de portée de toute défense logicielle.** C'est la limite fondamentale
de ce produit, et elle est affirmée ici plutôt que dissimulée.

## 3. Hypothèses

| # | Hypothèse | Si elle tombe |
|---|---|---|
| H1 | Le générateur aléatoire du noyau est correct et non compromis | effondrement total, aucun palliatif possible |
| H2 | Les implémentations RustCrypto d'Argon2id et de XChaCha20-Poly1305 sont correctes | effondrement total |
| H3 | Le système d'exploitation n'est pas compromis au moment du déverrouillage | équivaut à Ad4 |
| H4 | L'horloge système est approximativement juste | codes TOTP invalides (sans incidence sur le coffre) |
| H5 | L'utilisateur a choisi un mot de passe maître d'entropie suffisante | le KDF devient le seul rempart, et il ne peut pas compenser un secret devinable |
| H6 | L'utilisateur n'est pas sous contrainte physique | aucune résistance à la coercition |
| H7 | L'intégrité des binaires exécutés est celle attendue | Ad8 |

**H1 et H2 sont des hypothèses cryptographiques irréductibles.** Un gestionnaire de
mots de passe local ne peut ni vérifier la qualité du générateur du noyau ni
l'absence de porte dérobée dans une bibliothèque. Ce qu'on peut faire, et qui est
fait : choisir des bibliothèques largement auditées, éliminer les dépendances
superflues, verrouiller l'arbre par un `Cargo.lock`, et documenter explicitement la
dépendance. Prétendre le contraire serait malhonnête.

## 4. Table des menaces

Probabilités **qualitatives** sous H1–H7, pour un utilisateur desktop standard non
ciblé. Aucun chiffre de probabilité n'est avancé : il n'existe pas de données
permettant de les établir sérieusement, et en inventer donnerait une fausse
précision.

État : **F1**/**F2**/**F3** = traité respectivement en phase 1, 2 ou 3 (implémenté et
testé) · **F4.1** = livré à l'étape 1 de la phase 4 (récupération) · **F4**–**F7** =
prévu à la phase indiquée · **—** = hors périmètre ou non implémenté. Le contenu des
phases fait autorité dans [`ROADMAP.md`](ROADMAP.md).

| # | Menace | Impact | Prob. | Mesure défensive | Limite de la défense | État |
|---|---|---|---|---|---|---|
| T1 | Vol du fichier de coffre | Critique | Élevée | Argon2id memory-hard + AEAD authentifié | un mot de passe maître faible tombe malgré tout | **F1** |
| T2 | Copie des sauvegardes | Critique | Élevée | chiffrement de bout en bout ; une sauvegarde est une copie du fichier | une sauvegarde ancienne fige d'anciens paramètres KDF | **F1** |
| T3 | Accès disque sans l'application | Élevé | Moyenne | aucun secret en clair sur disque, aucun index clair, aucun cache | métadonnées du système de fichiers (taille, dates) visibles | **F1** |
| T4 | Force brute hors ligne | Critique | Élevée | Argon2id 256 Mio / t=3 / p=4 par défaut | repose entièrement sur l'entropie du mot de passe maître | **F1** |
| T5 | Attaque par dictionnaire | Critique | Élevée | idem T4 + avertissement d'entropie | un mot de passe « correct » mais devinable reste cassable | **F1** (mesure d'entropie : **F3**) |
| T6 | Attaques GPU/ASIC | Critique | Élevée | coût mémoire : chaque cœur d'attaque a besoin de 256 Mio → parallélisme plafonné par la mémoire | un attaquant disposant de beaucoup de mémoire reste efficace ; c'est un coût, pas un mur | **F1** |
| T7 | Corruption du coffre | Élevé (disponibilité) | Moyenne | tag AEAD ; écriture atomique ; sauvegardes | perte de données si aucune sauvegarde valide | **F1** |
| T8 | Modification malveillante du fichier | Critique | Faible | tag AEAD sur l'intégralité, **header inclus en AAD** | ne protège pas contre un retour en arrière (T10) | **F1** |
| T9 | Bit-flip aléatoire | Moyen | Faible | tag AEAD ; test exhaustif de corruption | aucune correction d'erreur — le coffre devient inutilisable, c'est voulu | **F1** |
| T10 | Restauration d'une sauvegarde antérieure | Critique | Moyenne | sentinelle hors du coffre + génération monotone ; **alerte**, jamais blocage | neutralisée si l'attaquant écrit **ou supprime** la sentinelle (la suppression est le chemin le plus simple) | **F1** (partielle) |
| T11 | Retour vers un coffre à KDF faible | Critique | Faible | la sentinelle détecte la régression de génération ; la migration incrémente la génération | ne détecte pas un coffre ancien sans sentinelle préalable | **F1** |
| T12 | Malware local non privilégié | Critique | **Élevée** | réduction de surface : aucun réseau, aucune extension navigateur, permissions 0600, verrou de fichier | accès complet au coffre **pendant** qu'il est déverrouillé | **F1** (partiel) |
| T13 | Keylogger | Critique | Élevée | saisie sans écho ; rien d'autre n'est fiable | **aucune défense réelle** contre un hook clavier | — |
| T14 | Détournement du presse-papiers | Élevé | Moyenne | effacement temporisé **avec vérification avant écrasement** | gestionnaires d'historique ; sur Wayland la relecture est refusée | **F4** |
| T15 | Capture d'écran | Élevé | Moyenne | `WDA_EXCLUDEFROMCAPTURE` sur **Windows uniquement** ; délai avant révélation | **aucun équivalent Linux** ; un appareil photo contourne tout | **F6** |
| T16 | Lecture de mémoire par un processus privilégié | Critique | Faible | `zeroize`, `mlock`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `MADV_DONTDUMP` | `ptrace` en `root` lit tout. Défense **impossible** contre Ad4 | F1 (partiel) |
| T17 | Navigateur compromis | Critique | Moyenne | **aucune intégration navigateur** ; le coffre n'écoute sur aucun socket | hors périmètre par choix, pas par oubli | — |
| T18 | Extension malveillante | Critique | Élevée | aucune surface exposée au navigateur | contournée par T12 si l'extension peut lire les fichiers | — |
| T19 | Vol du fichier de configuration | Faible | Moyenne | la configuration ne contient **aucun secret** ; sentinelle = condensé non réversible, sans nom de coffre | révèle qu'un coffre existe et quand il a été utilisé | **F1** |
| T20 | Extraction de secrets depuis les journaux | Critique | Moyenne | types secrets à `Debug` rédacteur ; erreurs sans donnée du coffre ; test automatisé | un `println!` sur une `String` non typée échappe au typage | **F1** |
| T21 | Fuite dans un vidage mémoire | Critique | Moyenne | `panic = "abort"`, vidages désactivés, `MADV_DONTDUMP`, pas de dépliage de pile | panique peut avoir formaté des données ; la pile reste en mémoire | **F1** (partiel, Linux) |
| T22 | Fichiers temporaires | Critique | Moyenne | écriture dans le répertoire du coffre, nom aléatoire, `O_CREAT|O_EXCL|O_NOFOLLOW` en 0600, fsync, renommage | un plantage peut laisser un `.tmp` — chiffré, donc sans fuite | **F1** |
| T23 | Fichier d'échange / pagefile | Critique | Moyenne | `mlock` / `VirtualLock` du matériel de clé | peut échouer ; ne couvre pas tout le tas | **F1** (best-effort) |
| T24 | Permissions incorrectes | Élevé | Moyenne | 0600 posé **à la création**, vérification et réparation au déverrouillage | dépend du système de fichiers ; sans effet sur FAT32/exFAT | **F1** (Unix) |
| T25 | Attaque par lien symbolique | Élevé | Faible | `O_NOFOLLOW` **sur chaque composant du chemin** (`open_dir_no_symlinks`, marche avec descripteurs tenus), plus sur le fichier temporaire ; nom imprévisible | **Windows** : pas de famille `*at`, la vérification est *préalable*, donc sujette à une course — protection **non équivalente**. Un répertoire traversable mais non lisible est refusé | **F1**, corrigé après l'audit |
| T26 | TOCTOU | Élevé | Faible | jamais `stat` puis `open` : `open` puis `fstat` sur le descripteur | courses sur les ancêtres du chemin | **F1** (partiel) |
| T27 | Injection (SQL, commande, format) | Élevé | Moyenne | **aucun langage de requête** : SQLite a été abandonné en phase 2 (ADR-020), le magasin est en Rust pur et la recherche est une **sous-chaîne littérale sans syntaxe** ; aucune commande externe ; jamais d'interpolation | les parseurs d'import (phase 4) seront des analyseurs à traiter comme hostiles. *Cette ligne décrivait FTS5 et son opérateur `MATCH` : elle était devenue fausse* | **F2** |
| T28 | Chemin contrôlé par l'utilisateur | Élevé | Moyenne | un titre d'entrée n'est jamais un chemin ; jetons aléatoires pour les fichiers internes ; octets nuls refusés | le répertoire choisi par l'utilisateur reste sous sa responsabilité | **F1** |
| T29 | Corruption du magasin | Élevé (disponibilité) | Faible | **il n'y a plus de base de données** : SQLite a été abandonné en phase 2 (ADR-020). Le décodage d'archive est **borné et vérifié** ; l'écriture du conteneur est atomique | une corruption du contenu reste un défaut du programme, pas un scénario exploitable ; une corruption du **fichier** est détectée par le tag AEAD. *Cette ligne décrivait une base SQLite : elle était devenue fausse* | **F2** |
| T30 | Compromission physique du périphérique | Critique | Faible | chiffrement au repos, verrouillage automatique | DMA, cold boot, puce espionne : hors périmètre | — |
| T31 | Perte totale de l'appareil | Élevé (disponibilité) | Moyenne | sauvegarde + **test de restauration** + clé de récupération | sans sauvegarde ni clé de récupération, la perte est **définitive** | **F4.1 partiel** — clé de récupération **livrée** ; sauvegardes et test de restauration à l'étape 3 |
| T32 | Traversée de chemin / zip slip | Élevé | Faible | assainissement des noms, `O_EXCL`, écriture dans un répertoire créé par nous | — | **F4** |

## 5. Scénarios d'attaque détaillés

Trois scénarios concrets, avec la défense et sa limite.

### 5.1 Un adversaire vole le fichier et attaque hors ligne (Ad1 + Ad2)

**Scénario.** Le fichier `coffre.plk` est copié depuis une clé USB ou un dossier
synchronisé. L'attaquant dispose d'un budget de calcul loué et cherche le mot de
passe maître.

**Défense.** Argon2id avec 256 Mio de mémoire. Chaque cœur d'attaque doit disposer
de 256 Mio, ce qui plafonne le parallélisme par la VRAM et la RAM disponibles plutôt
que par la puissance de calcul. Vérifié : l'attaquant ne peut pas réduire ces
paramètres, car le header entre dans l'AAD du payload — les abaisser invalide le tag.

**Limite.** Le durcissement ne fait que décaler la facture. Si le mot de passe maître
est un mot du dictionnaire avec quelques substitutions, il tombe. **Aucune décision
d'architecture ne corrige cela** ; seul le choix de l'utilisateur compte. C'est
pourquoi la phrase de passe est encouragée plutôt que le mot de passe, mais rien ne
peut l'imposer.

### 5.2 Un attaquant remplace le coffre par une version antérieure (Ad3 + Ad6)

**Scénario.** Après un changement de mot de passe maître — ou après la suppression
d'une entrée sensible — un attaquant restaure le fichier d'avant l'opération. Le tag
AEAD ne détecte rien : un ancien fichier est parfaitement authentique.

**Défense.** La génération, compteur monotone **à l'intérieur du payload chiffré**
(donc inforgeable sans la clé), est comparée à une sentinelle conservée dans le
répertoire de configuration de l'utilisateur — délibérément pas à côté du coffre.
Une régression déclenche une alerte détaillée.

**Limite — trois points, dont un plus grave que les autres.**

1. **Le HMAC empêche de forger, pas de restaurer.** Un attaquant ne peut pas inventer
   une sentinelle (il lui faudrait la DEK), mais il peut remettre en place une
   sentinelle authentique antérieure, ou recopier la courante. Rejouer une valeur
   valide n'exige aucune connaissance cryptographique.
2. **La suppression de la sentinelle désactive la détection**, et c'est le chemin le
   plus accessible : 64 octets à effacer. L'ouverture suivante rétablit la référence
   à la génération du coffre présenté — donc à celle de l'attaquant. Un avertissement
   est affiché, mais il est indiscernable d'une première ouverture sur une machine
   neuve.
3. **Aucune correction n'est possible dans une architecture entièrement locale.** Il
   faudrait un compteur monotone matériel (TPM), un support en ajout seul, ou un
   journal distant — les trois hors périmètre.

La seule défense restante est la formulation : « détection **partielle** de retour en
arrière », jamais « protection contre le retour en arrière ».

**Pourquoi l'alerte ne bloque pas.** Un blocage dur sur un retour en arrière
légitime — restauration d'une sauvegarde après sinistre — transformerait une
protection en perte de données.

### 5.3 Un attaquant remplace le coffre par un lien symbolique (Ad3)

**Scénario.** Un processus non privilégié remplace `coffre.plk` par un lien vers
`~/.bashrc`, ou pré-crée un lien au nom du fichier temporaire. L'application écrit
« dans son coffre » et écrase en réalité un fichier de l'utilisateur.

**Défense.** Le répertoire est ouvert avec `O_NOFOLLOW|O_DIRECTORY` ; le fichier
temporaire est créé avec `O_CREAT|O_EXCL|O_NOFOLLOW` sous un nom **aléatoire**
imprévisible ; le remplacement se fait par renommage, qui substitue l'entrée du lien
et non sa cible.

**Vérifié.** Tests d'intégration : `replacing_a_symlink_replaces_the_link_not_its_target`,
`a_pre_created_symlink_at_the_temporary_name_is_refused`,
`a_symlinked_directory_is_refused`, et, depuis la passe ciblée post-audit de la
phase 1 : `a_symlink_at_the_second_level_is_refused`,
`a_symlink_deep_in_the_path_is_refused`, `an_absolute_symlinked_prefix_is_refused`.
Le fichier victime est contrôlé intact après chaque tentative.

**Composants intermédiaires — CORRIGÉ.** `O_NOFOLLOW` ne s'applique qu'au **dernier**
composant d'un chemin : si `~/a` était un lien symbolique vers un répertoire attaquant
et le coffre en `~/a/coffre.plk`, toute l'écriture était redirigée. La marche composant
par composant annoncée ici comme manquante **a été implémentée**
(`open_dir_no_symlinks`) : chaque répertoire est ouvert avec `O_NOFOLLOW` **depuis le
descripteur du précédent**, ce qui refuse un lien n'importe où dans le chemin et
garantit qu'aucun composant ne peut être remplacé après vérification — ce qu'une simple
vérification préalable ne garantirait pas.

`openat2(RESOLVE_NO_SYMLINKS)` n'a **pas** été retenu, bien qu'il eût été plus élégant :
il n'existe qu'à partir de Linux 5.6, exige un numéro d'appel par architecture, est
absent de `libc`, et n'a **aucune transposition à Windows**. La marche est la seule
approche à la fois sûre et portable.

**Limite résiduelle, énoncée sans l'embellir.** Chaque composant est ouvert en lecture,
donc un répertoire traversable mais non lisible (mode `--x`) est refusé. Sur Windows,
l'absence de famille `*at` impose une vérification **préalable**, donc sujette à une
course : la protection n'y est **pas équivalente** à celle d'Unix, et elle n'est pas
présentée comme telle. Détail et statut dans `SECURITY.md`, limite **L1**.

## 6. Scénarios explicitement hors périmètre

| Hors périmètre | Raison |
|---|---|
| Système d'exploitation déjà compromis | aucune garantie logicielle n'est possible |
| Keylogger noyau ou matériel | idem |
| Attaque DMA, cold boot, puce espionne | nécessite du matériel spécifique ; hors de portée d'une application |
| Attaquant privilégié lisant la mémoire (`ptrace` en `root`) | idem |
| Écran observé physiquement | aucun équivalent Linux de `WDA_EXCLUDEFROMCAPTURE` |
| Contrainte physique sur l'utilisateur | pas de résistance à la coercition ; aucun « coffre leurre » (voir `DECISIONS.md`) |
| Intégration navigateur, remplissage automatique | surface d'attaque disproportionnée ; le navigateur est l'environnement le moins fiable du système |
| Mode de passe-partout partagé mot de passe + code TOTP | apporte **zéro** protection contre la compromission du coffre — voir §`DECISIONS.md` |
| Récupération par courriel ou question de sécurité | structurellement impossible (aucun serveur) et dangereux (second chemin attaquable) |

## 7. Ce que ce logiciel ne peut pas garantir

Liste à traiter comme un engagement d'honnêteté. **Le mot « sécurisé » n'est jamais
employé sans qualifier l'adversaire et les conditions.**

1. **Un malware avec contrôle total du système** lit le coffre déverrouillé. Aucune
   défense.
2. **Un keylogger** capture le mot de passe maître à la frappe. Aucune défense.
3. **Un système déjà compromis** invalide toutes les garanties.
4. **Une attaque privilégiée sur la mémoire** lit les secrets. Le durcissement
   appliqué ne concerne que les attaquants **non privilégiés**.
5. **Un écran observé physiquement** n'est protégé par rien sur Linux.
6. **L'effacement mémoire n'est pas garanti.** Détail en `docs/CRYPTO.md` §7.
7. **La suppression n'est pas physique.** Sur SSD (usure, TRIM) et sur les systèmes
   de fichiers à copie sur écriture (btrfs, ZFS, APFS), d'anciens blocs chiffrés
   subsistent. Aucun « effacement sécurisé » n'est implémenté, car il serait
   physiquement inopérant et donnerait une fausse assurance.
8. **Une entrée supprimée subsiste dans les sauvegardes déjà écrites.** Effacer une
   entrée du coffre n'a aucun effet sur les copies antérieures. C'est inévitable et
   doit être dit à l'utilisateur au moment de la suppression.
9. **La dénégation est impossible.** Un coffre chiffré se voit.
10. **La résistance à la coercition est nulle.** On ne peut pas prouver l'inexistence
    d'une clé à qui détient le pouvoir physique.
11. **Il n'existe aucune limitation du nombre de tentatives de déverrouillage.** Une
    interface qui réessaierait en boucle consommerait du temps CPU proportionnel.

## 8. Surface d'attaque

| Point d'entrée | Traite des données non fiables ? | Avant authentification ? | Protection |
|---|---|---|---|
| Fichier de coffre | oui | **oui** | layout à offsets fixes, aucune allocation dimensionnée par une valeur lue, bornes vérifiées, fuzzing |
| Sentinelle | oui | non (après déverrouillage) | taille fixe, HMAC |
| Arguments de ligne de commande | oui | oui | clap ; aucun secret accepté en argument |
| Entrée standard (mot de passe) | oui | oui | longueur bornée à 1024 octets, écho désactivé |
| Fichiers temporaires | non (nous les créons) | — | nom aléatoire, `O_EXCL|O_NOFOLLOW`, 0600 |
| Réseau | **aucun** | — | le crate cœur ne dépend d'aucune bibliothèque réseau, vérifiable par `cargo tree` |
| Bibliothèques tierces | — | — | arbre de dépendances minimal, `cargo-deny`, `Cargo.lock` versionné |

## 9. Politique de divulgation

Une vulnérabilité dans un gestionnaire de secrets n'est pas un rapport de bogue
ordinaire. Voir `SECURITY.md` §Divulgation.
