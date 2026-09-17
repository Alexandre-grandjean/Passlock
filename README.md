# Passlock

Gestionnaire de secrets **local**, hors ligne, sans compte et sans serveur.

Vous êtes propriétaire du fichier, de la clé et du format. Il n'existe aucun
mécanisme de récupération à distance, aucune télémétrie, aucune synchronisation
propriétaire — et ces absences sont des choix de conception, pas des
fonctionnalités manquantes.

> **Statut : phases 0 à 3 terminées et approuvées. Phase 4 en cours — étapes 1 et 2 sur 5 closes.**
>
> Existent et sont testés : le moteur cryptographique et le format de coffre
> (phase 1), le cœur de stockage — modèle de données, archive, migration, recherche,
> historique, corbeille (phase 2), le générateur de secrets avec le TOTP (phase 3),
> la **récupération** — clé de récupération et fichier-clé — et les **pièces jointes**
> chiffrées (phase 4, étapes 1 et 2 sur 5).
>
> N'existent **pas encore** : sauvegardes, test de restauration, import/export et
> presse-papiers *(phase 4, étapes 3 à 5)* ; centre de sécurité et analyse d'URL
> *(phase 5)* ; interface graphique *(phase 6)* ; audit externe, SBOM et build
> reproductible *(phase 7)*.
>
> Le contenu des phases fait autorité dans **[`ROADMAP.md`](ROADMAP.md)**.

## Ce que ce logiciel fait aujourd'hui

* Créer un coffre chiffré protégé par une phrase de passe.
* Stocker des entrées typées (identifiant, note, carte, clé d'API, clé SSH, Wi-Fi…)
  avec des champs personnalisés.
* Organiser en dossiers et tags, marquer des favoris, archiver.
* Rechercher — insensible à la casse et aux accents — et trier.
* Conserver un historique versionné, avec purge explicite.
* Corbeille, restauration, suppression définitive.
* Vérifier l'intégrité d'un coffre de bout en bout.
* Afficher les métadonnées publiques d'un coffre **sans le mot de passe**.
* Changer le mot de passe maître sans rechiffrer le contenu.
* Mesurer le coût réel de la dérivation de clé sur votre machine.
* Détecter qu'un coffre a reculé par rapport au dernier état connu (alerte, jamais
  blocage).
* **Engendrer des mots de passe**, avec les contraintes qu'imposent les sites, et
  **afficher l'entropie réellement obtenue** — y compris ce que la contrainte coûte.
* **Engendrer des phrases de passe** à partir d'une liste de mots, avec le nombre de
  bits correspondant à la liste **effectivement utilisée**.
* **Engendrer des secrets arbitraires** (hex, Base32, Base64url, alphanumérique).
* **Produire des codes TOTP**, et écrire un secret engendré directement dans le
  coffre sans jamais le faire transiter par la ligne de commande.
* **Ajouter une clé de récupération** de 256 bits, en Base32 Crockford avec total de
  contrôle, et ouvrir le coffre avec elle.
* **Ajouter un fichier-clé** sur support amovible, et ouvrir le coffre avec lui.
* **Vérifier qu'une clé de récupération ouvre réellement le coffre** — une clé jamais
  essayée n'est pas une récupération.
* **Attacher des fichiers** à une entrée, chiffrés séparément du coffre, et les restituer.
* **Vérifier l'intégrité des pièces jointes** et supprimer les blobs devenus orphelins.

## Ce que ce logiciel ne fait pas — et ne fera pas

* Il ne vous demandera **jamais** de créer un compte.
* Il n'enverra **jamais** vos secrets, ni un dérivé de vos secrets, vers un service
  distant. Le moteur cryptographique n'a **aucune dépendance réseau** : la propriété
  est vérifiable par `cargo tree`.
* Il n'existe **aucun** « mot de passe oublié par courriel ».
* Il ne promet **aucun** effacement mémoire garanti, ni aucune « suppression
  sécurisée » — ces deux promesses seraient fausses sur un SSD et sur un système
  d'exploitation moderne.

## Installation

Prérequis : Rust 1.88 ou plus récent (la toolchain est épinglée à 1.98.0 par
`rust-toolchain.toml`).

```sh
git clone <dépôt> passlock
cd passlock
cargo build --release
# binaire : target/release/passlock
```

## Démarrage

```sh
# Créer un coffre. La phrase de passe est demandée deux fois, sans écho.
passlock init ~/coffre.plk

# Voir ce que le fichier révèle sans le mot de passe
passlock info ~/coffre.plk

# Vérifier l'authenticité et déchiffrer
passlock verify ~/coffre.plk

# Changer la phrase de passe (le contenu n'est pas rechiffré)
passlock change-password ~/coffre.plk

# Mesurer les profils de dérivation sur cette machine
passlock calibrate --budget 5
```

### Engendrer un secret

Le **secret est écrit sur la sortie standard**, seul ; le **rapport d'entropie va sur
la sortie d'erreur**. `passlock secret > cle.txt` écrit donc exactement le secret.

```sh
# Mot de passe de 20 caractères : minuscules, majuscules, chiffres
passlock generate --length 20 --charset lud

# Avec les symboles, sans les caractères ambigus, et la contrainte d'un site
passlock generate --length 24 --charset luds --no-ambiguous --min-digits 2

# Phrase de passe : six mots de la liste française.
# Le séparateur par défaut est « . » : le tiret apparaît dans certains mots (« felt-tip »),
# ce qui rendrait la concaténation ambiguë et l'entropie annoncée surestimée.
passlock passphrase --words 6

# Liste anglaise, sans les entrées Diceware qui ne portent pas de lettre
passlock passphrase --words 6 --language en --letters-only

# Clé d'API en Base64url, regroupée par blocs de 8 pour la recopie
passlock secret --bytes 32 --format base64url --groups 8
```

Le rapport indique la **taille réelle de l'alphabet**, les **bits retenus**, et
lorsqu'une contrainte s'applique, **ce qu'elle coûte**. Exemple :

```
mot de passe de 16 caractères sur un alphabet de 94 symboles
  entropie sans contrainte 104.87 bits ; contrainte -0.27 bit ; retenu 104.60 bits
  bande : acceptable (plancher 104 bits)
  hypothèse : CSPRNG du noyau uniforme et non compromis
```

Aucune **durée de cassage** n'est annoncée : elle exigerait des hypothèses sur le
matériel de l'attaquant que ce projet ne peut pas vérifier. Voir
[`docs/DECISIONS.md`](docs/DECISIONS.md) ADR-026.

### Écrire un secret directement dans le coffre

`passlock entry add --field password=$(passlock generate)` place le secret dans
l'environnement du shell, où il peut être journalisé. Pour l'éviter :

```sh
# Le secret naît dans le processus et va directement dans l'archive.
# Ni argument de commande, ni tube, ni fichier temporaire.
passlock entry gen ~/coffre.plk 1b0bc070… --field password --length 24 --charset luds
```

### Codes TOTP

```sh
# Associer un secret existant (demandé par une invite masquée)
passlock entry totp set ~/coffre.plk 1b0bc070… --issuer Banque --account alice

# Ou en engendrer un neuf ; l'URI affichée sert à l'enrôlement
passlock entry totp new ~/coffre.plk 1b0bc070… --issuer Banque --account alice

# Afficher le code : le code sur stdout, le décompte sur stderr
passlock totp ~/coffre.plk 1b0bc070…

# Lister les entrées portant un TOTP
passlock totp ~/coffre.plk --list
```

**Aucun code n'est produisible sans déverrouillage du coffre**, et aucun n'est mis en
cache. Voir [`docs/TOTP.md`](docs/TOTP.md) pour le modèle complet et ses limites.

### Récupération

Un coffre peut porter jusqu'à trois chemins d'ouverture : le mot de passe maître, une
**clé de récupération** transcrite, et un **fichier-clé** sur support amovible. Les trois
produisent la clé de chiffrement par le **même chemin** — il n'y a donc pas de chemin
plus faible que les autres.

```sh
# Créer une clé de récupération : elle est affichée UNE FOIS, sur stdout
passlock recovery new ~/coffre.plk

# L'essayer pour de bon — une clé jamais essayée n'est pas une récupération
passlock recovery test ~/coffre.plk

# Ouvrir n'importe quelle commande avec cette clé
printf '%s\n' "$CLE" | passlock --recovery-key-stdin entry list ~/coffre.plk

# Fichier-clé : 32 octets aléatoires, écrits là où vous le demandez
passlock keyfile new ~/coffre.plk --key-file /media/cle/coffre.key
passlock keyfile test ~/coffre.plk --key-file /media/cle/coffre.key
```

La clé de récupération est en Base32 Crockford, groupée par blocs de cinq, avec un
**total de contrôle de 40 bits** : une faute de recopie est refusée avant toute tentative
de déverrouillage, et non après.

**Trois choses à savoir, et elles ne sont pas des précautions de style :**

* **chaque slot est un chemin d'entrée de plus.** Récupérabilité et résistance au vol
  varient en sens inverse : ce que vous gagnez contre la perte, vous le cédez contre le
  vol ;
* **un fichier-clé est un fichier : il se copie.** Ce n'est **pas** un jeton matériel
  inviolable. Rangez-le sur un support **physiquement distinct** du coffre et des
  sauvegardes, et retirez-le après usage. Un vrai facteur matériel (FIDO2) est repoussé,
  et cette absence est documentée plutôt que tue — voir `ADR-032` ;
* **ajouter un slot ré-écrit le payload** au prochain enregistrement : le header entre
  dans l'AAD du contenu, donc son tag doit être recalculé. Ce n'est pas instantané, et le
  contraire a été affirmé à tort dans une version antérieure de `SECURITY.md`.

Aucun secret n'est accepté en argument de commande : la clé vient d'une invite masquée ou
de l'entrée standard, jamais de `argv`, où `ps` la montrerait.

### Utilisation scriptée

Par défaut le mot de passe est lu de façon interactive, avec l'écho désactivé.
Pour un script, `--password-stdin` lit une ligne par invite sur l'entrée standard :

```sh
printf '%s\n%s\n' "$PHRASE" "$PHRASE" | passlock init --password-stdin ~/coffre.plk
```

**Il n'existe délibérément aucune option acceptant un mot de passe en argument de
ligne de commande.** Un tel argument serait visible dans la liste des processus
(`ps`) et dans l'historique du shell.

### Options

| Option | Effet |
|---|---|
| `--read-only` | Ouvre sans autoriser aucune écriture : rien n'est modifié, même en cas d'erreur |
| `--password-stdin` | Lit les invites (mot de passe, clé de récupération) sur l'entrée standard |
| `--state-dir <RÉPERTOIRE>` | Emplacement de la sentinelle anti-retour-en-arrière |
| `--recovery-key-stdin` | Ouvre le coffre avec une clé de récupération lue sur l'entrée standard |
| `--key-file <CHEMIN>` | Ouvre le coffre avec le fichier-clé situé à ce chemin |

## Format du coffre

Le format est **documenté octet par octet** et gelé à l'issue de la phase 1 :
`docs/VAULT_FORMAT.md`. Vous pouvez le lire, l'implémenter ailleurs, et récupérer vos
données sans cette application. Aucun verrouillage propriétaire n'existe, ni
techniquement ni juridiquement.

## Documentation

| Document | Contenu |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | **Source canonique de la feuille de route** : contenu, ordre, dépendances et état des phases 0 à 7. Les autres documents s'y réfèrent au lieu de la redéfinir |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Actifs, adversaires, hypothèses, 32 menaces, scénarios hors périmètre, **ce que le logiciel ne peut pas garantir** |
| [`SECURITY.md`](SECURITY.md) | Architecture, garanties et leur portée, limites connues avec suivi, **risques introduits par phase**, chaîne d'approvisionnement, divulgation |
| [`docs/CRYPTO.md`](docs/CRYPTO.md) | Primitives, hiérarchie de clés, paramètres justifiés, **mesures réelles** de latence |
| [`docs/VAULT_FORMAT.md`](docs/VAULT_FORMAT.md) | Spécification du **conteneur**, versionnement, migration |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | Le modèle de données : chaque type, chaque champ, **ce qui est volontairement absent** |
| [`docs/STORAGE_FORMAT.md`](docs/STORAGE_FORMAT.md) | L'**archive du corps** octet par octet, bornes, déterminisme, migration |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Découpage en crates, flux de données, invariants |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Journal des décisions, **y compris celles qui ont été annulées** |
| [`docs/TOTP.md`](docs/TOTP.md) | Modèle TOTP : ce qui est supporté, pourquoi SHA-1 est légitime, **l'horloge n'est pas vérifiée**, injection termininale, ce qui n'est pas revendiqué |
| [`crates/passlock-core/data/wordlists/ATTRIBUTION.md`](crates/passlock-core/data/wordlists/ATTRIBUTION.md) | Provenance, licence et empreinte des deux listes de mots embarquées |
| [`docs/AUDIT_PHASE4_1_RECUPERATION.md`](docs/AUDIT_PHASE4_1_RECUPERATION.md) | **Audit de la phase 4, étape 1** : clé de récupération, fichier-clé, création exclusive et durabilité, défaut de perte de données trouvé |
| [`docs/ATTACHMENT_FORMAT.md`](docs/ATTACHMENT_FORMAT.md) | Le **format des pièces jointes** octet par octet : découpage, AAD, ce que l'AEAD ne protège **pas**, ordre d'écriture, ramasse-miettes |
| [`docs/AUDIT_PHASE4_2_PIECES_JOINTES.md`](docs/AUDIT_PHASE4_2_PIECES_JOINTES.md) | **Audit de la phase 4, étape 2** : domaines de clés, format de blob, ramasse-miettes, oracle faux trouvé par le fuzzing |
| [`docs/AUDIT_PHASE3.md`](docs/AUDIT_PHASE3.md) | Audit adversarial du générateur et du TOTP : 35 vecteurs RFC, fuzzing, secret en mémoire, défauts trouvés |
| [`docs/AUDIT_PHASE2_SEMANTIQUE.md`](docs/AUDIT_PHASE2_SEMANTIQUE.md) | **Audit sémantique** du magasin par modèle de référence : 9 500 opérations comparées, 18 invariants |
| [`docs/AUDIT_PHASE2.md`](docs/AUDIT_PHASE2.md) | Audit adversarial du cœur de stockage |
| [`docs/AUDIT_PHASE1.md`](docs/AUDIT_PHASE1.md) | **Audit adversarial de la phase 1** : hiérarchie de clés, format octet par octet, AEAD, Argon2id, retour en arrière, mémoire, système de fichiers, 16 attaques, verdict et risques résiduels |

## Vérifier plutôt que croire

Les affirmations de sécurité de ce projet sont vérifiables :

```sh
cargo test --workspace          # 556 tests, dont 27 attaques adversariales et 9 500
                                # opérations comparées à un modèle de référence
cargo deny check                # avis de sécurité, licences, bans, sources

# Aucun `unsafe` dans le moteur cryptographique
grep -rn "unsafe" crates/passlock-core/src

# Le cœur n'a aucune dépendance réseau, et aucune macro procédurale
cargo tree -p passlock-core

# Permissions du coffre (attendu : 600)
stat -c '%a %n' ~/coffre.plk

# Latence de déverrouillage réellement mesurée
passlock calibrate --budget 5

# Le TOTP de bout en bout, contre un vecteur officiel de la RFC 6238
printf '%s\nGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' "$MOT_DE_PASSE" \
  | passlock entry totp set COFFRE "$ID" --password-stdin --digits 8
MOT_DE_PASSE="$MOT_DE_PASSE" passlock totp COFFRE "$ID" --at 59   # → 94287082

# La récupération, de bout en bout : la clé ouvre VRAIMENT le coffre
passlock recovery new COFFRE > cle.txt   # affichée une seule fois, sur stdout
passlock recovery test COFFRE < cle.txt  # le slot est désenroulé, le contenu déchiffré
printf '%s\n' "$CLE" | passlock --recovery-key-stdin entry list COFFRE

# Une clé mal recopiée est refusée par son total de contrôle, AVANT toute dérivation
passlock recovery test COFFRE < cle-fausse.txt   # → « total de contrôle … invalide »

# Le fichier-clé est en 0600 et n'est jamais écrit par-dessus un existant
passlock keyfile new COFFRE --key-file /media/cle/coffre.key
stat -c '%a %n' /media/cle/coffre.key            # 600

# Les pièces jointes : le blob survit au coffre, et l'ordre d'écriture est vérifiable
passlock attach add COFFRE "$ID" document.pdf
passlock attach get COFFRE "$BLOB" --output copie.pdf   # refuse d'écraser une cible
passlock attach verify COFFRE    # observe et signale ; ne supprime RIEN
passlock attach gc COFFRE --confirm "$VAULT_ID"         # supprime les seuls orphelins

# Ce que l'AEAD ne protège pas : une troncature propre est détectée par la métadonnée
truncate -s -100 COFFRE.attachments/<blob>
passlock attach verify COFFRE    # → défaut signalé, et le blob est PRÉSERVÉ

# Le fuzzing, cible par cible (nightly requis)
cd fuzz && cargo +nightly fuzz run parse_recovery_key --  -max_total_time=60
cd fuzz && cargo +nightly fuzz run parse_attachment_blob -- -max_total_time=60
```

## État de vérification

Chaque phase fait l'objet d'un **audit adversarial** documenté, et le rapport dit
séparément ce qui a été livré, ce qui a été **réellement exécuté**, ce qui a été
trouvé, et ce qui reste **non vérifié**.

* **Phase 1** — [`docs/AUDIT_PHASE1.md`](docs/AUDIT_PHASE1.md) : **huit défauts
  réels**, dont trois de gravité élevée portant sur le cycle de vie des secrets en
  mémoire (un coffre déchiffré restait en clair dans le tas libéré). Tous corrigés et
  couverts par un test de non-régression. Aucun défaut cryptographique.
* **Phase 2** — [`docs/AUDIT_PHASE2.md`](docs/AUDIT_PHASE2.md) et
  [`docs/AUDIT_PHASE2_SEMANTIQUE.md`](docs/AUDIT_PHASE2_SEMANTIQUE.md).
* **Phase 3** — [`docs/AUDIT_PHASE3.md`](docs/AUDIT_PHASE3.md).
* **Phase 4, étape 2 — pièces jointes** —
  [`docs/AUDIT_PHASE4_2_PIECES_JOINTES.md`](docs/AUDIT_PHASE4_2_PIECES_JOINTES.md) :
  **40,5 millions** d'exécutions de fuzzing, et **un défaut trouvé** — non dans le produit,
  mais dans **mon propre harnais** : une assertion affirmait une règle que le code
  n'applique pas, ce qui aurait « validé » un durcissement cassant la compatibilité de
  lecture.
* **Phase 4, étape 1 — récupération** —
  [`docs/AUDIT_PHASE4_1_RECUPERATION.md`](docs/AUDIT_PHASE4_1_RECUPERATION.md) :
  **un défaut de gravité élevée**, trouvé par un test. Le nettoyage d'un fichier-clé
  détruisait le fichier **préexistant** de l'utilisateur au moment même où il refusait
  de l'écraser — un refus qui devenait une perte définitive. Corrigé, et le chemin de
  suppression rendu inatteignable quand rien n'a été créé.

### La conformité TOTP ne vient pas de nous

Les tables de test HOTP et TOTP sont reproduites **verbatim** depuis les RFC 4226 et
6238, et Base32 depuis la RFC 4648 (§10). Ce n'est pas « ce code fait ce que son
auteur attendait », c'est « ce code fait ce que la norme prescrit » :

```sh
cargo test -p passlock-core --test rfc_vectors
# 10 vecteurs RFC 4226 + 18 vecteurs RFC 6238 + 7 vecteurs RFC 4648 §10
```

### Ce qui reste non vérifié, et ne doit pas être présenté comme acquis

* le comportement **Windows à l'exécution** : le code compile et les signatures FFI
  sont vérifiées, mais les tests ne s'y exécutent pas dans cet environnement ;
* les cibles `cargo-fuzz` : voir le rapport de phase 3 ;
* **l'absence de biais du CSPRNG du noyau** — hors périmètre : c'est l'ancre de
  confiance depuis la phase 1, et aucun test ne peut la valider depuis l'espace
  utilisateur ;
* **la détection de dérive d'horloge pour le TOTP** : non revendiquée, et
  structurellement hors de portée hors ligne ;
* **la qualité linguistique des listes de mots** : seuls le compte, le format,
  l'unicité et l'empreinte sont vérifiés ;
* aucun audit par un tiers.

## Ce que ce logiciel ne peut pas garantir

Résumé ; la liste complète et argumentée est dans `THREAT_MODEL.md` §7.

* Un malware avec contrôle total du système lit le coffre déverrouillé.
* Un keylogger capture la phrase de passe à la frappe.
* Un appareil compromis invalide toutes les garanties.
* L'effacement mémoire n'est pas garanti.
* La suppression n'est pas physique : d'anciennes données subsistent sur un SSD, et
  **dans toute sauvegarde déjà écrite**.
* La résistance à la coercition est nulle.

**Le mot « sécurisé » n'est jamais employé ici sans dire contre quel adversaire, dans
quelles conditions et sous quelles hypothèses.**

## Licence

MIT — voir [`LICENSE`](LICENSE).
