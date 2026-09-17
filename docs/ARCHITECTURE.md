# Architecture

## 1. Découpage en crates

```
passlock-cli        interface en ligne de commande (headless)
      │             #![forbid(unsafe_code)]
      ▼
passlock-core       cryptographie, format, coffre
      │             #![forbid(unsafe_code)] — AUCUN réseau, AUCUNE interface
      ▼
passlock-platform   primitives système — SEUL crate autorisé à utiliser `unsafe`
```

### Pourquoi cette séparation

**`passlock-platform` isole tout `unsafe`.** La règle du projet est vérifiable par une
simple recherche textuelle :

```sh
grep -rn "unsafe" crates/passlock-core/src    # ne doit rien retourner
```

Sa surface exposée est délibérément minuscule — mémoire, fichiers, terminal — et
chaque fonction qui manipule des adresses est documentée avec l'invariant qui rend
son `unsafe` correct. Aucune de ces fonctions **ne lit** le contenu des buffers
qu'elle manipule : `mlock`, `madvise` et `VirtualLock` n'agissent que sur l'état des
pages dans la table de pages du noyau.

**`passlock-core` n'a aucune dépendance réseau.** Il est donc *structurellement*
incapable d'exfiltrer des données, y compris par l'intermédiaire d'une dépendance
transitive. Cette propriété n'est pas une promesse de discipline : elle se vérifie
avec `cargo tree -p passlock-core`.

## 2. Modules du cœur

| Module | Rôle | Dépend de |
|---|---|---|
| `error` | type d'erreur sans secret, sémantique anti-oracle | — |
| `rng` | source d'aléa unique (`getrandom`, sans repli) | — |
| `secret` | types de matériel de clé : verrouillés, effacés, non affichables, non copiables | `platform` |
| `memory` | politique mémoire, réexport de `platform` | `platform` |
| `kdf` | Argon2id : profils, bornes anti-déni-de-service, calibration, migration | `rng`, `secret` |
| `keys` | MK → KEK → DEK → sous-clés, enveloppe des slots | `aead`, `kdf`, `rng` |
| `aead` | XChaCha20-Poly1305 avec AAD, erreur dédiée | `rng`, `secret` |
| `header` | layout binaire du header, validation, AAD des slots | `kdf`, `keys` |
| `container` | encre de niveau 1 : framing, scellement, ouverture, analyse | `aead`, `header`, `keys` |
| `payload` | enveloppe déchiffrée : schéma, génération, corps | `error` |
| `rollback` | sentinelle HMAC anti-retour-en-arrière | `keys`, `platform` |
| `vault` | orchestration : création, ouverture, enregistrement, changement de mot de passe | tous |

Les dépendances vont dans un seul sens. Aucun cycle.

## 3. Flux d'une ouverture

```
 1. acquérir le verrou d'écriture          ← sauf en lecture seule
 2. lire le fichier
 3. ParsedVault::parse                     ← AUCUN calcul cryptographique
      signature, version, drapeaux, longueur
      Header::decode  →  bornes vérifiées, paramètres validés
      (un fichier hostile annonçant 4 Gio est refusé ICI, avant toute allocation)
 4. derive_master_kek(header, mot de passe)
      Argon2id(sel du slot, paramètres du slot) → MK
      HKDF(MK, "…/kek") → KEK
 5. unlock_with_kek(bytes, KEK)
      KEK désenveloppe le slot      → DEK   (échec ⇒ UnlockFailed, indiscernable
      HKDF(DEK, …)                  → sous-clés    d'un mot de passe faux)
      K_records déchiffre le payload (échec ⇒ Corrupted : le mot de passe était juste)
      Payload::decode               → génération + corps
 6. vérifier et réparer les permissions
 7. comparer la génération à la sentinelle  → alerte éventuelle
 8. relâcher les octets du fichier
```

**Séparation entre 4 et 5.** Ce n'est pas un détail de style : `derive_master_kek` et
`unlock_with_kek` sont publiques parce qu'elles marquent la frontière entre « obtenir
une clé » et « ouvrir avec elle ». Conséquences concrètes :

* l'étape coûteuse (Argon2id) est testable **une seule fois** au lieu d'être repayée
  à chaque scénario (voir `DECISIONS.md` ADR-015) ;
* c'est le point d'insertion des futurs mécanismes d'ouverture — clé de récupération,
  clé matérielle — qui produiront une KEK par un autre chemin et réutiliseront tout
  le reste.

## 4. Flux d'une écriture

```
 1. génération += 1
 2. Payload::encode              → enveloppe : signature, version, génération, corps
 3. container::seal
      Header::encode              → octets déterministes
      construire le préfixe        = tout ce qui précède le nonce ⇒ c'est l'AAD
      XChaCha20-Poly1305(K_records, nonce aléatoire, payload, AAD = préfixe)
 4. nom temporaire aléatoire dans le répertoire du coffre
      openat(O_CREAT|O_EXCL|O_NOFOLLOW, 0600)   ← permissions posées À LA CRÉATION
      write_all ; fsync
 5. renameat(temporaire → coffre) ; fsync du répertoire
 6. écrire la sentinelle          ← l'échec est signalé, mais n'annule pas l'écriture
 7. en cas d'échec en 4 ou 5 : génération -= 1 (l'état mémoire reste cohérent
    avec le disque)
```

**Le coffre n'est jamais dans un état partiellement écrit.** Un observateur voit soit
l'ancien fichier complet, soit le nouveau. Un plantage laisse au pire un `.tmp`
chiffré, donc sans fuite.

## 5. Invariants

Propriétés que le code garantit, chacune couverte par au moins un test.

| # | Invariant | Où c'est vérifié |
|---|---|---|
| I1 | Aucune donnée du fichier n'est non authentifiée | `container` : modification d'un octet du header ⇒ tag invalide |
| I2 | L'encodage du header est déterministe | `header` : deux encodages identiques octet pour octet |
| I3 | Un fichier malformé ne provoque jamais de panique | fuzzing + parcours exhaustif des troncatures et des mutations |
| I4 | Aucune allocation n'est dimensionnée par une valeur non bornée lue dans le fichier | refus des paramètres pendant le décodage, `try_reserve` |
| I5 | « Mauvais mot de passe » et « coffre altéré » sont indiscernables avant déverrouillage | `error` : message sans cause interne |
| I6 | Après un changement de mot de passe, la DEK est **rigoureusement identique** | `vault` : comparaison en temps constant |
| I7 | Un slot déplacé vers un autre coffre ne s'ouvre pas | `header` : l'AAD du slot contient l'identifiant du coffre |
| I8 | Deux enveloppements de la même DEK produisent des nonces distincts | `keys` |
| I9 | Le coffre conserve ses permissions restrictives après réécriture | `passlock-platform` |
| I10 | Une écriture interrompue ne laisse jamais de coffre partiel | `passlock-platform` + écriture atomique |
| I11 | Aucun secret n'apparaît dans un `Debug` | `secret`, `keys`, `vault`, `container` |
| I12 | Le processus n'a aucune dépendance réseau | `cargo tree -p passlock-core` |
| I13 | Un slot déplacé vers un autre rôle ne s'ouvre pas | `header` : le rôle entre dans l'AAD du slot ; `tests/key_slots.rs` |
| I14 | Chaque rôle de slot est présent **au plus une fois** — imposé par l'**API** du coffre, **jamais par `Header::validate`** | `vault` : `install_slot` refuse un rôle déjà présent ; `tests/key_slots.rs` |
| I15 | Un fichier sensible neuf n'est jamais créé en écrasant une cible existante | `passlock-platform` : `O_CREAT\|O_EXCL` / `CREATE_NEW` ; `tests/fs_private.rs` |
| I16 | Un blob est durable avant que sa métadonnée soit enregistrée *(Unix)* | `passlock-platform` : `sync_file` **puis** `sync_dir` ; `tests/fs_private.rs` |

## 6. Ce qui n'est pas dans le cœur, et pourquoi

| Absent | Raison |
|---|---|
| Réseau | propriété de sécurité vérifiable, pas une convention |
| Interface utilisateur | le cœur doit rester testable sans terminal ni fenêtre |
| Sérialisation générique | le header est le seul chemin non fiable avant authentification (ADR-004) |
| Macros procédurales | exécutées avec les privilèges du build ; écartées du chemin critique |
| Pièces jointes dans le conteneur | un fichier de 500 Mo ne doit pas être réécrit à chaque modification de titre |

## 7. Extensions prévues, et où elles s'insèrent

**Le contenu, l'ordre, les dépendances et l'état des phases font autorité dans
[`ROADMAP.md`](../ROADMAP.md).** Cette section ne les redéfinit pas : elle répond à une
question **architecturale**, et à elle seule — *par quel point d'insertion chaque
extension entre dans le système existant*. Une extension sans point d'insertion
identifié serait une extension qui impose de réécrire quelque chose.

| Phase | Extension | Point d'insertion |
|---|---|---|
| **2** | modèle de données — entrées, dossiers, tags, historique, recherche *(livré)* | `vault::body` — le schéma vit **dans** le payload, le conteneur ne change pas |
| **3** | générateur et TOTP *(livré)* | nouveau module dans le cœur, **hors du chemin critique de la clé** ; le secret TOTP est un `Field` ordinaire |
| **4** | clé de récupération *(**livrée** — étape 1)* | `derive_master_kek` est devenu `derive_slot_kek(header, label, secret)` : le slot est choisi par **rôle** au lieu d'être cherché comme slot maître, et `unlock_with_kek(bytes, kek, label)` désenveloppe le slot visé. **Un seul chemin de dérivation** — Argon2id puis HKDF — pour les trois rôles, sans branche. Le **slot label 2 était déjà réservé** depuis la phase 1 : aucun changement de format |
| **4** | clé matérielle *(**livrée** — étape 1)* | **Même point d'insertion** : `unlock_with_kek` et `install_slot` ne connaissent que le rôle. La KEK provient du contenu d'un fichier de 32 octets au lieu d'une phrase transcrite. Le fichier est écrit par `create_private_file` (**création exclusive**) et non par `write_atomic`, dont la sémantique de remplacement écraserait une clé existante |
| **4** | pièces jointes | `SubKeys::attachments`, **déjà dérivée** depuis la phase 1 ; la section de métadonnées existe déjà dans l'archive (phase 2), bornée et présente même vide |
| **4** | import/export | couche de traduction au-dessus de `Archive` — aucun point d'insertion dans le format |
| **4** | presse-papiers | `passlock-platform`, à côté de `tty` et `process` : c'est du code plateforme, pas du cœur. **À réexaminer** : une dépendance pure Rust n'apporte aucun `unsafe`, et la placer dans `passlock-platform` — dont `passlock-core` dépend — ferait entrer son arbre dans celui du cœur (`I12`). Décision reportée à la porte E.0, §8.1 du plan |
| **5** | analyse d'URL | **pur, sans accès au coffre** : prend une chaîne, rend un verdict. Fonction libre, aucun état, aucune I/O |
| **5** | centre de sécurité | lecture seule sur `Archive` + `generator::entropy` de la phase 3. **Ne modifie rien**, n'écrit rien |
| **6** | interface graphique | crate `passlock-gui`, consommant `passlock-core` — **aucune logique de sécurité dupliquée** côté interface |
| **7** | durcissement et livrables | transverse : **aucun point d'insertion**, aucune extension fonctionnelle. Cette phase ne modifie pas l'architecture, elle en vérifie les limites |

**Aucune de ces extensions ne modifie le format du conteneur.** C'est la propriété qui
permet de faire évoluer le produit pendant des années sans casser une seule
sauvegarde. Les phases 1 à 3 l'ont vérifiée : la phase 2 a changé le **schéma du
corps**, la phase 3 n'a **rien** changé au format, et aucune n'a touché au conteneur.

**Deux extensions sortent du cadre « point d'insertion »** et doivent être signalées
comme telles :

* le **presse-papiers** (phase 4) n'entre pas dans le cœur : il appartient à
  `passlock-platform`, seul crate autorisé à utiliser `unsafe`. Le mettre dans le cœur
  romprait l'invariant « aucune primitive système dans le moteur cryptographique » ;
* la **liste des suffixes publics** (phase 5) est une **donnée embarquée**, pas un
  point d'insertion ni une dépendance de crate. **Décision prise** : elle suit le motif
  déjà établi pour les listes de mots — fichier verbatim sous
  `crates/passlock-core/data/public-suffix-list/`, embarqué par `include_str!`,
  empreinte SHA-256 épinglée par un test d'intégrité, provenance et licence
  (MPL-2.0) documentées dans `ATTRIBUTION.md`.

  Conséquence architecturale, et c'est l'intérêt de ce choix : **le graphe de crates du
  cœur reste inchangé**, et sa liste blanche de licences dans `deny.toml` reste exacte.
  Intégrer la PSL comme crate aurait fait entrer une licence de plus dans le graphe des
  dépendances exécutées — un coût sans contrepartie, puisqu'il s'agit de données
  statiques. Détail de la stratégie de mise à jour dans `ROADMAP.md` §5.4, et du trou
  de couverture de `cargo deny` dans `SECURITY.md` §6.3.
