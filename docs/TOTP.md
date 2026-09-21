# TOTP — modèle, conformité, limites

> Ce document décrit **ce que Passlock fait** en matière de TOTP, **ce qu'il ne peut
> pas faire**, et **comment ces affirmations sont vérifiées**.
>
> Règle de lecture : aucun élément n'est qualifié de « sûr ». Chaque propriété est
> énoncée avec l'adversaire et les conditions dans lesquelles elle tient, ou marquée
> **non vérifiée**.

---

## 1. Passlock est le prouveur, pas le validateur

La RFC 6238 définit deux rôles :

| Rôle | Qui | Ce qu'il fait |
|---|---|---|
| **Prouveur** | Passlock | Produit un code à partir d'un secret partagé et de l'heure |
| **Validateur** | Le serveur | Reçoit un code, le compare, décide |

Passlock n'implémente **que** le prouveur. Il n'y a ni fenêtre de tolérance, ni
comparaison de code reçu, ni resynchronisation.

**Conséquence directe, qui gouverne tout le reste :** la section 6 de la RFC 6238
(« Resynchronization ») décrit le comportement du **validateur**. Passlock ne peut
donc ni détecter ni corriger une dérive d'horloge — ce n'est pas une limite
d'implémentation, c'est une limite de rôle.

---

## 2. Paramètres

| Paramètre | Valeurs acceptées | Défaut | Source |
|---|---|---|---|
| Algorithme | SHA-1, SHA-256, SHA-512 | SHA-1 | RFC 6238 §1.2 : « TOTP implementations MAY use HMAC-SHA-256 or HMAC-SHA-512 […] instead of HMAC-SHA-1 » |
| Chiffres | 6, 8 | 6 | RFC 4226 §5.3 : « MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit » |
| Période | 1 à 600 s | 30 s | RFC 6238 §5.2 : « We RECOMMEND a default time-step size of 30 seconds » |
| Secret | 16 à 128 octets | 20 (160 bits) | RFC 4226 §4 R6 : « The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits » |

**Les chiffres à 7 sont refusés**, bien que la RFC 4226 les autorise. Motif : aucun
déploiement réel ne les utilise, et offrir une valeur jamais rencontrée élargirait la
surface de test sans bénéfice.

**Le type `hotp://` est refusé.** Son compteur n'est pas temporel, sa sémantique
diffère, et l'accepter « au cas où » créerait un chemin que rien n'éprouve.

---

## 3. Pourquoi SHA-1 est supporté

C'est le point qui sera mal lu si la justification n'est pas donnée, alors elle est
donnée verbatim.

**RFC 4226, appendice B.2 :**

> The new attacks on SHA-1 have no impact on the security of HMAC-SHA-1. […] HMAC is
> not a hash function. It is a message authentication code (MAC) that uses a hash
> function internally. […] What one needs to worry about with a MAC is forgery, not
> collisions.

**RFC 4226, appendice B.3 :**

> The security proof of HOTP requires that HMAC-SHA-1 behave like a pseudorandom
> function. The quality of HMAC-SHA-1 as a pseudorandom function is not impacted by
> the new attacks on SHA-1.

La règle de la phase 1 — « pas de SHA-1 » — vise SHA-1 comme **fonction de hachage**
et comme **fonction de dérivation de mot de passe**, où les collisions et la vitesse
comptent. Dans HMAC, l'attaque pertinente est la **falsification**, et les collisions
ne s'y transposent pas.

**Correction de précision.** Une note antérieure affirmait que « la RFC 6238 fait de
SHA-1 le défaut obligatoire pour l'interopérabilité ». **C'est faux.** La RFC 6238 ne
contient aucune phrase de ce type ; sa seule phrase sur le sujet est celle du §1.2
citée plus haut, et sa phrase réellement présente sur l'interopérabilité est « Keys
SHOULD be of the length of the HMAC output to facilitate interoperability ». La
justification de SHA-1 vient de la RFC 4226.

Par ailleurs, SHA-1 est ce que les serveurs déploient : le refuser rendrait la
fonction inutilisable.

---

## 4. Conformité : la preuve extérieure

Les tables de test sont reproduites **verbatim** depuis les RFC dans
`crates/passlock-core/tests/rfc_vectors.rs`. Elles ne disent pas « ce code fait ce
que son auteur attendait » mais « ce code fait ce que la norme prescrit ».

| Test | Source | Volume |
|---|---|---|
| HOTP | RFC 4226 appendice D | **10 vecteurs** (compteurs 0 à 9) |
| TOTP SHA-1 / SHA-256 / SHA-512 | RFC 6238 appendice B | **18 vecteurs** (3 algorithmes × 6 instants) |
| Base32 | RFC 4648 §10 | **7 vecteurs** |

Ces vecteurs couvrent notamment les deux pièges du protocole :

- le compteur `T` est encodé sur **huit** octets, jamais quatre — RFC 6238 §4.2
  l'exige au-delà de 2038 ;
- l'octet d'offset provient du **dernier** octet de l'empreinte HMAC, et
  `offset + 4 ≤ 19 < 20 ≤ longueur`.

**Ce que cette conformité ne prouve pas** : que le produit est sûr. Un TOTP conforme
n'est pas un coffre sûr. La conformité à une RFC est une condition nécessaire, jamais
suffisante.

---

## 5. Le secret, et où il vit

| Emplacement | Forme | Politique |
|---|---|---|
| **Au repos** | `Field { kind: Totp, value: "otpauth://…" }` | Chiffré par XChaCha20-Poly1305 dans l'archive |
| **Pendant le calcul** | `SecretVec` | Tampon verrouillé (`mlock`/`VirtualLock`), effacé au `Drop` |
| **L'empreinte HMAC** | `Zeroizing<[u8; 64]>` | Sur la pile, effacée à la sortie de `hotp` |
| **Le code produit** | `Zeroizing<String>` | Effacé à la destruction |

### Format de stockage

Le secret est stocké comme la **valeur d'un champ `otpauth://`** :

```
Field { key: "totp", kind: FieldKind::Totp, value: "otpauth://totp/…", … }
```

**Aucun changement de format n'a été nécessaire** : `FieldKind::Totp` existait depuis
la phase 2. Aucune montée de version, aucune migration, aucune fenêtre de
compatibilité.

Ce choix donne l'interopérabilité : l'URI `otpauth://` est le format d'échange de
fait, et ses paramètres (algorithme, chiffres, période) voyagent **avec** le secret —
les séparer risquerait de les désynchroniser.

`Field::new` impose `concealed: true` pour ce type, sans que l'appelant puisse le
contourner.

### Limite héritée

La valeur d'un champ est un `String` depuis la phase 2. **Un `String` ne s'efface pas
de façon fiable** : ses réallocations peuvent laisser des fragments dans le tas. Cette
limite est antérieure à la phase 3, elle n'est pas corrigée ici, et elle est
**documentée plutôt que passée sous silence**.

### Ce qui est refusé, et pourquoi

| Refus | Motif |
|---|---|
| Cache de codes entre invocations | Un code mis en cache survit à l'extinction du processus, dans un fichier que rien ne protège |
| Secret TOTP dans le trousseau système | Crée un **second chemin d'accès** au coffre, non protégé par le mot de passe maître |
| « Déverrouillage TOTP » sans mot de passe maître | Ferait du second facteur un moyen d'ouvrir le premier |
| Coffre TOTP séparé, à chiffrement plus faible | Même raison, sous une autre forme |
| Mode démon gardant la DEK en mémoire | Élargit la fenêtre d'exposition de la clé à la durée de vie de la machine |

**Conséquence pratique : aucun code n'est produisible sans déverrouillage.** Pour un
site demandant un code toutes les 30 s, cela impose un déverrouillage toutes les
30 s — inconfortable, et correct : la lenteur d'Argon2id (256 Mio, ~0,78 s) est
précisément ce qui protège le coffre. L'interface graphique (phase 6) résoudra le
confort par une session déverrouillée, pas en affaiblissant le modèle.

---

## 6. Horodatage et dérive d'horloge

### Le fond du problème

**Passlock n'a aucun moyen de savoir si l'horloge système est juste.** TOTP est un
protocole à secret partagé où le serveur est la seule référence temporelle.

**Aucune requête NTP, aucun appel réseau.** Le cœur n'a **aucune** dépendance réseau,
et c'est une propriété de sécurité de la phase 1. Une horloge réseau introduirait une
fuite d'information (le serveur consulté), une dépendance à un tiers, et une surface
de falsification — un NTP menteur décalerait tous les codes. Vérifier l'heure en
ligne dans un gestionnaire hors ligne serait une contradiction. Le paquet `keyring`
avait été écarté pour un motif voisin.

### Ce qui est fait à la place

| Mesure | Détail |
|---|---|
| **Temps injecté** | `code(&self, unix_time: u64)` : le cœur **ne lit jamais l'horloge**. Le CLI lit `SystemTime::now()` et le passe. Le module est donc déterministe, rejouable sur les vecteurs RFC |
| **Décompte affiché** | Secondes restantes dans le pas courant, toujours affichées |
| **Alerte de fin de pas** | Sous 5 secondes restantes, avertissement explicite |
| **Décalage manuel** | Réglage `totp_offset_seconds` dans `Archive::settings`, borné à ±3600 s. **Aucun changement de format** : le sac de réglages existait déjà |
| **Diagnostic** | `--at <horodatage>` produit le code d'un instant choisi, ce qui permet de **localiser** une dérive en comparant avec un autre outil |

### Ce qui n'est pas fait, faute de pouvoir le vérifier

**Aucune détection de saut d'horloge n'est revendiquée.** Un CLI vit quelques
millisecondes : comparer `Instant` et `SystemTime` sur cette durée ne détecte rien
d'utile. La comparaison a du sens dans une application longue (phase 6) et sera conçue
là, pas prétendue ici.

**Limite principale de cette phase, structurelle et non corrigeable hors ligne :**

> **Si l'horloge système est fausse, les codes sont faux, et Passlock ne peut pas le
> détecter.** L'utilisateur voit un code refusé et croit à une erreur du site.

Le remède est de corriger l'horloge de la machine, ou de renseigner un décalage
explicite avec `--at` pour diagnostic.

---

## 7. Surface d'entrée non fiable : l'URI `otpauth://`

L'analyseur traite du texte **authentifié mais non valide par construction** : il vient
d'un champ du coffre, donc l'AEAD l'a validé, mais il peut avoir été écrit par un
import (phase 4), par une version antérieure, ou forgé par quiconque détient la clé.

**Ce qui est refusé :** longueur > 2048 octets (vérifiée avant tout travail) ;
schéma autre que `otpauth` ; type autre que `totp` ; `secret` absent, vide, hors
alphabet Base32, ou donnant moins de 128 bits ; `secret` répété ; `digits` hors de
{6, 8} ; `period` hors de 1 à 600 ; `algorithm` inconnu ; séquence `%XX` malformée ;
**caractère de contrôle dans le libellé ou l'émetteur**.

**Ce qui est toléré :** les paramètres **inconnus sont ignorés**. Les URI réelles en
portent (`image=`, `lock=true`…) et les refuser rendrait l'analyse inutilisable.
Ignorer un paramètre inconnu n'est pas échouer ouvert : les paramètres connus sont
validés strictement.

### 7.1 Injection de séquences d'échappement dans le terminal

**Le risque le plus sous-estimé de cette phase.** Un libellé ou un émetteur peut
contenir une séquence ANSI. Imprimée telle quelle :

```
\x1b[2K\x1b[G  Code : 00000000     ← l'écran est réécrit, l'utilisateur lit un FAUX code
\x1b]0;pwned\x07                    ← le titre de la fenêtre est modifié
```

**Mesure :** refus des caractères de contrôle **à l'analyse**, et non échappement au
moment de l'affichage. Échapper à l'affichage serait une défense **au point d'usage**,
qu'un futur site d'affichage oublierait ; refuser à l'analyse est une défense **au
point d'entrée**, qui protège tous les usages présents et futurs.

Même logique que la phase 2 : *le lieu d'une vérification est lui-même une propriété
de sécurité.*

---

## 8. Affichage et copie

### Affichage

```
$ passlock totp COFFRE 1b0bc070…
174028
```
Le **code** va sur la sortie standard ; le **libellé, le décompte et les
avertissements** vont sur la sortie d'erreur. `passlock totp … > fichier` écrit donc
exactement le code.

`--json` produit une sortie exploitable par un script. **Le JSON ne contient jamais
de secret à longue durée de vie** : ni le secret partagé, ni l'URI.

### Copie : abandonnée par le gate E.0

Le presse-papiers est le canal le plus dangereux du produit, parce qu'il est
**public par conception**.

| Risque | Réalité |
|---|---|
| Lecture par toute application | Sous X11, n'importe quel client lit la sélection sans permission ni journal — **structurel**, aucun avertissement ne le corrige |
| Persistance après fermeture | Le presse-papiers survit à Passlock ; un gestionnaire d'historique peut en conserver des dizaines |
| Synchronisation entre machines | Transforme un secret local en secret réseau |
| Capture d'écran | Hors de portée du logiciel |

La conception qui avait été retenue — durée de vie **jamais supérieure au temps restant
du code**, vérification avant écrasement, effacement à la sortie y compris sur erreur,
avertissement **à la première utilisation par session** — **n'a pas été implémentée**.

**La copie vers le presse-papiers est abandonnée** par le gate E.0
(`docs/AUDIT_PHASE4_5_CLIPBOARD.md`, ADR-037) : `arboard 3.6.1` aurait exigé d'élargir la
liste de licences et d'affaiblir `multiple-versions` de `deny.toml`. Aucune dépendance
clipboard n'a été ajoutée, aucun contrôle de chaîne d'approvisionnement n'a été assoupli.
Le raisonnement de ce paragraphe reste : le presse-papiers est un canal public par
conception, et aucune garantie de sécurité n'aurait été possible. **Le code TOTP n'est donc
jamais copié automatiquement** ; l'utilisateur reste seul responsable de ce qu'il en fait.

### Ce qui n'est jamais fait

- Le code n'est **jamais journalisé** : ni dans le journal d'audit, ni dans un fichier
  de trace, ni dans un message d'erreur.
- Le type `Error` n'accepte que des `&'static str`, ce qui rend l'insertion d'un
  secret **impossible à écrire**, et pas seulement déconseillée.
- Aucun secret n'est accepté **en argument de commande** : un argument est visible
  dans `ps` et dans `/proc/<pid>/cmdline`.

**Attention à l'ordre sur l'entrée standard.** Avec `--password-stdin`, le mot de
passe maître est lu **en premier**, puis le secret TOTP. Fournir le secret seul ferait
consommer celui-ci comme mot de passe maître.

---

## 9. Tests

| Fichier | Contenu |
|---|---|
| `tests/rfc_vectors.rs` | Les 35 vecteurs officiels (10 HOTP + 18 TOTP + 7 Base32) |
| `tests/otpauth_adversarial.rs` | 20 000 entrées aléatoires, toutes les troncatures, injections terminales, bornes exactes, aller-retour complet |
| `tests/secret_inventory.rs` | Inventaire des copies, absence de secret dans `Debug`, `Display` et messages d'erreur |
| `src/totp.rs` (tests unitaires) | Analyse d'URI, bornes, caractères de contrôle, `Debug` |

**Vérification de bout en bout effectuée** : le secret de test de la RFC 6238,
enregistré dans un coffre chiffré, relu, décodé et transmis au calcul, produit
exactement `94287082 / 07081804 / 14050471 / 89005924 / 69279037 / 65353130` sur
l'algorithme SHA-1 à huit chiffres.

---

## 10. Ce que ce document ne prétend pas

- **La conformité aux vecteurs RFC prouve la conformité à la RFC**, pas la sécurité
  du produit.
- **Aucun test vert n'est une preuve de sécurité.** Il prouve que les propriétés
  écrites tiennent ; les propriétés non écrites ne sont pas couvertes.
- **La détection de dérive d'horloge n'est pas vérifiée** — elle n'est pas
  revendiquée (§6).
- **Le comportement Windows des tests n'est pas vérifié** : compilation croisée
  seulement.
- **L'exhaustivité de l'analyse par les outils** est limitée : Miri ne supporte pas
  `getrandom`, ce qui exclut les tests exigeant l'aléa du noyau.
