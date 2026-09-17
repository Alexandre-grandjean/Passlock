# Audit sémantique du magasin — phase 2

> Vérifie les **invariants métier** de `VaultStore` : ce que les opérations
> promettent, indépendamment de la manière dont elles l'implémentent.
>
> Ne couvre **pas** la cryptographie, le format ni les performances : voir
> `AUDIT_PHASE1.md` et `AUDIT_PHASE2.md`.

---

## 1. Méthode : un modèle de référence, pas les fixtures existantes

Les tests de `store.rs` vérifient des scénarios écrits à la main, avec les mêmes
helpers et les mêmes hypothèses que le code qu'ils éprouvent. **Ils partagent donc ses
angles morts** : ce que l'auteur n'a pas imaginé n'y est pas testé.

`tests/semantic_model.rs` prend le problème par l'autre bout :

1. un **modèle de référence** en quelques dizaines de lignes décrit la sémantique
   attendue — des `Vec`, des `BTreeMap`, aucune cryptographie, aucun fichier. Il est
   écrit pour être **évidemment correct**, pas pour être efficace ;
2. un générateur produit des **séquences aléatoires d'opérations**, y compris hostiles
   (identifiants inexistants, répétitions, références pendantes) ;
3. après **chaque** opération, le comportement du magasin est comparé à celui du
   modèle, et les invariants structurels sont revérifiés.

**Le modèle ne partage aucune ligne avec l'implémentation.** C'est ce qui en fait un
oracle plutôt qu'un miroir.

### Volume exécuté

| Campagne | Volume |
|---|---|
| Séquences longues | **60 graines × 150 opérations** = 9 000 opérations, comparées une à une |
| Séquences courtes | **40 graines × 12 opérations** = 480 opérations (états peu peuplés) |
| Invariants ciblés | 18 tests dédiés |
| **Total** | **~9 500 opérations** et 20 tests |

### Reproduction d'un échec

Le générateur est **déterministe** : un échec affiche la séquence complète avec
l'indice de l'opération fautive, et la graine permet de rejouer le cas à l'identique.

### Compromis assumé : pas de « shrinking »

Les cadriciels de tests par propriétés réduisent automatiquement un cas d'échec à sa
plus petite forme. Ici, l'échec donne la séquence complète, à réduire à la main.
C'est le prix de l'absence de dépendance de test. En pratique, les trois défauts
trouvés se réduisaient à une ou deux opérations.

---

## 2. Couverture des catégories demandées

### 2.1 CRUD

| Cas | Couvert par | Résultat |
|---|---|---|
| Création | `i1` (500 créations), séquences | conforme au modèle |
| Modification | `i3` (150 modifications), séquences | conforme |
| Suppression (corbeille) | `i10`, séquences | conforme |
| Restauration | `i10`, séquences | conforme |
| Purge | `i18`, séquences | conforme |
| Répétition des opérations | `i10` (5 répétitions par opération) | voir §3.1 |
| Entrée inexistante | `i15`, `OperateOnMissingEntry` | **toutes** les opérations échouent |

### 2.2 Historique

| Cas | Couvert par | Résultat |
|---|---|---|
| Ordre chronologique | `i3`, `i14` | conforme |
| Limite de 50 révisions | `i3` (450 modifications) | plafond appliqué |
| Limite de 90 jours | tests unitaires de `migrate` | appliquée |
| Purge | `i18`, séquences | conforme |
| Restauration d'une ancienne version | **NON IMPLÉMENTÉ** — voir §5 | — |
| Suppression d'une entrée avec historique | `i18` | historique emporté |
| Pas de révision fantôme après échec | `i4` | conforme |

### 2.3 Corbeille

| Cas | Couvert par | Résultat |
|---|---|---|
| Entrée active ≠ supprimée | `i5`, modèle | conforme |
| Restauration | `i10` | conforme |
| Purge définitive | `i18`, `i13` | conforme, y compris après réouverture |
| Recherche dans / hors corbeille | `i5` | conforme |
| Filtres CLI | corrigé pendant la phase 2 (défaut D4) | conforme |

### 2.4 Dossiers et tags

| Cas | Couvert par | Résultat |
|---|---|---|
| Référence vers objet inexistant | `i4`, variantes « fantômes » | **refusée** |
| Suppression d'un dossier utilisé | `i9` | **impossible** — l'API n'expose pas la suppression de dossier |
| Doublons | `i4`, `i16`, séquences | refusés, insensible à la casse |
| Cycles impossibles | `i7` | impossibles par construction de l'API |
| Entrée dans plusieurs tags | `i8` | conforme |
| Renommage | **NON IMPLÉMENTÉ** — voir §5 | — |
| Suppression | **NON IMPLÉMENTÉE** — voir §5 | — |

### 2.5 Atomicité

`i4` exécute **dix opérations vouées à l'échec** — dossier fantôme, tag fantôme, titre
hors bornes, échec volontaire de la closure, opérations sur un identifiant absent,
doublon de dossier — et compare l'archive **bit à bit** avant et après.

**Résultat :** l'archive est identique. Aucune mutation partielle.

La comparaison porte sur l'encodage complet, et non sur quelques champs choisis : un
écart dans une révision, un compteur d'historique ou un événement de journal serait
détecté.

### 2.6 Transactions et reprise après incident

| Scénario | Couvert par | Résultat |
|---|---|---|
| Échec **avant** écriture | `i11` (répertoire inaccessible) | coffre inchangé |
| Coffre interrompu (tronqué) | `i12` | refusé proprement, **la sauvegarde restaure l'état** |
| Restauration d'une sauvegarde | `i12` | état d'origine retrouvé à l'identique |
| Mutations non enregistrées | `i13` | **perdues — par contrat, testé comme tel** |
| Aller-retour par le fichier | `i14` (30 entrées, 10 modifications) | archive **identique octet pour octet** |
| Échec **pendant** l'écriture | couvert en phase 1 (`interrupted_writes_…`) | coffre jamais partiel |

### 2.7 Idempotence

`i10` distingue explicitement deux contrats. Voir §3.1 pour la décision.

### 2.8 Propriétés invariantes

Vérifiées **après chaque opération** de chaque séquence, et par les tests ciblés.

---

## 3. Décisions que la campagne a mises en évidence

### 3.1 Toutes les opérations ne doivent pas être idempotentes

La campagne force à trancher, et le résultat est consigné ici.

| Opération | Idempotente ? | Pourquoi |
|---|---|---|
| `trash_entry` | **oui** | converge vers un état : la répéter ne change rien. C'est ce qui rend une reprise après incident possible |
| `restore_entry` | **oui** | idem |
| `purge_history` | **oui** | l'historique vidé le reste ; retourne `0` la seconde fois |
| `update_entry` | **non, délibérément** | deux appels = deux modifications = deux révisions. Rendre l'opération idempotente perdrait une modification légitime |
| `add_entry` / `add_folder` / `add_tag` | **non** | chaque appel crée un objet neuf |
| `empty_trash` | **oui** | retourne `0` sur une corbeille vide |
| `purge_entry` sur une entrée **absente** | **non** — échoue | Voir ci-dessous |

**L'asymétrie `trash` / `purge` est délibérée et mérite d'être expliquée.** `trash` est
réversible : réussir sur une entrée déjà à la corbeille est sans conséquence. `purge`
est **irréversible** : signaler que la cible n'existe pas est une information utile —
elle indique que l'identifiant fourni ne désigne rien, donc qu'aucune suppression n'a
eu lieu, donc que l'utilisateur n'a probablement pas visé ce qu'il croyait.

L'alternative — réussir silencieusement — rendrait la reprise sur erreur plus simple,
au prix de masquer une erreur de cible. Le compromis a été tranché en faveur du signal,
et il est désormais **explicite** au lieu d'être un effet de bord.

### 3.2 Une référence d'audit peut légitimement pendre

`i6` constate qu'un événement de journal peut désigner une entrée **supprimée**
depuis. Ce n'est pas un défaut : le journal consigne **qu'un** événement a eu lieu, et
l'entrée peut avoir disparu ensuite.

L'invariant correct n'est donc pas « toute référence d'audit existe », mais « le
journal reste bien formé et borné ». C'est ce que vérifie `check_invariants`.

### 3.3 Les cycles de dossiers sont impossibles **par construction**, pas par vérification

`i7` le constate : `add_folder` n'accepte comme parent qu'un dossier **déjà existant**,
et un dossier ne peut pas être son propre parent puisqu'il n'existe pas encore au
moment de sa création.

`Archive::validate` détecte malgré tout les cycles, parce qu'un corps forgé par une
autre implémentation pourrait en contenir. **Deux protections, à deux niveaux** : la
construction rend le cas impossible, la validation le refuse s'il survient.

---

## 4. Invariants : verdict

| # | Invariant | Vérifié par | Verdict |
|---|---|---|---|
| I1 | Aucun identifiant dupliqué (entrées, dossiers, tags) | `i1` (500 créations), `check_invariants` après chaque opération | **VERIFIED** |
| I2 | Aucune référence orpheline (dossier, tags) | `i2`, `i4`, `i17`, `check_invariants` | **VERIFIED** |
| I3 | Aucun historique impossible (plafond, instantané non récursif) | `i3`, `i18`, `check_invariants` | **VERIFIED** |
| I4 | Aucun objet supprimé encore référencé | `i2`, `i18` | **VERIFIED** |
| I5 | Le journal reste bien formé et borné | `i6`, `check_invariants` | **VERIFIED** |
| I6 | Aucune mutation partielle après un échec | `i4` (10 opérations refusées, comparaison bit à bit) | **VERIFIED** |
| I7 | Le modèle prédit le résultat de chaque opération | 9 500 opérations comparées | **VERIFIED** |
| I8 | L'aller-retour par le fichier ne change rien | `i14`, `Reopen` dans les séquences | **VERIFIED** |
| I9 | Un coffre tronqué est refusé, la sauvegarde restaure | `i12` | **VERIFIED** |
| I10 | Les mutations non enregistrées sont perdues | `i13` | **VERIFIED** (comportement conforme au contrat) |
| I11 | `trash`/`restore`/`purge_history` idempotentes ; `update` non | `i10` | **VERIFIED** |
| I12 | Un coffre vide supporte toutes les opérations | `i15` | **VERIFIED** |
| I13 | Les bornes de longueur sont exactes | `i16` | **VERIFIED** |
| I14 | Une création annonce un objet qui existe | `i17` | **VERIFIED** |
| I15 | Les cycles de dossiers sont impossibles par construction | `i7` | **VERIFIED** |
| I16 | La recherche reflète corbeille et archivage | `i5` | **VERIFIED** |
| I17 | Aucun identifiant fantôme après création refusée | séquences (adoption/annulation) | **VERIFIED** |
| I18 | Une entrée purgée ne réapparaît pas après réouverture | `i18` | **VERIFIED** |

**Aucun invariant n'est PARTIALLY ou NOT VERIFIED.**

---

## 5. Ce que la campagne n'a **pas** éprouvé

Il faut le dire aussi précisément que ce qui a été vérifié.

1. **Restauration d'une ancienne version d'une entrée.** L'historique **conserve** les
   instantanés, mais **aucune opération ne les restaure** : il n'existe pas de
   `revert_to_revision`. La capacité est donc *stockée* sans être *exploitable*.
   L'interface devra l'ajouter, et ce sera une opération délicate — elle crée une
   modification à partir d'un état ancien, et doit produire sa propre révision.
2. **Renommage et suppression de dossier.** Non implémentés. Conséquence notable :
   **aucune référence orpheline ne peut apparaître par ce chemin**, ce que `i9`
   constate. Le jour où la suppression sera ajoutée, elle devra soit refuser un
   dossier occupé, soit réaffecter ses entrées — et cette décision n'est pas prise.
3. **Renommage et suppression de tag.** Même situation, mêmes conséquences.
4. **Séquences concurrentes.** Le modèle de concurrence est « propriété unique,
   `&mut self` » : la question ne se pose pas au niveau du magasin. Le verrou
   inter-processus est éprouvé en phase 1.
5. **Comportement sous Windows.** Le harnais compile pour Windows, mais ne s'y exécute
   pas — voir `AUDIT_PHASE2.md` §5.
6. **Ordre chronologique de l'historique sous 90 jours de rétention.** Les tests
   unitaires de `migrate` couvrent la borne ; les séquences aléatoires, non : elles
   s'exécutent en quelques secondes et ne franchissent jamais 90 jours.

---

## 6. Défauts trouvés par cette campagne

**Aucun défaut dans le magasin.** Trois défauts dans le **harnais lui-même**, ce qui
est le résultat le plus instructif : un oracle faux valide n'importe quoi.

| # | Défaut du harnais | Comment il s'est manifesté |
|---|---|---|
| 1 | **Ordre d'opérations inversé** : l'identifiant d'une entrée créée était réconcilié **avant** que le modèle ne la contienne | dépassement d'entier immédiat (`len() - 1` sur un vecteur vide). Réparé en réservant l'emplacement avant l'appel, puis en l'adoptant ou l'annulant |
| 2 | **Opération réussie dans une liste d'opérations devant échouer** : `add_folder("duplicat")` était appelé une première fois, ce qui modifiait légitimement l'archive, avant que le test n'accuse le magasin d'avoir changé | comparaison bit à bit en échec, à juste titre. Réparé en créant le témoin **avant** la photographie de référence |
| 3 | **Assertion affichant le buffer entier** dans un message d'échec, ce qui aurait déversé un corps de coffre dans le journal de la CI | corrigé : les messages n'affichent plus que des **positions** |

**Ce que cela dit du magasin.** Les 9 500 opérations comparées au modèle n'ont produit
**aucune divergence**. Le comportement observé correspond à la sémantique attendue sur
l'ensemble des séquences, y compris hostiles.

**Ce que cela ne dit pas.** Un modèle écrit par le même auteur que l'implémentation
partage ses intuitions. Les invariants vérifiés sont ceux que j'ai su formuler ; ceux
que je n'ai pas imaginés ne sont pas couverts. Et un test vert ne prouve pas la
sécurité — il prouve que les propriétés écrites tiennent.

---

## 7. Risques résiduels issus de cette campagne

| # | Risque | Traitement |
|---|---|---|
| S1 | L'historique est stocké mais **aucune opération ne le restaure** | à implémenter avec la couche qui l'affiche ; l'opération devra produire sa propre révision |
| S2 | La suppression d'un dossier ou d'un tag n'existe pas : la décision « refuser ou réaffecter » n'est pas prise | à trancher lors de l'implémentation |
| S3 | `purge_entry` échoue sur une cible absente, ce qui complique une reprise automatique | choix délibéré, documenté en §3.1 ; pourrait devenir configurable |
| S4 | La rétention à 90 jours n'est pas exercée par les séquences aléatoires | couverte par les tests unitaires de `migrate` |
| S5 | Le harnais s'exécute en 28 secondes : il ralentit sensiblement la suite complète | assumé — il s'agit d'un harnais d'audit, pas d'un test unitaire |

---

## 8. Verdict

**Tous les invariants formulés sont VERIFIED.** Aucune divergence entre le modèle de
référence et le magasin sur 9 500 opérations, y compris hostiles.

**Aucune modification de l'architecture, de la cryptographie ou du format n'a été
nécessitée par cette campagne** — conformément à la consigne, rien n'a été changé
puisque rien de défaillant n'a été trouvé.

Les trois défauts corrigés étaient dans le **harnais**, et les deux premiers
rappellent qu'un oracle doit être aussi soigneusement éprouvé que le code qu'il juge.
