# Sauvegardes et restauration

> Une sauvegarde jamais restaurée n'est pas une sauvegarde : c'est une copie de fichier
> dont personne ne sait si elle s'ouvre.

## 1. Ce qu'est une sauvegarde

**Un couple de chemins.**

```
<DESTINATION>                 le fichier de coffre, tel quel
<DESTINATION>.attachments/    les blobs des pièces jointes référencées
```

**Aucun format nouveau, aucune archive, aucun manifeste.** Le fichier produit est un
coffre : `info`, `verify`, `attach list` et `attach verify` l'ouvrent sans une ligne de
code supplémentaire.

**Pourquoi pas une archive unique.** Elle exigerait une dépendance (`zip`, `tar`,
`flate2` ne sont pas dans l'arbre) ou un conteneur maison — c'est-à-dire un **nouveau
format cryptographique**, avec sa surface d'attaque et son audit à refaire.

**Pourquoi pas de manifeste.** Ce serait un **second état**, susceptible de diverger du
contenu réel. Le projet refuse déjà les digestes globaux pour cette raison (ADR-022) :
l'intégrité se vérifie en **déchiffrant**, pas en comparant un résumé.

**Conséquence, énoncée plutôt que découverte :** une sauvegarde du seul fichier de coffre
ne préserve **pas** les pièces jointes. `backup create` le dit, `backup verify` le
détecte, et il n'existe aucun mode qui produirait silencieusement la moitié de l'ensemble.

## 2. Créer une sauvegarde

```sh
passlock backup create COFFRE sauvegardes/2026-09-17.plk
```

Ce que la commande fait, dans cet ordre :

1. elle ouvre le coffre **en lecture seule** et **sous verrou exclusif** ;
2. elle énumère ce qui doit être copié — le coffre, puis les blobs référencés, en lisant
   leur taille réelle ;
3. elle copie, **en flux**, chaque membre vers une destination créée en **exclusif** ;
4. elle rend chaque fichier durable (`fsync` du fichier, puis de son répertoire) ;
5. elle **vérifie la copie** — elle l'ouvre, décode son archive, et déchiffre chaque
   pièce jointe ;
6. si la vérification refuse la copie, elle **retire ce qu'elle a créé**.

### Pourquoi le verrou

L'écriture d'un conteneur est atomique : un lecteur voit toujours un fichier complet. Mais
une sauvegarde n'est pas un fichier, c'est un **ensemble**. Entre la copie du coffre et
celle des blobs, un écrivain concurrent pourrait ajouter une pièce jointe : la sauvegarde
contiendrait alors un coffre référençant un blob absent.

Le verrou gèle l'ensemble pendant toute la copie. Un écrivain concurrent est refusé ; un
lecteur ne l'est pas.

### Ce qui n'est pas revendiqué : l'atomicité de destination

La destination est écrite **en place**, pas dans un couple temporaire + renommage. C'est
le prix de `O_EXCL`, qui ferme toute fenêtre entre le contrôle d'existence et la création.

**Trois issues, dont deux seulement sont des garanties :**

| Issue | Ce qui est garanti |
|---|---|
| **Succès** | la paire est présente, complète et **vérifiée** |
| **Erreur contrôlée** | ce qui a été créé est retiré — et **rien d'autre** |
| **Interruption brutale** | **aucune garantie.** Une destination partielle peut subsister |

Une destination partielle **occupe le chemin** : une nouvelle tentative échoue, et le
reliquat doit être supprimé explicitement. Écraser silencieusement serait pire que
refuser. Une destination partielle **échoue à `backup verify`** — c'est ce qui distingue
une sauvegarde d'un fichier quelconque.

## 3. Tester une sauvegarde

```sh
passlock backup verify sauvegardes/2026-09-17.plk [--password-stdin] [--key-file …]
```

L'ouverture se fait par le **même chemin de déverrouillage** que le reste du produit : mot
de passe maître, clé de récupération ou fichier-clé.

**Aucun effet persistant.** Le test :

* ne crée **aucun** fichier — pas même un verrou ;
* ne **répare** pas les permissions du fichier testé ;
* n'écrit **aucune** sentinelle ;
* ne modifie pas la sauvegarde.

Ce n'est pas une discipline d'appelant : la configuration reçue est **écrasée** dans le
code testé, de sorte qu'aucun appelant ne puisse obtenir un effet persistant.

### Deux verdicts, séparés

**Intégrité** — la seule source de succès ou d'échec. La sauvegarde s'ouvre, son archive
se décode, **chaque pièce jointe est déchiffrée et authentifiée**, et le répertoire de
blobs est présent quand il le faut. Un défaut ⇒ code de retour non nul, avec la liste des
motifs.

**Ancienneté** — une **information**, jamais une erreur. Une sauvegarde est forcément
antérieure à l'état courant : restaurer une sauvegarde ancienne est **légitime**.

| Verdict | Signification |
|---|---|
| *au moins aussi récente* | l'état le plus récent connu de ce coffre |
| *antérieure* | elle date d'avant le dernier état connu — **normal** |
| *indéterminée* | aucune référence sur cette machine — **normal** pour une sauvegarde testée ailleurs |

**Pourquoi deux verdicts et non un seul.** Le retour en arrière (T14) se **détecte** par
la sentinelle, mais peut aussi se **légitimer** par une restauration. Les confondre ferait
apprendre à ignorer l'alerte ; taire l'ancienneté ferait perdre la seule détection
disponible. La sauvegarde indique donc l'ancienneté, l'ouverture décide.

### Paramètres de dérivation

Le test affiche les paramètres du slot maître **lus dans le fichier**, et signale ceux qui
sont inférieurs au profil par défaut actuel. Une sauvegarde ancienne fige d'anciennes
valeurs : le dire permet de les durcir après restauration.

## 4. Restaurer

**Aucune commande ne le fait.** Restaurer écrase un coffre vivant : c'est précisément
l'opération qu'il ne faut pas pouvoir déclencher par une faute de frappe. La procédure est
donc documentée — et rappelée par `backup verify`, avec les deux chemins exacts.

```sh
# 1. Fermez toute instance qui utilise le coffre.

# 2. Sauvegardez l'état actuel, au cas où.
cp coffre.plk            coffre.plk.avant-restauration
cp -a coffre.plk.attachments coffre.plk.attachments.avant-restauration

# 3. Restaurez, en DEUX copies.
cp    sauvegardes/2026-09-17.plk               coffre.plk
cp -a sauvegardes/2026-09-17.plk.attachments   coffre.plk.attachments

# 4. Vérifiez.
passlock backup verify sauvegardes/2026-09-17.plk
passlock verify --password-stdin coffre.plk
```

**Les deux lignes de l'étape 3 sont nécessaires.** La première seule donne un coffre dont
les pièces jointes manquent : `attach verify` le signalera comme une incohérence
d'intégrité, et les pièces jointes seront **introuvables** — pas silencieusement absentes.

Si le coffre restauré n'avait aucune pièce jointe, la seconde ligne est sans objet.

### Après restauration

* **L'alerte de retour en arrière se déclenchera** : la génération restaurée est
  antérieure à celle de la sentinelle. C'est le comportement voulu, pas une compromission —
  et c'est aussi ce qui **détecte** une restauration non désirée.
* Si les paramètres de dérivation sont plus faibles que le profil actuel,
  `change-password` permet de les durcir.
* Une sauvegarde n'est pas un effacement : les données restaurées peuvent subsister dans
  le coffre remplacé, dans les journaux du système de fichiers et dans toute sauvegarde
  antérieure.

## 5. Ce qu'une sauvegarde protège — et ne protège pas

| Protège | Ne protège pas |
|---|---|
| perte du fichier de coffre | perte simultanée de la sauvegarde et de son répertoire de blobs |
| corruption logique du coffre | corruption **présente dans la sauvegarde** (le test la détecte, la création refuse d'en produire) |
| suppression accidentelle d'une entrée | vols de support : la sauvegarde est chiffrée sous les mêmes clés |
| perte du répertoire `state_dir` (non copié) | modification du disque par un tiers |
| — | effacement définitif : la suppression n'est jamais physique |

Une sauvegarde **chiffrée** reste chiffrée : elle n'est lisible qu'avec les mêmes
identifiants. Si tous les identifiants sont perdus, la sauvegarde ne les retrouve pas.
