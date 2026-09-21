# Attribution de la liste des suffixes publics

Le fichier `public_suffix_list.dat` est **embarqué verbatim** dans le binaire
(`include_str!` depuis `crates/passlock-core/src/psl.rs`). Il est du contenu tiers,
sous licence, et sa provenance est vérifiable : son empreinte SHA-256 est **épinglée**
dans `crates/passlock-core/tests/public_suffix_integrity.rs`.

Il est **public par construction** : il ne contient aucun secret.

---

## 1. Provenance

| | |
|---|---|
| **Fichier** | `public_suffix_list.dat` |
| **Nom** | Public Suffix List |
| **Source** | <https://publicsuffix.org/list/public_suffix_list.dat> |
| **Dépôt** | <https://github.com/publicsuffix/list> |
| **Fichier amont** | `public_suffix_list.dat`, à la racine du dépôt |
| **Révision (commit SHA)** | `645b36c9a51ff0b3718df0ba02f6570aa6921632` |
| **Récupéré le** | 2026-09-20 (UTC) |
| **Taille** | 334 227 octets, 16 481 lignes |
| **SHA-256** | `d3fba7b2934b0e1b9c958baf42bef85107b53cd0115ff7e81a7e61c7119a36d0` |
| **Fins de ligne** | LF uniquement, verbatim (aucune conversion) |
| **Encodage** | UTF-8, verbatim |
| **Licence** | **MPL-2.0** — voir la tête du fichier et le dépôt amont |

## 2. Empreinte : comment elle est calculée et vérifiée

L'empreinte est celle du fichier **tel qu'il est versionné**, octet pour octet :

```sh
sha256sum public_suffix_list.dat
# d3fba7b2934b0e1b9c958baf42bef85107b53cd0115ff7e81a7e61c7119a36d0
```

`crates/passlock-core/tests/public_suffix_integrity.rs` recalcule cette empreinte sur
le fichier embarqué et **échoue** si elle diffère. Il vérifie aussi la taille, le nombre
de lignes cumulées et la présence des deux sections (ICANN et PRIVATE).

## 3. Licence

La Public Suffix List est distribuée sous **MPL-2.0**. Elle est intégrée comme **donnée
embarquée verbatim**, **non comme dépendance de crate** : le graphe de crates du cœur
reste donc **inchangé**, et la liste blanche de licences de `deny.toml`
(`MIT`, `Apache-2.0`, `BSD-3-Clause`) **n'est pas élargie**.

**Ce que cela implique, énoncé sans détour.** `cargo deny` **ne couvre pas** les données
embarquées : il vérifie les licences des *crates*, pas des fichiers livrés. Cette
conformité repose donc sur une **vérification manuelle**, pas sur un outil. Un
`ATTRIBUTION.md` peut être faux sans que rien ne le signale — c'est précisément ce que la
limite **L24** consigne. Le fichier distribué conservant sa licence d'origine, la licence
du projet reste **MIT**. **Cette appréciation est technique, pas juridique.**

## 4. Mise à jour

**Aucune mise à jour automatique, à aucun moment.** Ni au build, ni à l'exécution, ni par
un rafraîchissement périodique : la propriété « aucun réseau » du projet est
**constitutive**.

La liste est **ré-embarquée par un commit revu**, qui met à jour le commit amont, la date
de récupération, la taille et l'empreinte ci-dessus. Le test d'intégrité **échoue** tant
que l'empreinte n'a pas suivi.

**L'âge de la liste est une donnée publique** : la date de récupération est consignée
ici, et un suffixe absent de la liste produit un regroupement **incertain** plutôt qu'un
verdict ferme (limite **L25**).
