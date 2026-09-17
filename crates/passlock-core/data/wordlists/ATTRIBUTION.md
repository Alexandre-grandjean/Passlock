# Attribution des listes de mots

Les deux listes ci-dessous sont **embarquées verbatim** dans le binaire
(`include_str!` depuis `crates/passlock-core/src/wordlist.rs`). Elles sont du
contenu tiers, sous licence, et leur provenance est vérifiable : les empreintes
SHA-256 sont épinglées dans `crates/passlock-core/tests/wordlist_integrity.rs`.

Ces listes sont **publiques par construction**. Elles ne contiennent aucun secret,
et ne doivent jamais en contenir : un mot de la liste n'est pas confidentiel, seule
la **combinaison** tirée l'est.

---

## 1. Liste EFF (anglais)

| | |
|---|---|
| **Fichier** | `eff_large_wordlist.txt` |
| **Source** | <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt> |
| **Page de référence** | <https://www.eff.org/document/passphrase-wordlists> |
| **Auteur** | Electronic Frontier Foundation |
| **Licence** | CC BY (voir <https://www.eff.org/copyright>) |
| **Taille** | 108 800 octets, 7776 lignes |
| **SHA-256** | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` |
| **Récupérée le** | 2026-09-16 |
| **Format** | `NNNNN<TAB>mot`, clés de `11111` à `66666` (cinq jets de dé) |

**Entropie par mot** : `log₂(7776) = 12,9248` bits. Six mots donnent **77,55 bits**.

La liste EFF est conçue pour la mémorabilité : elle écarte délibérément les mots
rares, les bigrammes difficiles et les symboles. Ses 7776 entrées contiennent
**toutes** au moins une lettre.

---

## 2. Liste Diceware française

| | |
|---|---|
| **Fichier** | `diceware-fr-5-jets.txt` |
| **Source** | <https://raw.githubusercontent.com/chmduquesne/diceware-fr/master/diceware-fr-5-jets.txt> |
| **Dépôt** | <https://github.com/chmduquesne/diceware-fr> |
| **Auteur** | Christophe-Marie Duquesne |
| **Licence** | **CC-BY-3.0** (mentionnée explicitement dans le README du dépôt) |
| **Taille** | 91 466 octets, 7776 lignes |
| **SHA-256** | `49ef76a9379fed2781db30d08c1bd2ed3ccec9b13d372f183c42b2e97a95bd8b` |
| **Récupérée le** | 2026-09-16 |
| **Format** | `NNNNN mot`, **séparateur espace** (et non tabulation), clés de `11111` à `66666` |

**Entropie par mot** : `log₂(7776) = 12,9248` bits. Six mots donnent **77,55 bits**.

### Entrées sans lettre : ce ne sont pas des remplissages

**240 des 7776 entrées ne contiennent aucune lettre.** Le premier réflexe est d'y
voir des marqueurs de remplissage — l'inspection des premiers octets montre
`11111 =`, `11112 ==`, `11113 ===`. **Ce serait une erreur de conclusion.** La
liste complète de ces 240 entrées montre qu'il s'agit d'éléments **authentiques de
la méthode Diceware**, qui inclut délibérément des chiffres et de la ponctuation
pour couvrir un jeu de caractères plus large :

- ponctuation : `=`, `-`, `--`, `:-)`, `!`, `??`, `@`, `$$`, `*`, `&`, `#`, `%`, `+` ;
- nombres et années : `0` à `9`, `10`, `100`, `1492`, `1900`, `1975`, `2020`, `9876`,
  `5555`, `1234`, `4321`.

La liste originale de Reinhold suit la même structure. Ces entrées sont donc
**conservées par défaut**, et `W = 7776`.

**Vérifié** : les 7776 clés forment exactement l'ensemble `11111`–`66666`, sans trou,
sans doublon, et les 7776 mots sont tous distincts.

### Filtrage optionnel

`--letters-only` écarte ces 240 entrées et ramène `W` à **7536**, soit
`log₂(7536) = 12,8796` bits par mot — une perte de **0,045 bit par mot**, donc
**0,27 bit sur six mots**. Le coût est négligeable ; le choix revient à
l'utilisateur, et l'entropie affichée reflète toujours la liste **effectivement
utilisée**.

---

## 3. Ce que ces listes ne garantissent pas

- **Leur qualité linguistique** n'est pas vérifiée depuis ce projet. Un mot difficile
  à orthographier ou peu familier reste dans la liste.
- **L'absence de biais dans leur construction d'origine** n'est pas vérifiée. Le
  projet vérifie le compte, le format, l'unicité et l'empreinte — pas la méthode de
  sélection qui a produit la liste à la source.
- **Leur contenu n'est pas normalisé.** Les deux listes sont purement ASCII : aucun
  accent, aucune forme Unicode composée. C'est un avantage (une même lettre accentuée
  a deux encodages Unicode possibles, ce qui créerait des ambiguïtés) mais cela
  signifie aussi que le vocabulaire français est volontairement restreint.

---

## 4. Conformité des licences

Ces deux listes sont sous **CC-BY 3.0**, qui exige une attribution. Elle est
fournie ici, et le fichier de licence du projet reste **MIT** : le contenu tiers
embarqué conserve sa licence d'origine.

À noter : `cargo deny` **ne couvre pas** ces fichiers. Il vérifie les licences des
crates, pas les données embarquées. Cette vérification est donc manuelle, et c'est
la raison d'être de ce document.
