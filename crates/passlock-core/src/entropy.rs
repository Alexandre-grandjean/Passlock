//! Calcul d'entropie des secrets engendrés.
//!
//! ## Le principe, et ce qu'il exclut
//!
//! Un secret engendré uniformément n'a pas une entropie *estimée* : il a une
//! entropie **exacte**, qui vaut `log₂(|espace|)`. Ce module la **calcule**.
//!
//! Sont donc exclus, délibérément :
//!
//! - **les estimateurs de robustesse de mots de passe humains** (type zxcvbn).
//!   Ils sont calibrés sur des mots de passe *choisis par des humains* : leurs
//!   modèles détectent des motifs, des mots de dictionnaire, des dates. Une sortie
//!   uniforme ne contient aucun de ces motifs par construction, et leur score ne
//!   décrit donc pas la bonne chose. Pire, il *masquerait* le seul chiffre exact ;
//! - **les estimations en durée** (« cassable en 3 siècles »). Elles exigent des
//!   hypothèses sur le matériel de l'attaquant — nombre d'essais par seconde,
//!   coût, parallélisation — que ce projet ne peut pas vérifier. Un chiffre inventé
//!   dans un gestionnaire de mots de passe est un mensonge aux conséquences réelles.
//!   Ce module rend un **fait arithmétique** et une **politique assumée** ;
//!   la conversion en temps n'est pas faite ici et ne le sera pas.
//!
//! ## Ce que l'entropie annoncée suppose
//!
//! `H = longueur × log₂(|alphabet|)` n'est vraie que si le tirage est **uniforme**,
//! ce qui suppose un CSPRNG non compromis — l'ancre de confiance établie en
//! phase 1. L'entropie est donc une propriété *de conception*, pas un résultat
//! mesuré. Cette phrase doit accompagner le chiffre partout où il est affiché.
//!
//! ## Le coût d'une contrainte est compté, pas caché
//!
//! Exiger « au moins un chiffre » réduit l'espace réel. L'écart est calculé
//! **exactement** (voir [`Entropy::constrained`]) et le nombre de bits perdu est
//! exposé. Un générateur qui afficherait la formule non contrainte surestimerait
//! systématiquement la robustesse qu'il prétend fournir.

use crate::error::{Error, Result};

/// Seuil bas de la bande « faible », en bits.
const THRESHOLD_WEAK: f64 = 64.0;
/// Seuil bas de la bande « acceptable », en bits.
const THRESHOLD_ACCEPTABLE: f64 = 80.0;
/// Seuil bas de la bande « fort », en bits.
const THRESHOLD_STRONG: f64 = 128.0;

/// Probabilité d'acceptation en dessous de laquelle la génération est refusée.
///
/// Une probabilité plus faible signifierait des millions de tirages rejetés pour
/// un seul secret. Refuser est préférable à faire tourner la machine : la
/// contrainte demandée décrit un espace si étroit qu'elle n'a plus de sens.
pub const MIN_ACCEPTANCE: f64 = 1e-6;

/// Une contrainte « au moins `minimum` caractères issus d'une classe de
/// `class_size` symboles ».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// Nombre de symboles de l'alphabet appartenant à cette classe.
    pub class_size: usize,
    /// Nombre minimal de caractères devant provenir de cette classe.
    pub minimum: usize,
}

impl Requirement {
    /// Construit une contrainte.
    #[must_use]
    pub const fn new(class_size: usize, minimum: usize) -> Self {
        Self {
            class_size,
            minimum,
        }
    }
}

/// Bande qualitative d'une entropie.
///
/// **Les seuils sont une politique, pas une mesure.** Ils ne reposent sur aucune
/// observation de matériel : ils fixent la limite à partir de laquelle ce projet
/// considère qu'une énumération exhaustive n'est plus réalisable avec la
/// technologie connue. Les présenter comme un résultat expérimental serait faux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    /// Moins de 64 bits.
    Insufficient,
    /// De 64 à 79 bits.
    Weak,
    /// De 80 à 127 bits.
    Acceptable,
    /// 128 bits et plus.
    Strong,
}

impl Band {
    /// Bande correspondant à un nombre de bits.
    #[must_use]
    pub fn for_bits(bits: f64) -> Self {
        if bits < THRESHOLD_WEAK {
            Self::Insufficient
        } else if bits < THRESHOLD_ACCEPTABLE {
            Self::Weak
        } else if bits < THRESHOLD_STRONG {
            Self::Acceptable
        } else {
            Self::Strong
        }
    }

    /// Libellé français destiné à l'affichage.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Insufficient => "insuffisant",
            Self::Weak => "faible",
            Self::Acceptable => "acceptable",
            Self::Strong => "fort",
        }
    }
}

/// Résultat d'un calcul d'entropie.
#[derive(Debug, Clone, Copy)]
pub struct Entropy {
    /// Entropie retenue, en bits.
    pub bits: f64,
    /// Entropie de l'alphabet **sans** contrainte, en bits.
    pub unconstrained_bits: f64,
    /// Coût des contraintes, en bits. Toujours négatif ou nul.
    pub cost_bits: f64,
    /// Probabilité qu'un tirage uniforme satisfasse les contraintes.
    pub acceptance: f64,
}

impl Entropy {
    /// Entropie d'un tirage uniforme **sans** contrainte.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si l'alphabet est vide.
    pub fn unconstrained(length: usize, alphabet_size: usize) -> Result<Self> {
        Self::constrained(length, alphabet_size, &[])
    }

    /// Entropie exacte d'un tirage uniforme **sous contraintes**.
    ///
    /// # Méthode
    ///
    /// `|{chaînes satisfaisantes}|` est calculé exactement par une programmation
    /// dynamique sur des **probabilités**, avec des compteurs écrêtés à leur
    /// minimum requis.
    ///
    /// L'état est `(compteurs écrêtés)` ; la masse de l'état final, où tous les
    /// compteurs ont atteint leur minimum, est la probabilité d'acceptation `P`.
    /// Alors :
    ///
    /// ```text
    /// H = longueur × log₂(|alphabet|) + log₂(P)
    /// ```
    ///
    /// Le second terme est **négatif** : c'est exactement ce que la contrainte
    /// coûte, exprimé en bits.
    ///
    /// ## Pourquoi des probabilités et non un comptage
    ///
    /// `94^1024 ≈ 10^2019` dépasse largement la capacité d'un `f64` comme d'un
    /// `u128`. Une probabilité, elle, reste dans `[0, 1]` : aucun débordement
    /// n'est possible, et la précision relative se conserve sur toute la plage
    /// utile.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si l'alphabet est vide, si la somme des tailles de
    /// classes dépasse l'alphabet, si les minimums exigent plus de caractères que
    /// la longueur, ou si la contrainte est si étroite que la probabilité
    /// d'acceptation tombe sous [`MIN_ACCEPTANCE`].
    pub fn constrained(
        length: usize,
        alphabet_size: usize,
        requirements: &[Requirement],
    ) -> Result<Self> {
        if alphabet_size == 0 {
            return Err(Error::InvalidInput {
                reason: "alphabet vide : aucun secret ne peut être engendré",
            });
        }
        if length == 0 {
            return Err(Error::InvalidInput {
                reason: "longueur nulle : aucun secret ne peut être engendré",
            });
        }
        if requirements.len() > 8 {
            return Err(Error::InvalidInput {
                reason: "trop de classes de contraintes",
            });
        }

        let class_total: usize = requirements.iter().map(|r| r.class_size).sum();
        let other = alphabet_size
            .checked_sub(class_total)
            .ok_or(Error::InvalidInput {
                reason: "les classes de contraintes dépassent la taille de l'alphabet",
            })?;

        let required_total: usize = requirements.iter().map(|r| r.minimum).sum();
        if required_total > length {
            return Err(Error::InvalidInput {
                reason: "les minimums exigés dépassent la longueur demandée",
            });
        }

        // Cas sans contrainte : inutile de faire tourner la dynamique.
        if required_total == 0 {
            return Ok(Self {
                bits: unconstrained_formula(length, alphabet_size),
                unconstrained_bits: unconstrained_formula(length, alphabet_size),
                cost_bits: 0.0,
                acceptance: 1.0,
            });
        }

        // Radix de chaque compteur : de 0 à son minimum inclus.
        let radices: Vec<usize> = requirements.iter().map(|r| r.minimum + 1).collect();
        let state_count = radices
            .iter()
            .try_fold(1_usize, |acc, &radix| acc.checked_mul(radix))
            .ok_or(Error::InvalidInput {
                reason: "espace d'états de contraintes trop grand",
            })?;

        // Table de transitions, aplatie : `transitions[index * state_count + state]`
        // donne l'état atteint depuis `state` en tirant un caractère de la classe
        // `index`.
        //
        // La table est construite **par classe puis par état**, et non l'inverse :
        // l'écriture se fait alors en ajout successif, sans indexer une structure
        // par la variable de boucle — ce qui évite un parcours en colonne, moins
        // lisible et signalé par le lint `needless_range_loop`.
        let mut transitions = Vec::with_capacity(requirements.len() * state_count);
        for (index, requirement) in requirements.iter().enumerate() {
            for state in 0..state_count {
                let mut counters = decode_state(state, &radices);
                counters[index] = (counters[index] + 1).min(requirement.minimum);
                transitions.push(encode_state(&counters, &radices));
            }
        }

        let total = usize_to_f64(alphabet_size);
        let other_share = usize_to_f64(other) / total;

        let mut mass = vec![0.0_f64; state_count];
        mass[0] = 1.0;

        for _ in 0..length {
            let mut next_mass = vec![0.0_f64; state_count];
            for (state, &current) in mass.iter().enumerate() {
                if current <= 0.0 {
                    continue;
                }
                if other > 0 {
                    next_mass[state] += current * other_share;
                }
                for (index, requirement) in requirements.iter().enumerate() {
                    let share = usize_to_f64(requirement.class_size) / total;
                    // L'index est borné par construction : `index < requirements.len()`
                    // et `state < state_count`.
                    let target = transitions[index * state_count + state];
                    next_mass[target] += current * share;
                }
            }
            mass = next_mass;
        }

        // L'état acceptant est celui où **tous** les compteurs ont atteint leur
        // minimum : l'écrêtement fait de cet état le dernier de l'espace.
        let minimums: Vec<usize> = requirements.iter().map(|r| r.minimum).collect();
        let acceptance = mass[encode_state(&minimums, &radices)];

        if acceptance <= 0.0 {
            // Sous-dépassement de capacité : la contrainte est si étroite que la
            // probabilité n'est plus représentable. Refuser est la seule option
            // honnête — annoncer une entropie calculée sur une valeur nulle
            // donnerait `-inf` bits, afficher la formule non contrainte donnerait
            // un chiffre faux.
            return Err(Error::InvalidInput {
                reason: "contraintes trop étroites : la probabilité d'acceptation \
                         n'est pas représentable et la génération serait \
                         impraticable",
            });
        }

        if acceptance < MIN_ACCEPTANCE {
            return Err(Error::InvalidInput {
                reason: "contraintes trop étroites pour la longueur demandée : \
                         allongez la longueur ou relâchez une contrainte",
            });
        }

        let unconstrained = unconstrained_formula(length, alphabet_size);
        let cost = acceptance.log2();

        Ok(Self {
            bits: unconstrained + cost,
            unconstrained_bits: unconstrained,
            cost_bits: cost,
            acceptance,
        })
    }

    /// Rapport pour une **composition de choix indépendants**.
    ///
    /// Utilisé quand un secret résulte de plusieurs décisions uniformes distinctes —
    /// par exemple `mots` tirages dans une liste de `W` entrées, plus un séparateur
    /// choisi parmi `k`. Le total est calculé par [`product_bits`] ; il n'y a ni
    /// alphabet unique ni contrainte à retrancher, donc aucun coût.
    #[must_use]
    pub const fn from_composition(bits: f64) -> Self {
        Self {
            bits,
            unconstrained_bits: bits,
            cost_bits: 0.0,
            acceptance: 1.0,
        }
    }

    /// Bande qualitative.
    #[must_use]
    pub fn band(self) -> Band {
        Band::for_bits(self.bits)
    }

    /// Entropie arrondie **vers le bas**, en bits entiers.
    ///
    /// L'arrondi est dirigé : un affichage qui arrondirait vers le haut
    /// surestimerait, même d'une unité. Le choix est délibéré et vaut pour toute
    /// présentation de cette valeur.
    #[must_use]
    pub fn floor_bits(self) -> u32 {
        if self.bits <= 0.0 {
            return 0;
        }
        // `as` tronque vers zéro ; la saturation est traitée par le plafond.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "la valeur est positive et plafonnée juste après"
        )]
        let truncated = self.bits.min(f64::from(u32::MAX)) as u32;
        truncated
    }
}

/// Entropie d'une composition de choix uniformes indépendants.
///
/// Chaque composante est un couple `(nombre de tirages, nombre de possibilités par
/// tirage)`. Le total est la somme des `tirages × log₂(possibilités)`.
///
/// Exemple : six mots tirés d'une liste de 7776, avec un séparateur choisi parmi
/// trois, donne `6 × log₂(7776) + 1 × log₂(3)`.
///
/// # Erreurs
/// [`Error::InvalidInput`] si une composante annonce zéro possibilité : un choix
/// sans alternative n'existe pas, et le compter comme un apport d'entropie serait
/// faux — `log₂(1) = 0` est en revanche légitime.
pub fn product_bits(components: &[(usize, usize)]) -> Result<f64> {
    let mut total = 0.0;
    for (draws, possibilities) in components {
        if *possibilities == 0 {
            return Err(Error::InvalidInput {
                reason: "composition d'entropie : un choix sans possibilité",
            });
        }
        if *draws == 0 {
            continue;
        }
        total += usize_to_f64(*draws) * usize_to_f64(*possibilities).log2();
    }
    Ok(total)
}

/// Formule non contrainte : `longueur × log₂(|alphabet|)`.
fn unconstrained_formula(length: usize, alphabet_size: usize) -> f64 {
    usize_to_f64(length) * usize_to_f64(alphabet_size).log2()
}

/// Convertit un compteur en `f64`.
///
/// Les grandeurs concernées (longueur d'un secret, taille d'un alphabet) sont
/// bornées par les constantes du modèle et restent très en dessous de `2^53`, où
/// la conversion est exacte. Ce n'est pas une approximation tolérée, c'est une
/// conversion exacte sur le domaine réel.
#[allow(
    clippy::cast_precision_loss,
    reason = "les compteurs sont bornés bien en dessous de 2^53 : conversion exacte"
)]
fn usize_to_f64(value: usize) -> f64 {
    value as f64
}

/// Décompose un index d'état en compteurs.
fn decode_state(mut state: usize, radices: &[usize]) -> Vec<usize> {
    let mut counters = vec![0_usize; radices.len()];
    for index in (0..radices.len()).rev() {
        counters[index] = state % radices[index];
        state /= radices[index];
    }
    counters
}

/// Compose un index d'état à partir des compteurs.
fn encode_state(counters: &[usize], radices: &[usize]) -> usize {
    let mut state = 0_usize;
    for (counter, radix) in counters.iter().zip(radices) {
        state = state * radix + counter;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compte par force brute les chaînes satisfaisant une contrainte, sur un
    /// petit alphabet. Sert d'oracle indépendant pour la programmation dynamique.
    fn brute_force(
        length: usize,
        alphabet: &[u8],
        required: &[&[u8]],
        minimums: &[usize],
    ) -> usize {
        let mut count = 0;
        let space = alphabet
            .len()
            .pow(u32::try_from(length).expect("longueur de test"));
        for candidate in 0..space {
            let mut value = candidate;
            let mut chars = Vec::with_capacity(length);
            for _ in 0..length {
                chars.push(alphabet[value % alphabet.len()]);
                value /= alphabet.len();
            }

            let satisfied = required.iter().zip(minimums).all(|(class, minimum)| {
                chars.iter().filter(|c| class.contains(c)).count() >= *minimum
            });
            if satisfied {
                count += 1;
            }
        }
        count
    }

    #[test]
    fn unconstrained_entropy_matches_the_closed_formula() {
        // 20 caractères sur 94 symboles.
        let entropy = Entropy::unconstrained(20, 94).expect("calcul");
        let expected = 20.0 * 94.0_f64.log2();
        assert!((entropy.bits - expected).abs() < 1e-9, "{entropy:?}");
        assert!((entropy.bits - 131.091_777).abs() < 1e-5, "{entropy:?}");
        assert!(entropy.cost_bits.abs() < 1e-12);
        assert!((entropy.acceptance - 1.0).abs() < 1e-12);
        assert_eq!(entropy.floor_bits(), 131);
    }

    #[test]
    fn passphrase_entropy_uses_the_real_list_size() {
        // 6 mots d'une liste de 7776 entrées (EFF et Diceware FR).
        let entropy = Entropy::unconstrained(6, 7776).expect("calcul");
        assert!((entropy.bits - 77.55).abs() < 0.01, "{entropy:?}");
        assert_eq!(entropy.band(), Band::Weak);

        // Une liste plus courte doit donner MOINS : c'est le test qui attrape une
        // entropie calculée sur une taille supposée plutôt que réelle.
        let small = Entropy::unconstrained(6, 300).expect("calcul");
        assert!((small.bits - 49.372_912).abs() < 1e-5, "{small:?}");
        assert_eq!(small.band(), Band::Insufficient);
        assert!(small.bits < entropy.bits);
    }

    /// La dynamique doit reproduire un comptage exact, pas l'approcher.
    #[test]
    fn constrained_entropy_matches_brute_force() {
        // Alphabet {a,b,c} ; classe {a}, au moins 1 occurrence, longueur 2.
        let alphabet = b"abc";
        let class: &[u8] = b"a";
        let expected = brute_force(2, alphabet, &[class], &[1]);
        assert_eq!(expected, 5, "oracle : 3^2 - 2^2 = 5");

        let entropy = Entropy::constrained(2, alphabet.len(), &[Requirement::new(class.len(), 1)])
            .expect("calcul");

        let expected_bits = 5.0_f64.log2();
        assert!(
            (entropy.bits - expected_bits).abs() < 1e-9,
            "entropie {} contre {expected_bits} attendue",
            entropy.bits
        );
        assert!((entropy.unconstrained_bits - 2.0 * 3.0_f64.log2()).abs() < 1e-12);
        assert!(
            entropy.cost_bits < 0.0,
            "une contrainte doit coûter des bits"
        );
        assert!(
            (entropy.acceptance - 5.0 / 9.0).abs() < 1e-12,
            "acceptation {} contre 5/9",
            entropy.acceptance
        );
    }

    #[test]
    fn constrained_entropy_matches_brute_force_over_several_shapes() {
        let alphabet = b"abcd";

        // Cas : (longueur, classe, minimum)
        let cases: [(usize, &[u8], usize); 6] = [
            (2, b"a", 1),
            (2, b"ab", 1),
            (3, b"a", 1),
            (3, b"a", 2),
            (2, b"ab", 2),
            (4, b"a", 3),
        ];

        for (length, class, minimum) in cases {
            let expected = brute_force(length, alphabet, &[class], &[minimum]);
            assert!(
                expected > 0,
                "cas sans solution : {length} {class:?} {minimum}"
            );

            let entropy = Entropy::constrained(
                length,
                alphabet.len(),
                &[Requirement::new(class.len(), minimum)],
            )
            .expect("calcul");

            let expected_bits = usize_to_f64(expected).log2();
            assert!(
                (entropy.bits - expected_bits).abs() < 1e-9,
                "longueur {length}, classe {class:?}, minimum {minimum} : \
                 {} bits contre {expected_bits} (brute force = {expected})",
                entropy.bits
            );
        }
    }

    /// Deux classes simultanées, vérifiées contre la force brute.
    #[test]
    fn two_classes_are_counted_exactly() {
        let alphabet = b"abc";
        // Classe 1 : {a} ; classe 2 : {b}. Au moins 1 de chaque, longueur 3.
        let expected = brute_force(3, alphabet, &[b"a", b"b"], &[1, 1]);
        // Chaînes de longueur 3 sur {a,b,c} contenant au moins un a et un b.
        assert_eq!(expected, 12);

        let entropy = Entropy::constrained(
            3,
            alphabet.len(),
            &[Requirement::new(1, 1), Requirement::new(1, 1)],
        )
        .expect("calcul");

        let expected_bits = usize_to_f64(expected).log2();
        assert!(
            (entropy.bits - expected_bits).abs() < 1e-9,
            "{} contre {expected_bits}",
            entropy.bits
        );
    }

    #[test]
    fn impossible_constraints_are_refused_before_any_computation() {
        // Plus de minimums exigés que de caractères disponibles.
        let outcome =
            Entropy::constrained(1, 10, &[Requirement::new(5, 1), Requirement::new(5, 1)]);
        assert!(matches!(outcome, Err(Error::InvalidInput { .. })));

        // Classes plus grandes que l'alphabet.
        let outcome = Entropy::constrained(10, 5, &[Requirement::new(6, 1)]);
        assert!(matches!(outcome, Err(Error::InvalidInput { .. })));

        // Alphabet vide, longueur nulle.
        assert!(Entropy::unconstrained(10, 0).is_err());
        assert!(Entropy::unconstrained(0, 10).is_err());
    }

    /// Une contrainte étroite mais réalisable doit coûter des bits, et être
    /// refusée seulement quand elle devient impraticable.
    #[test]
    fn a_tight_constraint_costs_bits_and_is_eventually_refused() {
        // 4 caractères sur 94, exiger 3 chiffres (classe de 10) : réalisable.
        let entropy = Entropy::constrained(4, 94, &[Requirement::new(10, 3)]).expect("réalisable");
        assert!(entropy.cost_bits < 0.0);
        assert!(entropy.acceptance < 1.0);
        assert!(entropy.acceptance > MIN_ACCEPTANCE);

        // 64 caractères sur 94 exigeant 60 chiffres : la probabilité s'effondre.
        let outcome = Entropy::constrained(64, 94, &[Requirement::new(10, 60)]);
        assert!(
            matches!(outcome, Err(Error::InvalidInput { .. })),
            "une contrainte impraticable doit être refusée, pas subie"
        );
    }

    #[test]
    fn the_cost_is_never_positive() {
        // Le coût d'une contrainte ne peut pas être un gain : `log₂(P)` avec
        // `P ≤ 1` est toujours négatif ou nul.
        for (length, class_size, minimum) in [(8, 10, 1), (12, 26, 2), (20, 32, 3), (16, 10, 4)] {
            let entropy =
                Entropy::constrained(length, 94, &[Requirement::new(class_size, minimum)])
                    .expect("calcul");
            assert!(
                entropy.cost_bits <= 0.0,
                "coût positif ({}) pour {length}/{class_size}/{minimum}",
                entropy.cost_bits
            );
            assert!(entropy.bits <= entropy.unconstrained_bits + 1e-12);
        }
    }

    #[test]
    fn a_zero_minimum_is_not_a_constraint() {
        let with = Entropy::constrained(16, 94, &[Requirement::new(10, 0)]).expect("calcul");
        let without = Entropy::unconstrained(16, 94).expect("calcul");
        assert!((with.bits - without.bits).abs() < 1e-12);
        assert!(with.cost_bits.abs() < 1e-12);
    }

    #[test]
    fn bands_follow_the_documented_policy() {
        assert_eq!(Band::for_bits(63.9), Band::Insufficient);
        assert_eq!(Band::for_bits(64.0), Band::Weak);
        assert_eq!(Band::for_bits(79.9), Band::Weak);
        assert_eq!(Band::for_bits(80.0), Band::Acceptable);
        assert_eq!(Band::for_bits(127.9), Band::Acceptable);
        assert_eq!(Band::for_bits(128.0), Band::Strong);
        assert_eq!(Band::for_bits(256.0), Band::Strong);
    }

    #[test]
    fn the_floor_rounding_never_overstates() {
        // 20 × log₂(94) = 131,0917… : la troncature doit donner 131, jamais 132.
        let entropy = Entropy::unconstrained(20, 94).expect("calcul");
        assert!(entropy.bits > 131.0 && entropy.bits < 132.0, "{entropy:?}");
        assert_eq!(entropy.floor_bits(), 131);
    }

    /// La valeur d'entropie ne doit jamais dépasser ce que l'alphabet permet.
    #[test]
    fn entropy_is_bounded_by_the_alphabet() {
        let entropy = Entropy::unconstrained(32, 94).expect("calcul");
        assert!(entropy.bits <= 32.0 * 94.0_f64.log2() + 1e-12);

        // Un octet complet vaut exactement 8 bits.
        let byte = Entropy::unconstrained(32, 256).expect("calcul");
        assert!((byte.bits - 256.0).abs() < 1e-9);
    }
}
