//! Source d'aléa du moteur.
//!
//! ## Règle unique
//!
//! Tout octet aléatoire utilisé par le moteur provient du générateur du système
//! d'exploitation via `getrandom` : `getrandom(2)` sur Linux, `BCryptGenRandom`
//! sur Windows. Aucun générateur en espace utilisateur, aucun générateur
//! « injectable », aucun repli sur une horloge ou un compteur.
//!
//! **Pourquoi une règle aussi stricte.** Un générateur non cryptographique ne se
//! distingue pas d'un bon générateur à l'usage : le programme fonctionne, les
//! tests passent, et le défaut ne se révèle que lorsque les clés sont cassées. En
//! n'exposant qu'un point d'entrée unique et non substituable, on rend cette
//! erreur structurellement impossible à commettre dans ce projet.
//!
//! ## Pas de « fallback »
//!
//! Si `getrandom` échoue, l'opération échoue. Il n'existe **aucun** repli. Un
//! repli produirait des clés prédictibles, ce qui est strictement pire que refuser
//! de fonctionner : l'utilisateur croirait son coffre protégé.

use getrandom::fill as os_random;

use crate::error::{Error, Result};
use crate::secret::Key;

/// Remplit `out` avec des octets du générateur du système.
///
/// # Erreurs
/// [`Error::Io`] si le noyau refuse de fournir de l'aléa. Sur Linux ce cas
/// n'apparaît qu'avant l'initialisation du pool d'entropie, situation devenue rare
/// grâce à `getrandom(2)` bloquant ; l'échec reste traité comme fatal plutôt
/// qu'atténué.
pub fn fill(out: &mut [u8]) -> Result<()> {
    os_random(out).map_err(|err| {
        // L'erreur d'origine n'est pas propagée telle quelle : son message est
        // dépendant de la plateforme et ne contient aucun élément exploitable,
        // tandis que ce point de défaillance mérite un message explicite.
        let _ = err;
        Error::Internal {
            invariant: "générateur d'aléa du système indisponible",
        }
    })
}

/// Retourne un tableau de `N` octets aléatoires.
///
/// # Erreurs
/// Propage l'échec de [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Retourne un entier non signé de 64 bits aléatoire.
///
/// # Erreurs
/// Propage l'échec de [`fill`].
pub fn u64() -> Result<u64> {
    Ok(u64::from_be_bytes(array::<8>()?))
}

/// Limite haute de la plage **acceptée** pour une borne donnée.
///
/// Le nombre de tirages acceptés vaut `limite + 1 = 2⁶⁴ − 1 − ((2⁶⁴ − 1) mod
/// borne)`, qui est **toujours un multiple de la borne**. C'est précisément ce qui
/// garantit l'absence de biais modulo : chaque résidu est atteint exactement
/// `(limite + 1) / borne` fois.
const fn rejection_limit(bound: u64) -> u64 {
    u64::MAX - (u64::MAX % bound) - 1
}

/// Réduit un tirage 64 bits vers `0..bound` sans biais modulo.
///
/// Retourne `None` si le tirage tombe dans la plage de rejet, auquel cas
/// l'appelant doit **retirer** un nouveau tirage.
///
/// # Précondition
/// `bound` doit être **non nul**. C'est une précondition du contrat, pas une
/// condition d'exécution : [`below`] la vérifie avant d'entrer dans sa boucle, et
/// aucun autre appelant n'existe.
///
/// # Pourquoi cette fonction existe séparément
///
/// La réduction était auparavant noyée dans la boucle de [`below`], qui appelle
/// `rng::u64()` en interne. Elle était donc **invérifiable** : le projet interdit
/// tout générateur injectable, y compris sous `#[cfg(test)]`, et un test
/// statistique ne peut pas la valider — sur une source 64 bits et une petite
/// borne, le biais modulo vaut environ 2⁻⁶³, indétectable à l'exécution tout en
/// restant un défaut réel si la fonction était un jour réécrite sur une source
/// tronquée.
///
/// Extraite en fonction pure, elle devient testable sur ses valeurs d'entrée, et
/// la propriété qui compte — *le nombre de tirages acceptés est un multiple de la
/// borne* — s'énonce et se vérifie directement.
const fn reduce(candidate: u64, bound: u64) -> Option<u64> {
    if candidate <= rejection_limit(bound) {
        Some(candidate % bound)
    } else {
        None
    }
}

/// Retourne un entier de 64 bits aléatoire tiré uniformément dans `0..bound`.
///
/// # Erreurs
/// [`Error::Internal`] si `bound` vaut zéro, en cas d'échec du générateur.
///
/// ## Pourquoi un rejet plutôt qu'un modulo
///
/// `valeur % bound` n'est pas uniforme : les `bound` premières valeurs de
/// l'intervalle sont plus probables que les suivantes. Sur un tirage de sel ou de
/// nonce, ce biais réduirait l'espace effectif. On rejette donc les tirages qui
/// tombent dans la zone incomplète, ce qui est la méthode correcte et reste
/// négligeable en coût puisque le rejet se produit avec une probabilité
/// strictement inférieure à 1/2.
pub fn below(bound: u64) -> Result<u64> {
    if bound == 0 {
        return Err(Error::Internal {
            invariant: "tirage aléatoire demandé avec une borne nulle",
        });
    }

    loop {
        if let Some(value) = reduce(u64()?, bound) {
            return Ok(value);
        }
    }
}

/// Génère une clé de `N` octets depuis le générateur du système.
///
/// # Erreurs
/// Propage l'échec de [`fill`].
pub fn key<const N: usize>() -> Result<Key<N>> {
    // Le remplissage se fait **directement dans le buffer de la clé**, jamais via
    // un tableau intermédiaire.
    //
    // NOTE DE CORRECTION. Une version antérieure faisait
    // `let bytes = array::<N>()?; Key::from_array(bytes)`. Le tableau de pile
    // `bytes` n'était alors jamais effacé : la clé de données laissait une copie
    // complète dans une zone de pile recyclée sans nettoyage, ce qui annulait une
    // partie du bénéfice de `zeroize`. Un audit adversarial l'a relevé.
    let mut key = Key::<N>::zeroed();
    fill(key.expose_mut())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn fill_actually_writes() {
        let mut buf = [0_u8; 64];
        fill(&mut buf).expect("le générateur du système doit être disponible en test");
        assert!(buf.iter().any(|&b| b != 0), "buffer entièrement nul");
    }

    #[test]
    fn distinct_draws_differ() {
        // Vérifie l'absence d'un générateur constant, défaut qui passerait
        // inaperçu avec un simple test « ça remplit bien le buffer ».
        let a = array::<32>().expect("aléa");
        let b = array::<32>().expect("aléa");
        assert_ne!(
            a, b,
            "deux tirages successifs identiques : générateur suspect"
        );
    }

    #[test]
    fn below_stays_in_range_and_is_not_constant() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let value = below(10).expect("aléa");
            assert!(value < 10, "valeur {value} hors de 0..10");
            seen.insert(value);
        }
        assert!(
            seen.len() > 5,
            "distribution anormalement concentrée sur {} valeurs",
            seen.len()
        );
    }

    #[test]
    fn below_rejects_zero_bound() {
        assert!(matches!(below(0), Err(Error::Internal { .. })));
    }

    #[test]
    fn below_handles_bound_of_one() {
        assert_eq!(below(1).expect("aléa"), 0);
    }

    /// **La propriété qui garantit l'absence de biais modulo.**
    ///
    /// Le nombre de tirages acceptés doit être un multiple exact de la borne :
    /// c'est la condition pour que chaque résidu soit atteint le même nombre de
    /// fois. Cette égalité est vérifiable, contrairement à une mesure statistique
    /// du biais, qui serait indétectable à cette échelle.
    #[test]
    fn the_accepted_range_is_an_exact_multiple_of_the_bound() {
        let bounds = [
            1_u64,
            2,
            3,
            5,
            7,
            10,
            26,
            52,
            62,
            64,
            94,
            256,
            1000,
            7776,
            1 << 32,
            u64::from(u32::MAX),
            u64::MAX / 3,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];

        for bound in bounds {
            let accepted = rejection_limit(bound) + 1;
            assert_eq!(
                accepted % bound,
                0,
                "borne {bound} : {accepted} tirages acceptés n'est pas un multiple \
                 de la borne, donc un résidu est favorisé"
            );
            assert!(
                accepted >= bound,
                "borne {bound} : plus aucun tirage accepté"
            );
        }
    }

    /// La limite est la frontière exacte : acceptée elle-même, la valeur suivante
    /// ne l'est pas.
    #[test]
    fn reduce_accepts_the_limit_and_rejects_the_value_above_it() {
        for bound in [2_u64, 3, 7, 10, 94, 7776, u64::MAX / 2, u64::MAX - 1] {
            let limit = rejection_limit(bound);

            assert_eq!(reduce(0, bound), Some(0));
            assert!(
                reduce(limit, bound).is_some(),
                "borne {bound} : la limite {limit} doit être acceptée"
            );
            assert_eq!(
                reduce(limit + 1, bound),
                None,
                "borne {bound} : {limit} + 1 doit être rejeté"
            );
            assert_eq!(
                reduce(u64::MAX, bound),
                None,
                "borne {bound} : le tirage maximal doit être rejeté"
            );
        }
    }

    /// La valeur réduite est bien le reste, et jamais autre chose.
    #[test]
    fn reduce_returns_the_plain_remainder_for_accepted_draws() {
        for bound in [2_u64, 3, 7, 10, 94] {
            let limit = rejection_limit(bound);
            for candidate in [0_u64, 1, 2, 3, 100, 1000, limit / 2] {
                if candidate > limit {
                    continue;
                }
                assert_eq!(reduce(candidate, bound), Some(candidate % bound));
            }
        }
    }

    /// Autour de la borne maximale, le comportement reste défini.
    #[test]
    fn reduce_handles_the_extreme_bound() {
        // Pour `bound = u64::MAX`, la limite vaut `u64::MAX - 1` : seul le tirage
        // maximal est rejeté.
        assert_eq!(rejection_limit(u64::MAX), u64::MAX - 1);
        assert_eq!(reduce(u64::MAX - 1, u64::MAX), Some(u64::MAX - 1));
        assert_eq!(reduce(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn generated_keys_are_distinct_and_right_size() {
        let first = key::<32>().expect("aléa");
        let second = key::<32>().expect("aléa");
        assert_eq!(first.expose().len(), 32);
        assert!(!first.constant_time_eq(&second));
    }
}
