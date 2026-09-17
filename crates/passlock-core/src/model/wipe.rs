//! Effacement des données déchiffrées du modèle.
//!
//! # Pourquoi un trait plutôt que des `Drop` écrits à la main
//!
//! Le modèle de la phase 2 contient **beaucoup plus de texte** que le moteur
//! cryptographique : chaque titre, chaque valeur de champ, chaque nom de dossier.
//! Écrire un `Drop` par type serait répétitif, et surtout **oublier un champ lors
//! d'un ajout futur serait silencieux** — le défaut ne se verrait qu'en lisant un
//! vidage mémoire.
//!
//! Le trait [`Wipe`] rend l'opération **composable** : un type qui contient d'autres
//! types effaçables n'a qu'à déléguer, et l'ajout d'un champ se traduit par une
//! ligne à ajouter dans une méthode courte, sous les yeux du relecteur.
//!
//! # Ce que l'effacement garantit, et ce qu'il ne garantit pas
//!
//! Il couvre les buffers que nous possédons : ceux alloués par `String` et `Vec`,
//! écrits de façon volatile avec une barrière mémoire, ce qui empêche l'optimiseur
//! de supprimer l'écriture.
//!
//! Il ne couvre **pas** : les copies que le compilateur a pu placer dans des
//! registres, les blocs recyclés par l'allocateur système, et ce que le noyau
//! conserve (espace d'échange, vidage mémoire). Voir `docs/CRYPTO.md` §7. Aucune
//! formulation « effacement garanti » n'est employée.
//!
//! # Limite connue
//!
//! `Zeroize for String` efface les octets **initialisés** puis vide la chaîne ; la
//! capacité résiduelle du buffer n'est pas parcourue. C'est une conséquence de
//! `#![forbid(unsafe_code)]` : atteindre les octets non initialisés exigerait un
//! accès brut au buffer. L'information qui y subsisterait proviendrait d'un contenu
//! précédent de la même `String`, donc de données déjà sensibles — la limite est
//! réelle et consignée comme telle.

use zeroize::Zeroize;

/// Efface le contenu sensible d'une valeur.
pub(crate) trait Wipe {
    /// Écrase le contenu sensible.
    ///
    /// Ne doit jamais échouer, ni allouer, ni paniquer : cette méthode est appelée
    /// depuis des `Drop`, y compris pendant le déroulement d'une pile après une
    /// panique.
    fn wipe(&mut self);
}

impl Wipe for String {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl<T: Wipe> Wipe for Vec<T> {
    fn wipe(&mut self) {
        for item in self.iter_mut() {
            item.wipe();
        }
        self.clear();
        self.shrink_to_fit();
    }
}

impl<T: Wipe> Wipe for Option<T> {
    fn wipe(&mut self) {
        if let Some(inner) = self.as_mut() {
            inner.wipe();
        }
    }
}

impl Wipe for u8 {
    fn wipe(&mut self) {
        *self = 0;
    }
}

impl Wipe for u16 {
    fn wipe(&mut self) {
        *self = 0;
    }
}

impl Wipe for u32 {
    fn wipe(&mut self) {
        *self = 0;
    }
}

impl Wipe for u64 {
    fn wipe(&mut self) {
        *self = 0;
    }
}

impl Wipe for bool {
    fn wipe(&mut self) {
        *self = false;
    }
}

/// Efface un tableau d'octets de taille fixe.
impl<const N: usize> Wipe for [u8; N] {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

/// Déclare un `Drop` qui appelle [`Wipe::wipe`].
///
/// # Pourquoi une macro locale plutôt qu'une macro procédurale
///
/// La règle du projet interdit les macros procédurales dans ce crate (ADR-004).
/// `macro_rules!` est résolu à la compilation par le compilateur lui-même et
/// n'ajoute **aucune dépendance** : il ne contredit donc pas cette règle.
///
/// # Conséquence ergonomique, assumée
///
/// Un type qui implémente `Drop` ne peut plus être déstructuré par déplacement de
/// champ. Là où c'est nécessaire, le code utilise `std::mem::take` ou
/// `std::mem::replace`, ce qui rend le déplacement explicite — un coût mineur en
/// échange d'une garantie d'effacement qui ne dépend pas de la vigilance.
macro_rules! impl_wipe_on_drop {
    ($type:ty) => {
        impl Drop for $type {
            fn drop(&mut self) {
                self.wipe();
            }
        }
    };
}

pub(crate) use impl_wipe_on_drop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiping_a_string_empties_it() {
        let mut text = String::from("secret en clair");
        text.wipe();
        assert!(text.is_empty(), "la chaîne devrait être vidée");
    }

    #[test]
    fn wiping_a_vector_empties_every_element_and_the_vector() {
        let mut values = vec![String::from("a"), String::from("b")];
        values.wipe();
        assert!(values.is_empty());
        assert_eq!(values.capacity(), 0, "la capacité devrait être rendue");
    }

    #[test]
    fn wiping_an_option_reaches_the_inner_value() {
        let mut maybe = Some(String::from("secret"));
        maybe.wipe();
        assert!(maybe.as_ref().is_some_and(String::is_empty));
    }

    #[test]
    fn wiping_scalars_zeroes_them() {
        let mut number = 42_u64;
        number.wipe();
        assert_eq!(number, 0);

        let mut flag = true;
        flag.wipe();
        assert!(!flag);

        let mut array = [0xAB_u8; 16];
        array.wipe();
        assert_eq!(array, [0_u8; 16]);
    }

    #[test]
    fn wiping_is_idempotent() {
        // `wipe` est appelé depuis des `Drop`, y compris pendant un déroulement de
        // pile : il doit pouvoir s'exécuter deux fois sans conséquence.
        let mut text = String::from("secret");
        text.wipe();
        text.wipe();
        assert!(text.is_empty());
    }
}
