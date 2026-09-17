//! Types de matériel secret : verrouillés en RAM si possible, effacés à la
//! destruction, jamais affichables.
//!
//! ## Principes
//!
//! 1. **Jamais de `String`.** `String` est validée UTF-8, peut être réallouée et
//!    copiée par le compilateur. Tous les secrets circulent en `Vec<u8>` /
//!    `[u8]` et ne sont convertis en texte qu'au dernier moment, dans la couche
//!    d'affichage, sur une durée de vie minimale.
//! 2. **Pas de `Clone`.** Dupliquer un secret doit être un acte explicite, pas un
//!    effet de bord d'un `.clone()` oublié. Aucun type de ce module n'implémente
//!    `Clone`.
//! 3. **`Debug` rédacteur.** Un secret ne peut pas fuiter par un `{:?}` dans un
//!    message de journal ou de panic : la seule implémentation existante affiche
//!    un marqueur, jamais le contenu.
//! 4. **Pas de `PartialEq`.** Deux secrets ne se comparent pas avec `==`, ce qui
//!    serait une comparaison non constante en temps. La comparaison passe
//!    exclusivement par [`Key::constant_time_eq`], qui opère en temps constant.
//!
//! ## Limite assumée
//!
//! L'effacement ici est **fiable pour les emplacements que nous contrôlons** : le
//! buffer alloué sur le tas, effacé par `zeroize`, qui empêche l'optimiseur de
//! supprimer l'écriture. Il n'est **pas** garanti pour le reste :
//!
//! * le compilateur peut avoir copié un secret dans des registres ou sur la pile
//!   au cours d'un appel ;
//! * `mlock` peut avoir échoué, auquel cas une copie peut avoir atteint le swap ;
//! * ni le matériel ni le noyau ne sont obligés d'oublier une donnée.
//!
//! Aucune garantie d'effacement total ne doit être annoncée à l'utilisateur.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use passlock_platform::memory::LockedBuffer;

use crate::error::{Error, Result};

/// Buffer de taille variable contenant un secret.
///
/// Utilisé pour le mot de passe maître, dont la longueur est arbitraire, et pour
/// tout secret de longueur non fixée à la compilation.
pub struct SecretVec {
    buf: LockedBuffer,
}

impl SecretVec {
    /// Alloue un buffer secret de `len` octets, remis à zéro.
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self {
            buf: LockedBuffer::new(len),
        }
    }

    /// Construit un buffer secret à partir d'octets existants.
    ///
    /// Le buffer source n'est **pas** effacé : c'est à l'appelant de le faire s'il
    /// en est propriétaire. Cette fonction ne peut pas le faire à sa place sans
    /// créer l'illusion d'une garantie qu'elle n'a pas.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut secret = Self::zeroed(bytes.len());
        secret.expose_mut().copy_from_slice(bytes);
        secret
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Vrai si le buffer a pu être verrouillé en RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.buf.is_locked()
    }

    /// Accès en lecture au contenu.
    ///
    /// Le nom est volontairement explicite : chaque appel est un point où un
    /// secret est exposé, et ces points doivent rester peu nombreux et lisibles.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Accès en écriture au contenu.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        // `zeroize` écrit de façon volatile et pose une barrière mémoire, ce qui
        // empêche l'optimiseur de supprimer l'effacement parce que la valeur n'est
        // plus lue ensuite. C'est la seule raison d'utiliser cette crate plutôt
        // qu'un `fill(0)`.
        self.buf.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.buf.len())
            .field("contents", &"[EXPURGÉ]")
            .finish()
    }
}

/// Matériel de clé de taille fixée à la compilation.
///
/// La constance `N` n'est pas cosmétique : elle rend impossible d'affecter une clé
/// de 32 octets à un emplacement prévu pour 16, erreur qui produirait sinon une
/// clé tronquée silencieusement acceptée plus loin.
pub struct Key<const N: usize> {
    buf: LockedBuffer,
}

impl<const N: usize> Key<N> {
    /// Crée une clé dont tous les octets sont à zéro.
    ///
    /// Réservé aux cas où la clé va être écrite juste après (dérivation dans un
    /// buffer de sortie). Une clé nulle ne doit jamais être utilisée comme clé.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            buf: LockedBuffer::new(N),
        }
    }

    /// Copie une clé depuis un tableau de taille connue.
    #[must_use]
    pub fn from_array(bytes: [u8; N]) -> Self {
        let mut key = Self::zeroed();
        key.expose_mut().copy_from_slice(&bytes);
        key
    }

    /// Copie une clé depuis un slice, en vérifiant la taille.
    ///
    /// # Erreurs
    /// [`Error::InvalidLength`] si `bytes` ne fait pas exactement `N` octets. On
    /// refuse plutôt que de tronquer ou de compléter : une clé de longueur
    /// inattendue signale un défaut de programmation ou un format incohérent, et
    /// accepter silencieusement produirait un déverrouillage qui « marche » avec
    /// une clé fausse.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return Err(Error::InvalidLength {
                field: "key",
                expected: N,
                actual: bytes.len(),
            });
        }
        let mut key = Self::zeroed();
        key.expose_mut().copy_from_slice(bytes);
        Ok(key)
    }

    /// Vrai si le buffer a pu être verrouillé en RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.buf.is_locked()
    }

    /// Accès en lecture au matériel de clé.
    ///
    /// La longueur est `N`, connue à la compilation : il n'existe donc pas de
    /// méthode `len()`, et pas davantage de `is_empty()` — une clé de taille fixée
    /// par le type ne peut pas être vide.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    /// Comparaison en temps constant.
    ///
    /// À utiliser pour toute vérification d'égalité entre secrets. `subtle` compile
    /// en une séquence sans branche dépendante des données, ce qui évite qu'un
    /// attaquant local déduise un préfixe correct du temps de réponse.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.buf.as_slice().ct_eq(other.buf.as_slice()).into()
    }
}

impl<const N: usize> Drop for Key<N> {
    fn drop(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl<const N: usize> fmt::Debug for Key<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("len", &N)
            .field("contents", &"[EXPURGÉ]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_key_material() {
        let secret = SecretVec::from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("de"), "{rendered}");
        assert!(!rendered.contains("DE"), "{rendered}");
        assert!(!rendered.contains("222"), "{rendered}");
        assert!(rendered.contains("EXPURGÉ"), "{rendered}");

        let key = Key::<32>::from_array([0xDE; 32]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("222"), "{rendered}");
        assert!(rendered.contains("EXPURGÉ"), "{rendered}");
    }

    #[test]
    fn from_slice_rejects_wrong_length_instead_of_truncating() {
        let err = Key::<32>::from_slice(&[0u8; 31]);
        assert!(matches!(
            err,
            Err(Error::InvalidLength {
                expected: 32,
                actual: 31,
                ..
            })
        ));

        let err = Key::<32>::from_slice(&[0u8; 33]);
        assert!(matches!(err, Err(Error::InvalidLength { actual: 33, .. })));
    }

    #[test]
    fn constant_time_equality_matches_expectation() {
        let a = Key::<32>::from_array([7u8; 32]);
        let b = Key::<32>::from_array([7u8; 32]);
        let mut c_bytes = [7u8; 32];
        c_bytes[31] = 8;
        let c = Key::<32>::from_array(c_bytes);

        assert!(a.constant_time_eq(&b));
        assert!(!a.constant_time_eq(&c));
        assert!(!c.constant_time_eq(&a));
    }

    #[test]
    fn zeroed_key_is_all_zero_and_can_be_overwritten() {
        let mut key = Key::<16>::zeroed();
        assert!(key.expose().iter().all(|&b| b == 0));
        key.expose_mut().fill(0x42);
        assert!(key.expose().iter().all(|&b| b == 0x42));
    }

    #[test]
    fn secret_vec_roundtrips_bytes() {
        let secret = SecretVec::from_slice(b"correct horse battery staple");
        assert_eq!(secret.len(), 28);
        assert_eq!(secret.expose(), b"correct horse battery staple");
    }
}
