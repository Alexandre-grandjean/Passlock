//! Verrouillage de la mémoire sensible, façade portable.
//!
//! Le but est de soustraire les clés à deux mécanismes qui les copieraient hors
//! du contrôle du programme : le fichier d'échange (swap/pagefile) et les vidages
//! mémoire consécutifs à un plantage.
//!
//! ## Ce que cette protection ne fait pas
//!
//! * Elle **n'efface rien**. L'effacement est la responsabilité de `zeroize` dans
//!   `passlock-core` ; ce module ne fait que modifier l'état des pages.
//! * Elle ne protège **pas** contre un processus privilégié qui lit notre mémoire
//!   via `ptrace` / `/proc/<pid>/mem` / un accès DMA.
//! * Elle peut **échouer**, notamment quand `RLIMIT_MEMLOCK` est bas (cas par
//!   défaut sur la plupart des distributions Linux pour un processus non
//!   privilégié). L'échec est remonté à l'appelant via [`LockedBuffer::is_locked`].

use std::fmt;

pub use crate::backend::{exclude_from_dump, lock_region, unlock_region};

/// Buffer alloué sur le tas et verrouillé en RAM si le système le permet.
///
/// La taille est **fixée à la construction** et ne change jamais : une
/// réallocation déplacerait le buffer sur le tas et invaliderait le verrouillage,
/// qui porte sur des adresses. Le type n'expose donc aucune méthode de croissance.
///
/// L'implémentation de [`fmt::Debug`] n'affiche **jamais** le contenu, uniquement
/// la taille et l'état du verrouillage.
pub struct LockedBuffer {
    bytes: Vec<u8>,
    locked: bool,
    dump_excluded: bool,
}

impl LockedBuffer {
    /// Alloue `len` octets à zéro et tente de les verrouiller en RAM.
    #[must_use]
    pub fn new(len: usize) -> Self {
        let bytes = vec![0_u8; len];
        let locked = lock_region(bytes.as_ptr(), bytes.len()).is_ok();
        // `MADV_DONTDUMP` n'a de sens que si la zone est identifiée comme sensible ;
        // on le demande indépendamment du succès de `mlock`, dont l'échec est fréquent.
        let dump_excluded = exclude_from_dump(bytes.as_ptr(), bytes.len()).is_ok();
        Self {
            bytes,
            locked,
            dump_excluded,
        }
    }

    /// Vrai si la zone a effectivement pu être verrouillée en RAM.
    ///
    /// Un retour `false` signifie que le matériel de clé peut être écrit dans le
    /// fichier d'échange. L'appelant doit en informer l'utilisateur plutôt que
    /// d'ignorer silencieusement la dégradation.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Vrai si la zone a pu être exclue des vidages mémoire.
    #[must_use]
    pub fn is_dump_excluded(&self) -> bool {
        self.dump_excluded
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Libérer le verrouillage est nécessaire : le noyau maintient un compteur
        // par page, et laisser des pages verrouillées épuise lentement
        // `RLIMIT_MEMLOCK` au fil des cycles verrouillage/déverrouillage.
        if self.locked {
            let _ = unlock_region(self.bytes.as_ptr(), self.bytes.len());
        }
        // Aucun effacement ici : c'est le rôle de `zeroize` côté passlock-core, qui
        // garantit que l'effacement n'est pas supprimé par l'optimiseur. Dupliquer
        // cette logique ici donnerait une fausse impression de double protection.
    }
}

impl fmt::Debug for LockedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Le contenu n'est jamais affiché, même en `{:?}` : un buffer verrouillé
        // contient par définition du matériel de clé.
        f.debug_struct("LockedBuffer")
            .field("len", &self.bytes.len())
            .field("locked", &self.locked)
            .field("dump_excluded", &self.dump_excluded)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_contents() {
        let mut buf = LockedBuffer::new(32);
        buf.as_mut_slice().fill(0xAB);
        let rendered = format!("{buf:?}");
        assert!(
            !rendered.contains("ab") && !rendered.contains("AB") && !rendered.contains("171"),
            "le Debug d'un buffer de clé ne doit jamais exposer son contenu : {rendered}"
        );
    }

    #[test]
    fn allocation_and_drop_are_safe() {
        // Le verrouillage peut légitimement échouer (RLIMIT_MEMLOCK bas).
        // On vérifie ici que le cycle de vie ne panique pas et que la taille est
        // respectée, pas que le verrouillage a réussi.
        let mut buf = LockedBuffer::new(64);
        assert_eq!(buf.len(), 64);
        assert!(!buf.is_empty());
        buf.as_mut_slice()[0] = 1;
        assert_eq!(buf.as_slice()[0], 1);
    }

    #[test]
    fn zero_length_is_valid() {
        let buf = LockedBuffer::new(0);
        assert!(buf.is_empty());
    }
}
