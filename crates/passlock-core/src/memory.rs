//! Politique mémoire du moteur : verrouillage des zones sensibles et
//! durcissement du processus.
//!
//! Ce module ne réimplémente rien : il expose une vue stable du crate
//! `passlock-platform` et documente la politique du projet en un seul endroit,
//! afin qu'un lecteur n'ait pas à reconstituer celle-ci à partir de plusieurs
//! fichiers.
//!
//! ## Politique
//!
//! * Toute clé et tout buffer secret sont alloués via [`passlock_platform::memory::LockedBuffer`],
//!   donc `mlock`/`VirtualLock`, avec un **échec toléré** et **rapporté**.
//! * Le durcissement du processus est appliqué explicitement par le point d'entrée
//!   du binaire, jamais par l'initialisation de la bibliothèque : une bibliothèque
//!   ne doit pas modifier l'état global d'un processus hôte à son insu (les tests
//!   unitaires en seraient les premières victimes).
//! * Aucune de ces mesures ne protège contre un attaquant privilégié.

pub use passlock_platform::memory::{LockedBuffer, lock_region, unlock_region};
pub use passlock_platform::process::{HardeningOutcome, ProcessHardening, harden_process};

/// Vérifie qu'un buffer secret a bien pu être verrouillé.
///
/// Cette fonction existe pour forcer une décision explicite à chaque fois qu'un
/// secret est placé en mémoire. Un `is_locked() == false` signifie que le matériel
/// de clé peut être écrit dans le fichier d'échange et, sur Windows, apparaître
/// dans un vidage mémoire.
///
/// Le retour est un message destiné à l'utilisateur, prêt à afficher, et non une
/// erreur : une protection anti-swap absente ne doit **pas** empêcher l'usage du
/// coffre, elle doit être annoncée. Refuser de fonctionner serait disproportionné
/// et pousserait l'utilisateur à chercher un contournement.
#[must_use]
pub fn lock_status_warning(buffer: &LockedBuffer) -> Option<&'static str> {
    if buffer.is_locked() {
        None
    } else {
        Some(
            "Protection anti-swap indisponible : le système a refusé de verrouiller \
             les zones de clés en mémoire (limite RLIMIT_MEMLOCK atteinte ou quota \
             dépassé). Les clés peuvent donc être écrites dans le fichier d'échange \
             ou dans un vidage mémoire. Augmentez la limite avec `ulimit -l` \
             (Linux) ou réduisez la mémoire consommée par d'autres applications.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_lock_produces_an_explicit_message() {
        let buffer = LockedBuffer::new(32);
        match lock_status_warning(&buffer) {
            Some(message) => {
                // Le message doit dire quoi faire, pas seulement qu'il y a un problème.
                assert!(message.contains("swap"), "{message}");
                assert!(
                    message.contains("ulimit") || message.contains("quota"),
                    "{message}"
                );
            }
            // Le verrouillage a réussi sur cette machine : cas nominal.
            None => assert!(buffer.is_locked()),
        }
    }
}
