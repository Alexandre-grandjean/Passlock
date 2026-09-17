//! Durcissement du processus au démarrage.
//!
//! Ces mesures réduisent la probabilité qu'un matériel de clé quitte le processus
//! par un canal non contrôlé : vidage mémoire après plantage, ou lecture de notre
//! espace d'adressage par un autre processus non privilégié.
//!
//! ## Ce que ce module ne fait pas
//!
//! Rien ici ne protège contre un attaquant `root` / `Administrator`. Ces mesures
//! relèvent du principe de défense en profondeur contre un attaquant **local non
//! privilégié**, rien de plus. Toute communication à l'utilisateur doit le dire.
//!
//! ## Quand l'appeler
//!
//! [`harden_process`] modifie l'état **global du processus** (limites de
//! ressources, attribut de vidabilité). Il est donc appelé explicitement par le
//! point d'entrée du binaire, jamais par l'initialisation de la bibliothèque, afin
//! que les tests unitaires ne modifient pas leur propre processus.

use crate::backend;

/// Résultat d'une mesure de durcissement.
///
/// La distinction entre `Failed` et `Unsupported` est volontaire : elle permet de
/// dire à l'utilisateur *pourquoi* une protection est absente, plutôt que de
/// signaler un échec générique qui serait interprété comme un bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningOutcome {
    /// La mesure a été appliquée et vérifiée par le système.
    Applied,
    /// La plateforme ne propose pas cette mesure.
    Unsupported,
    /// La mesure existe mais l'appel a échoué.
    Failed,
}

/// Ensemble des mesures tentées, avec leur résultat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessHardening {
    /// Exclusion des vidages mémoire consécutifs à un plantage.
    pub core_dumps_disabled: HardeningOutcome,
    /// Restriction de l'accès à notre espace d'adressage par un autre processus
    /// du même utilisateur.
    pub ptrace_restricted: HardeningOutcome,
}

impl ProcessHardening {
    /// Vrai si au moins une mesure de durcissement n'a pas pu être appliquée.
    ///
    /// L'appelant doit en informer l'utilisateur : une protection silencieusement
    /// absente est pire qu'une protection absente annoncée.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !matches!(self.core_dumps_disabled, HardeningOutcome::Applied)
            || !matches!(self.ptrace_restricted, HardeningOutcome::Applied)
    }
}

/// Applique le durcissement du processus.
///
/// Idempotent : appeler cette fonction deux fois produit le même état.
#[must_use]
pub fn harden_process() -> ProcessHardening {
    ProcessHardening {
        core_dumps_disabled: backend::disable_core_dumps(),
        ptrace_restricted: backend::restrict_ptrace(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_degraded_reports_any_non_applied_measure() {
        let all_applied = ProcessHardening {
            core_dumps_disabled: HardeningOutcome::Applied,
            ptrace_restricted: HardeningOutcome::Applied,
        };
        assert!(!all_applied.is_degraded());

        for degraded in [
            ProcessHardening {
                core_dumps_disabled: HardeningOutcome::Failed,
                ptrace_restricted: HardeningOutcome::Applied,
            },
            ProcessHardening {
                core_dumps_disabled: HardeningOutcome::Applied,
                ptrace_restricted: HardeningOutcome::Unsupported,
            },
        ] {
            assert!(degraded.is_degraded());
        }
    }
}
