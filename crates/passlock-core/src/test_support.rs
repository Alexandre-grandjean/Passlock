//! Aides réservées aux tests unitaires du crate.
//!
//! Ce module n'existe pas dans un binaire compilé sans `cfg(test)`. Il ne contient
//! aucune logique de production et ne doit jamais en contenir.

use crate::kdf::{KdfParams, MIN_M_COST_KIB};

/// Paramètres de dérivation les plus légers **acceptés par la validation**.
///
/// # Pourquoi les tests n'utilisent pas un profil réaliste
///
/// Argon2id est une fonction purement calculatoire, et son coût est le facteur
/// limitant de cette suite de tests. Mesures faites sur la machine de
/// développement, pour une seule dérivation :
///
/// | Profil | Mémoire | Itérations | Profil `dev` | Profil `release` |
/// |---|---|---|---|---|
/// | `standard()` | 256 Mio | 3 | (non mesuré) | (non mesuré) |
/// | `low()` | 64 Mio | 3 | **~3,3 s** | **~0,155 s** |
/// | `cheap_params()` | 8 Mio | 1 | (déduit ≈ 0,14 s) | (déduit ≈ 6 ms) |
///
/// La suite complète a été mesurée à **685 s** avant ce changement, dominée par
/// deux tests qui appelaient `Vault::open` une fois par octet muté.
///
/// # Pourquoi ce n'est pas un affaiblissement de la couverture
///
/// Les paramètres de dérivation sont des **entrées** des fonctions concernées, pas
/// des branches. Le chemin de code parcouru est rigoureusement identique quelle que
/// soit leur valeur. Ce qui dépend réellement des valeurs — le refus des paramètres
/// hors bornes et l'avertissement « plus faible que la recommandation » — fait
/// l'objet de tests dédiés qui, eux, construisent et vérifient des valeurs
/// explicites sans effectuer de dérivation.
///
/// Les valeurs **livrées par défaut** ne sont pas touchées : `KdfParams::default()`
/// et `VaultConfig::default()` restent sur `standard()` (256 Mio, t=3, p=4).
#[must_use]
pub(crate) fn cheap_params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, 1, 1)
        .expect("les paramètres minimaux doivent toujours être acceptés par la validation")
}
