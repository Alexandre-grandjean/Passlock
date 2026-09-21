//! Moteur cryptographique et conteneur de coffre de Passlock.
//!
//! ## Ce que ce crate fait
//!
//! Dériver des clés, chiffrer et authentifier, sérialiser un conteneur de coffre,
//! et écrire un fichier sans jamais exposer de données en clair.
//!
//! ## Ce que ce crate ne fait pas
//!
//! * **Aucune interface utilisateur.** Ni terminal, ni fenêtre.
//! * **Aucun accès réseau.** Ce crate ne dépend d'aucune bibliothèque réseau et
//!   ne peut donc pas exfiltrer de données, y compris par accident. Cette
//!   propriété est vérifiable par `cargo tree`.
//! * **Aucune écriture de secret non chiffré sur disque.**
//!
//! ## `forbid(unsafe_code)`
//!
//! L'attribut ci-dessous est une garantie **vérifiable par l'outillage**, pas une
//! convention. Tout code système (`mlock`, `prctl`, appels Win32) est isolé dans
//! le crate `passlock-platform`, dont la surface exposée tient en quelques
//! fonctions qui ne lisent jamais le contenu des buffers qu'elles manipulent.
//!
//! Vérification : `grep -rn "unsafe" crates/passlock-core/src` ne doit rien
//! retourner en dehors des commentaires.

#![forbid(unsafe_code)]
// Dans les tests, `expect` et `unwrap` sont la manière idiomatique d'exprimer
// « cette étape doit réussir ». Les interdire en production vise à empêcher un
// arrêt brutal sur une entrée non fiable ; dans un test, un échec **doit** faire
// échouer le test. La règle est donc levée ici, et seulement ici.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod aead;
pub mod archive;
pub mod attachment;
pub mod backup;
mod bytes;
pub mod container;
pub mod encoding;
pub mod entropy;
pub mod error;
pub mod generator;
pub mod header;
pub mod kdf;
pub mod keys;
pub mod memory;
pub mod migrate;
pub mod model;
pub mod payload;
pub mod query;
pub mod recovery;
pub mod rng;
pub mod rollback;
pub mod secret;
pub mod store;
pub mod totp;
pub mod vault;
pub mod wordlist;

#[cfg(test)]
pub(crate) mod test_support;
