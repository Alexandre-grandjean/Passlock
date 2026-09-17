//! Primitives système non portables, isolées du reste du projet.
//!
//! Ce crate est le **seul** du projet autorisé à utiliser `unsafe`. Tout le reste
//! du code est couvert par `#![forbid(unsafe_code)]`, ce qui rend la règle
//! vérifiable par une simple recherche textuelle.
//!
//! ## Périmètre
//!
//! Les fonctions de ce crate manipulent des **adresses** de buffers. Elles ne
//! lisent ni ne modifient jamais le contenu des zones concernées : `mlock`,
//! `madvise` et leurs équivalents n'agissent que sur l'état des pages dans la
//! table de pages du noyau.
//!
//! ## Limites assumées
//!
//! * Aucune de ces mesures ne protège contre un attaquant disposant des
//!   privilèges `root` ou `Administrator`. Elles augmentent le coût d'une
//!   attaque non privilégiée, elles ne l'empêchent pas.
//! * L'échec d'un verrouillage mémoire est un cas de fonctionnement **normal**.
//!   Il doit être signalé à l'utilisateur, jamais traité comme une panique.

#![deny(unsafe_op_in_unsafe_fn)]
// Dans les tests, `expect` et `unwrap` sont la manière idiomatique d'exprimer
// « cette étape doit réussir ». Les interdire en production vise à empêcher un
// arrêt brutal sur une entrée non fiable ; dans un test, un échec **doit** faire
// échouer le test. La règle est donc levée ici, et seulement ici.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

#[cfg(unix)]
#[path = "linux.rs"]
mod backend;

#[cfg(windows)]
#[path = "windows.rs"]
mod backend;

pub mod fs;
pub mod memory;
pub mod process;
pub mod tty;
