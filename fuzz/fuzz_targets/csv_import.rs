#![no_main]

//! Fuzzing de l'analyse d'un CSV d'import.
//!
//! `portability::stage` est la partie **pure** de l'import : structure CSV, nombre de
//! colonnes, échappements, structure canonique des champs, types et bornes. Aucun
//! magasin n'est ouvert, donc aucun état n'est touché — et le contrat est simple :
//! **aucune entrée ne doit provoquer de panique**. Le résultat, lui, peut être une
//! erreur, un import vide, ou une liste d'entrées.
//!
//! La partie qui écrit (dossiers, tags, entrées) n'est pas fuzzée ici : elle exige un
//! coffre déverrouillé, et son contrat de sûreté — pas d'écriture partielle — est
//! couvert par les tests d'intégration.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = passlock_core::portability::stage(data, 0);
});
