#![no_main]

//! Fuzzing de l'analyse d'URL.
//!
//! L'analyse est **pure** : entrée `&str`, verdict, aucune E/S, aucun réseau, aucune
//! horloge. Le contrat de cette cible est l'**absence de panique** sur n'importe
//! quelle chaîne, y compris hostile ou non UTF-8.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = passlock_core::url::analyze(text);
    }
});
