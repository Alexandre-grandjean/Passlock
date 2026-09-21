#![no_main]

//! Fuzzing de l'estimation heuristique de robustesse.
//!
//! Contrat : **aucune entrée ne doit provoquer de panique**, y compris les chaînes
//! Unicode arbitraires. La fonction est pure, sans horloge et sans entrée/sortie.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = passlock_core::security::estimate_strength(text);
    }
});
