#![no_main]

//! Fuzzing de l'analyse de date du centre de sécurité.
//!
//! Contrat : **aucune entrée ne doit provoquer de panique**. On exerce les deux
//! directions de la conversion — l'analyse stricte `YYYY-MM-DD` et l'arithmétique
//! jours↔civil — sur des octets arbitraires.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = passlock_core::security::CivilDate::parse(text);
    }

    if data.len() >= 8 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let days = i64::from_be_bytes(bytes);
        let date = passlock_core::security::CivilDate::from_days(days);
        // L'aller-retour doit rester cohérent pour toute date représentable.
        let _ = date.to_days();
    }
});
