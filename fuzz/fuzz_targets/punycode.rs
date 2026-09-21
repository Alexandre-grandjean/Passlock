#![no_main]

//! Fuzzing du codec Punycode (RFC 3492).
//!
//! L'encodage et le décodage sont bornés et sans E/S. Le contrat est l'absence de
//! panique et de dépassement arithmétique sur une entrée arbitraire.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = passlock_core::encoding::punycode_decode(text);
        let _ = passlock_core::encoding::punycode_encode(text);
    }
});
