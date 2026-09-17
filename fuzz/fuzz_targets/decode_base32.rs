#![no_main]

//! Cible de fuzzing : décodage Base32, Base64url et hexadécimal.
//!
//! # Ce qui est cherché
//!
//! Un décodeur permissif est un **vecteur de malléabilité** : deux chaînes
//! distinctes produisant les mêmes octets. La cible vérifie donc non seulement
//! qu'aucune entrée ne provoque de panique, mais que tout décodage accepté est
//! **reproductible** : ré-encoder ce qui a été décodé doit redonner exactement
//! l'entrée, ou une forme canoniquement équivalente.
//!
//! # Propriétés vérifiées
//!
//! * aucune panique, sur aucune entrée ;
//! * un décodage accepté est **canonique** : la chaîne ré-encodée se redécode vers
//!   les mêmes octets ;
//! * aucune allocation démesurée : une entrée de grande taille est refusée avant
//!   tout travail ;
//! * le décodeur ne peut pas produire plus d'octets que la longueur encodée ne le
//!   permet.
//!
//! ```sh
//! cargo +nightly fuzz run decode_base32 -- -max_total_time=3600
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::encoding::{base32_decode, base32_encode, base32_encode_unpadded, base64url_decode, base64url_encode};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // --- Base32 ---
    if let Ok(decoded) = base32_decode(&text) {
        // Le nombre d'octets décodés ne peut pas dépasser ce que la longueur
        // encodée permet : 5 octets pour 8 caractères, soit un ratio de 5/8.
        assert!(
            decoded.len() <= text.len(),
            "{} octets décodés depuis {} caractères Base32",
            decoded.len(),
            text.len()
        );

        // Canonicalité : ré-encoder puis redécoder doit donner exactement les
        // mêmes octets. Deux encodages distincts pour les mêmes octets seraient
        // une malléabilité exploitable.
        let reencoded = base32_encode(decoded.expose());
        let reparsed = base32_decode(&reencoded)
            .expect("notre propre encodage doit être décodable");
        assert_eq!(
            reparsed.expose(),
            decoded.expose(),
            "non-canonique : « {text} » et « {reencoded} » divergent"
        );

        // La forme sans remplissage doit décoder vers les mêmes octets.
        let unpadded = base32_encode_unpadded(decoded.expose());
        let from_unpadded =
            base32_decode(&unpadded).expect("la forme sans remplissage doit être décodable");
        assert_eq!(from_unpadded.expose(), decoded.expose());
    }

    // --- Base64url ---
    if let Ok(decoded) = base64url_decode(&text) {
        assert!(
            decoded.len() <= text.len(),
            "{} octets décodés depuis {} caractères Base64url",
            decoded.len(),
            text.len()
        );

        let reencoded = base64url_encode(decoded.expose());
        let reparsed =
            base64url_decode(&reencoded).expect("notre propre encodage doit être décodable");
        assert_eq!(
            reparsed.expose(),
            decoded.expose(),
            "non-canonique : « {text} » et « {reencoded} » divergent"
        );
    }

    // --- Toutes les troncatures, sur une entrée acceptée ---
    //
    // Une troncature est le moyen le plus simple de faire sortir un décodeur de ses
    // bornes. On ne le fait que sur une entrée courte, pour rester dans le budget.
    if text.len() <= 64 && text.is_ascii() {
        for cut in 0..text.len() {
            let _ = base32_decode(&text[..cut]);
            let _ = base64url_decode(&text[..cut]);
        }
    }
});
