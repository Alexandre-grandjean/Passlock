#![no_main]

//! Cible de fuzzing : analyse d'une URI `otpauth://`.
//!
//! # Pourquoi cette entrée est non fiable
//!
//! La chaîne analysée vient d'un champ du coffre. Elle est donc **authentifiée**
//! par l'AEAD, mais elle n'est **pas valide par construction** : elle peut avoir été
//! écrite par une version antérieure, par un import (phase 4), ou forgée par
//! quiconque détient la clé. C'est la seule entrée non fiable introduite par la
//! phase 3.
//!
//! # Propriétés vérifiées
//!
//! * **aucune panique**, sur aucune entrée, y compris binaire ou non-UTF-8 ;
//! * une analyse réussie implique un **ré-encodage fidèle** : la même URI doit être
//!   reproduite, sinon deux chaînes distinctes désigneraient le même secret ;
//! * le secret retenu respecte le plancher de la RFC 4226 §4 R6 (128 bits) ;
//! * les paramètres acceptés restent dans les bornes documentées ;
//! * le libellé et l'émetteur ne contiennent **aucun caractère de contrôle** — la
//!   barrière contre l'injection de séquences d'échappement dans le terminal.
//!
//! ```sh
//! cargo +nightly fuzz run parse_otpauth -- -max_total_time=3600
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::totp::{MAX_PERIOD, MAX_SECRET_LEN, MAX_TEXT_LEN, MIN_PERIOD, MIN_SECRET_LEN, Totp};

fuzz_target!(|data: &[u8]| {
    // Toute suite d'octets est interprétée comme du texte, avec perte : c'est le
    // cas réaliste d'un champ corrompu, et cela évite de restreindre le corpus aux
    // seules entrées UTF-8 valides.
    let text = String::from_utf8_lossy(data);

    let Ok(totp) = Totp::parse_uri(&text) else {
        return;
    };

    // --- Invariants sur le secret ---
    assert!(
        totp.secret_len() >= MIN_SECRET_LEN,
        "secret de {} octets accepté, sous le plancher de la RFC 4226 §4 R6",
        totp.secret_len()
    );
    assert!(
        totp.secret_len() <= MAX_SECRET_LEN,
        "secret de {} octets accepté, au-delà du plafond",
        totp.secret_len()
    );

    // --- Invariants sur les paramètres ---
    assert!(
        (MIN_PERIOD..=MAX_PERIOD).contains(&totp.period()),
        "période {} acceptée hors bornes",
        totp.period()
    );
    assert!(
        matches!(totp.digits().count(), 6 | 8),
        "nombre de chiffres {} accepté hors de {{6, 8}}",
        totp.digits().count()
    );

    // --- Barrière contre l'injection termininale ---
    //
    // Une séquence d'échappement ANSI imprimée telle quelle réécrit le tampon de
    // l'écran : elle permettrait d'afficher un code qui n'est pas celui produit.
    // Le refus doit avoir lieu à l'analyse, et cette assertion est ce qui le
    // garantit pour TOUTE URI acceptée, pas seulement pour les cas testés.
    for (what, value) in [
        ("libellé", Some(totp.label())),
        ("émetteur", totp.issuer()),
    ] {
        if let Some(value) = value {
            assert!(
                !value.chars().any(char::is_control),
                "caractère de contrôle accepté dans le {what} : {value:?}"
            );
            assert!(
                value.len() <= MAX_TEXT_LEN,
                "{what} de {} octets accepté, au-delà du plafond",
                value.len()
            );
        }
    }

    // --- Aller-retour fidèle ---
    let uri = totp.to_uri();
    let reparsed = Totp::parse_uri(&uri)
        .expect("notre propre URI doit être réanalysable : sinon l'enregistrement \
                 produirait une entrée illisible");

    assert_eq!(reparsed.algorithm(), totp.algorithm(), "algorithme perdu");
    assert_eq!(reparsed.digits(), totp.digits(), "chiffres perdus");
    assert_eq!(reparsed.period(), totp.period(), "période perdue");
    assert_eq!(reparsed.label(), totp.label(), "libellé perdu");

    // Le secret doit survivre à l'aller-retour : c'est ce qui garantit que les
    // codes restent les mêmes après un enregistrement.
    assert_eq!(
        *totp.code(1_700_000_000).expect("code"),
        *reparsed.code(1_700_000_000).expect("code"),
        "les codes diffèrent après un aller-retour par l'URI"
    );

    // --- Le calcul ne doit jamais paniquer, à aucune borne d'instant ---
    for instant in [0_u64, 1, 59, 1_700_000_000, u32::MAX.into(), u64::MAX] {
        let _ = totp.code(instant);
        let _ = totp.remaining(instant);
        let _ = totp.counter_at(instant);
    }
});
