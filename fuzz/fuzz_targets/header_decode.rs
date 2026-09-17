#![no_main]

//! Cible de fuzzing : décodage du header.
//!
//! Le header est la partie la plus dense en champs contraints du format : rôles de
//! slot, algorithmes, versions, paramètres de dérivation, tailles fixes. Chaque
//! champ a une règle de validation, et cette cible vérifie qu'aucune d'elles ne peut
//! être contournée par une valeur inattendue.
//!
//! # Propriétés vérifiées
//!
//! * aucune panique, sur aucune entrée ;
//! * un décodage réussi implique un ré-encodage fidèle (pas d'ambiguïté d'encodage) ;
//! * les paramètres de dérivation acceptés restent dans les bornes documentées ;
//! * les identifiants de slot restent uniques.
//!
//! ```sh
//! cargo +nightly fuzz run header_decode -- -max_total_time=3600
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::header::Header;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = Header::decode(data) else {
        return;
    };

    // Ré-encodage fidèle : le décodage ne doit accepter que des formes que
    // l'encodage sait reproduire.
    let encoded = header
        .encode()
        .expect("un header décodé doit pouvoir être ré-encodé");
    assert_eq!(
        encoded, data,
        "le header ré-encodé diffère de l'entrée décodée"
    );

    // Invariants structurels : ils sont vérifiés par `validate()`, mais un
    // décodage ne doit jamais pouvoir produire une structure qui les viole.
    assert!(!header.slots.is_empty(), "aucun slot accepté");
    assert!(header.slots.len() <= 16, "trop de slots acceptés");

    for (index, slot) in header.slots.iter().enumerate() {
        assert!(
            !header.slots[..index].iter().any(|other| other.id == slot.id),
            "identifiants de slot dupliqués acceptés"
        );

        let params = slot.params;
        assert!(
            (8 * 1024..=2 * 1024 * 1024).contains(&params.m_cost_kib()),
            "coût mémoire hors bornes accepté : {}",
            params.m_cost_kib()
        );
        assert!(
            (1..=16).contains(&params.t_cost()),
            "nombre d'itérations hors bornes accepté"
        );
        assert!(
            (1..=16).contains(&params.p_cost()),
            "parallélisme hors bornes accepté"
        );
    }
});
