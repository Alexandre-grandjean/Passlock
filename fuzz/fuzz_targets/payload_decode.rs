#![no_main]

//! Cible de fuzzing : décodage de l'enveloppe de payload.
//!
//! # Une cible de priorité plus basse, et pourquoi elle existe quand même
//!
//! Le payload est décodé **après** que son tag a été vérifié : son entrée est donc
//! déjà authentifiée, contrairement au header. Le risque d'attaque y est bien plus
//! faible.
//!
//! La cible reste utile pour une raison différente : elle protège contre **nos
//! propres défauts d'encodage**. Si le format d'enveloppe et son décodeur
//! divergeaient, un coffre deviendrait silencieusement illisible, ou pire, un corps
//! tronqué serait accepté comme complet. Une erreur de ce type ne serait détectée
//! par aucun test fonctionnel tant qu'aucun coffre réel n'atteindrait la taille
//! concernée.
//!
//! ```sh
//! cargo +nightly fuzz run payload_decode -- -max_total_time=1800
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::payload::Payload;

fuzz_target!(|data: &[u8]| {
    let Ok(payload) = Payload::decode(data) else {
        return;
    };

    // Ré-encodage fidèle : ni octet manquant, ni octet excédentaire accepté.
    let encoded = payload
        .encode()
        .expect("un payload décodé doit pouvoir être re-encodé");
    // NOTE DE CORRECTION. Cette ligne comparait `Zeroizing<Vec<u8>>` à `&[u8]` : elle ne
    // compilait pas. La cible portait donc **zéro couverture depuis la phase 2**, tout en
    // figurant au manifeste — et personne ne l'a vu, parce qu'aucune exécution ne l'avait
    // atteinte. C'est le défaut que l'étape 3 met au jour en exécutant enfin les cibles
    // déclarées.
    assert_eq!(&encoded[..], data, "le payload ré-encodé diffère de l'entrée décodée");


    // La génération doit rester dans les bornes admises : un compteur qui
    // déborderait permettrait de masquer un retour en arrière en repartant de zéro.
    assert!(
        payload.generation < u64::MAX,
        "génération hors bornes acceptée"
    );

    // La longueur annoncée doit correspondre exactement au corps reçu.
    assert_eq!(
        data.len(),
        20 + payload.body.len(),
        "longueur de corps incohérente acceptée"
    );
});
