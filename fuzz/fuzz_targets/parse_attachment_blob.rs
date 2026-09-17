#![no_main]

//! Cible de fuzzing : décodage d'un header de pièce jointe.
//!
//! # Pourquoi cette surface-là
//!
//! Le header d'un blob est, comme celui du conteneur, une donnée **non fiable traitée
//! avant toute authentification** : il faut le lire pour savoir quoi déchiffrer. C'est
//! aussi lui qui porte les valeurs qui dimensionnent les allocations (`chunk_count`,
//! `chunk_size`, `plaintext_size`), donc le seul endroit où une valeur lue pourrait
//! commander une réservation mémoire.
//!
//! Le format n'a **pas de parseur** (ADR-004) : le décodage est une suite de lectures
//! bornées. Cette cible vérifie que cela reste vrai.
//!
//! # Propriétés vérifiées
//!
//! * aucune panique, sur aucune entrée, y compris toutes les troncatures ;
//! * un header accepté est **ré-encodable à l'identique** : l'encodage est
//!   déterministe, donc `decode(encode(h)) == h` ;
//! * un header accepté est **cohérent avec lui-même** : `chunk_count` recalculé depuis
//!   la taille et la taille de morceau, bornes respectées, champ réservé nul ;
//! * aucune allocation n'est commandée par une valeur non bornée : les bornes sont
//!   vérifiées **avant** tout usage.
//!
//! # Ce que cette cible ne couvre pas
//!
//! Le **lecteur** de blob exige un fichier : ses contrôles de structure (longueur
//! exacte, nombre de morceaux, empreinte) sont couverts par `tests/attachment_format.rs`
//! et `tests/attachment_store.rs`, pas ici. Le dire évite de croire que le fuzzing
//! couvre toute la surface.
//!
//! ```sh
//! cargo +nightly fuzz run parse_attachment_blob -- -max_total_time=3600
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::attachment::{ATTACHMENT_CHUNK_SIZE, BlobHeader, MAX_ATTACHMENT_BYTES};

/// Taille du header, redéclarée : l'épingler indépendamment du code de production est
/// ce qui permet à cette cible de détecter un décalage de format.
const BLOB_HEADER_LEN: usize = 40;

fuzz_target!(|data: &[u8]| {
    if data.len() < BLOB_HEADER_LEN {
        // Une entrée trop courte doit être refusée **proprement**, jamais paniquer.
        assert!(BlobHeader::decode(data).is_err());
        return;
    }

    let window = &data[..BLOB_HEADER_LEN];
    let Ok(header) = BlobHeader::decode(window) else {
        return;
    };

    // L'encodage est déterministe : deux encodages du même header sont identiques, et
    // le décodage d'un encodage redonne le même header.
    let reencoded = header.encode();
    let reparsed =
        BlobHeader::decode(&reencoded).expect("notre propre encodage doit être décodable");
    assert_eq!(
        reparsed, header,
        "l'encodage d'un header accepté doit être réversible à l'identique"
    );
    assert_eq!(
        reencoded.len(),
        BLOB_HEADER_LEN,
        "un header fait exactement {BLOB_HEADER_LEN} octets"
    );

    // Cohérence interne.
    assert!(header.chunk_count >= 1, "un blob porte au moins un morceau");
    assert!(header.chunk_size >= 1, "une taille de morceau nulle est refusée");
    assert!(
        header.chunk_size <= 64 * 1024 * 1024,
        "la taille de morceau décodée reste bornée"
    );
    assert!(
        header.plaintext_size <= MAX_ATTACHMENT_BYTES,
        "la taille en clair décodée reste bornée"
    );

    // Le nombre de morceaux est celui qu'impose la taille : c'est cette égalité qui rend
    // impossible un morceau court **non final**.
    let chunk = u64::from(header.chunk_size).max(1);
    let expected = if header.plaintext_size == 0 {
        1
    } else {
        header.plaintext_size.div_ceil(chunk)
    };
    assert_eq!(
        u64::from(header.chunk_count),
        expected,
        "le décodage doit recalculer le nombre de morceaux, jamais le croire sur parole"
    );

    // Le producteur écrit toujours la taille de morceau du format, mais le décodeur en
    // **tolère** une autre **dans la borne** : sans quoi un fichier écrit par une version
    // future — ou par une autre implémentation du format — deviendrait illisible. Cette
    // tolérance est bornée, et c'est la borne qui compte : `chunk_size` dimensionne une
    // allocation.
    //
    // NOTE DE CORRECTION. Une version antérieure de cette cible affirmait ici qu'une
    // taille supérieure à celle du format « n'est produite par aucune version connue » —
    // et l'exigeait donc absente. **C'était une croyance fausse sur notre propre
    // contrat**, et le fuzzing l'a mise en évidence en quelques centaines d'exécutions :
    // le décodeur accepte 2 Mio de morceau, et il a raison de le faire. L'assertion a été
    // retirée au profit de la borne réelle, ci-dessus.
    let _ = ATTACHMENT_CHUNK_SIZE;
});
