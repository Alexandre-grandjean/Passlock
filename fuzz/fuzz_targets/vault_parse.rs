#![no_main]

//! Cible de fuzzing : analyse d'un fichier de coffre complet.
//!
//! # Ce que cette cible cherche
//!
//! [`ParsedVault::parse`] est **le seul endroit du programme qui traite des données
//! non fiables avant toute authentification**. À ce stade, on ne sait pas si
//! l'utilisateur connaît le mot de passe : rien de ce qui est lu ne peut être cru.
//!
//! Deux classes de défauts sont recherchées :
//!
//! 1. **Panique.** Un gestionnaire de secrets qui s'arrête brutalement sur un
//!    fichier malformé est un déni de service ; un `panic` est aussi un point où des
//!    données peuvent se retrouver formatées dans un message.
//! 2. **Allocation non bornée.** Une longueur lue dans le fichier ne doit jamais
//!    dimensionner une allocation avant d'avoir été vérifiée. C'est ce qu'un
//!    fichier annonçant `header_len = u32::MAX` ou `m_cost = 4 Gio` chercherait à
//!    obtenir.
//!
//! # Comment l'exécuter
//!
//! ```sh
//! cargo install cargo-fuzz          # nécessite une toolchain nightly
//! cargo +nightly fuzz run vault_parse -- -max_total_time=3600
//! ```
//!
//! **Cette cible n'a pas été exécutée dans l'environnement de développement
//! actuel** : `cargo-fuzz` et la toolchain nightly n'y sont pas installés. Elle est
//! fournie pour l'intégration continue. La propriété correspondante est en revanche
//! vérifiée à chaque `cargo test` par
//! `crates/passlock-core/tests/malformed_input.rs`, qui est déterministe et
//! reproductible.

use libfuzzer_sys::fuzz_target;
use passlock_core::container::ParsedVault;

fuzz_target!(|data: &[u8]| {
    // P1 : ne doit jamais paniquer, quelle que soit l'entrée, y compris vide,
    // tronquée, ou composée de plusieurs mégaoctets de zéros.
    let Ok(parsed) = ParsedVault::parse(data) else {
        return;
    };

    // P2. Si le décodage a réussi, le ré-encodage doit être fidèle. Une divergence
    // signalerait que le décodeur accepte des formes que l'encodeur ne produit pas :
    // deux octets distincts représenteraient alors le même header, et l'AAD
    // deviendrait ambigu.
    let reencoded = parsed
        .header
        .encode()
        .expect("un header décodé doit pouvoir être ré-encodé");
    assert_eq!(
        &parsed.authenticated_prefix()[16..],
        reencoded.as_slice(),
        "le header ré-encodé diffère des octets décodés"
    );

    // P3. L'analyse ne doit rien déchiffrer : elle n'a pas de clé. Ce point vérifie
    // accessoirement que la taille du chiffré reste cohérente avec le fichier.
    assert_eq!(
        parsed.authenticated_prefix().len() + 24 + parsed.payload_ciphertext.len(),
        data.len(),
        "le découpage préfixe / nonce / chiffré ne couvre pas exactement le fichier"
    );
});
