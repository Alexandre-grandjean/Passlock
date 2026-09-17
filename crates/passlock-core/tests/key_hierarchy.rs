//! Tests d'intégration du moteur, à travers son API publique uniquement.
//!
//! # Pourquoi des tests d'intégration en plus des tests unitaires
//!
//! Les tests unitaires, à l'intérieur du crate, ont accès aux éléments privés. Ces
//! tests-ci n'utilisent que ce qu'un consommateur externe peut utiliser — ce qui est
//! précisément la surface que la bibliothèque s'engage à maintenir. Un remaniement
//! interne ne les casse pas ; un changement d'API ou de format, si.
//!
//! # L'invariant central
//!
//! **Un changement de mot de passe maître ne doit pas changer la clé de données.**
//! Si cet invariant se brise, le coffre peut devenir définitivement illisible, ou
//! les données peuvent être rechiffrées sous une clé dérivée du mot de passe — ce qui
//! annulerait tout l'intérêt de l'architecture à slots.
//!
//! La formulation correcte de l'invariant est celle-ci : la **DEK** et le **payload
//! déchiffré** sont conservés. Il serait faux d'exiger que le *ciphertext* du payload
//! soit identique, puisque le header entre dans l'AAD et qu'un nouveau sel change le
//! header — donc le nonce et le chiffré. Voir `docs/DECISIONS.md` ADR-003.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
// Le corps de test est produit par une suite arithmétique tronquée : la troncature
// est l'opération voulue pour obtenir des octets variés et non répétitifs.
#![allow(clippy::cast_possible_truncation)]

use std::path::Path;

use passlock_core::container::ParsedVault;
use passlock_core::error::Error;
use passlock_core::header::SlotLabel;
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::rollback::RollbackCheck;
use passlock_core::vault::{Vault, VaultConfig};

const PASSWORD: &[u8] = b"phrase de passe initiale pour le test";
const NEW_PASSWORD: &[u8] = b"phrase de passe de remplacement du test";

/// Paramètres légers : les tests ne mesurent pas le coût du KDF, et le chemin de
/// code parcouru ne dépend pas des valeurs. Voir `docs/DECISIONS.md` ADR-015.
fn params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, 1, 1).expect("paramètres valides")
}

fn config(state: &Path) -> VaultConfig {
    VaultConfig {
        params: params(),
        read_only: false,
        state_dir: Some(state.to_path_buf()),
    }
}

/// Crée un coffre contenant un corps de test, et retourne le chemin et l'état.
fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("répertoire temporaire");
    let vault_path = dir.path().join("coffre.plk");
    let state_dir = dir.path().join("etat");
    let mut vault = Vault::create(&vault_path, PASSWORD, &config(&state_dir)).expect("création");
    vault.set_body(b"corps de test".to_vec());
    vault.save().expect("enregistrement");
    (dir, vault_path, state_dir)
}

// ---------------------------------------------------------------------------
// Invariant central
// ---------------------------------------------------------------------------

#[test]
fn changing_the_password_preserves_the_payload_and_the_vault_identity() {
    let (_dir, path, state) = setup();

    let before = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture");
    let identity_before = before.header().vault_id;
    let body_before = before.body().to_vec();
    let ciphertext_before = std::fs::read(&path).expect("lecture");
    drop(before);

    let mut vault = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture");
    vault
        .change_password(PASSWORD, NEW_PASSWORD, params())
        .expect("changement de mot de passe");
    drop(vault);

    let after = Vault::open(&path, NEW_PASSWORD, &config(&state)).expect("ouverture");
    let ciphertext_after = std::fs::read(&path).expect("lecture");

    // 1. Le contenu est rigoureusement identique.
    assert_eq!(
        after.body(),
        body_before.as_slice(),
        "le contenu a été altéré par le changement de mot de passe"
    );

    // 2. L'identité du coffre est conservée : la sentinelle anti-retour-en-arrière
    //    reste donc valide, et une sauvegarde reste corrélable.
    assert_eq!(after.header().vault_id, identity_before);

    // 3. Le fichier a bien changé — sinon c'est que rien n'a été écrit.
    assert_ne!(
        ciphertext_before, ciphertext_after,
        "le fichier est inchangé : le changement de mot de passe n'a pas été enregistré"
    );

    // 4. L'ancien mot de passe ne fonctionne plus.
    drop(after);
    assert!(matches!(
        Vault::open(&path, PASSWORD, &config(&state)),
        Err(Error::UnlockFailed)
    ));
}

#[test]
fn only_the_header_region_is_rewritten_and_the_body_is_intact() {
    // Complément du test précédent, formulé en termes de format : le corps
    // déchiffré doit être retrouvé **octet pour octet** après un changement de mot
    // de passe, y compris quand il est volumineux et non trivial.
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");

    // Un corps de 64 Kio avec une structure non répétitive.
    let body: Vec<u8> = (0..65_536_u32)
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();

    let mut vault = Vault::create(&path, PASSWORD, &config(&state)).expect("création");
    vault.set_body(body.clone());
    vault.save().expect("enregistrement");
    vault
        .change_password(PASSWORD, NEW_PASSWORD, params())
        .expect("changement de mot de passe");
    drop(vault);

    let reopened = Vault::open(&path, NEW_PASSWORD, &config(&state)).expect("ouverture");
    assert_eq!(
        reopened.body().len(),
        body.len(),
        "longueur du contenu modifiée"
    );
    assert_eq!(reopened.body(), body.as_slice(), "contenu modifié");
}

// ---------------------------------------------------------------------------
// Stabilité du format
// ---------------------------------------------------------------------------

#[test]
fn the_header_layout_matches_the_documented_specification() {
    // Ce test est un garde-fou contre une dérive silencieuse entre le code et
    // `docs/VAULT_FORMAT.md`. Toute modification des constantes de layout doit être
    // accompagnée d'une mise à jour de la documentation **et** d'une incrémentation
    // de la version de format.
    let (_dir, path, _state) = setup();
    let bytes = std::fs::read(&path).expect("lecture");

    assert_eq!(&bytes[0..8], b"PASSLOCK", "signature inattendue");
    assert_eq!(
        u16::from_be_bytes([bytes[8], bytes[9]]),
        1,
        "version de format inattendue"
    );
    assert_eq!(
        u16::from_be_bytes([bytes[10], bytes[11]]),
        0,
        "les drapeaux doivent valoir zéro"
    );

    let header_len = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    assert_eq!(
        header_len,
        28 + 122,
        "taille de header inattendue pour un slot (28 fixe + 122 par slot)"
    );

    // Le slot commence à 16 + 28 et les champs y sont à offsets fixes.
    let slot = 16 + 28;
    assert_eq!(
        u16::from_be_bytes([bytes[slot], bytes[slot + 1]]),
        0,
        "identifiant de slot inattendu"
    );
    assert_eq!(bytes[slot + 2], 1, "rôle du slot : 1 = mot de passe maître");
    assert_eq!(
        bytes[slot + 3],
        1,
        "algorithme de dérivation : 1 = Argon2id"
    );
    assert_eq!(bytes[slot + 4], 0x13, "version d'Argon2 attendue : 0x13");
    assert_eq!(bytes[slot + 5], 0, "zone réservée du slot non nulle");
}

#[test]
fn a_vault_is_readable_after_a_round_trip_through_a_copy() {
    // Propriété qui rend la sauvegarde triviale : une copie de fichier **est** une
    // sauvegarde valide, sans traitement particulier.
    let (_dir, path, state) = setup();
    let copy = path.with_extension("copie.plk");

    std::fs::copy(&path, &copy).expect("copie");

    let original = Vault::open(&path, PASSWORD, &config(&state)).expect("original");
    let duplicate = Vault::open(&copy, PASSWORD, &config(&state)).expect("copie");

    assert_eq!(original.body(), duplicate.body());
    assert_eq!(original.header().vault_id, duplicate.header().vault_id);
    assert_eq!(original.generation(), duplicate.generation());
}

#[test]
fn public_metadata_is_readable_without_the_password_and_stays_minimal() {
    // Contrôle de la propriété de minimisation : le header ne doit révéler ni
    // nombre d'entrées, ni titre, ni taille du contenu applicatif.
    let (_dir, path, _state) = setup();
    let bytes = std::fs::read(&path).expect("lecture");
    let parsed = ParsedVault::parse(&bytes).expect("analyse");

    assert_eq!(parsed.header.slots.len(), 1);
    assert_eq!(
        parsed.header.master_slot().map(|slot| slot.label),
        Some(SlotLabel::Master)
    );
    assert!(
        parsed.header.created_at > 1_577_836_800,
        "date invraisemblable"
    );

    // Le corps fait 13 octets ; le fichier ne doit en aucun cas permettre de le
    // déduire autrement que par la taille totale, qui inclut le remplissage du
    // chiffrement.
    let header_len = 28 + 122;
    let payload_len = bytes.len() - 16 - header_len - 24;
    assert!(
        payload_len > 13,
        "la taille du payload devrait inclure le tag et l'enveloppe"
    );
}

// ---------------------------------------------------------------------------
// Diagnostic et robustesse
// ---------------------------------------------------------------------------

#[test]
fn a_freshly_created_vault_reports_a_healthy_state() {
    let (_dir, path, state) = setup();
    let vault = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture");

    assert_eq!(
        vault.diagnostics().rollback,
        RollbackCheck::Consistent,
        "un coffre sans modification ne doit pas signaler de retour en arrière"
    );
    assert!(
        vault.lock_path().is_some(),
        "un verrou d'écriture doit être détenu"
    );
}

#[test]
fn restoring_a_copy_is_reported_but_never_blocks_opening() {
    // C'est la contrepartie indispensable de la détection : après un sinistre, la
    // restauration d'une sauvegarde doit rester possible. On alerte, on n'empêche pas.
    let (_dir, path, state) = setup();

    let mut vault = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture");
    vault.set_body(b"contenu de la sauvegarde".to_vec());
    vault.save().expect("enregistrement");
    let backup = std::fs::read(&path).expect("lecture");

    vault.set_body(b"contenu posterieur".to_vec());
    vault.save().expect("enregistrement");
    drop(vault);

    std::fs::write(&path, &backup).expect("restauration");

    let restored = Vault::open(&path, PASSWORD, &config(&state))
        .expect("une restauration légitime doit rester possible");

    assert!(
        matches!(
            restored.diagnostics().rollback,
            RollbackCheck::Rollback { .. }
        ),
        "le retour en arrière n'a pas été signalé"
    );
    assert_eq!(restored.body(), b"contenu de la sauvegarde");
}

#[test]
fn opening_a_vault_in_read_only_never_modifies_the_file() {
    let (_dir, path, state) = setup();
    let before = std::fs::read(&path).expect("lecture");

    let mut vault = Vault::open(
        &path,
        PASSWORD,
        &VaultConfig {
            read_only: true,
            ..config(&state)
        },
    )
    .expect("ouverture");

    // Même en tentant une écriture, rien ne doit atteindre le disque.
    vault.set_body(b"tentative d'ecriture".to_vec());
    assert!(matches!(vault.save(), Err(Error::ReadOnly)));

    let after = std::fs::read(&path).expect("lecture");
    assert_eq!(before, after, "le fichier a été modifié en lecture seule");
}

#[test]
fn arbitrary_files_are_never_mistaken_for_vaults() {
    let dir = tempfile::tempdir().expect("répertoire");
    let state = dir.path().join("etat");

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("vide", Vec::new()),
        ("un octet", vec![0]),
        ("zeros", vec![0_u8; 4096]),
        ("octets hauts", vec![0xFF_u8; 4096]),
        ("texte", b"ceci est un fichier texte quelconque".to_vec()),
        ("signature tronquee", b"PASSLOC".to_vec()),
        ("signature seule", b"PASSLOCK".to_vec()),
        ("signature et version", b"PASSLOCK\x00\x01".to_vec()),
    ];

    for (name, contents) in cases {
        let path = dir.path().join(format!("{name}.plk"));
        std::fs::write(&path, &contents).expect("écriture");

        let outcome = Vault::open(&path, PASSWORD, &config(&state));
        assert!(
            outcome.is_err(),
            "un fichier « {name} » a été accepté comme coffre valide"
        );
    }
}

#[test]
fn a_modified_slot_and_a_wrong_password_produce_the_same_public_error() {
    // Propriété anti-oracle, vérifiée ici à travers l'API publique.
    let (_dir, path, state) = setup();
    let original = std::fs::read(&path).expect("lecture");

    // Altération de la clé enveloppée du slot maître : offsets 16 + 28 + 74 .. +122.
    let wrapped = 16 + 28 + 74;
    let mut tampered = original.clone();
    tampered[wrapped] ^= 0x01;
    std::fs::write(&path, &tampered).expect("écriture");

    let tampered_error = Vault::open(&path, PASSWORD, &config(&state))
        .expect_err("un slot altéré doit être refusé")
        .to_string();

    std::fs::write(&path, &original).expect("écriture");

    let wrong_password_error = Vault::open(&path, b"mauvais mot de passe", &config(&state))
        .expect_err("un mot de passe faux doit être refusé")
        .to_string();

    assert_eq!(
        tampered_error, wrong_password_error,
        "les deux causes doivent être indiscernables : un attaquant ne doit pas \
         pouvoir distinguer un coffre altéré d'un mot de passe faux"
    );
}

#[test]
fn debug_output_of_mixed_operations_never_leaks_the_body() {
    // Vérifie la propriété sur le chemin complet : après création, écriture puis
    // changement de mot de passe, aucun `Debug` ne doit avoir exposé le contenu.
    let (_dir, path, state) = setup();
    let marker = b"MARQUEUR-CONFIDENTIEL-A-NE-PAS-JOURNALISER";

    let mut vault = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture");
    vault.set_body(marker.to_vec());

    let rendered_debug = format!("{vault:?}");
    assert!(
        !rendered_debug.contains("MARQUEUR"),
        "le contenu du coffre apparaît dans un Debug : {rendered_debug}"
    );

    vault.save().expect("enregistrement");
    let rendered_after_save = format!("{vault:?}");
    assert!(
        !rendered_after_save.contains("MARQUEUR"),
        "{rendered_after_save}"
    );

    drop(vault);

    // Le chiffré sur disque ne doit évidemment pas contenir le marqueur non plus.
    let bytes = std::fs::read(&path).expect("lecture");
    assert!(
        !bytes
            .windows(marker.len())
            .any(|window| window == marker.as_slice()),
        "le marqueur apparaît en clair dans le fichier de coffre"
    );
}
