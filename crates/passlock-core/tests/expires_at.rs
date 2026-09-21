//! Tests de l'étape 5.3 : définition et remplacement de `expires_at`.
//!
//! # Ce qui est éprouvé ici, et que rien d'autre n'éprouve
//!
//! C'est la **seule écriture** de la phase 5. Ces tests vérifient qu'elle passe par
//! le chemin métier (`update_entry`), qu'elle préserve les invariants, qu'elle crée
//! une révision d'historique, et qu'elle **refuse** au lieu de deviner.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::expiry::{self, ExpiryWrite};
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{Entry, EntryId, EntryKind, Field, FieldKind};
use passlock_core::security::{self, CivilDate, EXPIRES_AT_KEY, ExpiryState, ExpiryUnknown};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

const PASSWORD: &[u8] = b"phrase de passe pour les tests d'expiration";
const NOW: u64 = 1_700_000_000;

fn params() -> KdfParams {
    KdfParams::new(MIN_M_COST_KIB, 1, 1).expect("paramètres valides")
}

fn config(state: &Path) -> VaultConfig {
    VaultConfig {
        params: params(),
        read_only: false,
        state_dir: Some(state.to_path_buf()),
        ..VaultConfig::default()
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    state: PathBuf,
    store: VaultStore,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    let store = VaultStore::create(&path, PASSWORD, &config(&state)).expect("création");
    Fixture {
        _dir: dir,
        path,
        state,
        store,
    }
}

fn entry_with(title: &str, fields: Vec<Field>) -> Entry {
    let mut entry = Entry::new(EntryKind::Login, title, NOW).expect("entrée");
    entry.fields = fields;
    entry
}

fn date_field(value: &str, ordinal: u16) -> Field {
    Field::new(EXPIRES_AT_KEY, FieldKind::Date, value, ordinal).expect("champ")
}

fn count_expires(store: &VaultStore, id: &EntryId) -> usize {
    store
        .archive()
        .entry(id)
        .expect("entrée")
        .fields
        .iter()
        .filter(|field| field.key == EXPIRES_AT_KEY)
        .count()
}

fn stored_value(store: &VaultStore, id: &EntryId) -> Option<String> {
    store
        .archive()
        .entry(id)
        .expect("entrée")
        .fields
        .iter()
        .find(|field| field.key == EXPIRES_AT_KEY)
        .map(|field| field.value.clone())
}

// ---------------------------------------------------------------------------
// Ajout, remplacement, unicité
// ---------------------------------------------------------------------------

#[test]
fn it_adds_the_field_when_absent() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("sans date", vec![]))
        .expect("ajout");

    let outcome = expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");
    assert_eq!(outcome, ExpiryWrite::Added);
    assert_eq!(count_expires(&fixture.store, &id), 1);
    assert_eq!(
        stored_value(&fixture.store, &id).as_deref(),
        Some("2026-06-15")
    );

    let field = fixture
        .store
        .archive()
        .entry(&id)
        .expect("entrée")
        .fields
        .iter()
        .find(|field| field.key == EXPIRES_AT_KEY)
        .expect("champ");
    assert_eq!(field.kind, FieldKind::Date, "le genre doit être `Date`");
}

#[test]
fn it_replaces_an_existing_field_without_duplicating_it() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("avec date", vec![date_field("2026-01-01", 0)]))
        .expect("ajout");

    let outcome = expiry::set_expires_at(&mut fixture.store, &id, "2027-03-04").expect("écriture");
    assert_eq!(outcome, ExpiryWrite::Replaced);
    assert_eq!(count_expires(&fixture.store, &id), 1, "jamais de doublon");
    assert_eq!(
        stored_value(&fixture.store, &id).as_deref(),
        Some("2027-03-04")
    );
}

#[test]
fn it_replaces_a_field_of_the_wrong_kind() {
    // Un champ `expires_at` de genre `Text` est remplacé **entièrement** : après
    // l'opération, l'unique champ est bien de genre `Date`.
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with(
            "genre inattendu",
            vec![Field::new(EXPIRES_AT_KEY, FieldKind::Text, "bientot", 0).expect("champ")],
        ))
        .expect("ajout");

    expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");
    let field = fixture
        .store
        .archive()
        .entry(&id)
        .expect("entrée")
        .fields
        .iter()
        .find(|field| field.key == EXPIRES_AT_KEY)
        .expect("champ");
    assert_eq!(field.kind, FieldKind::Date);
    assert_eq!(field.value, "2026-06-15");
}

#[test]
fn it_refuses_an_ambiguous_entry_without_deleting_anything() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with(
            "ambigu",
            vec![date_field("2026-01-01", 0), date_field("2027-01-01", 1)],
        ))
        .expect("ajout");
    fixture.store.save().expect("enregistrement");
    let before = std::fs::read(&fixture.path).expect("lecture");

    let outcome = expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15");
    assert!(outcome.is_err(), "l'ambiguïté doit être refusée");

    // Rien n'a été supprimé ni modifié.
    assert_eq!(count_expires(&fixture.store, &id), 2, "aucun champ retiré");
    drop(fixture.store);
    assert_eq!(
        std::fs::read(&fixture.path).expect("lecture"),
        before,
        "le fichier n'a pas bougé"
    );
}

#[test]
fn it_leaves_other_fields_untouched() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with(
            "avec mot de passe",
            vec![
                Field::new("password", FieldKind::Secret, "s3cr3t", 0).expect("champ"),
                Field::new("url", FieldKind::Url, "https://exemple.com", 1).expect("champ"),
            ],
        ))
        .expect("ajout");

    expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");

    let entry = fixture.store.archive().entry(&id).expect("entrée");
    let password = entry
        .fields
        .iter()
        .find(|field| field.key == "password")
        .expect("champ password");
    let url = entry
        .fields
        .iter()
        .find(|field| field.key == "url")
        .expect("champ url");
    assert_eq!(password.value, "s3cr3t");
    assert_eq!(url.value, "https://exemple.com");
    assert_eq!(entry.fields.len(), 3);
}

// ---------------------------------------------------------------------------
// Validation, bornes, bissextilité
// ---------------------------------------------------------------------------

#[test]
fn it_accepts_valid_dates_and_refuses_invalid_ones() {
    let valid = [
        "1970-01-01",
        "2024-02-29", // année bissextile
        "2000-02-29", // divisible par 400
        "2026-06-15",
        "9999-12-31",
    ];
    let invalid = [
        "2026-2-3",    // forme non canonique
        "2026-13-01",  // mois 13
        "2026-00-10",  // mois 00
        "2026-02-00",  // jour 00
        "2026-02-30",  // jour impossible
        "2026-04-31",  // 30 jours en avril
        "2023-02-29",  // non bissextile
        "1900-02-29",  // 1900 hors bornes, et non bissextile
        "1969-12-31",  // année < 1970
        "10000-01-01", // année > 9999 (forme)
        "",            // vide
        "2026/06/15",  // mauvais séparateur
    ];

    let mut fixture = fixture();
    for date in valid {
        let id = fixture
            .store
            .add_entry(entry_with(date, vec![]))
            .expect("ajout");
        assert!(
            expiry::set_expires_at(&mut fixture.store, &id, date).is_ok(),
            "« {date} » devrait être acceptée"
        );
    }

    for date in invalid {
        let id = fixture
            .store
            .add_entry(entry_with(date, vec![]))
            .expect("ajout");
        let outcome = expiry::set_expires_at(&mut fixture.store, &id, date);
        assert!(outcome.is_err(), "« {date} » devrait être refusée");
        assert_eq!(
            count_expires(&fixture.store, &id),
            0,
            "« {date} » : aucune écriture sur refus"
        );
    }
}

// ---------------------------------------------------------------------------
// Historique, révision, persistance
// ---------------------------------------------------------------------------

#[test]
fn a_successful_write_creates_a_history_revision() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("révision", vec![]))
        .expect("ajout");
    fixture.store.save().expect("enregistrement");

    let revision_before = fixture.store.archive().entry(&id).expect("entrée").revision;

    expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");

    let entry = fixture.store.archive().entry(&id).expect("entrée");
    assert_eq!(entry.revision, revision_before + 1);
    assert_eq!(
        entry.history.len(),
        1,
        "une révision d'historique est créée"
    );
    // L'instantané antérieur ne porte pas encore la date.
    assert!(
        entry.history[0]
            .snapshot
            .fields
            .iter()
            .all(|field| field.key != EXPIRES_AT_KEY)
    );
}

#[test]
fn the_write_survives_a_save_and_reload() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("persistant", vec![]))
        .expect("ajout");

    expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");
    fixture.store.save().expect("enregistrement");
    drop(fixture.store);

    let reopened =
        VaultStore::open(&fixture.path, PASSWORD, &config(&fixture.state)).expect("réouverture");
    assert_eq!(stored_value(&reopened, &id).as_deref(), Some("2026-06-15"));
    assert_eq!(count_expires(&reopened, &id), 1);
}

#[test]
fn a_failed_validation_leaves_the_file_unchanged() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("intacte", vec![]))
        .expect("ajout");
    fixture.store.save().expect("enregistrement");
    let before = std::fs::read(&fixture.path).expect("lecture");

    assert!(expiry::set_expires_at(&mut fixture.store, &id, "2026-02-30").is_err());
    assert!(!fixture.store.is_dirty(), "aucune mutation marquée");

    drop(fixture.store);
    assert_eq!(std::fs::read(&fixture.path).expect("lecture"), before);
}

// ---------------------------------------------------------------------------
// Intégration au centre de sécurité
// ---------------------------------------------------------------------------

#[test]
fn the_security_center_sees_the_new_date() {
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("expiration", vec![]))
        .expect("ajout");

    let state_at = |store: &VaultStore, reference: &str| {
        security::expiry_state(
            &store.archive().entry(&id).expect("entrée").fields,
            CivilDate::parse(reference).expect("référence"),
            security::DEFAULT_EXPIRY_WINDOW_DAYS,
        )
    };

    // Avant écriture : aucune date.
    assert_eq!(
        state_at(&fixture.store, "2026-06-15"),
        ExpiryState::Unknown(ExpiryUnknown::Absent)
    );

    expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").expect("écriture");

    // La date enregistrée est le 2026-06-15 ; c'est la **référence** qui varie :
    // après la date (expirée), le jour même (bientôt), à −30 (bientôt), à −31 (valide).
    assert_eq!(state_at(&fixture.store, "2026-06-16"), ExpiryState::Expired);
    assert_eq!(state_at(&fixture.store, "2026-06-15"), ExpiryState::Soon);
    assert_eq!(
        state_at(&fixture.store, "2026-05-16"),
        ExpiryState::Soon,
        "à 30 jours de la date : bientôt"
    );
    assert_eq!(
        state_at(&fixture.store, "2026-05-15"),
        ExpiryState::Valid,
        "à 31 jours : valide"
    );
}

// ---------------------------------------------------------------------------
// Entrée inexistante, corbeille, archivage
// ---------------------------------------------------------------------------

#[test]
fn a_missing_entry_is_refused_without_modification() {
    let mut fixture = fixture();
    let ghost = EntryId::generate().expect("aléa");
    assert!(expiry::set_expires_at(&mut fixture.store, &ghost, "2026-06-15").is_err());
    assert_eq!(fixture.store.archive().entries.len(), 0);
}

#[test]
fn a_trashed_entry_can_still_be_modified() {
    // `update_entry` ne distingue pas la corbeille : la règle existante s'applique.
    let mut fixture = fixture();
    let id = fixture
        .store
        .add_entry(entry_with("corbeille", vec![]))
        .expect("ajout");
    fixture.store.trash_entry(&id).expect("corbeille");

    assert!(expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").is_ok());
    assert_eq!(count_expires(&fixture.store, &id), 1);
}

#[test]
fn an_archived_entry_is_modified_normally() {
    let mut fixture = fixture();
    let mut entry = entry_with("archivée", vec![]);
    entry.archived = true;
    let id = fixture.store.add_entry(entry).expect("ajout");

    assert!(expiry::set_expires_at(&mut fixture.store, &id, "2026-06-15").is_ok());
    let entry = fixture.store.archive().entry(&id).expect("entrée");
    assert!(entry.archived, "le drapeau d'archivage est préservé");
    assert_eq!(count_expires(&fixture.store, &id), 1);
}
