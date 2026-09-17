//! Tests d'intégration des pièces jointes **à travers le magasin**.
//!
//! # Ce que ces tests exercent, et que les tests du codec n'exercent pas
//!
//! `tests/attachment_format.rs` vérifie le **format** : l'AAD, les morceaux, le MAC.
//! Ici, c'est la **frontière `Store` / `Vault::save`** qui est éprouvée — c'est-à-dire
//! l'endroit où l'ordre des opérations devient une propriété de sécurité.
//!
//! | Invariant | Ce qu'il protège |
//! |---|---|
//! | `I-BLOB-ORDER`, écriture | jamais de métadonnée sans son blob — au pire un orphelin |
//! | `I-BLOB-ORDER`, suppression | jamais de blob supprimé avant que le coffre ne le référence plus |
//! | Collision de nom | `O_EXCL` est la garantie ultime : rien n'est jamais écrasé |
//! | Séparation vérification / GC | une corruption ne devient jamais une perte de données |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::attachment::{self, sweep_blobs, verify_blob};
use passlock_core::error::Error;
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{Entry, EntryId, EntryKind};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

const PASSWORD: &[u8] = b"phrase de passe pour les tests de pieces jointes";

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

fn read_only_config(state: &Path) -> VaultConfig {
    VaultConfig {
        read_only: true,
        ..config(state)
    }
}

struct Fixture {
    /// Répertoire de travail : conservé vivant pour que le coffre et ses blobs
    /// existent pendant toute la durée du test.
    dir: tempfile::TempDir,
    path: PathBuf,
    state: PathBuf,
}

fn fixture() -> (Fixture, VaultStore, EntryId) {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    let mut store = VaultStore::create(&path, PASSWORD, &config(&state)).expect("création");
    let entry = store
        .add_entry(Entry::new(EntryKind::Login, "exemple.com", 1_700_000_000).expect("entrée"))
        .expect("ajout");
    store.save().expect("enregistrement");
    (Fixture { dir, path, state }, store, entry)
}

/// Écrit un fichier source de test.
fn source_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("écriture de la source");
    path
}

// ---------------------------------------------------------------------------
// I-BLOB-ORDER — écriture
// ---------------------------------------------------------------------------

#[test]
fn the_blob_is_on_disk_before_its_metadata_is_saved() {
    // **Le cœur de `I-BLOB-ORDER`**, à la frontière réelle `Store` / `Vault::save`.
    //
    // Après `add_attachment` et **avant** `save`, l'état doit être : blob **présent sur
    // le disque**, métadonnée **absente du fichier de coffre**. Si un incident survient
    // ici, il reste un orphelin — jamais une promesse non tenue.
    let (f, mut store, entry) = fixture();
    let source = source_file(f.dir.path(), "secret.bin", b"contenu attache");

    let meta = store
        .add_attachment(&entry, "secret.bin", &source)
        .expect("ajout");

    // 1. Le blob est écrit et durable.
    let blob = store.blob_path(&meta.id).expect("chemin");
    assert!(
        blob.exists(),
        "le blob doit être sur le disque avant tout `save`"
    );
    assert_eq!(store.attachments_of(&entry).len(), 1);

    // 2. Le coffre n'a pas encore été enregistré : un lecteur ne voit rien.
    let observer = VaultStore::open(&f.path, PASSWORD, &read_only_config(&f.state))
        .expect("ouverture en lecture seule");
    assert!(
        observer.attachments_of(&entry).is_empty(),
        "la métadonnée ne doit PAS être sur le disque avant `save` : c'est ce qui rend \
         l'incident bénin"
    );
    drop(observer);

    // 3. Après `save`, les deux sont là — et cohérents.
    store.save().expect("enregistrement");
    drop(store);

    let reopened = VaultStore::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    assert_eq!(reopened.attachments_of(&entry).len(), 1);
    let sweep = sweep_blobs(
        &reopened.attachment_dir(),
        reopened.archive(),
        reopened.vault().subkeys(),
        &reopened.vault().header().vault_id,
    )
    .expect("balayage");
    assert!(
        sweep.is_consistent(),
        "après enregistrement, aucune incohérence : {sweep:?}"
    );
}

#[test]
fn an_interruption_before_save_leaves_an_orphan_and_an_openable_vault() {
    // Un incident **entre** l'écriture du blob et l'enregistrement : le blob existe,
    // la métadonnée non. Conséquence attendue : un orphelin, et un coffre qui s'ouvre.
    let (f, mut store, entry) = fixture();
    let source = source_file(f.dir.path(), "interrompu.bin", b"blob orphelin");
    store
        .add_attachment(&entry, "interrompu.bin", &source)
        .expect("ajout");
    let dir = store.attachment_dir();
    // On simule l'interruption : rien n'est enregistré.
    drop(store);

    let reopened = VaultStore::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    assert!(reopened.attachments_of(&entry).is_empty());

    let sweep = sweep_blobs(
        &dir,
        reopened.archive(),
        reopened.vault().subkeys(),
        &reopened.vault().header().vault_id,
    )
    .expect("balayage");

    assert_eq!(
        sweep.orphans.len(),
        1,
        "le blob non référencé est un orphelin"
    );
    assert!(
        sweep.missing.is_empty(),
        "aucune métadonnée n'a été écrite, donc aucune promesse n'est rompue"
    );
}

// ---------------------------------------------------------------------------
// I-BLOB-ORDER — suppression
// ---------------------------------------------------------------------------

#[test]
fn removal_keeps_the_metadata_first_and_the_file_last() {
    let (f, mut store, entry) = fixture();
    let source = source_file(f.dir.path(), "a-retirer.bin", b"a retirer");
    let meta = store
        .add_attachment(&entry, "a-retirer.bin", &source)
        .expect("ajout");
    store.save().expect("enregistrement");

    let blob = store.blob_path(&meta.id).expect("chemin");
    assert!(blob.exists());

    // 1. La métadonnée est retirée, le fichier est **encore là** : c'est l'ordre voulu.
    store.remove_attachment(&meta.id).expect("retrait");
    assert!(
        blob.exists(),
        "le fichier ne doit pas disparaître avant que le coffre ne soit enregistré"
    );
    assert!(store.attachments_of(&entry).is_empty());

    // 2. Puis l'enregistrement, **puis** la suppression physique.
    store.save().expect("enregistrement");
    store.purge_blob(&meta.id).expect("suppression physique");
    assert!(
        !blob.exists(),
        "le fichier est supprimé après l'enregistrement"
    );

    // 3. Le résultat est cohérent, et le coffre s'ouvre.
    drop(store);
    let reopened = VaultStore::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    let sweep = sweep_blobs(
        &reopened.attachment_dir(),
        reopened.archive(),
        reopened.vault().subkeys(),
        &reopened.vault().header().vault_id,
    )
    .expect("balayage");
    assert!(sweep.is_consistent(), "{sweep:?}");
}

#[test]
fn removing_an_unknown_attachment_is_refused() {
    let (_f, mut store, _entry) = fixture();
    let unknown = passlock_core::model::BlobId::generate().expect("id");

    assert!(
        matches!(
            store.remove_attachment(&unknown),
            Err(Error::InvalidHeader { .. })
        ),
        "viser une pièce jointe absente signale une erreur de cible"
    );
}

// ---------------------------------------------------------------------------
// Collision de nom
// ---------------------------------------------------------------------------

#[test]
fn an_attachment_never_overwrites_an_occupant_of_the_blob_directory() {
    // On ne peut pas **provoquer** une collision de HMAC sur 128 bits, et prétendre le
    // contraire serait un test mensonger. Ce qui est éprouvable, et qui est la garantie
    // réelle, est vérifié ici : `create_private_file` repose sur `O_EXCL`, donc un
    // occupant du répertoire — quel qu'il soit — **survit** à un ajout.
    let (f, mut store, entry) = fixture();
    let dir = store.attachment_dir();
    std::fs::create_dir_all(&dir).expect("répertoire des blobs");

    // Un occupant au nom bien formé : impossible de savoir s'il sera un jour choisi,
    // mais s'il l'était, il ne doit pas être écrasé.
    let occupant = dir.join("0123456789abcdef0123456789abcdef");
    std::fs::write(&occupant, b"je ne dois pas disparaitre").expect("occupant");

    let source = source_file(f.dir.path(), "nouveau.bin", b"nouveau contenu");
    let meta = store
        .add_attachment(&entry, "nouveau.bin", &source)
        .expect("ajout");

    assert_eq!(
        std::fs::read(&occupant).expect("lecture"),
        b"je ne dois pas disparaitre",
        "aucun occupant du répertoire ne doit être écrasé"
    );
    assert_ne!(
        meta.id.to_hex(),
        "0123456789abcdef0123456789abcdef",
        "le blob ajouté a son propre identifiant"
    );
}

#[test]
fn deleting_a_blob_by_a_foreign_name_is_refused() {
    // Le ramasse-miettes ne peut donc pas être détourné vers un fichier qui n'est pas
    // un blob, ni sortir du répertoire des blobs.
    let (_f, store, _entry) = fixture();

    for name in [
        "notes.txt",
        "..",
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "court",
    ] {
        assert!(
            matches!(
                store.delete_blob_by_name(name),
                Err(Error::InvalidInput { .. })
            ),
            "« {name} » ne doit pas pouvoir être supprimé par cette voie"
        );
    }
}

// ---------------------------------------------------------------------------
// Séparation stricte entre vérification et ramasse-miettes
// ---------------------------------------------------------------------------

#[test]
fn a_corrupted_blob_is_reported_by_verify_and_never_deleted_by_gc() {
    // La propriété la plus importante de cette section : une pièce jointe **référencée
    // mais corrompue** est *présente*. Le balayage la classe donc ni orpheline ni
    // absente — elle n'est **jamais** candidate à la suppression. Sans quoi une
    // corruption se transformerait en perte de données, par l'effet d'un outil de
    // maintenance.
    let (f, mut store, entry) = fixture();
    let source = source_file(f.dir.path(), "corrompu.bin", b"contenu a corrompre");
    let meta = store
        .add_attachment(&entry, "corrompu.bin", &source)
        .expect("ajout");
    store.save().expect("enregistrement");

    let blob = store.blob_path(&meta.id).expect("chemin");

    // `attach verify` **observe et signale**.
    let keys = store.vault().subkeys();
    let vault_id = store.vault().header().vault_id;
    verify_blob(&blob, &meta, keys, &vault_id).expect("le blob est valide avant corruption");

    let mut bytes = std::fs::read(&blob).expect("lecture");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&blob, &bytes).expect("écriture");

    assert!(
        matches!(
            verify_blob(&blob, &meta, keys, &vault_id),
            Err(Error::Corrupted { .. })
        ),
        "la corruption est signalée"
    );

    // `attach gc` ne voit **rien** à supprimer : ni orphelin, ni absence.
    let sweep =
        sweep_blobs(&store.attachment_dir(), store.archive(), keys, &vault_id).expect("balayage");
    assert!(
        sweep.orphans.is_empty(),
        "un blob référencé n'est jamais orphelin, même corrompu"
    );
    assert!(
        sweep.missing.is_empty(),
        "il est présent : ce n'est pas une absence"
    );
    assert!(blob.exists(), "et il est toujours sur le disque");
}

#[test]
fn a_missing_blob_is_an_integrity_error_not_a_deletion_candidate() {
    let (f, mut store, entry) = fixture();
    let source = source_file(f.dir.path(), "absent.bin", b"bientot absent");
    let meta = store
        .add_attachment(&entry, "absent.bin", &source)
        .expect("ajout");
    store.save().expect("enregistrement");

    let blob = store.blob_path(&meta.id).expect("chemin");
    std::fs::remove_file(&blob).expect("suppression du fichier");

    let sweep = sweep_blobs(
        &store.attachment_dir(),
        store.archive(),
        store.vault().subkeys(),
        &store.vault().header().vault_id,
    )
    .expect("balayage");

    assert_eq!(sweep.missing.len(), 1, "l'absence est signalée");
    assert!(
        sweep.orphans.is_empty(),
        "une absence n'est pas un orphelin : il n'y a rien à supprimer"
    );
    assert!(!sweep.is_consistent());
}

// ---------------------------------------------------------------------------
// Aller-retour complet
// ---------------------------------------------------------------------------

#[test]
fn a_blob_added_through_the_store_is_readable_after_reopening() {
    let (f, mut store, entry) = fixture();
    let payload: Vec<u8> = (0..2_500_000_u32)
        .map(|index| u8::try_from(index % 253).unwrap_or(0))
        .collect();
    let source = source_file(f.dir.path(), "gros.bin", &payload);

    let meta = store
        .add_attachment(&entry, "gros.bin", &source)
        .expect("ajout");
    store.save().expect("enregistrement");
    assert_eq!(meta.chunk_count, 3, "deux morceaux pleins et un partiel");
    drop(store);

    let reopened = VaultStore::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    let stored = reopened
        .attachment(&meta.id)
        .expect("la métadonnée doit être relue");
    let blob = reopened.blob_path(&meta.id).expect("chemin");

    let mut reader = attachment::AttachmentReader::open(
        &blob,
        stored,
        reopened.vault().subkeys(),
        &reopened.vault().header().vault_id,
    )
    .expect("ouverture du blob");
    let mut out = Vec::new();
    reader.read_all(&mut out).expect("lecture");
    assert_eq!(
        out, payload,
        "le contenu doit survivre à un aller-retour complet"
    );
}
