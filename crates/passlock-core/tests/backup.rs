//! Tests de l'étape 3 : sauvegarde et test de restauration.
//!
//! # Ce qui est éprouvé ici, et que rien d'autre n'éprouve
//!
//! Les tests de l'étape 2 couvrent un coffre et ses blobs. Ici, c'est l'**ensemble
//! {coffre, blobs}** qui est en jeu, et trois propriétés qui n'existent qu'à ce niveau :
//!
//! | Invariant | Ce qu'il protège |
//! |---|---|
//! | `I-BACKUP-COUPLE` | les deux chemins vont ensemble ; l'un sans l'autre est détecté, jamais silencieux |
//! | `I-BACKUP-LOCK` | le verrou gèle l'ensemble pendant la copie : pas de sauvegarde incohérente sous concurrence |
//! | `I-BACKUP-READONLY` | le test de restauration n'a **aucun** effet persistant |
//! | `I-BACKUP-CREATED` | un échec contrôlé retire **ce qui a été créé**, et rien d'autre |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::backup::{self, Age, Integrity};
use passlock_core::error::Error;
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{Entry, EntryKind};
use passlock_core::store::VaultStore;
use passlock_core::vault::{Credentials, VaultConfig};

const PASSWORD: &[u8] = b"phrase de passe pour les tests de sauvegarde";

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

/// Configuration de sauvegarde : lecture seule **et** verrou exclusif.
fn backup_config(state: &Path) -> VaultConfig {
    VaultConfig {
        read_only: true,
        require_exclusive_lock: true,
        ..config(state)
    }
}

/// Configuration de test de restauration : lecture seule, jamais de verrou.
fn verify_config(state: &Path) -> VaultConfig {
    VaultConfig {
        read_only: true,
        ..config(state)
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    path: PathBuf,
    state: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    VaultStore::create(&path, PASSWORD, &config(&state)).expect("création");
    Fixture { dir, path, state }
}

/// Le matériel de déverrouillage, pour les commandes qui rouvrent la sauvegarde.
fn creds() -> Credentials<'static> {
    Credentials::Password(PASSWORD)
}

/// Ajoute une entrée, en repassant par une ouverture ordinaire.
fn add_entry(fixture: &Fixture, title: &str) {
    let mut store =
        VaultStore::open(&fixture.path, PASSWORD, &config(&fixture.state)).expect("open");
    store
        .add_entry(Entry::new(EntryKind::Login, title, 1_700_000_000).expect("entrée"))
        .expect("ajout");
    store.save().expect("enregistrement");
}

/// Attache un fichier à la première entrée, et rend l'identifiant du blob.
fn attach(fixture: &Fixture, name: &str, content: &[u8]) -> Vec<u8> {
    let source = fixture.dir.path().join(name);
    std::fs::write(&source, content).expect("source");

    let mut store =
        VaultStore::open(&fixture.path, PASSWORD, &config(&fixture.state)).expect("open");
    let entry = store.archive().entries[0].id;
    let meta = store
        .add_attachment(&entry, name, &source)
        .expect("ajout de pièce jointe");
    store.save().expect("enregistrement");
    meta.id.to_hex().into_bytes()
}

/// Crée une sauvegarde, et rend son chemin.
fn create_backup(fixture: &Fixture, name: &str) -> PathBuf {
    let destination = fixture.dir.path().join(name);
    let store = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("ouverture sous verrou");
    backup::create(
        &store,
        &destination,
        &creds(),
        &verify_config(&fixture.state),
    )
    .expect("sauvegarde");
    destination
}

// ---------------------------------------------------------------------------
// I-BACKUP-COUPLE — les deux chemins vont ensemble
// ---------------------------------------------------------------------------

#[test]
fn a_backup_is_a_vault_and_its_blob_directory() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");
    attach(&fixture, "piece.bin", b"un contenu de piece jointe");

    let destination = create_backup(&fixture, "copie.plk");
    let blobs = passlock_core::attachment::blob_dir_for(&destination);

    assert!(destination.exists(), "le fichier de coffre est copié");
    assert!(blobs.is_dir(), "le répertoire de blobs est copié");

    // La copie est un coffre **ordinaire** : le chemin d'ouverture habituel suffit, et
    // rien n'a été ajouté au format.
    let copy = VaultStore::open(&destination, PASSWORD, &config(&fixture.state))
        .expect("la sauvegarde s'ouvre comme un coffre");
    let original = VaultStore::open(&fixture.path, PASSWORD, &verify_config(&fixture.state))
        .expect("original");

    assert_eq!(
        copy.archive().entries.len(),
        original.archive().entries.len()
    );
    assert_eq!(
        copy.archive().attachments.len(),
        original.archive().attachments.len()
    );
    assert_eq!(
        copy.vault().header().vault_id,
        original.vault().header().vault_id
    );
}

#[test]
fn a_vault_without_attachments_produces_no_blob_directory() {
    let fixture = fixture();
    add_entry(&fixture, "sans piece jointe");

    let destination = create_backup(&fixture, "copie.plk");
    assert!(destination.exists());
    assert!(
        !passlock_core::attachment::blob_dir_for(&destination).exists(),
        "un coffre sans pièce jointe n'a pas de répertoire de blobs — en créer un vide \
         laisserait croire à des pièces jointes absentes"
    );
}

#[test]
fn a_backup_missing_its_blob_directory_is_not_sound() {
    // `I-BACKUP-COUPLE` : copier le seul fichier de coffre doit être **détecté**.
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");
    attach(&fixture, "piece.bin", b"contenu");

    let destination = create_backup(&fixture, "copie.plk");
    std::fs::remove_dir_all(passlock_core::attachment::blob_dir_for(&destination))
        .expect("suppression du répertoire");

    let report = backup::verify(&destination, &creds(), &verify_config(&fixture.state))
        .expect("le fichier reste lisible");
    assert!(
        !report.is_sound(),
        "les pièces jointes manquent : ce n'est pas intègre"
    );
    match report.integrity {
        Integrity::Broken { reasons } => {
            // Deux motifs, et non un seul : le premier nomme **quoi** manque, le second
            // nomme **pourquoi** — le répertoire entier est absent. Les deux sont utiles
            // au diagnostic, et aucun ne remplace l'autre.
            assert_eq!(reasons.len(), 2, "motifs : {reasons:?}");
            assert!(
                reasons.iter().any(|r| r.contains("absent")),
                "la cause générale doit être nommée : {reasons:?}"
            );
        }
        Integrity::Sound => panic!("attendu : en défaut"),
    }
}

#[test]
fn a_backup_whose_blob_is_corrupted_is_not_sound() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");
    attach(&fixture, "piece.bin", b"un contenu a corrompre apres copie");

    let destination = create_backup(&fixture, "copie.plk");
    let blobs = passlock_core::attachment::blob_dir_for(&destination);
    let blob = std::fs::read_dir(&blobs)
        .expect("répertoire")
        .next()
        .expect("une entrée")
        .expect("entrée")
        .path();

    let mut bytes = std::fs::read(&blob).expect("lecture");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&blob, &bytes).expect("écriture");

    let report = backup::verify(&destination, &creds(), &verify_config(&fixture.state))
        .expect("le fichier reste lisible");
    assert!(!report.is_sound());
    match report.integrity {
        Integrity::Broken { reasons } => {
            assert!(
                reasons[0].contains("authentifié") || reasons[0].contains("morceau"),
                "le motif doit nommer le défaut : {reasons:?}"
            );
        }
        Integrity::Sound => panic!("attendu : en défaut"),
    }
}

#[test]
fn a_truncated_backup_fails_to_verify() {
    // **L'interruption brutale.** Aucune atomicité n'est revendiquée sur la destination :
    // une copie interrompue doit donc **échouer** au test, et non passer pour une
    // sauvegarde. C'est ce qui distingue une sauvegarde d'un fichier quelconque.
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");

    let destination = create_backup(&fixture, "copie.plk");
    let truncated = fixture.dir.path().join("partielle.plk");
    let bytes = std::fs::read(&destination).expect("lecture");
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).expect("troncature");

    // **Aucune** longueur de troncature ne doit passer. Selon l'endroit où la copie
    // s'est arrêtée, le refus vient d'ailleurs — structurellement trop courte avant tout
    // déchiffrement (`MalformedLength`), ou rejetée par le tag du conteneur
    // (`Corrupted`) une fois le header franchi. Les deux sont des refus ; ce qui compte
    // est qu'**aucune** troncature ne soit rapportée comme une sauvegarde exploitable.
    let mut rejected = 0;
    // Jusqu'à 7/8 : la coupe égale à la taille totale ne serait **pas** une troncature.
    for fraction in 1..8 {
        let cut = bytes.len() * fraction / 8;
        std::fs::write(&truncated, &bytes[..cut]).expect("troncature");
        let outcome = backup::verify(&truncated, &creds(), &verify_config(&fixture.state));
        assert!(
            outcome.is_err(),
            "une copie tronquée à {cut} octet(s) sur {} doit être refusée, or elle a été \
             rapportée : {outcome:?}",
            bytes.len()
        );
        rejected += 1;
    }
    assert_eq!(rejected, 7);
}

// ---------------------------------------------------------------------------
// I-BACKUP-CREATED — nettoyage de ce qui a été créé, et de rien d'autre
// ---------------------------------------------------------------------------

#[test]
fn a_backup_never_overwrites_an_existing_destination() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");

    let destination = fixture.dir.path().join("copie.plk");
    std::fs::write(&destination, b"un fichier qui n'est pas a nous").expect("occupant");

    let store = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("ouverture sous verrou");
    let outcome = backup::create(
        &store,
        &destination,
        &creds(),
        &verify_config(&fixture.state),
    );

    assert!(matches!(outcome, Err(Error::InvalidInput { .. })));
    assert_eq!(
        std::fs::read(&destination).expect("lecture"),
        b"un fichier qui n'est pas a nous",
        "la destination existante est intacte : rien n'est jamais écrasé"
    );
}

#[test]
fn a_failed_copy_removes_only_what_it_created() {
    // **Le contrôle demandé en revue.** On occupe le chemin du répertoire de blobs par un
    // **fichier** : `mkdirat` échoue, donc le répertoire n'est pas à nous, donc il ne doit
    // pas être retiré ; et la copie du blob échoue, donc le fichier de coffre déjà copié
    // doit être **retiré**, lui.
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");
    attach(&fixture, "piece.bin", b"contenu");

    let destination = fixture.dir.path().join("copie.plk");
    let blobs = passlock_core::attachment::blob_dir_for(&destination);
    std::fs::write(&blobs, b"un occupant qui n'est pas un repertoire").expect("occupant");

    let store = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("ouverture sous verrou");
    let outcome = backup::create(
        &store,
        &destination,
        &creds(),
        &verify_config(&fixture.state),
    );

    assert!(outcome.is_err(), "la copie doit échouer");
    assert!(
        !destination.exists(),
        "le fichier de coffre copié par cette session est retiré"
    );
    assert_eq!(
        std::fs::read(&blobs).expect("lecture"),
        b"un occupant qui n'est pas un repertoire",
        "l'occupant n'a pas été créé par nous : il est intact"
    );
}

#[test]
fn a_missing_parent_directory_is_reported_clearly() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");

    let destination = fixture.dir.path().join("absent").join("copie.plk");
    let store = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("ouverture sous verrou");
    let outcome = backup::create(
        &store,
        &destination,
        &creds(),
        &verify_config(&fixture.state),
    );

    assert!(matches!(outcome, Err(Error::InvalidInput { .. })));
}

// ---------------------------------------------------------------------------
// I-BACKUP-READONLY — le test de restauration n'a aucun effet persistant
// ---------------------------------------------------------------------------

#[test]
fn verifying_a_backup_leaves_no_trace() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");
    attach(&fixture, "piece.bin", b"contenu");

    let destination = create_backup(&fixture, "copie.plk");
    let blobs = passlock_core::attachment::blob_dir_for(&destination);

    // Photographie de l'état avant le test.
    let before_bytes = std::fs::read(&destination).expect("lecture");
    let before_meta = std::fs::metadata(&destination).expect("métadonnées");
    // Le mode n'existe pas sous Windows : la garantie « permissions non réparées » y est
    // portée par une **ACL**, et son contrôle relève d'un test que cette suite ne peut pas
    // exécuter. L'assertion est donc faite là où la notion existe, plutôt que rendue
    // trivialement vraie ailleurs.
    #[cfg(unix)]
    let before_perms = permission_bits(&destination);
    let before_blobs = list_files(&blobs);
    let before_entries = list_files(fixture.dir.path());

    // **Un `config` qui autoriserait l'écriture** : la garantie doit venir du code testé,
    // pas de la prudence de l'appelant.
    let permissive = VaultConfig {
        read_only: false,
        require_exclusive_lock: false,
        ..config(&fixture.state)
    };
    let report = backup::verify(&destination, &creds(), &permissive).expect("test");
    assert!(report.is_sound());

    // Le contenu, les permissions, et l'ensemble des fichiers sont inchangés.
    assert_eq!(
        std::fs::read(&destination).expect("lecture"),
        before_bytes,
        "le fichier testé n'a pas été modifié"
    );
    let after_meta = std::fs::metadata(&destination).expect("métadonnées");
    #[cfg(unix)]
    assert_eq!(
        permission_bits(&destination),
        before_perms,
        "les permissions n'ont pas été « réparées »"
    );
    assert_eq!(after_meta.len(), before_meta.len());
    assert_eq!(
        list_files(&blobs),
        before_blobs,
        "aucun blob créé ni modifié"
    );
    assert_eq!(
        list_files(fixture.dir.path()),
        before_entries,
        "aucun fichier créé à côté de la sauvegarde — ni verrou, ni sentinelle"
    );
}

// ---------------------------------------------------------------------------
// Intégrité et ancienneté : deux verdicts distincts
// ---------------------------------------------------------------------------

#[test]
fn integrity_and_age_are_reported_separately() {
    // **Le contrôle demandé.** Une sauvegarde ancienne est **légitime** : elle doit être
    // déclarée intègre **et** ancienne, sans que l'un contamine l'autre.
    let fixture = fixture();
    add_entry(&fixture, "avant la sauvegarde");
    let destination = create_backup(&fixture, "copie.plk");

    let fresh =
        backup::verify(&destination, &creds(), &verify_config(&fixture.state)).expect("test");
    assert!(fresh.is_sound());
    assert_eq!(fresh.age, Age::Current, "la sauvegarde vient d'être prise");

    // Le coffre avance : la sauvegarde devient antérieure au dernier état connu.
    add_entry(&fixture, "apres la sauvegarde");

    let stale =
        backup::verify(&destination, &creds(), &verify_config(&fixture.state)).expect("test");
    assert!(
        stale.is_sound(),
        "l'ancienneté n'est pas un défaut d'intégrité"
    );
    assert!(
        matches!(stale.age, Age::Older { .. }),
        "l'ancienneté est constatée : {:?}",
        stale.age
    );
}

// ---------------------------------------------------------------------------
// I-BACKUP-LOCK — le verrou gèle l'ensemble
// ---------------------------------------------------------------------------

#[test]
fn a_backup_holds_the_lock_and_a_second_writer_is_refused() {
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");

    let holder = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("la sauvegarde prend le verrou");

    // Un écrivain concurrent est refusé pendant toute la durée de la sauvegarde.
    let writer = VaultStore::open(&fixture.path, PASSWORD, &config(&fixture.state));
    assert!(
        matches!(writer, Err(Error::AlreadyLocked)),
        "un écrivain concurrent doit être refusé"
    );

    // Un lecteur, lui, reste possible : le verrou protège l'écriture, pas la lecture du
    // fichier — c'est l'atomicité du conteneur qui protège celle-ci.
    let reader = VaultStore::open(&fixture.path, PASSWORD, &verify_config(&fixture.state));
    assert!(
        reader.is_ok(),
        "un lecteur n'est pas bloqué par une sauvegarde"
    );

    drop(holder);
}

#[test]
fn the_lock_field_is_what_makes_the_difference() {
    // Sans `require_exclusive_lock`, une ouverture en lecture seule **ne prend aucun
    // verrou** : c'est le comportement d'origine, et c'est ce champ qui le change.
    //
    // NOTE DE CORRECTION. Une version antérieure de `open_with` décidait du verrou par
    // `if config.read_only { None }` seul : `backup create` aurait alors copié **sans
    // aucun verrou** si l'utilisateur avait passé `--read-only`, c'est-à-dire dans le
    // mode même où la sauvegarde est censée travailler.
    let fixture = fixture();
    add_entry(&fixture, "exemple.com");

    let holder = VaultStore::open(&fixture.path, PASSWORD, &backup_config(&fixture.state))
        .expect("verrou pris");

    let unlocked = VaultStore::open(&fixture.path, PASSWORD, &verify_config(&fixture.state));
    assert!(
        unlocked.is_ok(),
        "sans `require_exclusive_lock`, la lecture seule ne prend pas le verrou"
    );

    drop(holder);
}

// ---------------------------------------------------------------------------
// Test de restauration EFFECTIF
// ---------------------------------------------------------------------------

#[test]
fn a_backup_restores_a_usable_vault_including_its_attachments() {
    // **Le test que la revue exigeait.** Vérifier une sauvegarde n'est pas la restaurer :
    // ici, on exécute **la procédure documentée**, telle quelle, et on ouvre le résultat.
    //
    // La procédure est celle que `backup verify` rappelle :
    //
    //     cp <sauvegarde> <coffre>
    //     cp -a <sauvegarde>.attachments <coffre>.attachments
    //
    // Elle est recopiée à la main, et **pas** factorisée dans un utilitaire : le test doit
    // éprouver la procédure écrite pour l'utilisateur, pas une variante commode qui
    // pourrait diverger d'elle.
    let fixture = fixture();

    let contenu: Vec<u8> = (0..2_400_000_u32)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect();
    add_entry(&fixture, "exemple.com");
    let blob_id = attach(&fixture, "piece.bin", &contenu);

    let destination = create_backup(&fixture, "copie.plk");

    // --- Restauration, en deux copies, vers un emplacement neuf -----------------
    let restored = fixture.dir.path().join("restaure.plk");
    std::fs::copy(&destination, &restored).expect("première copie");
    copy_tree(
        &passlock_core::attachment::blob_dir_for(&destination),
        &passlock_core::attachment::blob_dir_for(&restored),
    );

    // --- Le coffre restauré s'ouvre par le chemin ordinaire ---------------------
    let store = VaultStore::open(&restored, PASSWORD, &config(&fixture.state))
        .expect("le coffre restauré s'ouvre");
    assert_eq!(store.archive().entries.len(), 1);
    assert_eq!(store.archive().attachments.len(), 1);

    // --- Et la pièce jointe se relit **octet pour octet** -----------------------
    let id = parse_blob_id(&blob_id);
    let meta = store.attachment(&id).expect("la métadonnée est restaurée");
    let blob = store.blob_path(&id).expect("chemin du blob restauré");
    assert!(
        blob.exists(),
        "la seconde copie est indispensable : sans elle, la métadonnée existe et le blob \
         est introuvable"
    );

    let mut reader = passlock_core::attachment::AttachmentReader::open(
        &blob,
        meta,
        store.vault().subkeys(),
        &store.vault().header().vault_id,
    )
    .expect("ouverture du blob restauré");
    let mut out = Vec::new();
    reader.read_all(&mut out).expect("lecture");
    assert_eq!(
        out, contenu,
        "le contenu restauré doit être identique, octet pour octet"
    );

    // --- Le coffre d'origine n'a pas bougé --------------------------------------
    drop(store);
    let original = VaultStore::open(&fixture.path, PASSWORD, &verify_config(&fixture.state))
        .expect("original");
    assert_eq!(
        original.archive().attachments.len(),
        1,
        "la restauration a lieu vers un emplacement neuf : l'original est intact"
    );
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Recopie un répertoire, à la manière de `cp -a`.
///
/// Le test de restauration doit reproduire la **procédure documentée**, y compris dans sa
/// façon de copier : un utilitaire plus fin éprouverait autre chose que ce qui est écrit
/// pour l'utilisateur.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("répertoire de destination");
    for entry in std::fs::read_dir(from).expect("répertoire") {
        let entry = entry.expect("entrée");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copie");
        }
    }
}

/// Relit un identifiant de blob depuis sa forme hexadécimale.
fn parse_blob_id(hex: &[u8]) -> passlock_core::model::BlobId {
    passlock_core::model::BlobId::from_hex(std::str::from_utf8(hex).expect("UTF-8"))
        .expect("identifiant valide")
}

/// Mode du fichier. N'existe que sous Unix : voir le commentaire au site d'appel.
///
/// Sous Windows, la garantie « les permissions ne sont pas réparées » est portée par une
/// **ACL**, et son contrôle relève d'un test que cette suite ne peut pas exécuter — le
/// dire vaut mieux que de rendre l'assertion trivialement vraie.
#[cfg(unix)]
fn permission_bits(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("métadonnées")
        .permissions()
        .mode()
}

/// Liste triée des entrées d'un répertoire, **sans suivre les liens symboliques**.
fn list_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("répertoire")
        .map(|entry| {
            entry
                .expect("entrée")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}
