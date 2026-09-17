//! Tests des primitives de création, de suppression et de durabilité.
//!
//! Ces tests portent sur des propriétés **de sécurité**, pas sur du
//! fonctionnement : création exclusive, refus des liens symboliques, permissions
//! effectives, absence de résidu, et **niveau de durabilité réellement rendu**.
//!
//! Ils s'exécutent sur un système de fichiers réel, donc ils éprouvent ce que le
//! noyau fait vraiment plutôt que ce que nous croyons lui avoir demandé.
//!
//! # Portabilité, et honnêteté
//!
//! Les tests sont écrits pour **les deux plateformes**. Ceux qui dépendent d'une
//! primitive propre à Unix (mode `0600`, `symlink`) sont marqués `#[cfg(unix)]` et
//! ne s'exécutent pas ailleurs. Les tests Windows existent, compilent, et ne
//! s'exécutent **pas** dans cet environnement : ils portent la mention
//! « NON VÉRIFIÉE » et ne doivent pas être présentés comme exécutés.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use passlock_platform::fs::{
    Durability, create_dir_private, create_private_file, list_dir, make_durable, path_exists,
    platform_durability, read_file, remove_dir, remove_file,
};

fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("répertoire temporaire")
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::symlink_metadata(path)
        .expect("métadonnées")
        .permissions()
        .mode()
        & 0o777
}

// ---------------------------------------------------------------------------
// create_private_file — création exclusive
// ---------------------------------------------------------------------------

#[test]
fn create_private_file_creates_a_new_file() {
    let dir = sandbox();
    let target = dir.path().join("cle.key");

    let mut file = create_private_file(&target).expect("création");
    std::io::Write::write_all(&mut file, b"contenu").expect("écriture");
    drop(file);

    assert_eq!(fs::read(&target).expect("lecture"), b"contenu");
}

#[test]
fn create_private_file_refuses_an_existing_target() {
    let dir = sandbox();
    let target = dir.path().join("cle.key");

    fs::write(&target, b"contenu deja present").expect("écriture initiale");

    let outcome = create_private_file(&target);
    assert_eq!(
        outcome.expect_err("la création aurait dû échouer").kind(),
        ErrorKind::AlreadyExists,
        "la création exclusive doit refuser d'écraser une cible existante"
    );
    assert_eq!(
        fs::read(&target).expect("lecture"),
        b"contenu deja present",
        "la cible existante ne doit pas avoir été modifiée"
    );
}

#[cfg(unix)]
#[test]
fn create_private_file_refuses_a_symlink_at_the_target() {
    let dir = sandbox();
    let victim = dir.path().join("victime.txt");
    let target = dir.path().join("cle.key");
    fs::write(&victim, b"a ne pas ecraser").expect("écriture");
    std::os::unix::fs::symlink(&victim, &target).expect("lien");

    let outcome = create_private_file(&target);
    assert!(
        outcome.is_err(),
        "un lien symbolique pré-créé au nom exact de la cible doit être refusé"
    );
    assert_eq!(
        fs::read(&victim).expect("lecture"),
        b"a ne pas ecraser",
        "la cible du lien ne doit pas avoir été touchée"
    );
}

#[cfg(unix)]
#[test]
fn create_private_file_refuses_a_symlinked_parent_component() {
    let dir = sandbox();
    let real = dir.path().join("reel");
    fs::create_dir(&real).expect("répertoire réel");
    let link = dir.path().join("lien");
    std::os::unix::fs::symlink(&real, &link).expect("lien");

    let outcome = create_private_file(&link.join("cle.key"));
    let err = outcome.expect_err("un parent symbolique doit être refusé");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidInput,
        "le refus doit nommer la cause, pas échouer par accident"
    );
    assert!(
        !real.join("cle.key").exists(),
        "rien ne doit avoir été écrit à travers le lien"
    );
}

#[cfg(unix)]
#[test]
fn create_private_file_creates_in_0600() {
    let dir = sandbox();
    let target = dir.path().join("cle.key");

    let file = create_private_file(&target).expect("création");
    drop(file);

    assert_eq!(
        mode_of(&target),
        0o600,
        "le mode doit être posé à la création, jamais hérité de l'umask"
    );
}

#[test]
fn a_failed_creation_leaves_the_directory_unchanged() {
    let dir = sandbox();
    let target = dir.path().join("cle.key");
    fs::write(&target, b"occupe").expect("écriture initiale");

    let before = entry_count(dir.path());
    let _ = create_private_file(&target);
    let after = entry_count(dir.path());

    assert_eq!(
        before, after,
        "une création refusée ne doit laisser aucun résidu"
    );
}

fn entry_count(dir: &Path) -> usize {
    fs::read_dir(dir).expect("listage").count()
}

// ---------------------------------------------------------------------------
// create_dir_private, remove_file, remove_dir, list_dir, path_exists
// ---------------------------------------------------------------------------

#[test]
fn create_dir_private_refuses_an_existing_directory() {
    let dir = sandbox();
    let target = dir.path().join("blobs");

    let durability = create_dir_private(&target).expect("création");
    assert_eq!(
        durability,
        expected_durability(),
        "le niveau de durabilité doit correspondre à la plateforme"
    );
    assert!(target.is_dir());
    assert!(
        create_dir_private(&target).is_err(),
        "un répertoire existant ne doit pas être adopté"
    );
}

#[test]
fn remove_file_refuses_a_directory() {
    let dir = sandbox();
    let target = dir.path().join("blobs");
    fs::create_dir(&target).expect("répertoire");

    assert!(
        remove_file(&target).is_err(),
        "retirer un répertoire par `remove_file` doit échouer"
    );
    assert!(target.is_dir(), "le répertoire doit être intact");
}

#[test]
fn remove_dir_refuses_a_non_empty_directory() {
    let dir = sandbox();
    let target = dir.path().join("blobs");
    fs::create_dir(&target).expect("répertoire");
    fs::write(target.join("fichier"), b"contenu").expect("écriture");

    assert!(
        remove_dir(&target).is_err(),
        "un répertoire non vide ne doit jamais être supprimé"
    );

    fs::remove_file(target.join("fichier")).expect("nettoyage");
    remove_dir(&target).expect("le répertoire vide doit pouvoir être supprimé");
    assert!(!target.exists());
}

#[test]
fn list_dir_returns_the_entries_without_the_dots() {
    let dir = sandbox();
    let target = dir.path().join("blobs");
    fs::create_dir(&target).expect("répertoire");
    fs::write(target.join("a"), b"").expect("écriture");
    fs::write(target.join("b"), b"").expect("écriture");

    let mut names: Vec<String> = list_dir(&target)
        .expect("listage")
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();

    assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn path_exists_sees_a_file_and_not_a_missing_entry() {
    let dir = sandbox();
    let present = dir.path().join("present");
    fs::write(&present, b"").expect("écriture");

    assert!(path_exists(&present));
    assert!(!path_exists(&dir.path().join("absent")));
}

// ---------------------------------------------------------------------------
// make_durable — le niveau, et la distinction capacité absente / erreur
// ---------------------------------------------------------------------------

/// Niveau attendu sur la plateforme courante.
///
/// Unix synchronise le fichier **et** le répertoire ; Windows ne synchronise que le
/// fichier, et ce niveau réduit est **rendu**, pas dissimulé.
fn expected_durability() -> Durability {
    if cfg!(unix) {
        Durability::DirectoryEntrySynced
    } else {
        Durability::FileOnly
    }
}

#[test]
fn make_durable_succeeds_on_both_platforms() {
    // C'est le test qui matérialise la levée de la contradiction : l'absence de
    // capacité de synchronisation de répertoire sous Windows **n'est pas une
    // erreur**, elle change la valeur retournée. Aucune opération de la phase 4 ne
    // doit échouer faute de cette capacité.
    let dir = sandbox();
    let target = dir.path().join("cle.key");
    let mut file = create_private_file(&target).expect("création");
    std::io::Write::write_all(&mut file, b"contenu").expect("écriture");

    let durability = make_durable(&file, dir.path()).expect("durabilité");

    assert_eq!(
        durability,
        expected_durability(),
        "le niveau rendu doit être celui de la plateforme"
    );
    assert_eq!(
        durability.directory_entry_is_durable(),
        cfg!(unix),
        "la persistance du nom n'est revendiquée que là où elle est réellement obtenue"
    );
}

#[test]
fn platform_durability_matches_what_make_durable_returns() {
    // La déclaration de plateforme et le comportement réel ne doivent pas pouvoir
    // diverger : c'est cette égalité qui autorise à **rapporter** le niveau à
    // l'ouverture du coffre sans avoir rien écrit.
    let dir = sandbox();
    let target = dir.path().join("cle.key");
    let mut file = create_private_file(&target).expect("création");
    std::io::Write::write_all(&mut file, b"contenu").expect("écriture");

    let observed = make_durable(&file, dir.path()).expect("durabilité");
    assert_eq!(
        observed,
        platform_durability(),
        "le niveau annoncé par la plateforme doit être celui que `make_durable` rend"
    );
}

#[test]
fn make_durable_reports_a_real_io_error() {
    // « Capacité absente » et « échec » ne doivent pas être confondus : un
    // répertoire inexistant est une **vraie** erreur, et elle doit remonter.
    let dir = sandbox();
    let target = dir.path().join("cle.key");
    let mut file = create_private_file(&target).expect("création");
    std::io::Write::write_all(&mut file, b"contenu").expect("écriture");

    let missing = dir.path().join("repertoire-inexistant");
    let outcome = make_durable(&file, &missing);

    assert!(
        outcome.is_err(),
        "un répertoire inexistant est une erreur d'entrée/sortie, pas une absence de capacité"
    );
}

#[test]
fn the_durability_level_cannot_be_ignored() {
    // `Durability` est `#[must_use]` : omettre la valeur déclenche un avertissement
    // du compilateur, transformé en **erreur** par la CI (`RUSTFLAGS = "-D warnings"`).
    // Cette application est vérifiée par clippy, pas par un test d'exécution.
    //
    // Ce que ce test vérifie ici : chaque niveau est **exploitable** — il porte une
    // description utilisateur, et l'on peut décider de sa portée.
    for level in [Durability::DirectoryEntrySynced, Durability::FileOnly] {
        assert!(
            !level.description().is_empty(),
            "un niveau de durabilité doit pouvoir être expliqué à l'utilisateur"
        );
    }
    assert!(Durability::DirectoryEntrySynced.directory_entry_is_durable());
    assert!(!Durability::FileOnly.directory_entry_is_durable());
}

// ---------------------------------------------------------------------------
// Lecture bornée
// ---------------------------------------------------------------------------

#[test]
fn read_file_reads_a_small_file_and_refuses_an_oversized_one() {
    let dir = sandbox();
    let target = dir.path().join("donnees");
    fs::write(&target, b"douze octets").expect("écriture");

    assert_eq!(read_file(&target, 1024).expect("lecture"), b"douze octets");

    let outcome = read_file(&target, 4);
    assert_eq!(
        outcome.expect_err("le dépassement doit être refusé").kind(),
        ErrorKind::InvalidData,
        "la borne est structurelle : elle n'est pas déduite d'une taille annoncée"
    );
}

#[test]
fn read_file_refuses_a_directory() {
    let dir = sandbox();
    let target = dir.path().join("repertoire");
    fs::create_dir(&target).expect("répertoire");

    assert!(
        read_file(&target, 1024).is_err(),
        "un répertoire n'est pas un fichier ordinaire"
    );
}

// ---------------------------------------------------------------------------
// Spécificités Windows — compilées, NON EXÉCUTÉES dans cet environnement
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn make_durable_returns_file_only_on_windows() {
    // NON VÉRIFIÉE À L'EXÉCUTION. Ce test compile et s'exécuterait sur Windows,
    // mais aucun binaire Windows n'est lié ni lancé ici. Il est écrit pour que la
    // propriété soit **affirmée** là où elle s'applique, plutôt que supposée.
    let dir = sandbox();
    let target = dir.path().join("cle.key");
    let mut file = create_private_file(&target).expect("création");
    std::io::Write::write_all(&mut file, b"contenu").expect("écriture");

    let durability = make_durable(&file, dir.path()).expect("durabilité");
    assert_eq!(durability, Durability::FileOnly);
    assert!(!durability.directory_entry_is_durable());
}

#[cfg(windows)]
#[test]
fn mark_windows_acl_as_not_verified() {
    // La DACL est posée à la création, ou la création échoue : jamais un succès
    // silencieux avec des droits plus larges que voulu (échec fermé).
    //
    // **Ce que ce test ne peut pas faire :** vérifier que la DACL obtenue ne contient
    // qu'une ACE pour l'utilisateur courant. Cette vérification exigerait
    // `GetNamedSecurityInfoW` + parcours d'ACL, et surtout une **exécution** sur
    // Windows, qui n'est pas disponible ici. La propriété reste donc marquée
    // **NON VÉRIFIÉE** — voir SECURITY.md, limite L2.
    let dir = sandbox();
    let target = dir.path().join("cle.key");

    match create_private_file(&target) {
        Ok(file) => {
            drop(file);
            assert!(target.exists());
        }
        Err(err) => {
            // Échec fermé assumé : mieux vaut refuser que créer avec des droits
            // hérités. Ce chemin signalerait une DACL non constructible.
            panic!("la DACL n'a pas pu être posée, donc la création a échoué : {err}");
        }
    }
}
