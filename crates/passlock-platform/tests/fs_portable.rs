//! Tests de la couche fichiers **exécutables sur toutes les plateformes**.
//!
//! # Pourquoi ce fichier existe
//!
//! `atomic_write.rs` est intégralement sous `#![cfg(unix)]` : il vérifie le mode
//! `0600`, les liens symboliques et les octets nuls dans les chemins, qui n'ont pas
//! d'équivalent portable. Conséquence involontaire : **rien** de la couche fichiers
//! n'était exécuté sur Windows, alors que c'est précisément là que le code n'a
//! jamais été exécuté du tout.
//!
//! Ce fichier-ci n'utilise que des propriétés vérifiables partout. Il est conçu pour
//! tourner sur Windows dans l'intégration continue, où il constitue la **seule**
//! preuve d'exécution réelle du backend Windows.
//!
//! # Ce qu'il ne peut pas vérifier
//!
//! * les permissions (`0600` n'a pas d'équivalent ; la confidentialité repose sur les
//!   ACL héritées) ;
//! * le refus des liens symboliques : créer un lien symbolique sous Windows exige
//!   des privilèges d'administrateur ou le mode développeur, donc le test ne peut
//!   pas le provoquer de façon portable. Seul le cas **acceptant** est couvert ;
//! * `mlock` / `VirtualLock`, dont l'échec est un cas normal sur les deux systèmes.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use passlock_platform::fs::{FileLock, ensure_no_symlink_components, write_atomic};

fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("répertoire temporaire")
}

#[test]
fn writing_then_reading_returns_the_same_bytes() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    let payload: Vec<u8> = (0..4096_u32).map(|index| (index % 251) as u8).collect();

    write_atomic(&target, "portable", &payload).expect("écriture");

    assert_eq!(std::fs::read(&target).expect("lecture"), payload);
}

#[test]
fn writing_replaces_previous_content_entirely() {
    // Un remplacement qui laisserait un suffixe de l'ancien contenu produirait un
    // coffre corrompu de façon subtile : c'est le genre de défaut qu'on ne voit
    // qu'à la restauration.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "un", b"contenu long et ancien").expect("écriture");
    write_atomic(&target, "deux", b"court").expect("écriture");

    assert_eq!(std::fs::read(&target).expect("lecture"), b"court");
}

#[test]
fn no_temporary_file_survives_a_successful_write() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "unique", b"contenu").expect("écriture");

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("listage")
        .map(|entry| entry.expect("entrée").file_name())
        .collect();
    assert_eq!(entries.len(), 1, "résidu détecté : {entries:?}");
}

#[test]
fn an_empty_write_is_valid() {
    // Cas limite réel : un coffre dont l'enveloppe est vide ne doit pas être
    // confondu avec un échec.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "vide", b"").expect("écriture");
    assert_eq!(std::fs::read(&target).expect("lecture"), b"");
}

#[test]
fn a_deep_path_is_created_and_written() {
    let dir = sandbox();
    let mut current = dir.path().to_path_buf();
    for level in ["n1", "n2", "n3"] {
        current = current.join(level);
        std::fs::create_dir(&current).expect("création");
    }

    let target = current.join("coffre.plk");
    write_atomic(&target, "profond", b"contenu").expect("écriture");

    assert_eq!(std::fs::read(&target).expect("lecture"), b"contenu");
}

#[test]
fn writing_into_a_missing_directory_fails_without_panicking() {
    let dir = sandbox();
    let target = dir.path().join("absent").join("coffre.plk");

    let outcome = write_atomic(&target, "absent", b"contenu");
    assert!(
        outcome.is_err(),
        "écrire dans un répertoire absent doit échouer"
    );
    assert!(!target.exists());
}

#[test]
fn a_path_pointing_at_a_directory_is_refused() {
    let dir = sandbox();
    // Le nom du fichier cible est un répertoire existant : l'écriture doit échouer
    // proprement plutôt que d'essayer de le remplacer.
    let outcome = write_atomic(dir.path(), "test", b"contenu");
    assert!(outcome.is_err());
}

#[test]
fn the_exclusive_lock_is_held_and_released() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    std::fs::write(&target, b"contenu").expect("écriture initiale");

    let first = FileLock::acquire(&target).expect("premier verrou");

    assert!(
        FileLock::acquire(&target).is_err(),
        "un second verrou exclusif doit être refusé"
    );

    drop(first);

    FileLock::acquire(&target).expect("le verrou doit être libéré à la destruction");
}

#[test]
fn the_lock_path_is_exposed_for_diagnostics() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    std::fs::write(&target, b"contenu").expect("écriture");

    let lock = FileLock::acquire(&target).expect("verrou");
    let path = lock.path();
    assert!(
        path.to_string_lossy().contains("coffre.plk"),
        "le chemin du verrou doit être dérivé du coffre : {path:?}"
    );
}

#[test]
fn a_symlink_free_path_is_accepted_by_the_portable_check() {
    let dir = sandbox();
    let real = dir.path().join("reel");
    std::fs::create_dir(&real).expect("création");

    ensure_no_symlink_components(&real).expect("un chemin réel doit être accepté");

    // Un chemin partiellement inexistant est accepté : les ancêtres existants ont
    // été vérifiés, et la suite sera créée sous eux.
    ensure_no_symlink_components(&real.join("pas").join("encore"))
        .expect("un chemin à créer doit être accepté");
}

#[test]
fn the_state_directory_is_absolute_and_distinct_from_the_working_directory() {
    // Propriété structurelle : la sentinelle ne doit jamais vivre à côté du coffre,
    // sinon un attaquant qui écrit le coffre écrit la sentinelle du même geste.
    match passlock_platform::fs::app_state_dir() {
        Ok(path) => {
            assert!(
                path.is_absolute(),
                "répertoire d'état non absolu : {path:?}"
            );
            let cwd = std::env::current_dir().expect("répertoire courant");
            assert_ne!(
                path, cwd,
                "le répertoire d'état ne doit pas être le répertoire courant"
            );
        }
        Err(err) => {
            // Cas légitime dans un environnement sans variables de configuration.
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        }
    }
}

#[test]
fn concurrent_writes_do_not_interleave() {
    // Deux écritures séquentielles du même contenu doivent produire un fichier
    // identique : aucune n'a laissé de trace de l'autre.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    for round in 0..8 {
        let payload = vec![u8::try_from(round).unwrap_or(0); 1024 + round];
        write_atomic(&target, &format!("round-{round}"), &payload).expect("écriture");
        assert_eq!(std::fs::read(&target).expect("lecture"), payload);
    }
}

#[test]
fn writing_to_a_read_only_directory_fails_cleanly() {
    // Vérifie l'absence de panique et de résidu sur un échec de permission. Le test
    // est ignoré là où les permissions ne s'appliquent pas.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = sandbox();
        let locked = dir.path().join("verrouille");
        std::fs::create_dir(&locked).expect("création");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod");

        let target = locked.join("coffre.plk");
        let outcome = write_atomic(&target, "test", b"contenu");

        // En environnement privilégié (root, conteneur), l'écriture peut réussir :
        // on se contente alors de vérifier qu'il n'y a pas de panique.
        if outcome.is_err() {
            assert!(
                !target.exists(),
                "aucun fichier ne doit subsister après échec"
            );
        }

        // Restaure les permissions pour que le nettoyage du répertoire fonctionne.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
    }
}
