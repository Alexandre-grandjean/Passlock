//! Tests d'intégration de l'écriture atomique et du verrouillage.
//!
//! Ces tests portent sur des propriétés **de sécurité**, pas sur du
//! fonctionnement : permissions effectives, refus des liens symboliques, absence
//! de fichier partiel, non-altération de fichiers hors périmètre.
//!
//! Ils s'exécutent sur un système de fichiers réel, donc ils testent ce que le
//! noyau fait réellement plutôt que ce que nous croyons lui avoir demandé.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![cfg(unix)]

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use passlock_platform::fs::{FileLock, verify_private, write_atomic};

/// Crée un répertoire temporaire propre à un test.
fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("répertoire temporaire")
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("métadonnées")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn new_file_is_created_with_owner_only_permissions() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "suffixe-de-test", b"contenu").expect("écriture");

    assert_eq!(fs::read(&target).expect("lecture"), b"contenu");
    assert_eq!(
        mode_of(&target),
        0o600,
        "le coffre doit être créé en 0600, jamais avec les permissions de l'umask"
    );
}

#[test]
fn permissions_are_not_widened_by_replacement() {
    // Un coffre déjà en 0600 doit le rester après réécriture : le nouveau fichier
    // est recréé, donc les permissions doivent être posées de nouveau, pas héritées.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "un", b"premier").expect("écriture");
    assert_eq!(mode_of(&target), 0o600);

    write_atomic(&target, "deux", b"second").expect("écriture");
    assert_eq!(fs::read(&target).expect("lecture"), b"second");
    assert_eq!(mode_of(&target), 0o600);
}

#[test]
fn no_temporary_file_is_left_behind_on_success() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");

    write_atomic(&target, "unique", b"contenu").expect("écriture");

    let entries: Vec<_> = fs::read_dir(dir.path())
        .expect("listage")
        .map(|entry| entry.expect("entrée").file_name())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "un résidu temporaire subsiste : {entries:?}"
    );
}

#[test]
fn replacing_a_symlink_replaces_the_link_not_its_target() {
    // Scénario d'attaque : un attaquant remplace le coffre par un lien vers un
    // fichier sensible de l'utilisateur. Une écriture qui suivrait le lien
    // détruirait ce fichier. Le renommage doit remplacer l'entrée du lien.
    let dir = sandbox();
    let victim = dir.path().join("victime.txt");
    fs::write(&victim, b"CONTENU A PRESERVER").expect("écriture de la victime");

    let target = dir.path().join("coffre.plk");
    symlink(&victim, &target).expect("création du lien");

    write_atomic(&target, "test-lien", b"nouveau coffre").expect("écriture");

    assert_eq!(
        fs::read(&victim).expect("lecture de la victime"),
        b"CONTENU A PRESERVER",
        "le fichier ciblé par le lien symbolique a été écrasé : écriture à travers un lien"
    );
    let metadata = fs::symlink_metadata(&target).expect("métadonnées");
    assert!(
        metadata.is_file(),
        "le coffre doit désormais être un fichier ordinaire, pas encore un lien"
    );
    assert_eq!(fs::read(&target).expect("lecture"), b"nouveau coffre");
}

#[test]
fn a_pre_created_symlink_at_the_temporary_name_is_refused() {
    // Scénario d'attaque : deviner le nom du fichier temporaire et y placer un
    // lien symbolique, pour nous faire écrire à travers. `O_EXCL` doit refuser.
    let dir = sandbox();
    let victim = dir.path().join("victime.txt");
    fs::write(&victim, b"CONTENU A PRESERVER").expect("écriture de la victime");

    let target = dir.path().join("coffre.plk");
    let sabotaged_temp = dir.path().join(".coffre.plk.tmp-suffixe-impose");
    symlink(&victim, &sabotaged_temp).expect("création du lien");

    let outcome = write_atomic(&target, "suffixe-impose", b"nouveau coffre");

    assert!(
        outcome.is_err(),
        "l'écriture a traversé un lien symbolique pré-créé au nom temporaire"
    );
    assert_eq!(
        fs::read(&victim).expect("lecture de la victime"),
        b"CONTENU A PRESERVER",
        "le fichier victime a été modifié via le lien symbolique"
    );
    assert!(
        !target.exists(),
        "le coffre ne doit pas exister après un échec d'écriture"
    );
}

#[test]
fn a_symlinked_directory_is_refused() {
    // Un répertoire remplacé par un lien symbolique doit être refusé par
    // `O_NOFOLLOW`, sans quoi toute écriture serait redirigée ailleurs.
    let dir = sandbox();
    let real = dir.path().join("reel");
    fs::create_dir(&real).expect("création");
    let link = dir.path().join("lien");
    symlink(&real, &link).expect("création du lien");

    let target = link.join("coffre.plk");
    let outcome = write_atomic(&target, "test", b"contenu");

    assert!(
        outcome.is_err(),
        "un répertoire atteint par lien symbolique doit être refusé"
    );
    assert!(!real.join("coffre.plk").exists());
}

#[test]
fn target_without_parent_directory_component_is_handled() {
    // Chemin relatif réduit à un nom de fichier : le répertoire cible est le
    // répertoire courant. On ne teste pas l'écriture (elle polluerait le
    // répertoire de travail) mais l'absence de panique sur la décomposition.
    let dir = sandbox();
    let target = dir.path().join("nom-simple.plk");
    write_atomic(&target, "x", b"y").expect("écriture");

    // Un chemin sans nom de fichier doit être refusé proprement.
    let outcome = write_atomic(Path::new("/"), "x", b"y");
    assert!(outcome.is_err());
    assert_eq!(
        outcome.expect_err("erreur attendue").kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn a_path_containing_a_nul_byte_is_refused() {
    // Un octet nul tronquerait le chemin côté noyau : on doit refuser plutôt que
    // d'écrire dans un fichier différent de celui qu'on croit viser.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = sandbox();
    let malicious = dir.path().join(OsStr::from_bytes(b"coffre\0.plk"));
    let outcome = write_atomic(&malicious, "x", b"y");

    assert!(
        outcome.is_err(),
        "un chemin contenant un octet nul a été accepté"
    );
    assert_eq!(
        outcome.expect_err("erreur attendue").kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn large_content_roundtrips_exactly() {
    // Vérifie qu'aucune troncature silencieuse n'a lieu sur un contenu de taille
    // réaliste pour un coffre.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    let payload: Vec<u8> = (0..512_u32)
        .flat_map(|chunk| (0..1024).map(move |offset| ((chunk * 1024 + offset) % 251) as u8))
        .collect();

    write_atomic(&target, "gros", &payload).expect("écriture");

    assert_eq!(fs::read(&target).expect("lecture"), payload);
}

#[test]
fn exclusive_lock_is_refused_while_held_and_released_on_drop() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    fs::write(&target, b"contenu").expect("écriture initiale");

    let first = FileLock::acquire(&target).expect("premier verrou");

    let second = FileLock::acquire(&target);
    assert!(
        second.is_err(),
        "un second verrou exclusif a été accordé alors que le premier était détenu"
    );

    drop(first);

    FileLock::acquire(&target).expect("le verrou doit être libéré à la destruction");
}

#[test]
fn lock_does_not_follow_a_symlink_at_its_location() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    fs::write(&target, b"contenu").expect("écriture initiale");

    let victim = dir.path().join("victime.txt");
    fs::write(&victim, b"NE PAS OUVRIR").expect("écriture de la victime");
    symlink(&victim, dir.path().join("coffre.plk.lock")).expect("lien sur l'emplacement du verrou");

    let outcome = FileLock::acquire(&target);
    assert!(
        outcome.is_err(),
        "le verrou a suivi un lien symbolique à son emplacement"
    );
    assert_eq!(
        fs::read(&victim).expect("lecture"),
        b"NE PAS OUVRIR",
        "le fichier victime a été modifié"
    );
}

#[test]
fn permission_repair_is_reported_once_and_is_idempotent() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    fs::write(&target, b"contenu").expect("écriture");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("chmod");

    assert_eq!(mode_of(&target), 0o644);

    let corrected = verify_private(&target).expect("vérification");
    assert!(
        corrected,
        "des permissions 0644 doivent être signalées comme corrigées"
    );
    assert_eq!(mode_of(&target), 0o600);

    let corrected_again = verify_private(&target).expect("vérification");
    assert!(
        !corrected_again,
        "une seconde vérification ne doit rien avoir à corriger"
    );
}

#[test]
fn already_restrictive_permissions_are_left_alone() {
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    fs::write(&target, b"contenu").expect("écriture");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).expect("chmod");

    let corrected = verify_private(&target).expect("vérification");
    assert!(
        !corrected,
        "un mode 0400 est déjà restrictif et ne doit pas être élargi à 0600"
    );
    assert_eq!(mode_of(&target), 0o400);
}

#[test]
fn verify_private_rejects_a_non_regular_file() {
    let dir = sandbox();
    let outcome = verify_private(dir.path());
    assert!(outcome.is_err());
    assert_eq!(
        outcome.expect_err("erreur attendue").kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn interrupted_writes_never_leave_a_partial_vault() {
    // Simule une écriture abandonnée en cours de route : on crée les fichiers
    // temporaires qu'un plantage laisserait, puis on vérifie que le coffre
    // existant reste intact et lisible.
    let dir = sandbox();
    let target = dir.path().join("coffre.plk");
    write_atomic(&target, "initial", b"VERSION VALIDE").expect("écriture");

    // Résidus d'exécutions interrompues.
    fs::write(dir.path().join(".coffre.plk.tmp-aaaa"), b"partiel").expect("résidu");
    fs::write(dir.path().join(".coffre.plk.tmp-bbbb"), b"partiel").expect("résidu");

    assert_eq!(
        fs::read(&target).expect("lecture"),
        b"VERSION VALIDE",
        "le coffre a été altéré par des résidus temporaires"
    );

    // Et une nouvelle écriture doit encore réussir malgré les résidus.
    write_atomic(&target, "suivante", b"NOUVELLE VERSION").expect("écriture");
    assert_eq!(fs::read(&target).expect("lecture"), b"NOUVELLE VERSION");
}

// ---------------------------------------------------------------------------
// Liens symboliques sur les composants INTERMÉDIAIRES
//
// `O_NOFOLLOW` ne s'applique qu'au dernier composant d'un chemin. Ces tests
// couvrent la correction : une marche qui ouvre chaque répertoire depuis le
// descripteur du précédent, en refusant tout composant symbolique.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlink_at_the_second_level_is_refused() {
    use std::os::unix::fs::symlink;

    let dir = sandbox();
    let attacker = dir.path().join("attaquant");
    fs::create_dir_all(attacker.join("b")).expect("création");

    symlink(&attacker, dir.path().join("a")).expect("lien");
    let target = dir.path().join("a").join("b").join("coffre.plk");

    let outcome = write_atomic(&target, "test", b"contenu");
    assert!(
        outcome.is_err(),
        "un composant symbolique au deuxième niveau doit être refusé"
    );
    assert!(!attacker.join("b").join("coffre.plk").exists());
}

#[cfg(unix)]
#[test]
fn a_symlink_deep_in_the_path_is_refused() {
    use std::os::unix::fs::symlink;

    let dir = sandbox();
    let attacker = dir.path().join("attaquant");
    fs::create_dir_all(&attacker).expect("création");

    // Chemin profond, toutes les composantes réelles sauf la dernière avant la cible.
    let mut current = dir.path().to_path_buf();
    for level in ["n1", "n2", "n3"] {
        current = current.join(level);
        fs::create_dir(&current).expect("création");
    }
    symlink(&attacker, current.join("piege")).expect("lien");

    let target = current.join("piege").join("coffre.plk");
    assert!(
        write_atomic(&target, "test", b"contenu").is_err(),
        "un composant symbolique profond doit être refusé"
    );
    assert!(!attacker.join("coffre.plk").exists());
}

#[cfg(unix)]
#[test]
fn an_absolute_symlinked_prefix_is_refused() {
    use std::os::unix::fs::symlink;

    let dir = sandbox();
    let attacker = dir.path().join("attaquant");
    fs::create_dir_all(&attacker).expect("création");
    let link = dir.path().join("prefixe");
    symlink(&attacker, &link).expect("lien");

    // Chemin **absolu** : l'ancrage est la racine, et la marche doit néanmoins
    // détecter le composant symbolique.
    let target = link.join("coffre.plk");
    assert!(target.is_absolute(), "le chemin de test doit être absolu");

    assert!(
        write_atomic(&target, "test", b"contenu").is_err(),
        "un préfixe symbolique dans un chemin absolu doit être refusé"
    );
    assert!(!attacker.join("coffre.plk").exists());
}

#[test]
fn a_deep_legitimate_path_still_works() {
    // Contrepartie indispensable : la correction ne doit pas casser les chemins
    // ordinaires. Sans ce test, un refus trop large passerait inaperçu.
    let dir = sandbox();
    let mut current = dir.path().to_path_buf();
    for level in ["n1", "n2", "n3", "n4"] {
        current = current.join(level);
        fs::create_dir(&current).expect("création");
    }

    let target = current.join("coffre.plk");
    write_atomic(&target, "test", b"contenu profond").expect("écriture");

    assert_eq!(fs::read(&target).expect("lecture"), b"contenu profond");
    assert_eq!(mode_of(&target), 0o600);
}

#[test]
fn a_relative_path_with_parent_components_still_works() {
    // `..` doit rester accepté : c'est une entrée de répertoire ordinaire, jamais
    // un lien symbolique, et la refuser casserait des usages légitimes.
    let dir = sandbox();
    let nested = dir.path().join("sous").join("niveau");
    fs::create_dir_all(&nested).expect("création");

    let target = nested.join("..").join("..").join("coffre.plk");
    write_atomic(&target, "test", b"contenu").expect("écriture");

    assert!(dir.path().join("coffre.plk").exists());
    assert_eq!(
        fs::read(dir.path().join("coffre.plk")).expect("lecture"),
        b"contenu"
    );
}

#[test]
fn a_curdir_component_still_works() {
    let dir = sandbox();
    let target = dir.path().join(".").join("coffre.plk");
    write_atomic(&target, "test", b"contenu").expect("écriture");
    assert!(dir.path().join("coffre.plk").exists());
}

#[test]
fn ensure_no_symlink_components_accepts_and_rejects() {
    let dir = sandbox();
    let real = dir.path().join("reel");
    fs::create_dir(&real).expect("création");

    assert!(passlock_platform::fs::ensure_no_symlink_components(&real).is_ok());

    // Un chemin partiellement inexistant est accepté : les ancêtres existants ont
    // été vérifiés, et la création se fera sous eux.
    assert!(
        passlock_platform::fs::ensure_no_symlink_components(&real.join("pas").join("encore"))
            .is_ok()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = dir.path().join("lien");
        symlink(&real, &link).expect("lien");
        let outcome = passlock_platform::fs::ensure_no_symlink_components(&link);
        assert!(outcome.is_err(), "un composant symbolique doit être refusé");
        assert!(
            outcome
                .expect_err("refus attendu")
                .to_string()
                .contains("lien"),
            "le message doit nommer le composant fautif"
        );
    }
}
