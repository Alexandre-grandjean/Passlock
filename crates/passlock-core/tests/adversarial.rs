//! Harnais adversarial : attaques par manipulation du fichier de coffre.
//!
//! # Objet
//!
//! Les tests de `key_hierarchy.rs` vérifient que les propriétés **tiennent**. Ce
//! fichier-ci fait l'inverse : il essaie de les **casser**. Chaque test construit
//! une attaque concrète contre le format et vérifie qu'elle échoue — ou, quand ce
//! n'est pas le cas, le documente explicitement comme une limite reconnue.
//!
//! Les attaques purement structurelles (troncature, longueurs) sont traitées au
//! niveau du conteneur, avec une clé brute : pas de dérivation Argon2id, donc des
//! tests rapides et déterministes. Les attaques qui font intervenir la dérivation
//! utilisent le plancher de validation ([`MIN_M_COST_KIB`], t=1, p=1) pour la même
//! raison : **le chemin de code ne dépend pas de la valeur des paramètres**.
//!
//! # Ce que ce fichier n'est pas
//!
//! Il ne remplace pas un audit par un tiers. Il vérifie qu'un ensemble précis
//! d'attaques connues échoue ; il ne prouve pas qu'aucune autre n'existe.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::container::{self, ParsedVault};
use passlock_core::error::Error;
use passlock_core::header::{Header, Slot, SlotLabel};
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::keys::{KEY_LEN, WRAPPED_DEK_LEN, WrappedKey};
use passlock_core::secret::Key;
use passlock_core::vault::{Vault, VaultConfig};

const PASSWORD: &[u8] = b"phrase de passe pour le harnais adversarial";

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

/// Crée un coffre et retourne son chemin, son état et ses octets.
fn make_vault(dir: &Path, name: &str, body: &[u8]) -> (PathBuf, PathBuf, Vec<u8>) {
    let vault_path = dir.join(name);
    let state_dir = dir.join(format!("{name}.state"));
    let mut vault = Vault::create(&vault_path, PASSWORD, &config(&state_dir)).expect("création");
    vault.set_body(body.to_vec());
    vault.save().expect("enregistrement");
    drop(vault);
    let bytes = std::fs::read(&vault_path).expect("lecture");
    (vault_path, state_dir, bytes)
}

// ---------------------------------------------------------------------------
// Géométrie du format, telle que spécifiée dans docs/VAULT_FORMAT.md
// ---------------------------------------------------------------------------

const PREFIX_LEN: usize = 16;
const HEADER_FIXED_LEN: usize = 28;
const SLOT_LEN: usize = 122;
const NONCE_LEN: usize = 24;
/// Le `vault_id` commence juste après le préfixe de conteneur.
const VAULT_ID_OFFSET: usize = PREFIX_LEN;

/// Décalage de la fin du header, donc du nonce du payload.
fn body_start(file: &[u8]) -> usize {
    let header_len = u32::from_be_bytes([file[12], file[13], file[14], file[15]]) as usize;
    PREFIX_LEN + header_len
}

/// Recopie une région d'un fichier dans un autre.
fn splice(target: &mut [u8], source: &[u8], range: std::ops::Range<usize>) {
    target[range.clone()].copy_from_slice(&source[range]);
}

// ---------------------------------------------------------------------------
// 1. Mélange de deux coffres
// ---------------------------------------------------------------------------

#[test]
fn swapping_the_ciphertext_between_two_vaults_is_refused() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, a) = make_vault(dir.path(), "a.plk", b"contenu du coffre A");
    let (_, _, b) = make_vault(dir.path(), "b.plk", b"contenu du coffre B");

    // Les deux coffres ont des identifiants distincts : vérification préalable,
    // sans quoi le test ne prouverait rien.
    let pa = ParsedVault::parse(&a).expect("analyse A");
    let pb = ParsedVault::parse(&b).expect("analyse B");
    assert_ne!(pa.header.vault_id, pb.header.vault_id);

    // Le chiffré de B mis dans A : le slot reste celui de A, donc la clé est la
    // bonne, et c'est bien le tag du payload qui doit refuser.
    let mut mixed = a.clone();
    let start = body_start(&a) + NONCE_LEN;
    let length = a.len() - start;
    mixed[start..].copy_from_slice(&b[body_start(&b) + NONCE_LEN..][..length]);

    let parsed = ParsedVault::parse(&mixed).expect("structure toujours valide");
    let key = recovery_key_for(&mixed);
    assert!(
        key.is_none(),
        "ce test ne doit pas dépendre d'une clé récupérée"
    );

    // Vérification par l'API complète : le mot de passe de A doit échouer.
    let path = dir.path().join("mixte.plk");
    std::fs::write(&path, &mixed).expect("écriture");
    let outcome = Vault::open(&path, PASSWORD, &config(&dir.path().join("mixte.state")));
    assert!(
        matches!(outcome, Err(Error::Corrupted { .. })),
        "un chiffré provenant d'un autre coffre a été accepté : {outcome:?}"
    );
    let _ = parsed;
}

#[test]
fn swapping_the_payload_nonce_between_two_vaults_is_refused() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, a) = make_vault(dir.path(), "a.plk", b"contenu A");
    let (_, _, b) = make_vault(dir.path(), "b.plk", b"contenu B");

    let mut mixed = a.clone();
    let nonce = body_start(&a);
    splice(&mut mixed, &b, nonce..nonce + NONCE_LEN);

    let path = dir.path().join("nonce-melange.plk");
    std::fs::write(&path, &mixed).expect("écriture");
    let outcome = Vault::open(
        &path,
        PASSWORD,
        &config(&dir.path().join("nonce-melange.state")),
    );
    assert!(
        matches!(outcome, Err(Error::Corrupted { .. })),
        "un nonce provenant d'un autre coffre a été accepté"
    );
}

#[test]
fn transplanting_a_whole_slot_from_another_vault_is_refused() {
    // Attaque la plus intéressante : le slot de B est structurellement valide, ses
    // paramètres et son sel sont cohérents, et pourtant il ne doit pas pouvoir
    // s'ouvrir dans le coffre A. C'est l'AAD du slot qui l'en empêche, via
    // l'identifiant du coffre.
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, a) = make_vault(dir.path(), "a.plk", b"contenu A");
    let (_, _, b) = make_vault(dir.path(), "b.plk", b"contenu B");

    let mut mixed = a.clone();
    let slot = PREFIX_LEN + HEADER_FIXED_LEN;
    splice(&mut mixed, &b, slot..slot + SLOT_LEN);

    let path = dir.path().join("slot-transplante.plk");
    std::fs::write(&path, &mixed).expect("écriture");

    // Le slot transplanté a la structure attendue : le refus doit venir de
    // l'authentification, pas du format.
    assert!(
        ParsedVault::parse(&mixed).is_ok(),
        "le slot transplanté devrait rester structurellement valide"
    );

    // Ni le mot de passe de A ni celui de B ne doivent l'ouvrir : l'AAD lie le slot
    // à l'identifiant du coffre qui le contient.
    for candidate in [PASSWORD, b"une autre phrase de passe" as &[u8]] {
        let outcome = Vault::open(
            &path,
            candidate,
            &config(&dir.path().join("slot-transplante.state")),
        );
        assert!(
            outcome.is_err(),
            "un slot transplanté depuis un autre coffre a été accepté"
        );
    }
}

#[test]
fn splicing_two_halves_of_different_vaults_is_refused() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, a) = make_vault(dir.path(), "a.plk", b"contenu A identique");
    let (_, _, b) = make_vault(dir.path(), "b.plk", b"contenu B identique");

    // Première moitié de A, seconde moitié de B.
    let mut mixed = vec![0_u8; a.len().max(b.len())];
    let cut = mixed.len() / 2;
    mixed[..cut].copy_from_slice(&a[..cut]);
    mixed[cut..].copy_from_slice(&b[cut..]);

    let path = dir.path().join("moitie-moitie.plk");
    std::fs::write(&path, &mixed).expect("écriture");
    assert!(
        Vault::open(&path, PASSWORD, &config(&dir.path().join("moitie.state"))).is_err(),
        "un fichier assemblé à partir de deux coffres a été accepté"
    );
}

// ---------------------------------------------------------------------------
// 2. Substitution et réordonnancement de champs
// ---------------------------------------------------------------------------

#[test]
fn swapping_two_slots_in_the_header_invalidates_the_payload() {
    // Construit un header à deux slots, puis les intervertit. Chaque slot reste
    // individuellement valide et les identifiants restent uniques : seule l'AAD du
    // payload peut détecter l'échange.
    let slot = |id: u16, label: SlotLabel| Slot {
        id,
        label,
        params: KdfParams::low(),
        salt: [u8::try_from(id).unwrap_or(0); 32],
        wrapped: WrappedKey::new([u8::try_from(id).unwrap_or(0); 24], [7_u8; WRAPPED_DEK_LEN]),
    };

    let header = Header::from_parts(
        [0x11; 16],
        1_700_000_000,
        vec![slot(0, SlotLabel::Master), slot(1, SlotLabel::Recovery)],
    )
    .expect("header");
    let key = Key::<KEY_LEN>::from_array([0x42; KEY_LEN]);
    let plaintext = b"contenu du coffre";
    let file = container::seal(&header, &key, plaintext).expect("scellement");

    // Cas nominal : le fichier doit s'ouvrir.
    let parsed = ParsedVault::parse(&file).expect("analyse");
    assert_eq!(
        parsed.decrypt(&key).expect("déchiffrement").as_slice(),
        plaintext
    );

    // Échange des deux slots.
    let first = PREFIX_LEN + HEADER_FIXED_LEN;
    let second = first + SLOT_LEN;
    let mut swapped = file.clone();
    let (left, right) = swapped.split_at_mut(second);
    left[first..first + SLOT_LEN].swap_with_slice(&mut right[..SLOT_LEN]);

    assert!(
        ParsedVault::parse(&swapped).is_ok(),
        "les deux slots restent structurellement valides après échange"
    );
    let parsed = ParsedVault::parse(&swapped).expect("analyse");
    assert!(
        parsed.decrypt(&key).is_err(),
        "l'échange de deux slots n'a pas invalidé le tag du payload"
    );
}

#[test]
fn changing_the_slot_label_is_refused_structurally() {
    // NOTE DE CORRECTION, ET POINT DE DOCUMENTATION IMPORTANT.
    //
    // Ce test attendait initialement `UnlockFailed`. Le comportement réel est
    // `InvalidHeader` : transformer le seul slot en « récupération » laisse un
    // coffre **sans slot maître**, ce qui est une violation d'invariant
    // structurel, détectée avant toute dérivation.
    //
    // Les deux comportements sont corrects — ils refusent tous deux l'ouverture —
    // mais la documentation affirmait « toute altération de slot produit
    // UnlockFailed », ce qui était faux. La règle exacte est :
    //
    //   * altération qui viole un invariant structurel → erreur de format explicite ;
    //   * altération qui préserve la structure → `UnlockFailed`.
    //
    // Aucune des deux ne dépend du mot de passe : il n'y a donc pas d'oracle. Le
    // rôle du slot reste par ailleurs bien authentifié par l'AAD, ce que vérifie
    // `keys::tests::unwrap_fails_with_a_different_aad`.
    let dir = tempfile::tempdir().expect("répertoire");
    let (path, state, original) = make_vault(dir.path(), "roles.plk", b"contenu");

    let mut tampered = original.clone();
    // label = offset 2 dans le slot.
    tampered[PREFIX_LEN + HEADER_FIXED_LEN + 2] = 2; // Recovery
    std::fs::write(&path, &tampered).expect("écriture");

    let outcome = Vault::open(&path, PASSWORD, &config(&state));
    assert!(
        matches!(outcome, Err(Error::InvalidHeader { .. })),
        "changer le rôle du seul slot doit être refusé structurellement, obtenu {outcome:?}"
    );

    // Le message doit décrire la **structure** sans rien dire de la valeur du mot de
    // passe. On ne cherche donc pas des mots-clés — « slot de mot de passe maître »
    // est un terme structurel parfaitement légitime — mais la valeur elle-même.
    let message = outcome.expect_err("refus attendu").to_string();
    let password = String::from_utf8_lossy(PASSWORD).to_string();
    assert!(
        !message.contains(&password),
        "le message d'erreur contient le mot de passe : {message}"
    );
    assert!(
        message.contains("slot"),
        "le message devrait désigner la structure en cause : {message}"
    );
}

#[test]
fn changing_the_kdf_parameters_preserves_structure_but_fails_authentication() {
    // Contre-exemple du test précédent : modifier un paramètre de dérivation ne
    // viole aucun invariant structurel (la valeur reste dans les bornes), donc le
    // refus doit venir de l'authentification — c'est l'AAD du slot qui lie les
    // paramètres.
    let dir = tempfile::tempdir().expect("répertoire");
    let (path, state, original) = make_vault(dir.path(), "kdf.plk", b"contenu");

    let mut tampered = original.clone();
    let offset = PREFIX_LEN + HEADER_FIXED_LEN + 10; // t_cost
    tampered[offset..offset + 4].copy_from_slice(&2_u32.to_be_bytes());
    std::fs::write(&path, &tampered).expect("écriture");

    assert!(
        matches!(
            Vault::open(&path, PASSWORD, &config(&state)),
            Err(Error::UnlockFailed)
        ),
        "modifier les paramètres de dérivation doit invalider l'AAD du slot"
    );
}

#[test]
fn changing_the_vault_id_invalidates_every_slot() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (path, state, original) = make_vault(dir.path(), "id.plk", b"contenu");

    // NOTE DE CORRECTION : la première version de ce test modifiait l'octet 0, qui
    // appartient à la **signature** « PASSLOCK » et non à l'identifiant du coffre.
    // Le refus obtenu était `NotAVault`, correct mais sans rapport avec ce que le
    // test prétendait vérifier. Le `vault_id` commence à l'offset 16, immédiatement
    // après le préfixe de conteneur ; il faut aussi recalculer l'AAD… ce que le code
    // fait de lui-même, puisque l'AAD est construite à partir du header décodé.
    let mut tampered = original.clone();
    tampered[VAULT_ID_OFFSET] ^= 0x01;

    std::fs::write(&path, &tampered).expect("écriture");
    assert!(
        matches!(
            Vault::open(&path, PASSWORD, &config(&state)),
            Err(Error::UnlockFailed)
        ),
        "modifier l'identifiant du coffre n'a pas invalidé les slots"
    );
}

#[test]
fn changing_the_format_version_is_refused_explicitly() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, original) = make_vault(dir.path(), "version.plk", b"contenu");
    let path = dir.path().join("version-modifiee.plk");

    for version in [0_u16, 2, 99, u16::MAX] {
        let mut tampered = original.clone();
        tampered[8..10].copy_from_slice(&version.to_be_bytes());
        std::fs::write(&path, &tampered).expect("écriture");

        let outcome = ParsedVault::parse(&tampered);
        let _ = outcome;
        let outcome = Vault::open(&path, PASSWORD, &config(&dir.path().join("version.state")));
        assert!(
            outcome.is_err(),
            "une version de format {version} a été acceptée"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Bornes et allocations
// ---------------------------------------------------------------------------

#[test]
fn absurd_declared_lengths_never_cause_an_allocation() {
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, original) = make_vault(dir.path(), "bornes.plk", b"contenu");

    for value in [0_u32, 1, 4096, 4097, 65_535, 4_000_000_000, u32::MAX] {
        let mut tampered = original.clone();
        tampered[12..16].copy_from_slice(&value.to_be_bytes());

        // L'analyse doit refuser sans jamais paniquer ni réserver la taille
        // annoncée. Un `header_len` supérieur à la borne est refusé avant tout.
        assert!(
            ParsedVault::parse(&tampered).is_err(),
            "une longueur de header de {value} a été acceptée"
        );
    }
}

#[test]
fn a_hostile_memory_cost_is_refused_during_parsing() {
    // Attaque par déni de service : un fichier réclamant 4 Gio de mémoire pour la
    // dérivation. Le refus doit intervenir pendant le décodage du header, donc
    // avant que la moindre allocation liée à cette valeur n'ait lieu.
    let dir = tempfile::tempdir().expect("répertoire");
    let (_, _, original) = make_vault(dir.path(), "memoire.plk", b"contenu");

    let mut tampered = original.clone();
    let offset = PREFIX_LEN + HEADER_FIXED_LEN + 6; // m_cost_kib
    tampered[offset..offset + 4].copy_from_slice(&(4_u32 * 1024 * 1024).to_be_bytes());

    match ParsedVault::parse(&tampered) {
        Err(Error::RejectedKdfParams { .. }) => {}
        other => panic!("attendu RejectedKdfParams, obtenu {other:?}"),
    }
}

#[test]
fn a_huge_file_is_refused_without_being_loaded() {
    // Le fichier est créé avec une taille dépassant la borne, mais creux : le
    // système ne réserve pas réellement l'espace. On vérifie que la lecture bornée
    // refuse sans charger les 512 Mio en mémoire.
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("enorme.plk");

    let file = std::fs::File::create(&path).expect("création");
    let oversize = 512_u64 * 1024 * 1024 + 1;
    file.set_len(oversize).expect("allocation creuse");
    drop(file);

    let outcome = Vault::open(&path, PASSWORD, &config(&dir.path().join("enorme.state")));
    assert!(
        matches!(outcome, Err(Error::MalformedLength { .. })),
        "un fichier hors bornes devrait être refusé, obtenu {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Système de fichiers : démonstration d'une limite NON corrigée
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlinked_immediate_parent_is_refused() {
    // Cas protégé : le répertoire **immédiat** est ouvert avec O_NOFOLLOW.
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("répertoire");
    let real = dir.path().join("reel");
    std::fs::create_dir(&real).expect("création");
    let link = dir.path().join("lien");
    symlink(&real, &link).expect("lien");

    let path = link.join("coffre.plk");
    let outcome = Vault::create(&path, PASSWORD, &config(&dir.path().join("etat")));

    assert!(
        outcome.is_err(),
        "un parent immédiat symbolique doit être refusé"
    );
    assert!(
        !real.join("coffre.plk").exists(),
        "aucun fichier ne doit être écrit"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_intermediate_parent_is_now_refused() {
    // NON-RÉGRESSION — la limite a été corrigée, et ce test était auparavant écrit
    // pour **échouer** si elle l'était un jour. Il a fait son travail : il a échoué
    // dès que la correction a été appliquée, ce qui a forcé sa réécriture.
    //
    // Rappel de la limite d'origine : `O_NOFOLLOW` ne s'applique qu'au **dernier**
    // composant d'un chemin. Écrire dans `a/b/coffre.plk` avec `a` symbolique
    // écrivait donc chez l'attaquant.
    //
    // La correction est une marche composant par composant, chaque répertoire étant
    // ouvert avec `O_NOFOLLOW` **depuis le descripteur du précédent**. Le
    // descripteur tenu garantit qu'aucun composant ne peut être remplacé après
    // vérification, ce qu'une simple vérification préalable ne garantirait pas.
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("répertoire");
    let attacker = dir.path().join("attaquant");
    std::fs::create_dir_all(attacker.join("b")).expect("création");

    let link = dir.path().join("a");
    symlink(&attacker, &link).expect("lien");

    let path = link.join("b").join("coffre.plk");
    let outcome = Vault::create(&path, PASSWORD, &config(&dir.path().join("etat")));

    assert!(
        outcome.is_err(),
        "un composant intermédiaire symbolique doit être refusé depuis la correction"
    );
    assert!(
        !attacker.join("b").join("coffre.plk").exists(),
        "aucun fichier ne doit être écrit chez l'attaquant"
    );

    // Le message doit être actionnable : nommer le composant et indiquer le remède.
    let message = outcome.expect_err("refus attendu").to_string();
    assert!(
        message.contains('a'),
        "le message devrait nommer le composant fautif : {message}"
    );
    assert!(
        message.contains("realpath") || message.contains("résolu"),
        "le message devrait indiquer le remède : {message}"
    );
}

#[test]
fn creating_a_vault_never_overwrites_an_existing_one() {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");

    let first = Vault::create(&path, PASSWORD, &config(&state)).expect("création");
    let original = std::fs::read(&path).expect("lecture");
    drop(first);

    // Le verrou est pris **avant** le contrôle d'existence : une seconde création
    // doit être refusée, et le fichier rester intact.
    let second = Vault::create(&path, b"autre phrase de passe", &config(&state));
    assert!(second.is_err(), "une seconde création a été acceptée");

    assert_eq!(
        std::fs::read(&path).expect("lecture"),
        original,
        "le coffre existant a été modifié par une tentative de création"
    );
}

// ---------------------------------------------------------------------------
// 5. Concurrence
// ---------------------------------------------------------------------------

#[test]
fn a_second_writer_is_refused_and_the_vault_stays_readable() {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("concurrence.plk");
    let state = dir.path().join("etat");

    let mut holder = Vault::create(&path, PASSWORD, &config(&state)).expect("création");
    holder.set_body(b"contenu du detenteur".to_vec());
    holder.save().expect("enregistrement");

    let contender = Vault::open(&path, PASSWORD, &config(&state));
    assert!(
        matches!(contender, Err(Error::AlreadyLocked)),
        "un second écrivain a été autorisé pendant que le verrou était détenu"
    );

    // La lecture seule reste possible : l'écriture étant atomique, un lecteur voit
    // toujours un fichier complet.
    let reader = Vault::open(
        &path,
        PASSWORD,
        &VaultConfig {
            read_only: true,
            ..config(&state)
        },
    )
    .expect("lecture pendant écriture");
    assert_eq!(reader.body(), b"contenu du detenteur");

    drop(holder);

    // Après libération, le coffre doit être intact et modifiable.
    let mut after = Vault::open(&path, PASSWORD, &config(&state)).expect("ouverture après verrou");
    after.set_body(b"nouveau contenu".to_vec());
    after.save().expect("enregistrement");
    assert_eq!(after.body(), b"nouveau contenu");
}

// ---------------------------------------------------------------------------
// 6. Non-régression : la course à la création
// ---------------------------------------------------------------------------

#[test]
fn concurrent_creations_never_silently_overwrite_each_other() {
    // NON-RÉGRESSION. `Vault::create` testait auparavant `path.exists()` **avant**
    // d'acquérir le verrou. Deux créations simultanées franchissaient alors toutes
    // les deux le contrôle, se sérialisaient sur le verrou, et la seconde écrasait
    // silencieusement le coffre de la première.
    //
    // Ce test lance les deux créations en parallèle, plusieurs fois, et exige qu'il
    // y ait **exactement un succès** à chaque essai.
    //
    // Note : `flock` porte sur la description de fichier ouverte, donc deux
    // descripteurs du même processus se disputent bien le verrou. Le test est donc
    // représentatif d'une concurrence entre processus.
    for attempt in 0..12 {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("course.plk");
        let state = dir.path().join("etat");

        let outcomes = std::thread::scope(|scope| {
            let path_a = path.clone();
            let path_b = path.clone();
            let state_a = state.clone();
            let state_b = state;

            let a = scope
                .spawn(move || Vault::create(&path_a, b"phrase A", &config(&state_a)).map(drop));
            let b = scope
                .spawn(move || Vault::create(&path_b, b"phrase B", &config(&state_b)).map(drop));

            vec![a.join().expect("thread A"), b.join().expect("thread B")]
        });

        let successes = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(
            successes, 1,
            "essai {attempt} : {successes} créations ont réussi, il en faut exactement une              (résultats : {outcomes:?})"
        );

        // Et le coffre survivant doit être ouvrable avec l'un des deux mots de passe,
        // sans quoi la « réussite » serait un fichier corrompu.
        let survivors = [
            Vault::open(&path, b"phrase A", &config(&dir.path().join("verif"))).is_ok(),
            Vault::open(&path, b"phrase B", &config(&dir.path().join("verif"))).is_ok(),
        ];
        assert!(
            survivors.iter().filter(|ok| **ok).count() == 1,
            "essai {attempt} : le coffre survivant n'est pas ouvrable avec exactement un              mot de passe ({survivors:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Utilitaire : aucune clé n'est récupérable depuis un fichier forgé
// ---------------------------------------------------------------------------

/// Retourne toujours `None`.
///
/// Existe pour rendre explicite que les tests ci-dessus ne s'appuient sur aucune
/// clé extraite du fichier : ils partent du mot de passe, comme le ferait un
/// utilisateur.
fn recovery_key_for(_file: &[u8]) -> Option<Key<KEY_LEN>> {
    None
}
