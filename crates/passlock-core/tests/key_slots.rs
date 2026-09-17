//! Tests d'intégration des **slots supplémentaires** : clé de récupération et
//! clé matérielle.
//!
//! # Ce que ces tests établissent, et pourquoi
//!
//! Un slot supplémentaire est un **chemin d'entrée de plus** dans le coffre. Deux
//! propriétés décident que ce n'est pas une dégradation :
//!
//! 1. **la DEK ne change pas.** Tous les slots enveloppent la même clé de données :
//!    ajouter, remplacer ou révoquer un slot ne rechiffre aucun contenu et ne rend
//!    aucun autre accès invalide ;
//! 2. **un slot ne se transpose pas.** Le rôle, le sel, les paramètres et
//!    l'identifiant du coffre entrent dans l'AAD du slot : un slot déplacé vers un
//!    autre coffre, ou vers un autre rôle, ne s'ouvre pas.
//!
//! La première se vérifie sur les **sous-clés dérivées de la DEK** — un observateur
//! public de la DEK — et non sur un simple constat que « le coffre s'ouvre encore ».
//!
//! # Ce qui resterait vert en cas de régression
//!
//! Comparer les **octets du fichier** avant et après ne prouverait rien : le header
//! entre dans l'AAD du payload, donc tout changement de slot change légitimement le
//! chiffré (ADR-003, ADR-005). C'est pourquoi ces tests comparent des sous-clés.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::container::{PREFIX_LEN, ParsedVault};
use passlock_core::error::{Error, Result};
use passlock_core::header::{Header, SlotLabel};
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::recovery::RecoveryKey;
use passlock_core::vault::{Credentials, Unlocked, Vault, VaultConfig};

const PASSWORD: &[u8] = b"phrase de passe du coffre de test";
const OTHER_PASSWORD: &[u8] = b"phrase de passe d'un autre coffre";

/// Dimensions du header, **redéclarées ici** plutôt qu'importées.
///
/// Le format est gelé et documenté octet par octet (`docs/VAULT_FORMAT.md`) : les
/// épingler indépendamment du code de production est ce qui permet à ce test de
/// détecter un décalage de format. Le harnais adversarial de la phase 1 fait de même.
const HEADER_FIXED_LEN: usize = 28;
const SLOT_LEN: usize = 122;

/// Paramètres légers : le chemin de code ne dépend pas des valeurs (ADR-015).
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

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    state: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("répertoire temporaire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    let mut vault = Vault::create(&path, PASSWORD, &config(&state)).expect("création");
    vault.set_body(b"corps de test".to_vec());
    vault.save().expect("enregistrement");
    Fixture {
        _dir: dir,
        path,
        state,
    }
}

/// Déverrouille un fichier par un rôle et un secret donnés.
fn unlock(path: &Path, label: SlotLabel, secret: &[u8]) -> Result<Unlocked> {
    let bytes = std::fs::read(path).expect("lecture");
    passlock_core::vault::unlock_with_slot_label(&bytes, label, secret)
}

/// Octets de `K_records`, dérivés de la DEK, via une ouverture par mot de passe.
///
/// C'est l'observateur **public** de la DEK : si la clé de données changeait, ces
/// octets changeraient, alors qu'un constat « le coffre s'ouvre » resterait vrai.
fn data_key_view(f: &Fixture) -> Vec<u8> {
    unlock(&f.path, SlotLabel::Master, PASSWORD)
        .expect("déverrouillage par mot de passe")
        .subkeys
        .records
        .expose()
        .to_vec()
}

/// Installe un slot de récupération et enregistre.
fn install_recovery(f: &Fixture, key: &RecoveryKey) {
    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");
    vault
        .install_slot(SlotLabel::Recovery, key.expose(), params())
        .expect("installation");
    vault.save().expect("enregistrement");
}

// ---------------------------------------------------------------------------
// La DEK ne change pas
// ---------------------------------------------------------------------------

#[test]
fn installing_a_recovery_slot_preserves_the_data_key() {
    let f = fixture();
    let before = data_key_view(&f);

    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&f, &key);

    assert_eq!(
        before,
        data_key_view(&f),
        "ajouter un slot ne doit pas changer la clé de données"
    );

    // Et la clé de récupération mène à la **même** DEK, donc aux mêmes sous-clés.
    let via_key = unlock(&f.path, SlotLabel::Recovery, key.expose())
        .expect("déverrouillage par clé de récupération");
    assert_eq!(
        via_key.subkeys.records.expose(),
        before.as_slice(),
        "les deux chemins d'ouverture doivent produire la même clé de données"
    );
}

#[test]
fn the_payload_is_rewritten_and_still_openable() {
    // L'ajout d'un slot change le header, qui entre dans l'AAD du payload : le
    // fichier est donc légitimement ré-écrit. Ce test fixe **le fait** (le fichier
    // change) et **la conséquence qui compte** (il reste ouvrable).
    let f = fixture();
    let before = std::fs::read(&f.path).expect("lecture");

    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&f, &key);

    let after = std::fs::read(&f.path).expect("lecture");
    assert_ne!(before, after, "le payload doit avoir été ré-écrit");

    let reopened = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    assert_eq!(reopened.body(), b"corps de test");
}

#[test]
fn the_vault_is_still_openable_with_the_password_after_installing_a_slot() {
    let f = fixture();
    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&f, &key);

    let reopened = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("réouverture");
    assert_eq!(reopened.body(), b"corps de test");
    assert_eq!(
        reopened.slot_labels(),
        vec![SlotLabel::Master, SlotLabel::Recovery]
    );
}

#[test]
fn a_hardware_slot_uses_the_same_path_as_a_recovery_slot() {
    // « Un seul chemin de code » : le rôle ne change que le label et le matériel.
    let f = fixture();
    let file_key = [0x5A_u8; 32];

    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");
    vault
        .install_slot(SlotLabel::Hardware, &file_key, params())
        .expect("installation");
    vault.save().expect("enregistrement");
    drop(vault);

    let reopened = Vault::open_with(&f.path, &Credentials::KeyFile(&file_key), &config(&f.state))
        .expect("ouverture par fichier-clé");
    assert_eq!(reopened.body(), b"corps de test");
}

// ---------------------------------------------------------------------------
// Refus : rôles, doublons, dernier slot
// ---------------------------------------------------------------------------

#[test]
fn installing_a_second_slot_of_the_same_role_is_refused() {
    let f = fixture();
    let key = RecoveryKey::generate().expect("génération");

    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");
    vault
        .install_slot(SlotLabel::Recovery, key.expose(), params())
        .expect("première installation");

    let outcome = vault.install_slot(SlotLabel::Recovery, key.expose(), params());
    assert!(
        matches!(outcome, Err(Error::InvalidInput { .. })),
        "un second slot de même rôle doit être refusé, pas écraser le premier"
    );
}

#[test]
fn the_master_role_cannot_be_touched_by_the_slot_api() {
    let f = fixture();
    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");

    assert!(
        matches!(
            vault.install_slot(SlotLabel::Master, PASSWORD, params()),
            Err(Error::InvalidInput { .. })
        ),
        "installer un slot maître contournerait la ré-authentification"
    );
    assert!(
        matches!(
            vault.replace_slot(SlotLabel::Master, PASSWORD, params()),
            Err(Error::InvalidInput { .. })
        ),
        "remplacer le slot maître doit passer par `change_password`"
    );
    assert!(
        matches!(
            vault.revoke_slot(SlotLabel::Master),
            Err(Error::InvalidInput { .. })
        ),
        "révoquer le dernier slot maître rendrait le coffre inouvrable par mot de passe"
    );
}

#[test]
fn revoking_a_missing_role_is_refused() {
    let f = fixture();
    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");

    assert!(
        matches!(
            vault.revoke_slot(SlotLabel::Recovery),
            Err(Error::InvalidHeader { .. })
        ),
        "révoquer un rôle absent doit échouer explicitement"
    );
}

#[test]
fn replacing_a_slot_keeps_its_identifier() {
    let f = fixture();
    let first = RecoveryKey::generate().expect("génération");
    let second = RecoveryKey::generate().expect("génération");

    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");
    vault
        .install_slot(SlotLabel::Recovery, first.expose(), params())
        .expect("installation");
    let id_before = vault
        .header()
        .slots
        .iter()
        .find(|slot| slot.label == SlotLabel::Recovery)
        .expect("slot")
        .id;

    vault
        .replace_slot(SlotLabel::Recovery, second.expose(), params())
        .expect("remplacement");
    let id_after = vault
        .header()
        .slots
        .iter()
        .find(|slot| slot.label == SlotLabel::Recovery)
        .expect("slot")
        .id;

    assert_eq!(
        id_before, id_after,
        "l'identifiant du slot doit être conservé"
    );

    vault.save().expect("enregistrement");
    drop(vault);

    Vault::open_with(
        &f.path,
        &Credentials::RecoveryKey(&second),
        &config(&f.state),
    )
    .expect("la clé de remplacement doit ouvrir");
    assert!(
        Vault::open_with(
            &f.path,
            &Credentials::RecoveryKey(&first),
            &config(&f.state)
        )
        .is_err(),
        "la clé remplacée ne doit plus ouvrir le coffre"
    );
}

#[test]
fn revoking_a_recovery_slot_leaves_the_password_path_intact() {
    let f = fixture();
    let key = RecoveryKey::generate().expect("génération");
    let before = data_key_view(&f);

    install_recovery(&f, &key);

    let mut vault = Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture");
    vault.revoke_slot(SlotLabel::Recovery).expect("révocation");
    vault.save().expect("enregistrement");
    drop(vault);

    assert_eq!(before, data_key_view(&f));

    assert!(
        Vault::open_with(&f.path, &Credentials::RecoveryKey(&key), &config(&f.state)).is_err(),
        "après révocation, la clé de récupération ne doit plus ouvrir le coffre"
    );
    Vault::open(&f.path, PASSWORD, &config(&f.state))
        .expect("le mot de passe doit toujours ouvrir");
}

// ---------------------------------------------------------------------------
// Un slot ne se transpose pas (invariant I7)
// ---------------------------------------------------------------------------

#[test]
fn a_recovery_slot_transplanted_into_another_vault_does_not_open() {
    // Coffre A : mot de passe + clé de récupération.
    let a = fixture();
    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&a, &key);

    // Coffre B : mot de passe seul, identifiant de coffre différent.
    let b_dir = tempfile::tempdir().expect("répertoire temporaire");
    let b_path = b_dir.path().join("autre.plk");
    let b_state = b_dir.path().join("etat");
    let mut b = Vault::create(&b_path, OTHER_PASSWORD, &config(&b_state)).expect("création B");
    b.set_body(b"corps de B".to_vec());
    b.save().expect("enregistrement B");
    drop(b);

    // Greffe : le slot de récupération de A remplace le slot maître de B. Les octets
    // du slot sont authentiques, mais son AAD porte l'identifiant de **A**.
    let a_bytes = std::fs::read(&a.path).expect("lecture A");
    let mut b_bytes = std::fs::read(&b_path).expect("lecture B");

    let recovery_offset = PREFIX_LEN + HEADER_FIXED_LEN + SLOT_LEN;
    let donor = a_bytes[recovery_offset..recovery_offset + SLOT_LEN].to_vec();

    let target = PREFIX_LEN + HEADER_FIXED_LEN;
    b_bytes[target..target + SLOT_LEN].copy_from_slice(&donor);

    // Le header reste structurellement valide — un seul slot, de rôle récupération.
    let parsed = ParsedVault::parse(&b_bytes).expect("le header greffé doit rester décodable");
    assert_eq!(parsed.header.slots.len(), 1);
    assert_eq!(parsed.header.slots[0].label, SlotLabel::Recovery);

    // Mais le désenveloppement échoue : l'AAD du slot contient l'identifiant du coffre
    // d'origine, que la greffe ne peut pas falsifier.
    let outcome =
        passlock_core::vault::unlock_with_slot_label(&b_bytes, SlotLabel::Recovery, key.expose());
    assert!(
        matches!(outcome, Err(Error::UnlockFailed)),
        "un slot déplacé vers un autre coffre ne doit pas s'ouvrir"
    );
}

// ---------------------------------------------------------------------------
// Observation P2 n° 2 : un slot Recovery est décodable, et ignoré
// ---------------------------------------------------------------------------

#[test]
fn a_recovery_slot_is_decoded_and_ignored_by_the_password_path() {
    // Observation de la phase 4, P2 : le décodage **ne resserre rien**. Un header
    // portant un slot de récupération est décodable, il ne perturbe pas l'ouverture
    // par mot de passe, et il n'ouvre rien sans sa clé.
    let f = fixture();
    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&f, &key);

    let bytes = std::fs::read(&f.path).expect("lecture");
    let decoded = Header::decode(&bytes[PREFIX_LEN..PREFIX_LEN + HEADER_FIXED_LEN + 2 * SLOT_LEN])
        .expect("le header à deux slots doit se décoder");
    assert_eq!(
        decoded
            .slots
            .iter()
            .map(|slot| slot.label)
            .collect::<Vec<_>>(),
        vec![SlotLabel::Master, SlotLabel::Recovery]
    );

    // Le mot de passe ouvre ; un mauvais mot de passe échoue — le slot de récupération
    // ne « rattrape » rien.
    Vault::open(&f.path, PASSWORD, &config(&f.state)).expect("ouverture par mot de passe");
    assert!(
        matches!(
            Vault::open(&f.path, b"mauvais mot de passe", &config(&f.state)),
            Err(Error::UnlockFailed)
        ),
        "le slot de récupération ne doit pas ouvrir le coffre à la place du mot de passe"
    );
}

// ---------------------------------------------------------------------------
// Bout en bout : la clé de récupération est le seul chemin disponible
// ---------------------------------------------------------------------------

#[test]
fn a_vault_without_its_password_is_recovered_by_the_recovery_key_alone() {
    let f = fixture();
    let key = RecoveryKey::generate().expect("génération");
    install_recovery(&f, &key);

    // La clé est **transcrite puis relue** : c'est le chemin réel de l'utilisateur, et
    // cela vérifie au passage que l'encodage survit au passage par du texte.
    let transcribed = key.encode();
    let reread = RecoveryKey::decode(&transcribed).expect("relecture");

    let recovered = Vault::open_with(
        &f.path,
        &Credentials::RecoveryKey(&reread),
        &config(&f.state),
    )
    .expect("récupération");
    assert_eq!(recovered.body(), b"corps de test");
    // Le coffre détenait le verrou exclusif : sans le relâcher, la tentative suivante
    // échouerait sur `AlreadyLocked` et le test ne mesurerait plus ce qu'il croit.
    drop(recovered);

    // Une clé de récupération étrangère, avec un total de contrôle valide, échoue.
    let wrong = RecoveryKey::generate().expect("génération");
    assert!(
        matches!(
            Vault::open_with(
                &f.path,
                &Credentials::RecoveryKey(&wrong),
                &config(&f.state)
            ),
            Err(Error::UnlockFailed)
        ),
        "une clé de récupération étrangère ne doit pas ouvrir le coffre"
    );
}
