//! Tests du magasin, à travers son API publique.
//!
//! Les propriétés vérifiées ici sont celles qui protègent les **données de
//! l'utilisateur** : atomicité d'une mutation refusée, politique de rétention de
//! l'historique, et suppression effective. Elles ne se voient pas dans les tests du
//! codec, qui ne connaissent que la forme.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{AuditKind, Entry, EntryKind, Field, FieldKind};
use passlock_core::query::{SearchQuery, SortOrder, search};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

const PASSWORD: &[u8] = b"phrase de passe pour les tests du magasin";

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

/// Crée un coffre neuf et retourne le magasin, le chemin et l'état.
fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, VaultStore) {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    let store = VaultStore::create(&path, PASSWORD, &config(&state)).expect("création");
    (dir, path, state, store)
}

fn sample_entry(title: &str) -> Entry {
    let mut entry = Entry::new(EntryKind::Login, title, 1_700_000_000).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, "s3cr3t", 0).expect("champ"));
    entry
}

// ---------------------------------------------------------------------------
// Cycle de vie
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_store_round_trips_through_the_file() {
    let (dir, path, state, mut store) = setup();

    let folder = store.add_folder("travail", None).expect("dossier");
    let tag = store.add_tag("important").expect("tag");

    let mut entry = sample_entry("exemple.com");
    entry.folder = Some(folder);
    entry.tags.push(tag);
    let id = store.add_entry(entry).expect("ajout");

    store.save().expect("enregistrement");
    drop(store);

    let reopened = VaultStore::open(&path, PASSWORD, &config(&state)).expect("ouverture");

    assert_eq!(reopened.archive().entries.len(), 1);
    assert_eq!(reopened.archive().folders.len(), 1);
    assert_eq!(reopened.archive().tags.len(), 1);

    let entry = reopened.archive().entry(&id).expect("entrée retrouvée");
    assert_eq!(entry.title, "exemple.com");
    assert_eq!(entry.folder, Some(folder));
    assert_eq!(entry.tags, vec![tag]);
    assert_eq!(entry.field("password").expect("champ").value, "s3cr3t");

    drop(dir);
}

#[test]
fn a_new_store_is_not_dirty() {
    let (_dir, _path, _state, store) = setup();
    assert!(
        !store.is_dirty(),
        "un coffre fraîchement créé n'a rien à enregistrer"
    );
}

#[test]
fn mutations_mark_the_store_dirty() {
    let (_dir, _path, _state, mut store) = setup();

    store.add_entry(sample_entry("a")).expect("ajout");
    assert!(store.is_dirty());

    store.save().expect("enregistrement");
    assert!(!store.is_dirty());

    store.add_entry(sample_entry("b")).expect("ajout");
    assert!(store.is_dirty());

    assert!(store.save_if_dirty().expect("enregistrement conditionnel"));
    assert!(!store.save_if_dirty().expect("rien à faire"));
}

#[test]
fn a_read_only_store_refuses_to_persist_changes() {
    let (dir, path, state, mut store) = setup();
    store.add_entry(sample_entry("a")).expect("ajout");
    store.save().expect("enregistrement");
    drop(store);

    let read_only_config = VaultConfig {
        read_only: true,
        ..config(&state)
    };
    let mut store = VaultStore::open(&path, PASSWORD, &read_only_config).expect("ouverture");

    let before = std::fs::read(&path).expect("lecture");

    // Les modifications en mémoire sont permises, mais ne doivent jamais atteindre
    // le disque.
    store.add_entry(sample_entry("b")).expect("ajout");
    assert!(
        store.save().is_err(),
        "un enregistrement en lecture seule doit échouer"
    );
    assert!(
        store.save_if_dirty().is_err(),
        "un enregistrement conditionnel implicite doit aussi être refusé"
    );

    assert_eq!(
        std::fs::read(&path).expect("lecture"),
        before,
        "le fichier a été modifié en lecture seule"
    );
    drop(dir);
}

// ---------------------------------------------------------------------------
// Atomicité des mutations
// ---------------------------------------------------------------------------

#[test]
fn a_refused_mutation_leaves_the_archive_unchanged() {
    // La propriété la plus importante du magasin : une modification qui échoue ne
    // doit **rien** laisser derrière elle. Sans le motif « valider puis appliquer »,
    // une entrée serait restée à moitié modifiée.
    let (_dir, path, _state, mut store) = setup();

    let folder = store.add_folder("existant", None).expect("dossier");
    let mut entry = sample_entry("cible");
    entry.folder = Some(folder);
    let id = store.add_entry(entry).expect("ajout");
    store.save().expect("enregistrement");

    let before = std::fs::read(&path).expect("lecture");
    let revision_before = store.archive().entry(&id).expect("entrée").revision;

    // La mutation référence un dossier inexistant : elle doit être refusée, et
    // l'entrée rester intacte.
    let ghost = passlock_core::model::FolderId::generate().expect("aléa");
    let outcome = store.update_entry(&id, |entry| {
        entry.title = "titre modifié".to_string();
        entry.folder = Some(ghost);
        Ok(())
    });
    assert!(outcome.is_err(), "une référence pendante doit être refusée");

    let after = store.archive().entry(&id).expect("entrée");
    assert_eq!(
        after.title, "cible",
        "le titre a été modifié malgré le refus"
    );
    assert_eq!(
        after.folder,
        Some(folder),
        "le dossier a été modifié malgré le refus"
    );
    assert_eq!(
        after.revision, revision_before,
        "la révision a été incrémentée"
    );

    // Et rien ne doit avoir été marqué modifié : le fichier est identique.
    assert!(
        !store.is_dirty(),
        "un refus ne doit pas marquer le coffre modifié"
    );
    assert_eq!(std::fs::read(&path).expect("lecture"), before);
}

#[test]
fn a_failing_closure_leaves_the_archive_unchanged() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("intacte")).expect("ajout");

    let outcome = store.update_entry(&id, |entry| {
        entry.title = "modifié puis abandonné".to_string();
        Err(passlock_core::error::Error::Internal {
            invariant: "échec volontaire du test",
        })
    });
    assert!(outcome.is_err());

    assert_eq!(store.archive().entry(&id).expect("entrée").title, "intacte");
}

// ---------------------------------------------------------------------------
// Historique
// ---------------------------------------------------------------------------

#[test]
fn updating_an_entry_preserves_the_previous_state() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("avant")).expect("ajout");

    store
        .update_entry(&id, |entry| {
            entry.title = "après".to_string();
            Ok(())
        })
        .expect("modification");

    let entry = store.archive().entry(&id).expect("entrée");
    assert_eq!(entry.title, "après");
    assert_eq!(entry.revision, 2);
    assert_eq!(entry.history.len(), 1);
    assert_eq!(
        entry.history[0].snapshot.title, "avant",
        "l'état antérieur doit être conservé"
    );
    assert_eq!(
        entry.history[0].snapshot.fields[0].value, "s3cr3t",
        "l'instantané doit contenir les champs, et pas seulement le titre"
    );
}

#[test]
fn the_history_is_capped_by_the_retention_policy() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("entrée")).expect("ajout");

    // Bien au-delà du plafond : l'historique doit rester borné.
    for index in 0..(passlock_core::model::MAX_HISTORY_PER_ENTRY + 30) {
        store
            .update_entry(&id, |entry| {
                entry.title = format!("révision {index}");
                Ok(())
            })
            .expect("modification");
    }

    let entry = store.archive().entry(&id).expect("entrée");
    assert_eq!(
        entry.history.len(),
        passlock_core::model::MAX_HISTORY_PER_ENTRY,
        "la rétention par nombre doit être appliquée"
    );
}

#[test]
fn purging_the_history_removes_every_revision() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("entrée")).expect("ajout");

    for _ in 0..3 {
        store.update_entry(&id, |_| Ok(())).expect("modification");
    }
    assert_eq!(store.archive().entry(&id).expect("entrée").history.len(), 3);

    let removed = store.purge_history(&id).expect("purge");
    assert_eq!(removed, 3);
    assert!(
        store
            .archive()
            .entry(&id)
            .expect("entrée")
            .history
            .is_empty()
    );

    // L'événement doit être consigné : purger un historique est une action qui a des
    // conséquences, et elle ne doit pas être silencieuse.
    assert!(
        store
            .audit()
            .iter()
            .any(|event| event.kind == AuditKind::HistoryPurged),
        "la purge de l'historique doit figurer au journal"
    );
}

// ---------------------------------------------------------------------------
// Corbeille et suppression
// ---------------------------------------------------------------------------

#[test]
fn trashing_and_restoring_an_entry() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("cible")).expect("ajout");

    store.trash_entry(&id).expect("mise à la corbeille");
    assert!(store.archive().entry(&id).expect("entrée").is_trashed());
    assert!(!store.archive().entry(&id).expect("entrée").is_active());

    store.restore_entry(&id).expect("restauration");
    assert!(!store.archive().entry(&id).expect("entrée").is_trashed());
}

#[test]
fn purging_an_entry_removes_it_entirely() {
    let (_dir, _path, _state, mut store) = setup();
    let id = store.add_entry(sample_entry("à supprimer")).expect("ajout");

    for _ in 0..3 {
        store.update_entry(&id, |_| Ok(())).expect("modification");
    }

    store.purge_entry(&id).expect("suppression");

    assert!(
        store.archive().entry(&id).is_none(),
        "l'entrée devrait avoir disparu"
    );
    assert_eq!(store.archive().entries.len(), 0);
    assert!(
        store
            .archive()
            .audit
            .iter()
            .any(|e| e.kind == AuditKind::EntryPurged),
        "la suppression définitive doit figurer au journal"
    );
}

#[test]
fn emptying_the_trash_leaves_active_entries_alone() {
    let (_dir, _path, _state, mut store) = setup();

    let kept = store.add_entry(sample_entry("conservée")).expect("ajout");
    let first = store.add_entry(sample_entry("corbeille 1")).expect("ajout");
    let second = store.add_entry(sample_entry("corbeille 2")).expect("ajout");

    store.trash_entry(&first).expect("mise à la corbeille");
    store.trash_entry(&second).expect("mise à la corbeille");

    assert_eq!(store.empty_trash().expect("vidage"), 2);
    assert_eq!(store.archive().entries.len(), 1);
    assert!(store.archive().entry(&kept).is_some());
}

// ---------------------------------------------------------------------------
// Organisation
// ---------------------------------------------------------------------------

#[test]
fn folders_reject_duplicates_and_excessive_depth() {
    let (_dir, _path, _state, mut store) = setup();

    let root = store.add_folder("racine", None).expect("dossier");
    assert!(
        store.add_folder("racine", None).is_err(),
        "un doublon au même niveau doit être refusé"
    );

    // Descente jusqu'à la profondeur maximale.
    let mut parent = Some(root);
    for level in 0..passlock_core::model::MAX_FOLDER_DEPTH - 1 {
        parent = Some(
            store
                .add_folder(&format!("niveau {level}"), parent)
                .expect("dossier"),
        );
    }
    assert!(
        store.add_folder("trop profond", parent).is_err(),
        "la profondeur maximale doit être appliquée"
    );
}

#[test]
fn tags_reject_duplicate_names() {
    let (_dir, _path, _state, mut store) = setup();
    store.add_tag("important").expect("tag");
    assert!(
        store.add_tag("IMPORTANT").is_err(),
        "la comparaison doit être insensible à la casse"
    );
}

#[test]
fn an_entry_cannot_reference_a_missing_tag() {
    let (_dir, _path, _state, mut store) = setup();

    let mut entry = sample_entry("orpheline");
    entry
        .tags
        .push(passlock_core::model::TagId::generate().expect("aléa"));

    assert!(
        store.add_entry(entry).is_err(),
        "une entrée portant un tag inexistant doit être refusée"
    );
    assert_eq!(store.archive().entries.len(), 0);
}

// ---------------------------------------------------------------------------
// Recherche intégrée
// ---------------------------------------------------------------------------

#[test]
fn search_finds_decrypted_content_after_a_round_trip() {
    let (_dir, path, state, mut store) = setup();

    let mut entry = Entry::new(EntryKind::Login, "Banque Générale", 0).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, "clé-secrète", 0).expect("champ"));
    store.add_entry(entry).expect("ajout");
    store.save().expect("enregistrement");
    drop(store);

    let store = VaultStore::open(&path, PASSWORD, &config(&state)).expect("ouverture");

    let hits = search(store.archive(), &SearchQuery::new("banque generale"));
    assert_eq!(
        hits.len(),
        1,
        "la recherche doit ignorer la casse et les accents"
    );

    let hits = search(store.archive(), &SearchQuery::new("clé-secrète"));
    assert_eq!(
        hits.len(),
        1,
        "un champ secret doit être trouvable par son contenu"
    );
}

#[test]
fn sorting_is_applied_to_persisted_entries() {
    let (_dir, path, state, mut store) = setup();

    for title in ["zèbre", "abeille", "méduse"] {
        store
            .add_entry(Entry::new(EntryKind::Login, title, 0).expect("entrée"))
            .expect("ajout");
    }
    store.save().expect("enregistrement");
    drop(store);

    let store = VaultStore::open(&path, PASSWORD, &config(&state)).expect("ouverture");
    let query = SearchQuery {
        sort: SortOrder::Title,
        ..SearchQuery::new("")
    };
    let hits = search(store.archive(), &query);

    let titles: Vec<String> = hits
        .iter()
        .map(|hit| {
            store
                .archive()
                .entry(&hit.id)
                .expect("entrée")
                .title
                .clone()
        })
        .collect();
    assert_eq!(titles, vec!["abeille", "méduse", "zèbre"]);
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

#[test]
fn a_version_one_vault_opens_and_migrates_transparently() {
    // Un coffre créé par la phase 1 porte un corps vide et un schéma de version 1.
    // Il doit s'ouvrir, se migrer, et rester utilisable — c'est la promesse de
    // compatibilité entre les deux phases.
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("ancien.plk");
    let state = dir.path().join("etat");

    // On crée le coffre avec l'API de la phase 1 — qui ne connaît pas le modèle de
    // données et laisse donc un corps vide.
    let vault = passlock_core::vault::Vault::create(&path, PASSWORD, &config(&state))
        .expect("création phase 1");
    drop(vault);

    // NON-RÉGRESSION. L'ouverture d'un coffre à corps vide échouait autrefois :
    // `Vault::create` écrit l'enveloppe courante avec un corps vide, et le décodeur
    // exigeait une signature d'archive. Le coffre annonçait donc un schéma sans
    // contenir l'archive correspondante — un fichier cohérent en apparence mais
    // inouvrable. Un corps vide ne peut être une archive valide pour aucune version :
    // le lire comme une archive vide est la seule lecture possible.
    let store = VaultStore::open(&path, PASSWORD, &config(&state))
        .expect("un coffre à corps vide doit rester ouvrable");
    assert!(store.archive().entries.is_empty());

    // Et un ajout doit fonctionner sur un coffre issu de la phase 1.
    let mut store = store;
    store
        .add_entry(sample_entry("après migration"))
        .expect("ajout");
    store.save().expect("enregistrement");

    drop(store);
    let reopened = VaultStore::open(&path, PASSWORD, &config(&state)).expect("réouverture");
    assert_eq!(reopened.archive().entries.len(), 1);
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

#[test]
fn the_audit_log_never_contains_entry_content() {
    // Le journal consigne **qu'un** événement a eu lieu, jamais **ce qui** y
    // figurait. Ce test le vérifie sur le contenu réel du journal après des
    // opérations portant des valeurs reconnaissables.
    let (_dir, _path, _state, mut store) = setup();

    let marker = "MARQUEUR-CONFIDENTIEL-A-NE-PAS-JOURNALISER";
    let mut entry = Entry::new(EntryKind::Login, marker, 0).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, marker, 0).expect("champ"));
    let id = store.add_entry(entry).expect("ajout");
    store
        .update_entry(&id, |entry| {
            entry.title = marker.to_string();
            Ok(())
        })
        .expect("modification");
    store.trash_entry(&id).expect("corbeille");
    store.purge_entry(&id).expect("suppression");

    for event in store.audit() {
        let rendered = format!("{event:?}");
        assert!(
            !rendered.contains(marker),
            "le journal contient du contenu d'entrée : {rendered}"
        );
    }
}

#[test]
fn the_audit_log_is_bounded() {
    let (_dir, _path, _state, mut store) = setup();

    // Bien au-delà de la borne : le journal doit rester circulaire, sinon le coffre
    // grossirait indéfiniment au fil des ouvertures.
    for _ in 0..(passlock_core::model::MAX_AUDIT_EVENTS + 50) {
        store.record(AuditKind::Unlock, None);
    }

    assert_eq!(store.audit().len(), passlock_core::model::MAX_AUDIT_EVENTS);
}

#[test]
fn a_locking_event_does_not_mark_the_store_dirty() {
    // Consigner chaque ouverture rendrait toute consultation modifiante, et
    // forcerait une écriture pour une simple lecture. Le compromis est explicite.
    let (_dir, _path, _state, mut store) = setup();
    store.save().expect("enregistrement");

    store.record_without_dirty(AuditKind::Unlock, None);

    assert!(
        !store.is_dirty(),
        "consigner une ouverture ne doit pas rendre le coffre modifié"
    );
    assert_eq!(store.audit().len(), 1);
}

// ---------------------------------------------------------------------------
// Débogage
// ---------------------------------------------------------------------------

#[test]
fn debug_output_never_reveals_content() {
    let (_dir, _path, _state, mut store) = setup();

    let marker = "MARQUEUR-DE-FUITE";
    let mut entry = Entry::new(EntryKind::Login, marker, 0).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, marker, 0).expect("champ"));
    store.add_entry(entry).expect("ajout");

    let rendered = format!("{store:?}");
    assert!(
        !rendered.contains(marker),
        "le contenu du coffre apparaît dans le Debug : {rendered}"
    );

    // Les types du modèle sont eux aussi rédacteurs.
    let entry = &store.archive().entries[0];
    for rendered in [format!("{entry:?}"), format!("{:?}", entry.fields[0])] {
        assert!(!rendered.contains(marker), "{rendered}");
    }
    assert!(format!("{:?}", store.archive()).contains("entries"));
}
