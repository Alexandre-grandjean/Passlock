//! Tests de l'étape 4 : import/export CSV canonique.
//!
//! # Ce qui est éprouvé ici, et que rien d'autre n'éprouve
//!
//! Les autres suites couvrent le coffre et ses blobs. Ici, c'est la **projection
//! textuelle** qui est en jeu, et quatre propriétés qui n'existent qu'à ce niveau :
//!
//! | Invariant | Ce qu'il protège |
//! |---|---|
//! | `I-EXPORT-CONTENT` | l'export ne dépend ni de l'ordre d'insertion, ni des identifiants internes |
//! | `I-EXPORT-ROUNDTRIP` | `export → import → export` est identique octet pour octet |
//! | `I-EXPORT-ESCAPE` | l'échappement est canonique et contextuel, jamais permissif |
//! | `I-IMPORT-ATOMIC` | un import refusé ne laisse **aucune** modification persistante |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{
    Archive, Entry, EntryKind, Field, FieldKind, Folder, FolderId, Tag, TagId,
};
use passlock_core::portability::{self, HEADER};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

const PASSWORD: &[u8] = b"phrase de passe pour les tests d'import-export";
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
}

fn fixture(name: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join(name);
    let state = dir.path().join("etat");
    Fixture {
        _dir: dir,
        path,
        state,
    }
}

fn create(fixture: &Fixture) -> VaultStore {
    VaultStore::create(&fixture.path, PASSWORD, &config(&fixture.state)).expect("création")
}

fn sample(title: &str) -> Entry {
    let mut entry = Entry::new(EntryKind::Login, title, NOW).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, "s3cr3t", 0).expect("champ"));
    entry
}

/// Exporte une archive en texte.
fn text(archive: &Archive) -> String {
    let bytes = portability::export(archive).expect("export");
    String::from_utf8(bytes.to_vec()).expect("export UTF-8")
}

/// Exporte le coffre d'un magasin en octets.
fn export_bytes(store: &VaultStore) -> Vec<u8> {
    portability::export(store.archive())
        .expect("export")
        .to_vec()
}

/// Construit une ligne de données valide à 12 colonnes.
fn data_row(kind: &str, title: &str) -> String {
    [
        "E00000001",
        kind,
        title,
        "",
        "",
        "",
        "[]",
        "false",
        "false",
        "false",
        "1700000000",
        "1700000000",
    ]
    .join(",")
}

fn header_line() -> String {
    HEADER.join(",")
}

// ---------------------------------------------------------------------------
// I-EXPORT-CONTENT — déterminisme
// ---------------------------------------------------------------------------

#[test]
fn export_is_independent_of_insertion_order_and_ids() {
    let mut first = Archive::new(0);
    let mut second = Archive::new(0);

    // Mêmes entrées logiques, ordre d'insertion **différent**, identifiants
    // aléatoires **différents** (chaque `Entry::new` en tire un neuf).
    for title in ["zèbre", "abeille", "méduse"] {
        first.entries.push(sample(title));
    }
    for title in ["méduse", "zèbre", "abeille"] {
        second.entries.push(sample(title));
    }

    assert_ne!(
        first.entries[0].id, second.entries[2].id,
        "les identifiants internes doivent différer pour que le test ait du sens"
    );
    assert_eq!(text(&first), text(&second));
}

#[test]
fn rows_are_sorted_by_the_eleven_columns_and_ref_is_assigned_after() {
    let mut archive = Archive::new(0);
    for title in ["zèbre", "abeille", "méduse"] {
        archive.entries.push(sample(title));
    }

    let rendered = text(&archive);
    let lines: Vec<&str> = rendered.lines().collect();

    assert_eq!(lines[0], header_line(), "l'en-tête est fixe");
    // Tri bytewise UTF-8 sur le titre : a < m < z.
    assert!(lines[1].starts_with("E00000001,login,abeille,"));
    assert!(lines[2].starts_with("E00000002,login,méduse,"));
    assert!(lines[3].starts_with("E00000003,login,zèbre,"));
}

#[test]
fn trashed_entries_are_excluded_and_archived_entries_are_kept() {
    let mut archive = Archive::new(0);
    archive.entries.push(sample("active"));

    let mut archived = sample("archivée");
    archived.archived = true;
    archive.entries.push(archived);

    let mut trashed = sample("corbeille");
    trashed.trashed_at = Some(NOW);
    archive.entries.push(trashed);

    let rendered = text(&archive);
    assert!(rendered.contains("active"));
    assert!(rendered.contains("archivée"));
    assert!(!rendered.contains("corbeille"));
    assert_eq!(rendered.lines().count(), 3, "en-tête + 2 entrées");
}

#[test]
fn history_is_never_exported() {
    let fixture = fixture("coffre.plk");
    let mut store = create(&fixture);

    // Une modification conserve l'état antérieur dans l'historique. Cet état ne doit
    // pas se retrouver dans l'export : seule la version courante compte.
    let id = store.add_entry(sample("TITRE-ANCIEN")).expect("ajout");
    store
        .update_entry(&id, |entry| {
            entry.title = "titre actuel".to_string();
            Ok(())
        })
        .expect("modification");

    let rendered = text(store.archive());
    assert!(rendered.contains("titre actuel"));
    assert!(
        !rendered.contains("TITRE-ANCIEN"),
        "l'historique ne doit jamais apparaître dans l'export"
    );
    assert_eq!(
        rendered.lines().count(),
        2,
        "en-tête + une seule ligne de données : l'historique n'est pas une ligne"
    );
}

// ---------------------------------------------------------------------------
// I-EXPORT-ESCAPE — échappement canonique et contextuel
// ---------------------------------------------------------------------------

#[test]
fn the_three_escapes_are_contextual() {
    let mut archive = Archive::new(0);

    let folder = FolderId::generate().expect("aléa");
    archive.folders.push(Folder {
        id: folder,
        name: "Travail/Pro".to_string(),
        parent: None,
        ordinal: 0,
    });
    let tag = TagId::generate().expect("aléa");
    archive.tags.push(Tag {
        id: tag,
        name: "cri|tique".to_string(),
    });

    let mut entry = Entry::new(EntryKind::Login, "50% / 100|200", NOW).expect("entrée");
    entry.subtitle = "u|x".to_string();
    entry.folder = Some(folder);
    entry.tags.push(tag);
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, "a%b/c|d", 0).expect("champ"));
    archive.entries.push(entry);

    let rendered = text(&archive);
    let row = rendered.lines().nth(1).expect("ligne de données");

    // `%` est échappé partout ; `/` seulement dans un composant de dossier ; `|`
    // seulement dans un tag.
    assert!(
        row.starts_with("E00000001,login,50%25 / 100|200,u|x,Travail%2FPro,cri%7Ctique,"),
        "ligne inattendue : {row}"
    );
    // La cellule `fields` est citée (le CSV double donc ses guillemets) et contient
    // le `/` et le `|` **littéraux** de la valeur, sans rôle structurel.
    assert!(
        row.contains("\"\"value\"\":\"\"a%25b/c|d\"\""),
        "cellule des champs inattendue : {row}"
    );
}

#[test]
fn unknown_malformed_and_lowercase_escapes_are_refused() {
    let mut store = create(&fixture("coffre.plk"));

    let cases = [
        // Séquence inconnue.
        data_row("login", "a%41b"),
        // Séquence incomplète.
        data_row("login", "a%2"),
        // `%2F` hors d'un composant de dossier.
        data_row("login", "a%2Fb"),
        // Minuscules.
        data_row("login", "a%2fb"),
    ];

    for row in cases {
        let mut csv = header_line();
        csv.push('\n');
        csv.push_str(&row);
        csv.push('\n');
        let outcome = portability::import(&mut store, csv.as_bytes(), NOW);
        assert!(outcome.is_err(), "séquence acceptée à tort : {row}");
    }
    assert!(
        store.archive().entries.is_empty(),
        "aucune entrée ne doit avoir été créée"
    );
}

#[test]
fn nul_is_refused_on_import_and_on_export() {
    // À l'import : un octet NUL brut dans le fichier.
    let mut store = create(&fixture("coffre.plk"));
    let mut csv = header_line();
    csv.push('\n');
    csv.push_str(&data_row("login", "titre"));
    let mut bytes = csv.into_bytes();
    bytes.push(b'\0');
    assert!(portability::import(&mut store, &bytes, NOW).is_err());

    // À l'export : une valeur qui contient un NUL.
    let mut archive = Archive::new(0);
    let mut entry = Entry::new(EntryKind::Login, "titre", NOW).expect("entrée");
    entry
        .fields
        .push(Field::new("password", FieldKind::Secret, "a\0b", 0).expect("champ"));
    archive.entries.push(entry);
    assert!(
        portability::export(&archive).is_err(),
        "un contenu porteur de NUL ne peut pas être exporté"
    );
}

// ---------------------------------------------------------------------------
// I-EXPORT-ROUNDTRIP — export → import → export
// ---------------------------------------------------------------------------

#[test]
fn export_import_export_is_byte_identical() {
    let source = fixture("source.plk");
    let mut store = create(&source);

    let folder = store.add_folder("Travail", None).expect("dossier");
    let tag = store.add_tag("perso").expect("tag");

    for (index, title) in ["exemple.com", "banque", "note"].iter().enumerate() {
        let mut entry = Entry::new(EntryKind::Login, *title, NOW).expect("entrée");
        entry.subtitle = format!("user{index}@exemple.com");
        entry.folder = Some(folder);
        entry.tags.push(tag);
        entry.fields.push(
            Field::new(
                "password",
                FieldKind::Secret,
                format!("s3cr3t-{index}%"),
                u16::try_from(index).expect("indice"),
            )
            .expect("champ"),
        );
        if index == 1 {
            entry.favorite = true;
        }
        store.add_entry(entry).expect("ajout");
    }

    // Une entrée à la corbeille : elle ne doit pas être exportée.
    let trashed = store.add_entry(sample("corbeille")).expect("ajout");
    store.trash_entry(&trashed).expect("corbeille");
    store.save().expect("enregistrement");

    let first = export_bytes(&store);

    // Import dans un coffre neuf, puis ré-export.
    let target = fixture("cible.plk");
    let mut target_store = create(&target);
    let report = portability::import(&mut target_store, &first, NOW).expect("import");
    assert_eq!(report.entries, 3);
    target_store.save().expect("enregistrement");

    let second = export_bytes(&target_store);
    assert_eq!(first, second, "l'aller-retour doit être identique");
}

#[test]
fn unicode_edge_cases_round_trip() {
    let mut archive = Archive::new(0);

    // Astral (hors BMP), combinants, CJK, RTL, contrôle C0 (VT), emoji.
    let values = [
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
        "e\u{0301}combining",
        "東京タワー",
        "مرحبا",
        "tab\u{000B}vertical",
        "🔐cadenas",
    ];
    for value in values {
        let mut entry = Entry::new(EntryKind::SecureNote, value, NOW).expect("entrée");
        entry
            .fields
            .push(Field::new("note", FieldKind::Multiline, value, 0).expect("champ"));
        archive.entries.push(entry);
    }

    // Le caractère de contrôle est encodé canoniquement dans la cellule des champs.
    let rendered = text(&archive);
    assert!(
        rendered.contains("\\u000B"),
        "un C0 sans raccourci doit être encodé \\u00XX"
    );

    // Aller-retour : on importe dans un coffre neuf et on ré-exporte.
    let fixture = fixture("unicode.plk");
    let mut store = create(&fixture);
    let report = portability::import(&mut store, rendered.as_bytes(), NOW).expect("import");
    assert_eq!(report.entries, values.len());
    let reexported = text(store.archive());
    assert_eq!(rendered, reexported);
}

// ---------------------------------------------------------------------------
// I-IMPORT-STRICT — structure et valeurs
// ---------------------------------------------------------------------------

#[test]
fn missing_or_extra_columns_are_refused() {
    let mut store = create(&fixture("coffre.plk"));

    for row in [
        // Une colonne en moins.
        "E00000001,login,titre,,,,false,false,false,1700000000",
        // Une colonne en plus.
        "E00000001,login,titre,,,,,false,false,false,1700000000,1700000000",
    ] {
        let mut csv = header_line();
        csv.push('\n');
        csv.push_str(row);
        csv.push('\n');
        assert!(
            portability::import(&mut store, csv.as_bytes(), NOW).is_err(),
            "nombre de colonnes accepté à tort : {row}"
        );
    }
}

#[test]
fn invalid_values_are_refused() {
    let mut store = create(&fixture("coffre.plk"));

    let cases = [
        // Type d'entrée inconnu.
        data_row("bogus", "titre"),
        // Référence mal formée.
        "Z00000001,login,titre,,,,[],false,false,false,1700000000,1700000000".to_string(),
        // Booléen non canonique.
        "E00000001,login,titre,,,,[],yes,false,false,1700000000,1700000000".to_string(),
        // Horodatage avec zéro de tête.
        "E00000001,login,titre,,,,[],false,false,false,01700000000,1700000000".to_string(),
        // Cellule `fields` invalide (clé d'objet dans le désordre).
        "E00000001,login,titre,,,,\"[{\"\"kind\"\":\"\"text\"\",\"\"key\"\":\"\"a\"\",\"\"value\"\":\"\"v\"\",\"\"ordinal\"\":0,\"\"concealed\"\":false}]\",false,false,false,1700000000,1700000000".to_string(),
    ];

    for row in cases {
        let mut csv = header_line();
        csv.push('\n');
        csv.push_str(&row);
        csv.push('\n');
        assert!(
            portability::import(&mut store, csv.as_bytes(), NOW).is_err(),
            "valeur acceptée à tort : {row}"
        );
    }
}

#[test]
fn a_truncated_fields_structure_is_refused() {
    let mut store = create(&fixture("coffre.plk"));
    let mut csv = header_line();
    csv.push('\n');
    csv.push_str("E00000001,login,titre,,,,\"[{\"\"key\"\":\"\"a\"\"\",false,false,false,1700000000,1700000000");
    csv.push('\n');
    assert!(portability::import(&mut store, csv.as_bytes(), NOW).is_err());
}

#[test]
fn crlf_line_endings_are_accepted_and_normalized_to_lf() {
    let mut store = create(&fixture("coffre.plk"));
    let lf = format!("{}\n{}\n", header_line(), data_row("login", "titre"));
    let crlf = lf.replace('\n', "\r\n");

    let report = portability::import(&mut store, crlf.as_bytes(), NOW).expect("import CRLF");
    assert_eq!(report.entries, 1);
    // L'export, lui, reste en LF canonique : l'entrée importée ressort identique.
    assert_eq!(text(store.archive()), lf);
}

// ---------------------------------------------------------------------------
// I-IMPORT-ATOMIC — aucun effet persistant en cas d'échec
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_import_leaves_the_vault_untouched() {
    let fixture = fixture("coffre.plk");
    let mut store = create(&fixture);
    store.save().expect("enregistrement");

    let before = std::fs::read(&fixture.path).expect("lecture");

    // En-tête valide, première ligne valide, deuxième ligne invalide : la validation
    // échoue **avant** toute mutation.
    let mut csv = header_line();
    csv.push('\n');
    csv.push_str(&data_row("login", "valide"));
    csv.push('\n');
    csv.push_str(&data_row("login", "a%2Fb"));
    csv.push('\n');

    let outcome = portability::import(&mut store, csv.as_bytes(), NOW);
    assert!(outcome.is_err());
    assert!(
        store.archive().entries.is_empty(),
        "une validation refusée ne doit créer aucune entrée, même en mémoire"
    );
    assert!(
        !store.is_dirty(),
        "le magasin ne doit pas être marqué modifié"
    );

    drop(store);
    assert_eq!(
        std::fs::read(&fixture.path).expect("lecture"),
        before,
        "le fichier ne doit pas avoir bougé"
    );
}

#[test]
fn a_read_only_target_cannot_persist_an_import() {
    let fixture = fixture("coffre.plk");
    let mut store = create(&fixture);
    store.save().expect("enregistrement");
    drop(store);

    let read_only = VaultConfig {
        read_only: true,
        ..config(&fixture.state)
    };
    let mut store = VaultStore::open(&fixture.path, PASSWORD, &read_only).expect("ouverture");
    let before = std::fs::read(&fixture.path).expect("lecture");

    let mut csv = header_line();
    csv.push('\n');
    csv.push_str(&data_row("login", "titre"));
    csv.push('\n');

    // L'import réussit en mémoire…
    portability::import(&mut store, csv.as_bytes(), NOW).expect("import en mémoire");
    // … mais l'enregistrement est refusé, et le fichier reste intact.
    assert!(store.save().is_err());
    drop(store);
    assert_eq!(std::fs::read(&fixture.path).expect("lecture"), before);
}

// ---------------------------------------------------------------------------
// Coexistence et invariants du modèle
// ---------------------------------------------------------------------------

#[test]
fn import_coexists_with_existing_data_and_reuses_names() {
    // Source : une entrée dans le dossier « Travail », tag « perso ».
    let source = fixture("source.plk");
    let mut source_store = create(&source);
    let folder = source_store.add_folder("Travail", None).expect("dossier");
    let tag = source_store.add_tag("perso").expect("tag");
    let mut entry = sample("exemple.com");
    entry.folder = Some(folder);
    entry.tags.push(tag);
    source_store.add_entry(entry).expect("ajout");
    let exported = export_bytes(&source_store);

    // Cible : possède déjà le dossier et le tag, plus une entrée propre.
    let target = fixture("cible.plk");
    let mut target_store = create(&target);
    target_store.add_folder("Travail", None).expect("dossier");
    target_store.add_tag("perso").expect("tag");
    target_store.add_entry(sample("déjà là")).expect("ajout");

    let report = portability::import(&mut target_store, &exported, NOW).expect("import");
    assert_eq!(report.entries, 1);
    assert_eq!(report.folders_created, 0, "« Travail » doit être réutilisé");
    assert_eq!(report.tags_created, 0, "« perso » doit être réutilisé");
    assert_eq!(target_store.archive().entries.len(), 2);
    assert_eq!(target_store.archive().folders.len(), 1, "pas de doublon");
    assert_eq!(target_store.archive().tags.len(), 1, "pas de doublon");

    target_store.save().expect("enregistrement");
    target_store
        .archive()
        .validate()
        .expect("les invariants du modèle doivent tenir après import");

    // Le coffre cible contient bien les deux entrées, dont celle importée.
    assert!(
        target_store
            .archive()
            .entries
            .iter()
            .any(|entry| entry.title == "exemple.com")
    );
}

#[test]
fn imported_entries_respect_model_invariants() {
    let source = fixture("source.plk");
    let mut source_store = create(&source);
    let folder = source_store.add_folder("A", None).expect("dossier");
    let child = source_store.add_folder("B", Some(folder)).expect("dossier");
    let tag = source_store.add_tag("t").expect("tag");
    let mut entry = Entry::new(EntryKind::ApiKey, "clé", NOW).expect("entrée");
    entry.subtitle = "sous-titre".to_string();
    entry.folder = Some(child);
    entry.tags.push(tag);
    entry.sensitive = true;
    entry
        .fields
        .push(Field::new("secret", FieldKind::Secret, "v", 0).expect("champ"));
    source_store.add_entry(entry).expect("ajout");
    let exported = export_bytes(&source_store);

    let target = fixture("cible.plk");
    let mut target_store = create(&target);
    portability::import(&mut target_store, &exported, NOW).expect("import");

    target_store
        .archive()
        .validate()
        .expect("archive cohérente");
    let found = target_store
        .archive()
        .entries
        .iter()
        .find(|entry| entry.title == "clé")
        .expect("entrée importée");
    assert!(found.sensitive);
    assert_eq!(found.subtitle, "sous-titre");
    // Le chemin de dossier est reconstruit : deux niveaux.
    let leaf = found.folder.expect("dossier");
    let leaf_folder = target_store
        .archive()
        .folders
        .iter()
        .find(|folder| folder.id == leaf)
        .expect("dossier feuille");
    assert_eq!(leaf_folder.name, "B");
    assert!(
        leaf_folder.parent.is_some(),
        "la hiérarchie doit être recréée"
    );
}

// ---------------------------------------------------------------------------
// Robustesse : aucune entrée hostile ne doit paniquer
// ---------------------------------------------------------------------------

#[test]
fn adversarial_inputs_do_not_panic() {
    let header = header_line();

    let with = |suffix: &str| {
        let mut value = header.clone();
        value.push('\n');
        value.push_str(suffix);
        value.push('\n');
        value.into_bytes()
    };

    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0xFF, 0xFE, 0xFD, 0x00],
        header.clone().into_bytes(),
        // En-tête suivi d'une ligne vide.
        with(""),
        // Cellule `fields` tronquée.
        with("E00000001,login,x,,,,\"[{\"key\":\"a\",false,false,false,1,1"),
        // Guillemet non fermé.
        with("E00000001,login,\"non fermé"),
        // Beaucoup de virgules.
        with(",,,,,,,,,,,"),
        // Échappements partout.
        with("%25%2F%7C%00%E"),
    ];

    for case in cases {
        // Le seul contrat est de ne pas paniquer : le résultat, lui, peut être une
        // erreur ou un refus.
        let _ = portability::stage(&case, NOW);
    }
}
