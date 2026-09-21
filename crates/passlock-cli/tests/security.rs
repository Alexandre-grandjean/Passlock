//! Tests d'intégration du binaire pour la commande `security`.
//!
//! # Ce qui est éprouvé ici, et que rien d'autre n'éprouve
//!
//! La présentation est une **couche** : ces tests vérifient qu'elle n'ajoute ni fuite,
//! ni écriture, ni verdict abusif. Ils pilotent le binaire réel par
//! `std::process::Command`, sans dépendance de test.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use passlock_core::security::CivilDate;

const PASSWORD: &str = "phrase de passe du test security";

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        let path = std::env::temp_dir().join(format!("passlock-sec-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("répertoire de travail");
        Self { path }
    }

    fn vault(&self) -> String {
        self.path
            .join("coffre.plk")
            .to_str()
            .expect("chemin UTF-8")
            .to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Un coffre de test contient une vraie clé : il ne doit pas survivre au test.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&str], stdin: &[&str]) -> Output {
    use std::io::Write as _;

    let mut child = Command::new(env!("CARGO_BIN_EXE_passlock"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lancement du binaire");

    {
        let mut input = child.stdin.take().expect("entrée standard");
        for line in stdin {
            writeln!(input, "{line}").expect("écriture sur l'entrée standard");
        }
    }

    child.wait_with_output().expect("attente du binaire")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn init(test: &str) -> Scratch {
    let scratch = Scratch::new(test);
    let vault = scratch.vault();
    let output = run(&["init", "--password-stdin", &vault], &[PASSWORD, PASSWORD]);
    assert!(
        output.status.success(),
        "création échouée : {}",
        stderr_of(&output)
    );
    scratch
}

/// Ajoute une entrée et rend son identifiant.
fn add_entry(scratch: &Scratch, extra: &[&str]) -> String {
    let vault = scratch.vault();
    let mut args = vec!["entry", "add", "--password-stdin", &vault];
    args.extend_from_slice(extra);
    let output = run(&args, &[PASSWORD]);
    assert!(
        output.status.success(),
        "ajout échoué : {}",
        stderr_of(&output)
    );
    stdout_of(&output)
        .lines()
        .next()
        .expect("première ligne")
        .split(':')
        .nth(1)
        .expect("identifiant")
        .trim()
        .to_string()
}

fn set_expiry(scratch: &Scratch, id: &str, date: &str) {
    let vault = scratch.vault();
    let output = run(
        &[
            "entry",
            "expires",
            "--date",
            date,
            "--password-stdin",
            &vault,
            id,
        ],
        &[PASSWORD],
    );
    assert!(
        output.status.success(),
        "expiration échouée : {}",
        stderr_of(&output)
    );
}

fn security(scratch: &Scratch) -> Output {
    let vault = scratch.vault();
    run(&["security", "--password-stdin", &vault], &[PASSWORD])
}

/// Date UTC d'aujourd'hui, décalée de `offset` jours.
fn today_plus(offset: i64) -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    CivilDate::from_days(CivilDate::from_unix_seconds(seconds).to_days() + offset).to_string()
}

/// Liste triée des entrées d'un répertoire.
fn list_dir(dir: &std::path::Path) -> Vec<String> {
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

/// Vrai si la sortie contient un jeton de 64 caractères hexadécimaux (une empreinte).
fn contains_hex_fingerprint(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || "—,;:()•«»".contains(c))
        .any(|token| {
            token.len() == 64
                && token
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
}

const HEADINGS: [&str; 6] = [
    "Réutilisation",
    "Ancienneté",
    "Robustesse estimée",
    "Entrées faibles",
    "Absence de TOTP",
    "Expiration",
];

// ---------------------------------------------------------------------------
// Arguments, verrouillage
// ---------------------------------------------------------------------------

#[test]
fn a_missing_argument_is_refused() {
    let output = run(&["security"], &[]);
    assert!(!output.status.success(), "le coffre est requis");
    assert!(!stderr_of(&output).is_empty());
}

#[test]
fn a_wrong_password_is_refused() {
    let scratch = init("wrong-password");
    let vault = scratch.vault();
    let output = run(
        &["security", "--password-stdin", &vault],
        &["mauvais mot de passe"],
    );
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("mot de passe incorrect"));
}

// ---------------------------------------------------------------------------
// Les six indicateurs, sans fuite, sans score
// ---------------------------------------------------------------------------

#[test]
fn an_empty_vault_shows_the_six_indicators_and_no_global_score() {
    let scratch = init("empty");
    let output = security(&scratch);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    for heading in HEADINGS {
        assert!(
            stdout.contains(heading),
            "indicateur absent : {heading}\n{stdout}"
        );
    }

    let lowered = stdout.to_lowercase();
    for forbidden in ["score", "pourcent", "global", "classement"] {
        assert!(
            !lowered.contains(forbidden),
            "aucun verdict agrégé ne doit apparaître (« {forbidden} ») : {stdout}"
        );
    }
}

#[test]
fn seeded_indicators_are_shown_without_leaking_any_value() {
    // Court et peu varié : partagé **et** faible, sans être une sous-chaîne
    // apparaissant ailleurs dans la sortie.
    const SHARED: &str = "abcd1234";

    let scratch = init("seeded");

    // a : mot de passe partagé + TOTP (donc pas « absence de TOTP »).
    add_entry(
        &scratch,
        &[
            "--title",
            "avec totp",
            "--field",
            &format!("password={SHARED}"),
            "--field",
            "totp=otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
        ],
    );
    // b : même mot de passe, sans TOTP, court (donc faible et réutilisé).
    let b = add_entry(
        &scratch,
        &["--title", "court", "--field", &format!("password={SHARED}")],
    );
    // c : expiration passée.
    let c = add_entry(
        &scratch,
        &[
            "--title",
            "expiree",
            "--field",
            "password=un-mot-de-passe-long-42",
        ],
    );
    set_expiry(&scratch, &c, "1970-01-02");

    let output = security(&scratch);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);

    // Les six indicateurs, et du contenu explicable.
    for heading in HEADINGS {
        assert!(stdout.contains(heading), "{stdout}");
    }
    assert!(
        stdout.contains("2 entrées"),
        "réutilisation attendue : {stdout}"
    );
    assert!(stdout.contains("aucun TOTP détecté"), "{stdout}");
    assert!(stdout.contains("expirée"), "{stdout}");
    assert!(
        stdout.to_lowercase().contains("très faible"),
        "une estimation faible attendue : {stdout}"
    );

    // **Aucune valeur**, aucune empreinte.
    assert!(
        !stdout.contains(SHARED),
        "une valeur secrète a fuité : {stdout}"
    );
    assert!(
        !contains_hex_fingerprint(&stdout),
        "une empreinte de réutilisation a fuité : {stdout}"
    );

    // L'identifiant de l'entrée faible apparaît bien (référence, pas valeur).
    assert!(
        stdout.contains(&b),
        "l'entrée faible doit être nommée : {stdout}"
    );
    let _ = b;
}

#[test]
fn unknown_and_indeterminate_states_are_shown_as_such() {
    let scratch = init("unknown");
    // Mot de passe non-ASCII : l'estimation est **indéterminée**.
    add_entry(
        &scratch,
        &["--title", "non-ascii", "--field", "password=café!"],
    );

    let output = security(&scratch);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("indéterminée"),
        "un état indéterminé doit être affiché comme tel : {stdout}"
    );
    assert!(
        stdout.contains("aucune date"),
        "une expiration absente doit être dite « aucune date » : {stdout}"
    );
    // Jamais présenté comme valide ni comme fort.
    assert!(!stdout.contains("fort"), "{stdout}");
}

// ---------------------------------------------------------------------------
// Expiration : trois états
// ---------------------------------------------------------------------------

#[test]
fn the_three_expiry_states_are_shown() {
    let scratch = init("expiry-states");
    let expired = add_entry(&scratch, &["--title", "passee"]);
    let soon = add_entry(&scratch, &["--title", "bientot"]);
    let valid = add_entry(&scratch, &["--title", "lointaine"]);
    set_expiry(&scratch, &expired, "1970-01-02");
    set_expiry(&scratch, &soon, &today_plus(15));
    set_expiry(&scratch, &valid, "9999-12-31");

    let stdout = stdout_of(&security(&scratch));
    assert!(stdout.contains("expirée"), "{stdout}");
    assert!(stdout.contains("bientôt expirée"), "{stdout}");
    assert!(stdout.contains("valide"), "{stdout}");
}

// ---------------------------------------------------------------------------
// Lecture seule, déterminisme, corbeille
// ---------------------------------------------------------------------------

#[test]
fn the_command_is_read_only_and_deterministic() {
    let scratch = init("readonly");
    let id = add_entry(
        &scratch,
        &[
            "--title",
            "témoin",
            "--field",
            "password=un-mot-de-passe-correct",
        ],
    );
    set_expiry(&scratch, &id, "2026-06-15");

    let vault_path = PathBuf::from(scratch.vault());
    let before = std::fs::read(&vault_path).expect("lecture");
    let files_before = list_dir(&scratch.path);

    let first = security(&scratch);
    let second = security(&scratch);
    assert!(first.status.success() && second.status.success());

    // Déterministe.
    assert_eq!(stdout_of(&first), stdout_of(&second));
    // Aucune écriture.
    assert_eq!(
        std::fs::read(&vault_path).expect("lecture"),
        before,
        "le coffre a été modifié"
    );
    assert_eq!(
        list_dir(&scratch.path),
        files_before,
        "un fichier a été créé ou supprimé"
    );
}

#[test]
fn trashed_entries_are_excluded_from_the_report() {
    let scratch = init("trash");
    let kept = add_entry(&scratch, &["--title", "conservée"]);
    let removed = add_entry(&scratch, &["--title", "corbeille"]);

    let vault = scratch.vault();
    let trashed = run(
        &["entry", "rm", "--password-stdin", &vault, &removed],
        &[PASSWORD],
    );
    assert!(trashed.status.success(), "{}", stderr_of(&trashed));

    let stdout = stdout_of(&security(&scratch));
    assert!(stdout.contains("1 entrée(s) analysée(s)"), "{stdout}");
    assert!(stdout.contains(&kept), "{stdout}");
    assert!(
        !stdout.contains(&removed),
        "l'entrée à la corbeille ne doit pas apparaître : {stdout}"
    );
}
