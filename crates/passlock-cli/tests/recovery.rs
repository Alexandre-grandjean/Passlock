//! Premiers tests d'intégration du **binaire** `passlock`.
//!
//! # Pourquoi ces tests n'existaient pas, et pourquoi ils existent maintenant
//!
//! Les phases 1 à 3 testaient le moteur, jamais l'interface. C'était défendable tant
//! que l'interface ne faisait que transmettre. La phase 4 change cela : elle ajoute
//! des **chemins d'ouverture** (clé de récupération, fichier-clé), des options
//! globales qui les propagent, et des écritures de fichiers sensibles. Ces mécanismes
//! ne sont éprouvés par aucun test du cœur — ils vivent dans la ligne de commande.
//!
//! # Aucune dépendance ajoutée
//!
//! Les tests pilotent le binaire par `std::process::Command` et
//! `env!("CARGO_BIN_EXE_passlock")`. Pas de `assert_cmd`, pas de `snapbox` : une
//! dépendance de test est une dépendance, et celle-ci n'apporterait que du confort.
//!
//! # Coût
//!
//! La CLI utilise les paramètres de dérivation **livrés** (256 Mio, t=3, p=4) : c'est
//! une propriété du produit, pas un réglage de test, et ces tests la payent. Les
//! scénarios sont donc regroupés pour limiter le nombre de dérivations.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "phrase de passe du test de fumee";
const OTHER_PASSWORD: &str = "phrase de passe d'un autre coffre";

/// Répertoire de travail propre à un test, supprimé à la destruction.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        let path = std::env::temp_dir().join(format!("passlock-cli-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("répertoire de travail");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn vault(&self) -> PathBuf {
        self.join("coffre.plk")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Un coffre de test contient une vraie clé : il ne doit pas survivre au test.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Lance le binaire avec une entrée standard donnée.
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

/// Crée un coffre, en renvoyant sa racine de travail.
fn init(test: &str) -> Scratch {
    let scratch = Scratch::new(test);
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");

    let output = run(&["init", "--password-stdin", vault], &[PASSWORD, PASSWORD]);
    assert!(
        output.status.success(),
        "la création a échoué : {}",
        stderr_of(&output)
    );
    scratch
}

/// Installe une clé de récupération et rend sa forme textuelle.
fn install_recovery(scratch: &Scratch) -> String {
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");

    let output = run(&["recovery", "new", "--password-stdin", vault], &[PASSWORD]);
    assert!(
        output.status.success(),
        "l'installation a échoué : {}",
        stderr_of(&output)
    );

    // La clé est sur la sortie standard **seule** : `passlock recovery new > cle.txt`
    // doit écrire exactement la clé, sinon le mode d'emploi documenté est faux.
    stdout_of(&output).trim().to_string()
}

// ---------------------------------------------------------------------------
// Clé de récupération
// ---------------------------------------------------------------------------

#[test]
fn the_recovery_key_is_only_on_stdout_and_the_report_on_stderr() {
    let scratch = init("recovery-streams");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");

    let output = run(&["recovery", "new", "--password-stdin", vault], &[PASSWORD]);
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);

    let key = stdout.trim();
    assert_eq!(
        stdout.lines().count(),
        1,
        "la sortie standard ne doit porter que la clé, or : {stdout:?}"
    );
    assert_eq!(
        key.chars().filter(|c| *c != '-').count(),
        60,
        "la clé doit faire 60 caractères hors séparateurs"
    );
    assert!(
        stderr.contains("qu'une fois"),
        "le mode d'emploi doit être sur la sortie d'erreur"
    );
    assert!(
        !stderr.contains(key),
        "la clé ne doit pas être recopiée sur la sortie d'erreur"
    );
}

#[test]
fn the_recovery_key_opens_the_vault_for_any_command() {
    let scratch = init("recovery-opens");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let key = install_recovery(&scratch);

    let output = run(&["--recovery-key-stdin", "entry", "list", vault], &[&key]);
    assert!(
        output.status.success(),
        "l'ouverture par clé de récupération a échoué : {}",
        stderr_of(&output)
    );

    // `recovery test` fait la même chose, mais le dit.
    let tested = run(&["recovery", "test", "--password-stdin", vault], &[&key]);
    assert!(tested.status.success());
    assert!(stdout_of(&tested).contains("valide"));
}

#[test]
fn a_mistyped_key_is_refused_by_its_checksum_before_any_derivation() {
    let scratch = init("recovery-checksum");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let key = install_recovery(&scratch);

    // Une seule substitution, en conservant la longueur : le total de contrôle doit
    // la refuser **avant** toute tentative de déverrouillage.
    let mut characters: Vec<char> = key.chars().collect();
    let position = characters
        .iter()
        .position(char::is_ascii_alphanumeric)
        .expect("caractère");
    characters[position] = if characters[position] == 'A' {
        'B'
    } else {
        'A'
    };
    let mistyped: String = characters.into_iter().collect();

    let output = run(
        &["recovery", "test", "--password-stdin", vault],
        &[&mistyped],
    );
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("total de contrôle"),
        "le refus doit nommer la cause : {}",
        stderr_of(&output)
    );
}

#[test]
fn a_foreign_recovery_key_does_not_open_the_vault() {
    let scratch = init("recovery-foreign");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let _key = install_recovery(&scratch);

    // Une clé valide, mais d'un autre coffre : elle est bien formée, et n'ouvre rien.
    let other = Scratch::new("recovery-foreign-other");
    let other_vault = other.join("autre.plk");
    let other_vault = other_vault.to_str().expect("chemin UTF-8");
    assert!(
        run(
            &["init", "--password-stdin", other_vault],
            &[OTHER_PASSWORD, OTHER_PASSWORD]
        )
        .status
        .success()
    );
    let other_key = {
        let output = run(
            &["recovery", "new", "--password-stdin", other_vault],
            &[OTHER_PASSWORD],
        );
        assert!(output.status.success());
        stdout_of(&output).trim().to_string()
    };

    let output = run(
        &["recovery", "test", "--password-stdin", vault],
        &[&other_key],
    );
    assert!(
        !output.status.success(),
        "la clé d'un autre coffre ne doit pas ouvrir celui-ci"
    );
}

#[test]
fn installing_a_slot_requires_the_master_password() {
    // La clé de récupération ne doit **pas** permettre d'installer ou de révoquer un
    // slot : sinon elle deviendrait un moyen de modifier les chemins d'accès, et le
    // mot de passe maître perdrait sa primauté.
    let scratch = init("recovery-reauth");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let key = install_recovery(&scratch);

    let output = run(&["recovery", "new", "--password-stdin", vault], &[&key]);
    assert!(
        !output.status.success(),
        "la clé de récupération ne doit pas servir de mot de passe maître"
    );
    assert!(stderr_of(&output).contains("mot de passe incorrect"));
}

#[test]
fn revoking_a_slot_requires_the_matching_confirmation() {
    let scratch = init("recovery-confirm");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let _key = install_recovery(&scratch);

    let identifier = {
        let output = run(&["info", vault], &[]);
        let line = stdout_of(&output);
        let first = line.lines().next().expect("première ligne");
        first
            .split(':')
            .nth(1)
            .expect("identifiant")
            .trim()
            .to_string()
    };

    let refused = run(
        &[
            "recovery",
            "remove",
            "--password-stdin",
            vault,
            "--confirm",
            "mauvais",
        ],
        &[PASSWORD],
    );
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("confirmation"));

    let accepted = run(
        &[
            "recovery",
            "remove",
            "--password-stdin",
            vault,
            "--confirm",
            &identifier,
        ],
        &[PASSWORD],
    );
    assert!(accepted.status.success(), "{}", stderr_of(&accepted));

    // Et la clé ne doit plus ouvrir.
    let after = run(
        &["recovery", "test", "--password-stdin", vault],
        &[PASSWORD],
    );
    assert!(
        !after.status.success(),
        "après révocation, `recovery test` ne doit plus trouver de slot"
    );
}

// ---------------------------------------------------------------------------
// Fichier-clé
// ---------------------------------------------------------------------------

#[test]
fn a_key_file_is_created_private_and_opens_the_vault() {
    let scratch = init("keyfile");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let key_path = scratch.join("cle.bin");
    let key_path_text = key_path.to_str().expect("chemin UTF-8");

    let output = run(
        &[
            "keyfile",
            "new",
            "--password-stdin",
            vault,
            "--key-file",
            key_path_text,
        ],
        &[PASSWORD],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(
        std::fs::metadata(&key_path).expect("métadonnées").len(),
        32,
        "un fichier-clé fait exactement 32 octets"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&key_path)
                .expect("métadonnées")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "le fichier-clé doit être créé en 0600"
        );
    }

    let tested = run(
        &["keyfile", "test", vault, "--key-file", key_path_text],
        &[],
    );
    assert!(tested.status.success(), "{}", stderr_of(&tested));
}

#[test]
fn a_key_file_is_never_overwritten() {
    let scratch = init("keyfile-clobber");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let key_path = scratch.join("cle.bin");
    let key_path_text = key_path.to_str().expect("chemin UTF-8");

    // Un fichier-clé préexistant peut être le seul exemplaire d'une clé installée
    // ailleurs : l'écraser serait une perte définitive.
    std::fs::write(&key_path, b"contenu preexistant").expect("écriture");

    let output = run(
        &[
            "keyfile",
            "new",
            "--password-stdin",
            vault,
            "--key-file",
            key_path_text,
        ],
        &[PASSWORD],
    );
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(&key_path).expect("lecture"),
        b"contenu preexistant",
        "le fichier préexistant ne doit pas avoir été modifié"
    );
}

#[test]
fn a_truncated_key_file_is_refused() {
    let scratch = init("keyfile-truncated");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");
    let short = scratch.join("court.bin");
    std::fs::write(&short, b"trop court").expect("écriture");

    let output = run(
        &[
            "keyfile",
            "test",
            vault,
            "--key-file",
            short.to_str().expect("chemin UTF-8"),
        ],
        &[],
    );
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("32 octets"),
        "le refus doit dire ce qui est attendu : {}",
        stderr_of(&output)
    );
}

#[test]
fn a_vault_without_recovery_slot_reports_it_explicitly() {
    // Un coffre neuf n'a qu'un slot : `recovery test` doit le dire, et non échouer
    // par un « mot de passe incorrect » qui enverrait l'utilisateur sur une fausse
    // piste.
    let scratch = init("no-recovery-slot");
    let vault = scratch.vault();
    let vault = vault.to_str().expect("chemin UTF-8");

    let key = {
        // On fabrique une clé bien formée sans l'installer.
        let scratch2 = init("no-recovery-slot-source");
        let other = scratch2.vault();
        let other = other.to_str().expect("chemin UTF-8");
        let output = run(&["recovery", "new", "--password-stdin", other], &[PASSWORD]);
        assert!(output.status.success());
        stdout_of(&output).trim().to_string()
    };

    let output = run(&["recovery", "test", "--password-stdin", vault], &[&key]);
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("aucun slot de clé de récupération"),
        "le message doit désigner l'absence de slot : {}",
        stderr_of(&output)
    );
}

/// Le chemin du binaire existe : garde-fou contre un test qui ne teste rien.
#[test]
fn the_binary_is_available() {
    let path = Path::new(env!("CARGO_BIN_EXE_passlock"));
    assert!(path.is_file(), "binaire introuvable : {path:?}");
}
