//! Interface en ligne de commande de Passlock.
//!
//! # Ce que cette CLI est, et ce qu'elle n'est pas
//!
//! C'est un outil **headless** qui expose le moteur cryptographique sans aucune
//! interface graphique. Elle sert trois objectifs :
//!
//! 1. rendre la phase 1 (moteur crypto et format de coffre) réellement
//!    utilisable et vérifiable par un humain ;
//! 2. servir de harnais de test d'intégration sur le chemin réel, avec de vrais
//!    fichiers et de vrais verrous ;
//! 3. permettre l'administration d'un coffre sur une machine sans environnement
//!    graphique — un serveur, une session de dépannage, une clé USB.
//!
//! Elle ne gère aucune entrée du coffre : le modèle de données arrive en phase 2.
//! À ce stade, un coffre contient son header, ses slots de clé et un payload vide.
//!
//! # Ce que cette CLI ne fait pas, volontairement
//!
//! * Elle **ne stocke aucune trace** : pas d'historique de commandes, pas de
//!   fichier de configuration propre.
//! * Elle accepte un mot de passe par l'entrée standard (`--password-stdin`) pour
//!   l'usage scripté. C'est un compromis assumé : un mot de passe passé en
//!   argument de ligne de commande serait visible dans la liste des processus
//!   (`ps`) et dans l'historique du shell. **Aucune option de ce type n'existe**,
//!   et il ne faut pas en ajouter.

mod generate;
mod totp;

use std::io::{self, Read as _, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Arg, ArgAction, Command};

use passlock_core::container::ParsedVault;
use passlock_core::error::Error;
use passlock_core::kdf::{self, KdfParams};
use passlock_core::memory::lock_status_warning;
use passlock_core::model::{Entry, EntryId, EntryKind, Field, FieldKind};
use passlock_core::query::{SearchQuery, SortOrder, search};
use passlock_core::secret::SecretVec;
use passlock_core::store::VaultStore;
use passlock_core::vault::{Vault, VaultConfig};

use passlock_platform::tty::EchoGuard;
use zeroize::Zeroize;

fn main() -> ExitCode {
    // Le durcissement est appliqué explicitement ici, au point d'entrée du binaire,
    // et non à l'initialisation de la bibliothèque : une bibliothèque ne doit pas
    // modifier l'état global du processus hôte à son insu.
    let hardening = passlock_platform::process::harden_process();

    match run(hardening) {
        Ok(()) => ExitCode::SUCCESS,

        Err(CliError(message)) => {
            eprintln!("erreur : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Erreur de la couche CLI : un message prêt à afficher.
///
/// Les erreurs du moteur sont converties en texte à cette frontière. Aucune ne
/// contient de secret (voir `passlock_core::error`), ce qui permet de les afficher
/// sans précaution particulière.
pub(crate) struct CliError(pub(crate) String);

impl From<Error> for CliError {
    fn from(value: Error) -> Self {
        Self(value.to_string())
    }
}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self(format!("entrée/sortie : {value}"))
    }
}

pub(crate) type CliResult = Result<(), CliError>;

/// Paramètres communs extraits de la ligne de commande.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GlobalOptions {
    /// Lit les mots de passe sur l'entrée standard plutôt que de les demander.
    pub(crate) password_stdin: bool,
    /// Mesures de durcissement du processus, à signaler si elles sont incomplètes.
    pub(crate) hardening: passlock_platform::process::ProcessHardening,
}

/// Construit la configuration d'ouverture à partir des options globales.
///
/// Les paramètres de dérivation valent [`KdfParams::standard`] : c'est le profil
/// **durci**. Ils ne sont utilisés qu'à la **création** — à l'ouverture, les
/// paramètres sont lus dans le fichier et jamais pris dans une constante du code,
/// ce qui permet de durcir les défauts sans rendre illisible un coffre existant.
pub(crate) fn config_from(matches: &clap::ArgMatches) -> VaultConfig {
    VaultConfig {
        params: KdfParams::standard(),
        read_only: matches.get_flag("read-only"),
        state_dir: matches.get_one::<String>("state-dir").map(PathBuf::from),
    }
}

/// Aiguille vers la sous-commande demandée.
fn run(hardening: passlock_platform::process::ProcessHardening) -> CliResult {
    let matches = build_command().get_matches();
    let options = GlobalOptions {
        password_stdin: matches.get_flag("password-stdin"),
        hardening,
    };
    let config = config_from(&matches);

    match matches.subcommand() {
        Some(("init", sub)) => cmd_init(sub, options, &config),
        Some(("info", sub)) => cmd_info(sub),
        Some(("verify", sub)) => cmd_verify(sub, options, &config),
        Some(("change-password", sub)) => cmd_change_password(sub, options, &config),
        Some(("calibrate", sub)) => cmd_calibrate(sub, options),
        Some(("entry", sub)) => cmd_entry(sub, options, &config),
        Some(("search", sub)) => cmd_search(sub, options, &config),
        Some(("history", sub)) => cmd_history(sub, options, &config),
        Some(("generate", sub)) => generate::cmd_generate(sub),
        Some(("passphrase", sub)) => generate::cmd_passphrase(sub),
        Some(("secret", sub)) => generate::cmd_secret(sub),
        Some(("totp", sub)) => totp::cmd_totp(sub, options, &config),
        _ => Err(CliError(
            "aucune sous-commande : utilisez --help".to_string(),
        )),
    }
}

/// Crée un coffre neuf.
fn cmd_init(matches: &clap::ArgMatches, options: GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    report_hardening(options.hardening);

    let password = read_password("Mot de passe maître : ", options.password_stdin)?;
    let confirmation = read_password("Confirmez : ", options.password_stdin)?;

    if password.expose() != confirmation.expose() {
        // Les deux saisies diffèrent : on refuse plutôt que de créer un coffre dont
        // l'utilisateur ne connaît pas le mot de passe.
        return Err(CliError(
            "les deux saisies diffèrent ; aucun coffre n'a été créé".to_string(),
        ));
    }

    let vault = Vault::create(&path, password.expose(), config)?;
    report_diagnostics(&vault);

    println!("Coffre créé : {}", path.display());
    println!("Identifiant : {}", hex(&vault.header().vault_id));
    println!(
        "Dérivation : Argon2id, {} Kio, {} itérations, {} voies",
        config.params.m_cost_kib(),
        config.params.t_cost(),
        config.params.p_cost()
    );
    println!(
        "\nSauvegardez ce fichier. Sans lui et sans son mot de passe, son contenu est \
         définitivement inaccessible : il n'existe aucun mécanisme de récupération à \
         distance, et c'est délibéré."
    );
    Ok(())
}

/// Affiche les métadonnées publiques, sans mot de passe.
fn cmd_info(matches: &clap::ArgMatches) -> CliResult {
    let path = vault_path(matches)?;
    let bytes = std::fs::read(&path)?;
    let parsed = ParsedVault::parse(&bytes)?;
    print_header(&parsed);
    Ok(())
}

/// Ouvre le coffre et vérifie son authenticité de bout en bout.
fn cmd_verify(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    report_hardening(options.hardening);

    let password = read_password("Mot de passe maître : ", options.password_stdin)?;
    let vault = Vault::open(&path, password.expose(), config)?;
    report_diagnostics(&vault);

    println!("Coffre vérifié : authentification et déchiffrement réussis.");
    println!("Génération : {}", vault.generation());
    println!("Contenu applicatif : {} octet(s)", vault.body().len());
    Ok(())
}

/// Change le mot de passe maître.
fn cmd_change_password(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    report_hardening(options.hardening);

    let current = read_password("Mot de passe actuel : ", options.password_stdin)?;
    let new = read_password("Nouveau mot de passe : ", options.password_stdin)?;
    let confirmation = read_password("Confirmez : ", options.password_stdin)?;

    if new.expose() != confirmation.expose() {
        return Err(CliError(
            "les deux saisies du nouveau mot de passe diffèrent ; rien n'a été modifié".to_string(),
        ));
    }

    let mut vault = Vault::open(&path, current.expose(), config)?;
    vault.change_password(current.expose(), new.expose(), KdfParams::standard())?;
    report_diagnostics(&vault);

    println!("Mot de passe maître modifié.");
    println!("Génération : {}", vault.generation());
    println!(
        "\nRappel : le contenu du coffre n'a pas été rechiffré sous une nouvelle clé. La clé \
         de données est inchangée et a seulement été ré-enveloppée. Les sauvegardes \
         antérieures restent donc lisibles avec l'ancien mot de passe."
    );
    Ok(())
}

/// Mesure le coût des profils de dérivation sur cette machine.
fn cmd_calibrate(matches: &clap::ArgMatches, options: GlobalOptions) -> CliResult {
    let budget = match matches.get_one::<String>("budget") {
        Some(value) => value
            .parse::<f64>()
            .map_err(|_| CliError(format!("budget invalide : « {value} »")))?,
        None => DEFAULT_BUDGET_SECONDS,
    };

    if !budget.is_finite() || budget <= 0.0 {
        return Err(CliError(
            "le budget doit être un nombre de secondes strictement positif".to_string(),
        ));
    }

    let password = read_password("Mot de passe de mesure : ", options.password_stdin)?;
    println!("Mesure en cours, chaque profil est dérivé une fois…\n");

    let report = kdf::calibrate(
        password.expose(),
        std::time::Duration::from_secs_f64(budget),
    )?;

    print_calibration(&report, budget);
    Ok(())
}

/// Budget de latence visé par défaut, en secondes.
///
/// Une seconde est un ordre de grandeur confortable pour un déverrouillage manuel :
/// assez court pour ne pas gêner, assez long pour que le profil retenu soit
/// nettement au-dessus des minima destinés à une authentification serveur.
const DEFAULT_BUDGET_SECONDS: f64 = 1.0;

/// Affiche le rapport de calibration.
fn print_calibration(report: &kdf::CalibrationReport, budget: f64) {
    println!(
        "  {:>9}  {:>3}  {:>3}  {:>10}",
        "MÉMOIRE", "t", "p", "MESURÉ"
    );
    for measurement in &report.measurements {
        let marker = if measurement.params == report.selected.params {
            "  ← retenu"
        } else {
            ""
        };
        println!(
            "  {:>7} Kio  {:>3}  {:>3}  {:>8.2} s{}",
            measurement.params.m_cost_kib(),
            measurement.params.t_cost(),
            measurement.params.p_cost(),
            measurement.observed.as_secs_f64(),
            marker
        );
    }

    if report.budget_exceeded {
        println!(
            "\nAttention : au moins un profil dépasse le budget de {budget:.2} s et n'a pas été \
             mesuré."
        );
    }

    println!(
        "\nProfil retenu : {} Kio, t={}, p={}, mesuré en {:.2} s.",
        report.selected.params.m_cost_kib(),
        report.selected.params.t_cost(),
        report.selected.params.p_cost(),
        report.selected.observed.as_secs_f64()
    );
    println!(
        "\nCette mesure vaut pour CETTE machine, à cet instant, dans cette version du binaire \
         (un binaire de développement non optimisé est environ vingt fois plus lent). Elle ne \
         borne en rien le coût pour un attaquant disposant de matériel dédié : c'est \
         précisément l'effet recherché, mais cela signifie que « calibré » ne veut pas dire \
         « suffisant »."
    );
}

/// Construit la description de la ligne de commande.
///
/// La longueur est inhérente : la fonction énumère chaque sous-commande et chaque
/// option à plat, ce qui est la forme la plus lisible pour une description d'interface.
/// La découper en fabriques par sous-commande masquerait la structure d'ensemble sans
/// rien simplifier.
#[allow(clippy::too_many_lines)]
fn build_command() -> Command {
    Command::new("passlock")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Gestionnaire de secrets local. Fonctionne hors ligne, sans compte et sans serveur.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("read-only")
                .long("read-only")
                .help("Ouvre le coffre sans autoriser aucune écriture")
                .global(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("password-stdin")
                .long("password-stdin")
                .help("Lit les mots de passe sur l'entrée standard au lieu de les demander")
                .global(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("RÉPERTOIRE")
                .global(true)
                .help(
                    "Emplacement de la sentinelle anti-rollback (par défaut : répertoire \
                     de configuration de l'utilisateur)",
                ),
        )
        .subcommand(
            Command::new("init")
                .about("Crée un coffre neuf")
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("info")
                .about("Affiche les métadonnées publiques d'un coffre, sans le mot de passe")
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("verify")
                .about("Ouvre le coffre et vérifie son authenticité de bout en bout")
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("change-password")
                .about("Change le mot de passe maître sans rechiffrer le contenu")
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("entry")
                .about("Crée, liste, affiche, déplace à la corbeille ou supprime une entrée")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("add")
                        .about("Ajoute une entrée")
                        .arg(vault_argument())
                        .arg(
                            Arg::new("type")
                                .long("type")
                                .value_name("TYPE")
                                .default_value("login")
                                .help("login, note, card, identity, apikey, sshkey, wifi, passkey, custom"),
                        )
                        .arg(Arg::new("title").long("title").value_name("TITRE").required(true))
                        .arg(Arg::new("subtitle").long("subtitle").value_name("SOUS-TITRE"))
                        .arg(
                            Arg::new("field")
                                .long("field")
                                .value_name("CLE=VALEUR")
                                .action(ArgAction::Append)
                                .help("Répétable. Les clés « password », « pin » et « totp » sont masquées par défaut."),
                        )
                        .arg(Arg::new("favorite").long("favorite").action(ArgAction::SetTrue))
                        .arg(
                            Arg::new("sensitive")
                                .long("sensitive")
                                .action(ArgAction::SetTrue)
                                .help("Exigera une réauthentification avant toute révélation"),
                        ),
                )
                .subcommand(
                    Command::new("list")
                        .about("Liste les entrées")
                        .arg(vault_argument())
                        .arg(
                            Arg::new("trash")
                                .long("trash")
                                .action(ArgAction::SetTrue)
                                .help("N'affiche que la corbeille"),
                        )
                        .arg(
                            Arg::new("archived")
                                .long("archived")
                                .action(ArgAction::SetTrue)
                                .help("N'affiche que les entrées archivées"),
                        )
                        .arg(
                            Arg::new("all")
                                .long("all")
                                .action(ArgAction::SetTrue)
                                .help("Affiche tout, corbeille et archives comprises"),
                        ),
                )
                .subcommand(
                    Command::new("show")
                        .about("Affiche une entrée")
                        .arg(vault_argument())
                        .arg(Arg::new("id").value_name("ID").required(true))
                        .arg(
                            Arg::new("reveal")
                                .long("reveal")
                                .action(ArgAction::SetTrue)
                                .help("Affiche les valeurs masquées (par défaut, elles sont remplacées)"),
                        ),
                )
                .subcommand(
                    Command::new("rm")
                        .about("Déplace une entrée à la corbeille")
                        .arg(vault_argument())
                        .arg(Arg::new("id").value_name("ID").required(true)),
                )
                .subcommand(
                    Command::new("restore")
                        .about("Restaure une entrée depuis la corbeille")
                        .arg(vault_argument())
                        .arg(Arg::new("id").value_name("ID").required(true)),
                )
                .subcommand(totp::entry_totp_command())
                .subcommand(totp::entry_gen_command())
                .subcommand(
                    Command::new("purge")
                        .about("Supprime définitivement une entrée, historique compris")
                        .arg(vault_argument())
                        .arg(Arg::new("id").value_name("ID").required(true))
                        .arg(
                            Arg::new("confirm")
                                .long("confirm")
                                .value_name("ID")
                                .required(true)
                                .help("Recopiez l'identifiant : la suppression est irréversible"),
                        ),
                ),
        )
        .subcommand(
            Command::new("search")
                .about("Recherche dans le coffre (sous-chaîne littérale, insensible à la casse et aux accents)")
                .arg(vault_argument())
                .arg(Arg::new("text").value_name("TEXTE").required(true))
                .arg(Arg::new("limit").long("limit").value_name("N"))
                .arg(
                    Arg::new("sort")
                        .long("sort")
                        .value_name("ORDRE")
                        .default_value("relevance")
                        .help("relevance, title, created, updated"),
                )
                .arg(Arg::new("all").long("all").action(ArgAction::SetTrue).help("Inclut archives et corbeille")),
        )
        .subcommand(
            Command::new("history")
                .about("Affiche l'historique d'une entrée")
                .arg(vault_argument())
                .arg(Arg::new("id").value_name("ID").required(true))
                .arg(
                    Arg::new("purge")
                        .long("purge")
                        .action(ArgAction::SetTrue)
                        .help("Supprime définitivement l'historique de cette entrée"),
                ),
        )
        .subcommand(generate::generate_command())
        .subcommand(generate::passphrase_command())
        .subcommand(generate::secret_command())
        .subcommand(totp::command())
        .subcommand(
            Command::new("calibrate")
                .about("Mesure le coût des profils de dérivation sur cette machine")
                .arg(
                    Arg::new("budget")
                        .long("budget")
                        .value_name("SECONDES")
                        .help("Latence de déverrouillage visée (défaut : 1.0)"),
                ),
        )
}

pub(crate) fn vault_argument() -> Arg {
    Arg::new("vault")
        .value_name("COFFRE")
        .required(true)
        .help("Chemin du fichier de coffre")
}

pub(crate) fn vault_path(matches: &clap::ArgMatches) -> Result<PathBuf, CliError> {
    matches
        .get_one::<String>("vault")
        .map(PathBuf::from)
        .ok_or_else(|| CliError("chemin de coffre manquant".to_string()))
}

/// Lit un mot de passe, soit sur l'entrée standard, soit de façon interactive.
///
/// ## Précautions
///
/// * En mode interactif, l'écho du terminal est désactivé : sans cela le mot de
///   passe maître se retrouverait dans le tampon défilant du terminal et dans tout
///   enregistrement de session, c'est-à-dire dans un canal que l'application ne
///   contrôle pas du tout.
/// * En mode redirigé, aucune invite n'est affichée : une invite écrite dans un
///   tube polluerait les données que l'appelant attend sur la sortie.
/// * Le tampon intermédiaire est effacé après usage. Cela ne garantit pas qu'aucune
///   copie n'existe (voir la documentation de `secret.rs`), mais évite d'en laisser
///   une volontairement.
pub(crate) fn read_password(invitation: &str, from_stdin: bool) -> Result<SecretVec, CliError> {
    use std::io::BufRead as _;

    // La capacité est réservée **une fois pour toutes**, à la taille maximale
    // acceptée plus la fin de ligne.
    //
    // NOTE DE CORRECTION. Une version antérieure partait d'une `String::new()` :
    // `read_line` réallouait alors le tampon au fil de la croissance, laissant
    // derrière lui des copies partielles du mot de passe dans des blocs de tas
    // recyclés sans nettoyage — copies que le `zeroize` final ne pouvait pas
    // atteindre. Réserver la capacité supprime ces réallocations.
    let capacity = kdf::MAX_PASSWORD_LEN + 2;
    let mut line = String::with_capacity(capacity);

    if !from_stdin && !passlock_platform::tty::stdin_is_terminal() {
        return Err(CliError(
            "l'entrée standard n'est pas un terminal : utilisez --password-stdin pour \
             lire les mots de passe depuis un tube"
                .to_string(),
        ));
    }

    let guard = if from_stdin {
        None
    } else {
        passlock_platform::tty::prompt(invitation)?;
        Some(EchoGuard::disable()?)
    };

    // La lecture est bornée : sans cette limite, un tube sans fin de ligne
    // ferait croître le tampon jusqu'à l'épuisement de la mémoire. On lit un octet
    // de plus que la taille admise afin de pouvoir distinguer « exactement à la
    // limite » de « dépasse la limite ».
    let limit = u64::try_from(capacity).unwrap_or(u64::MAX);
    let read = io::stdin().lock().take(limit).read_line(&mut line);

    drop(guard);
    if !from_stdin {
        // Le terminal n'a pas affiché le retour chariot de la validation.
        let _ = writeln!(io::stderr());
    }
    read?;

    let trimmed = line.trim_end_matches(['\n', '\r']);
    let oversize = trimmed.len() > kdf::MAX_PASSWORD_LEN;
    let secret = SecretVec::from_slice(trimmed.as_bytes());
    line.zeroize();

    if oversize {
        return Err(CliError(format!(
            "mot de passe au-delà de la longueur maximale acceptée ({} octets)",
            kdf::MAX_PASSWORD_LEN
        )));
    }
    if secret.is_empty() {
        return Err(CliError("mot de passe vide refusé".to_string()));
    }
    Ok(secret)
}

/// Affiche les mesures de durcissement non appliquées.
///
/// On les annonce plutôt que de les taire : une protection silencieusement absente
/// est pire qu'une protection absente annoncée, parce qu'elle fausse le jugement de
/// l'utilisateur sur son propre risque.
pub(crate) fn report_hardening(hardening: passlock_platform::process::ProcessHardening) {
    use passlock_platform::process::HardeningOutcome;

    if matches!(hardening.core_dumps_disabled, HardeningOutcome::Applied)
        && matches!(hardening.ptrace_restricted, HardeningOutcome::Applied)
    {
        return;
    }

    eprintln!("Avertissements de durcissement du processus :");
    match hardening.core_dumps_disabled {
        HardeningOutcome::Applied => {}
        HardeningOutcome::Unsupported => eprintln!(
            "  - vidages mémoire : non supporté sur cette plateforme. Un plantage pendant \
             que le coffre est déverrouillé peut écrire des secrets dans un fichier de vidage."
        ),
        HardeningOutcome::Failed => eprintln!(
            "  - vidages mémoire : l'application n'a pas pu les désactiver. Un plantage \
             pendant que le coffre est déverrouillé peut écrire des secrets dans un fichier \
             de vidage."
        ),
    }
    match hardening.ptrace_restricted {
        HardeningOutcome::Applied => {}
        HardeningOutcome::Unsupported => eprintln!(
            "  - lecture de mémoire : non supporté sur cette plateforme. Un autre processus \
             du même utilisateur peut lire l'espace mémoire de celui-ci."
        ),
        HardeningOutcome::Failed => eprintln!(
            "  - lecture de mémoire : l'application n'a pas pu restreindre l'accès à son \
             espace d'adressage."
        ),
    }
}

/// Affiche les observations faites à l'ouverture.
fn report_diagnostics(vault: &Vault) {
    let diagnostics = vault.diagnostics();

    if diagnostics.permissions_corrected {
        eprintln!(
            "Note : les permissions du fichier étaient trop ouvertes et ont été ramenées à \
             un accès réservé au propriétaire."
        );
    }

    if diagnostics.params_below_recommendation {
        eprintln!(
            "Avertissement : ce coffre utilise des paramètres de dérivation plus faibles que \
             le profil par défaut actuel. Il reste ouvrable, mais un attaquant qui \
             obtiendrait le fichier le casserait plus vite. `change-password` permet de les \
             durcir."
        );
    }

    match diagnostics.rollback {
        passlock_core::rollback::RollbackCheck::Rollback { known, found } => {
            eprintln!(
                "AVERTISSEMENT — RETOUR EN ARRIÈRE DÉTECTÉ : le coffre présenté est à la \
                 génération {found}, alors que le dernier état connu était {known}."
            );
            eprintln!(
                "  Causes possibles : restauration d'une sauvegarde antérieure, OU \
                 substitution du fichier par une version plus ancienne."
            );
            eprintln!(
                "  Conséquences réelles : des entrées supprimées peuvent réapparaître, et un \
                 ancien mot de passe maître peut redevenir valide."
            );
        }
        passlock_core::rollback::RollbackCheck::NoSentinel => {
            eprintln!(
                "Note : aucune sentinelle de référence n'existe pour ce coffre (première \
                 ouverture sur cette machine, ou sentinelle effacée). La détection partielle \
                 de retour en arrière est donc inactive ; une référence vient d'être établie."
            );
        }
        passlock_core::rollback::RollbackCheck::Consistent => {}
    }

    if diagnostics.sentinel_corrupted {
        eprintln!(
            "Note : une sentinelle existait mais était inutilisable. Elle a été reconstruite."
        );
    }

    if diagnostics.sentinel_write_failed {
        eprintln!(
            "Note : la sentinelle anti-retour-en-arrière n'a pas pu être enregistrée. Le \
             coffre, lui, a bien été écrit."
        );
    }

    if let Some(message) = lock_status_warning_check() {
        eprintln!("Note : {message}");
    }
}

/// Vérifie l'état du verrouillage mémoire sur un buffer représentatif.
///
/// Le message produit ne dépend pas de la taille du buffer : il porte sur la
/// capacité du système à verrouiller des pages, pas sur une allocation précise.
fn lock_status_warning_check() -> Option<&'static str> {
    let probe = passlock_platform::memory::LockedBuffer::new(4096);
    lock_status_warning(&probe)
}

/// Affiche le header d'un coffre sans le déverrouiller.
fn print_header(parsed: &ParsedVault<'_>) {
    let header = &parsed.header;
    println!("Identifiant      : {}", hex(&header.vault_id));
    println!("Créé le          : {}", format_timestamp(header.created_at));
    println!("Slots de clé     : {}", header.slots.len());
    println!(
        "Payload chiffré  : {} octet(s)",
        parsed.payload_ciphertext.len()
    );
    println!();

    for slot in &header.slots {
        println!(
            "  Slot {} — {}",
            slot.id,
            match slot.label {
                passlock_core::header::SlotLabel::Master => "mot de passe maître",
                passlock_core::header::SlotLabel::Recovery => "clé de récupération",
                passlock_core::header::SlotLabel::Hardware => "clé matérielle",
            }
        );
        println!(
            "    Argon2id : {} Kio, {} itération(s), {} voie(s)",
            slot.params.m_cost_kib(),
            slot.params.t_cost(),
            slot.params.p_cost()
        );
        if slot.params.is_below_recommendation() {
            println!("    ⚠ paramètres plus faibles que le profil par défaut actuel");
        }
    }

    println!(
        "\nCes informations sont lisibles sans le mot de passe : elles sont nécessaires au \
         déchiffrement."
    );
    println!(
        "ATTENTION : leur authenticité n'est PAS vérifiée ici. Ces champs sont bien couverts \
         par le tag du contenu, mais contrôler ce tag exige la clé. Un fichier modifié peut \
         donc afficher une date ou des paramètres différents de ceux d'origine — la \
         falsification ne sera détectée qu'au déverrouillage (commande `verify`)."
    );
}

/// Encode des octets en hexadécimal minuscule.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` dans une `String` ne peut pas échouer ; l'écriture directe évite
        // d'allouer une chaîne intermédiaire par octet.
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

/// Formate un horodatage Unix en date lisible, sans dépendance de calendrier.
///
/// ## Pourquoi ce calcul est fait à la main
///
/// Une crate de dates (chrono, time) apporte un fuseau horaire, une base de données
/// de règles et un parseur — plusieurs milliers de lignes pour afficher une date.
/// Le calcul ci-dessous couvre les années 1970–2100 en une vingtaine de lignes et
/// n'introduit aucune dépendance.
///
/// Il n'est **pas** utilisé pour une décision de sécurité : seul l'affichage
/// l'emploie.
fn format_timestamp(seconds: u64) -> String {
    const SECONDS_PER_DAY: u64 = 86_400;
    const DAYS_PER_ERA: u64 = 146_097; // 400 ans
    const DAYS_PER_YEAR: u64 = 365;

    let days = seconds / SECONDS_PER_DAY;
    let remainder = seconds % SECONDS_PER_DAY;
    let hour = remainder / 3_600;
    let minute = (remainder % 3_600) / 60;
    let second = remainder % 60;

    // Algorithme de Howard Hinnant : conversion jours → (année, mois, jour) dans le
    // calendrier grégorien proleptique, valable pour toute date positive.
    let shifted = days + 719_468;
    let era = shifted / DAYS_PER_ERA;
    let day_of_era = shifted % DAYS_PER_ERA;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / DAYS_PER_YEAR;
    let year = year_of_era + era * 400;
    let day_of_year =
        day_of_era - (DAYS_PER_YEAR * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

// ---------------------------------------------------------------------------
// Commandes du modèle de données (phase 2)
// ---------------------------------------------------------------------------

/// Ouvre le magasin, en signalant une éventuelle migration.
pub(crate) fn open_store(
    path: &Path,
    options: GlobalOptions,
    config: &VaultConfig,
) -> Result<VaultStore, CliError> {
    report_hardening(options.hardening);
    let password = read_password("Mot de passe maître : ", options.password_stdin)?;

    let store = VaultStore::open(path, password.expose(), config)?;

    if let Some(from) = store.diagnostics().migrated_from {
        // Une migration modifie la forme des données de l'utilisateur : elle ne doit
        // jamais être silencieuse.
        eprintln!(
            "Note : ce coffre utilisait le schéma v{from} et a été mis à niveau en \
             mémoire. La nouvelle forme sera écrite au prochain enregistrement."
        );
    }

    report_diagnostics(store.vault());
    Ok(store)
}

/// Aiguille vers les sous-commandes de `entry`.
fn cmd_entry(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    match matches.subcommand() {
        Some(("add", sub)) => cmd_entry_add(sub, options, config),
        Some(("list", sub)) => cmd_entry_list(sub, options, config),
        Some(("show", sub)) => cmd_entry_show(sub, options, config),
        Some(("rm", sub)) => cmd_entry_trash(sub, options, config),
        Some(("restore", sub)) => cmd_entry_restore(sub, options, config),
        Some(("purge", sub)) => cmd_entry_purge(sub, options, config),
        Some(("totp", sub)) => totp::cmd_entry_totp(sub, options, config),
        Some(("gen", sub)) => totp::cmd_entry_gen(sub, options, config),
        _ => Err(CliError("sous-commande « entry » inconnue".to_string())),
    }
}

/// Traduit un nom de type en type d'entrée.
fn parse_kind(text: &str) -> Result<EntryKind, CliError> {
    Ok(match text.to_lowercase().as_str() {
        "login" => EntryKind::Login,
        "note" | "securenote" => EntryKind::SecureNote,
        "card" | "creditcard" => EntryKind::CreditCard,
        "identity" => EntryKind::Identity,
        "apikey" | "api" => EntryKind::ApiKey,
        "sshkey" | "ssh" => EntryKind::SshKey,
        "wifi" => EntryKind::Wifi,
        "passkey" => EntryKind::PasskeyMetadata,
        "custom" => EntryKind::Custom,
        other => {
            return Err(CliError(format!("type d'entrée inconnu : « {other} »")));
        }
    })
}

/// Devine la nature d'un champ d'après sa clé.
///
/// Évite d'imposer à l'utilisateur de qualifier chaque champ. Une clé inconnue
/// devient du texte libre, ce qui laisse les champs personnalisés utilisables sans
/// configuration.
pub(crate) fn infer_field_kind(key: &str) -> FieldKind {
    match key.to_lowercase().as_str() {
        "password" | "passphrase" | "secret" | "privatekey" | "private_key" => FieldKind::Secret,
        "pin" => FieldKind::Pin,
        "totp" | "otp" => FieldKind::Totp,
        "url" | "website" | "uri" => FieldKind::Url,
        "email" | "mail" => FieldKind::Email,
        "note" | "notes" | "comment" => FieldKind::Multiline,
        _ => FieldKind::Text,
    }
}

/// Ajoute une entrée.
fn cmd_entry_add(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;

    let kind = parse_kind(
        matches
            .get_one::<String>("type")
            .map_or("login", String::as_str),
    )?;

    let title = matches
        .get_one::<String>("title")
        .ok_or_else(|| CliError("titre manquant".to_string()))?;

    let mut entry =
        Entry::new(kind, title.clone(), now_seconds()).map_err(|err| CliError(err.to_string()))?;

    if let Some(subtitle) = matches.get_one::<String>("subtitle") {
        entry.subtitle.clone_from(subtitle);
    }
    entry.favorite = matches.get_flag("favorite");
    entry.sensitive = matches.get_flag("sensitive");

    let mut ordinal = 0_u16;
    if let Some(fields) = matches.get_many::<String>("field") {
        for specification in fields {
            // Format `cle=valeur`. Une spécification sans « = » est refusée plutôt
            // que devinée : une clé sans valeur produirait un champ vide, ce qui est
            // presque toujours une erreur de saisie.
            let (key, value) = specification.split_once('=').ok_or_else(|| {
                CliError(format!(
                    "champ « {specification} » mal formé : attendu CLE=VALEUR"
                ))
            })?;

            if key.is_empty() {
                return Err(CliError("clé de champ vide".to_string()));
            }

            entry.fields.push(
                Field::new(key, infer_field_kind(key), value, ordinal)
                    .map_err(|err| CliError(err.to_string()))?,
            );
            ordinal = ordinal.saturating_add(1);
        }
    }

    let id = store.add_entry(entry)?;
    store.save()?;

    println!("Entrée ajoutée : {id}");
    println!("Révision : 1");
    Ok(())
}

/// Liste les entrées.
fn cmd_entry_list(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    // Vue demandée. Les drapeaux sont **sélectifs** et non cumulatifs : demander la
    // corbeille doit montrer la corbeille, pas « tout plus la corbeille ».
    //
    // NOTE DE CORRECTION : la première version passait directement les drapeaux en
    // `include_trashed` / `include_archived`, ce qui *ajoutait* les catégories au
    // lieu de les sélectionner. `entry list --trash` affichait donc les entrées
    // actives, et l'utilisateur n'avait aucun moyen de voir la corbeille. Le défaut
    // ne se voyait qu'en exerçant réellement la commande.
    let views = [
        matches.get_flag("trash"),
        matches.get_flag("archived"),
        matches.get_flag("all"),
    ];
    if views.iter().filter(|requested| **requested).count() > 1 {
        return Err(CliError(
            "les options --trash, --archived et --all s'excluent mutuellement".to_string(),
        ));
    }
    let trash_only = matches.get_flag("trash");
    let archived_only = matches.get_flag("archived");
    let everything = matches.get_flag("all");

    // La requête récupère largement, le filtre ci-dessous sélectionne la vue.
    let query = SearchQuery {
        include_trashed: true,
        include_archived: true,
        sort: SortOrder::Title,
        limit: passlock_core::query::MAX_RESULTS,
        ..SearchQuery::new("")
    };

    let hits: Vec<_> = search(store.archive(), &query)
        .into_iter()
        .filter(|hit| {
            store.archive().entry(&hit.id).is_some_and(|entry| {
                if everything {
                    true
                } else if trash_only {
                    entry.is_trashed()
                } else if archived_only {
                    entry.archived && !entry.is_trashed()
                } else {
                    entry.is_active()
                }
            })
        })
        .take(store.archive().entries.len())
        .collect();

    if hits.is_empty() {
        println!("Aucune entrée.");
        return Ok(());
    }

    for hit in &hits {
        let Some(entry) = store.archive().entry(&hit.id) else {
            continue;
        };
        let marks = [
            if entry.favorite { "★" } else { " " },
            if entry.archived { "A" } else { " " },
            if entry.is_trashed() { "C" } else { " " },
        ]
        .concat();

        println!(
            "{marks} {}  {:<12} {}",
            entry.id,
            entry.kind.label(),
            entry.title
        );
    }

    let view = if everything {
        "toutes"
    } else if trash_only {
        "corbeille"
    } else if archived_only {
        "archivées"
    } else {
        "actives"
    };
    println!(
        "\n{} entrée(s) — vue : {view}. Légende : ★ favori, A archivée, C corbeille.",
        hits.len()
    );
    Ok(())
}

/// Affiche une entrée.
fn cmd_entry_show(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    let id = parse_entry_id(matches)?;
    let entry = store
        .archive()
        .entry(&id)
        .ok_or_else(|| CliError("entrée introuvable".to_string()))?;

    let reveal = matches.get_flag("reveal");

    println!("Identifiant : {}", entry.id);
    println!("Type        : {}", entry.kind.label());
    println!("Titre       : {}", entry.title);
    if !entry.subtitle.is_empty() {
        println!("Sous-titre  : {}", entry.subtitle);
    }
    println!("Révision    : {}", entry.revision);
    println!("Modifiée le : {}", format_timestamp(entry.updated_at));
    println!(
        "État        : {}{}{}",
        if entry.is_trashed() {
            "corbeille "
        } else {
            "active "
        },
        if entry.archived { "archivée " } else { "" },
        if entry.sensitive { "sensible" } else { "" }
    );

    if !entry.tags.is_empty() {
        let names: Vec<String> = entry
            .tags
            .iter()
            .filter_map(|id| store.archive().tags.iter().find(|tag| tag.id == *id))
            .map(|tag| tag.name.clone())
            .collect();
        println!("Tags        : {}", names.join(", "));
    }

    if !entry.fields.is_empty() {
        println!("\nChamps :");
        for field in &entry.fields {
            // Par défaut, une valeur masquée n'est **jamais** écrite sur la sortie
            // standard. C'est le mode sûr : révéler doit être un acte explicite.
            let shown = if field.concealed && !reveal {
                format!(
                    "[masquée, {} octet(s) — utilisez --reveal]",
                    field.value.len()
                )
            } else {
                field.value.clone()
            };
            println!("  {:<16} {} = {}", field.key, field.kind.label(), shown);
        }
    }

    println!("\nHistorique  : {} révision(s)", entry.history.len());
    Ok(())
}

/// Déplace une entrée à la corbeille.
fn cmd_entry_trash(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;
    let id = parse_entry_id(matches)?;

    store.trash_entry(&id)?;
    store.save()?;

    println!("Entrée déplacée à la corbeille : {id}");
    println!(
        "\nElle reste dans le coffre. Utilisez `entry restore` pour la rétablir, ou \
         `entry purge` pour la supprimer définitivement — en gardant à l'esprit que \
         les sauvegardes déjà écrites en contiennent toujours une copie."
    );
    Ok(())
}

/// Restaure une entrée.
fn cmd_entry_restore(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;
    let id = parse_entry_id(matches)?;

    store.restore_entry(&id)?;
    store.save()?;

    println!("Entrée restaurée : {id}");
    Ok(())
}

/// Supprime définitivement une entrée.
fn cmd_entry_purge(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;
    let id = parse_entry_id(matches)?;

    // Confirmation par recopie de l'identifiant : une suppression définitive ne doit
    // pas pouvoir être déclenchée par une faute de frappe ou une complétion
    // automatique.
    let confirmation = matches
        .get_one::<String>("confirm")
        .ok_or_else(|| CliError("confirmation manquante".to_string()))?;

    if confirmation.trim() != id.to_hex() {
        return Err(CliError(
            "la confirmation ne correspond pas à l'identifiant : rien n'a été supprimé".to_string(),
        ));
    }

    let history_len = store
        .archive()
        .entry(&id)
        .map_or(0, |entry| entry.history.len());

    store.purge_entry(&id)?;
    store.save()?;

    println!("Entrée supprimée définitivement : {id}");
    if history_len > 0 {
        println!("{history_len} révision(s) d'historique supprimée(s) avec elle.");
    }
    println!(
        "\nAVERTISSEMENT : cette suppression n'a aucun effet sur les sauvegardes déjà \
         écrites. Toute copie antérieure du coffre contient toujours cette entrée, et \
         cela ne peut pas être annulé depuis cette application."
    );
    Ok(())
}

/// Recherche dans le coffre.
fn cmd_search(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    let text = matches
        .get_one::<String>("text")
        .ok_or_else(|| CliError("texte manquant".to_string()))?;

    let sort = match matches
        .get_one::<String>("sort")
        .map_or("relevance", String::as_str)
    {
        "relevance" => SortOrder::Relevance,
        "title" => SortOrder::Title,
        "created" => SortOrder::CreatedDesc,
        "updated" => SortOrder::UpdatedDesc,
        other => {
            return Err(CliError(format!(
                "ordre de tri inconnu : « {other} » (attendu : relevance, title, created, updated)"
            )));
        }
    };

    let limit = match matches.get_one::<String>("limit") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| CliError(format!("limite invalide : « {value} »")))?,
        None => passlock_core::query::DEFAULT_LIMIT,
    };

    let all = matches.get_flag("all");
    let query = SearchQuery {
        include_archived: all,
        include_trashed: all,
        sort,
        limit,
        ..SearchQuery::new(text.clone())
    };

    let hits = search(store.archive(), &query);
    if hits.is_empty() {
        println!("Aucun résultat.");
        return Ok(());
    }

    for hit in &hits {
        let Some(entry) = store.archive().entry(&hit.id) else {
            continue;
        };
        println!(
            "{score:>5}  {id}  {kind:<12}  {title}",
            score = hit.score,
            id = entry.id,
            kind = entry.kind.label(),
            title = entry.title
        );
    }

    println!("\n{} résultat(s).", hits.len());
    Ok(())
}

/// Affiche ou purge l'historique d'une entrée.
fn cmd_history(
    matches: &clap::ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;
    let id = parse_entry_id(matches)?;

    if matches.get_flag("purge") {
        let removed = store.purge_history(&id)?;
        store.save()?;

        println!("{removed} révision(s) supprimée(s) de l'historique de {id}.");
        println!(
            "\nAVERTISSEMENT : ces versions n'existent plus dans ce coffre, mais elles \
             subsistent dans toute sauvegarde déjà écrite. La purge ne peut pas les \
             atteindre."
        );
        return Ok(());
    }

    let entry = store
        .archive()
        .entry(&id)
        .ok_or_else(|| CliError("entrée introuvable".to_string()))?;

    println!("Historique de {} — {}\n", entry.id, entry.title);

    if entry.history.is_empty() {
        println!("Aucune révision conservée.");
    } else {
        for (index, revision) in entry.history.iter().enumerate() {
            println!(
                "  {index:>3}. {} — titre : {}",
                format_timestamp(revision.at),
                revision.snapshot.title
            );
        }
    }

    println!(
        "\nPolitique : {} révisions au plus, {} jours au plus. Ce qui est conservé le \
         reste **dans le coffre** : une valeur que vous croyez supprimée peut y \
         subsister. `history --purge` les efface ici, et seulement ici.",
        passlock_core::model::MAX_HISTORY_PER_ENTRY,
        passlock_core::migrate::HISTORY_RETENTION_DAYS
    );
    Ok(())
}

/// Lit l'identifiant passé en argument.
fn parse_entry_id(matches: &clap::ArgMatches) -> Result<EntryId, CliError> {
    let raw = matches
        .get_one::<String>("id")
        .ok_or_else(|| CliError("identifiant manquant".to_string()))?;

    EntryId::from_hex(raw.trim()).map_err(|_| {
        CliError(format!(
            "identifiant invalide : « {raw} » (attendu : 32 caractères hexadécimaux)"
        ))
    })
}

/// Date courante, en secondes depuis l'époque Unix.
pub(crate) fn now_seconds() -> u64 {
    passlock_core::rollback::now_unix()
}
