//! Commandes TOTP, et génération directe dans le coffre.
//!
//! ## Passlock est le prouveur, pas le validateur
//!
//! Ces commandes produisent un code à partir d'un secret partagé et de l'heure.
//! Elles ne vérifient rien, ne comparent rien, et ne resynchronisent rien : la
//! section 6 de la RFC 6238 décrit le comportement du **validateur**, qui n'a pas
//! d'objet ici.
//!
//! ## L'horloge n'est pas vérifiée, et ne peut pas l'être
//!
//! Le temps vient de l'horloge système, passée explicitement au calcul. Passlock
//! **ne la vérifie pas** : il n'y a aucun appel réseau, et il n'y en aura pas —
//! l'absence de réseau est une propriété de sécurité établie en phase 1, pas une
//! commodité.
//!
//! Conséquence, écrite plutôt que découverte : **si l'horloge système est fausse,
//! les codes sont faux, et Passlock ne peut pas le détecter.** L'utilisateur voit
//! un code refusé et croit à une erreur du site. Le remède est de corriger l'horloge
//! de la machine, ou de renseigner un décalage explicite.
//!
//! ## Un code n'est jamais journalisé
//!
//! Aucun code TOTP n'apparaît dans le journal d'audit, dans un fichier de trace, ni
//! dans un message d'erreur. Le type `Error` n'accepte que des `&'static str`, ce
//! qui rend la faute **impossible à écrire** plutôt que simplement déconseillée.

use clap::{Arg, ArgAction, ArgMatches, Command};
use zeroize::Zeroizing;

use passlock_core::model::{Entry, EntryId, Field, FieldKind};
use passlock_core::totp::{Algorithm, DEFAULT_PERIOD, Digits, MAX_PERIOD, MIN_PERIOD, Totp};
use passlock_core::vault::VaultConfig;

use crate::{CliError, CliResult, GlobalOptions, open_store, read_password, vault_path};

/// Clé du champ portant un TOTP.
const TOTP_FIELD_KEY: &str = "totp";

/// Clé du réglage de décalage d'horloge, dans `Archive::settings`.
const OFFSET_SETTING_KEY: &str = "totp_offset_seconds";

/// Décalage d'horloge maximal, en secondes.
const MAX_OFFSET_SECONDS: i64 = 3600;

/// Seuil d'avertissement sur la fin de validité, en secondes.
const EXPIRY_WARNING_SECONDS: u32 = 5;

// ---------------------------------------------------------------------------
// Définitions
// ---------------------------------------------------------------------------

/// `passlock totp`.
pub(crate) fn command() -> Command {
    Command::new("totp")
        .about("Affiche le code TOTP d'une entrée")
        .arg(crate::vault_argument())
        .arg(
            Arg::new("id")
                .value_name("ID")
                .help("Identifiant de l'entrée"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .action(ArgAction::SetTrue)
                .help("Lister les entrées portant un TOTP"),
        )
        .arg(
            Arg::new("at")
                .long("at")
                .value_name("HORODATAGE")
                .help("Calculer le code pour un instant Unix donné, au lieu de l'heure courante"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Sortie JSON, pour usage scripté"),
        )
}

/// `passlock entry totp`.
pub(crate) fn entry_totp_command() -> Command {
    Command::new("totp")
        .about("Associe ou engendre un secret TOTP sur une entrée")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("set")
                .about("Associe un secret TOTP existant")
                .long_about(
                    "Associe un secret TOTP existant à une entrée.\n\n                     Le secret n'est jamais accepté en argument : un argument est                      visible dans `ps` et dans /proc/<pid>/cmdline. Il est demandé                      par une invite masquée, ou lu sur l'entrée standard avec                      --password-stdin.\n\n                     ATTENTION à l'ordre sur l'entrée standard : le mot de passe                      maître est lu EN PREMIER, le secret TOTP ENSUITE. Fournir le                      secret seul ferait consommer celui-ci comme mot de passe                      maître.\n\n                     --uri-stdin lit une URI otpauth:// complète, avec le même                      ordre : mot de passe maître, puis URI.",
                )
                .arg(crate::vault_argument())
                .arg(Arg::new("id").value_name("ID").required(true))
                .arg(
                    Arg::new("issuer")
                        .long("issuer")
                        .value_name("EMETTEUR")
                        .help("Émetteur (nom du service)"),
                )
                .arg(
                    Arg::new("account")
                        .long("account")
                        .value_name("COMPTE")
                        .help("Compte associé au secret"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .value_name("ALGO")
                        .help("SHA1 (défaut), SHA256 ou SHA512"),
                )
                .arg(
                    Arg::new("digits")
                        .long("digits")
                        .value_name("N")
                        .help("Nombre de chiffres : 6 (défaut) ou 8"),
                )
                .arg(
                    Arg::new("period")
                        .long("period")
                        .value_name("SECONDES")
                        .help("Période en secondes (1 à 600, défaut 30)"),
                )
                .arg(
                    Arg::new("uri-stdin")
                        .long("uri-stdin")
                        .action(ArgAction::SetTrue)
                        .help("Lire une URI otpauth:// complète sur l'entrée standard"),
                ),
        )
        .subcommand(
            Command::new("new")
                .about("Engendre un secret TOTP neuf et l'associe")
                .arg(crate::vault_argument())
                .arg(Arg::new("id").value_name("ID").required(true))
                .arg(
                    Arg::new("issuer")
                        .long("issuer")
                        .value_name("EMETTEUR")
                        .help("Émetteur (nom du service)"),
                )
                .arg(
                    Arg::new("account")
                        .long("account")
                        .value_name("COMPTE")
                        .help("Compte associé au secret"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .value_name("ALGO")
                        .help("SHA1 (défaut), SHA256 ou SHA512"),
                )
                .arg(
                    Arg::new("digits")
                        .long("digits")
                        .value_name("N")
                        .help("Nombre de chiffres : 6 (défaut) ou 8"),
                )
                .arg(
                    Arg::new("period")
                        .long("period")
                        .value_name("SECONDES")
                        .help("Période en secondes (1 à 600, défaut 30)"),
                ),
        )
}

/// `passlock entry gen`.
pub(crate) fn entry_gen_command() -> Command {
    Command::new("gen")
        .about("Engendre un secret et l'écrit directement dans le coffre")
        .long_about(
            "Engendre un secret et l'écrit directement dans le coffre.\n\n\
             Cette commande existe pour éviter un anti-modèle : \
             `passlock entry add --field password=$(passlock generate)` place le \
             secret dans l'environnement du shell, où il peut être journalisé. Ici, \
             le secret naît dans le processus et va directement dans l'archive : il \
             ne transite ni par un argument (visible dans `ps`), ni par une \
             substitution de commande, ni par un fichier temporaire.",
        )
        .arg(crate::vault_argument())
        .arg(Arg::new("id").value_name("ID").required(true))
        .arg(
            Arg::new("field")
                .long("field")
                .value_name("CLE")
                .required(true)
                .help("Clé du champ à écrire (créé s'il n'existe pas)"),
        )
        .arg(
            Arg::new("length")
                .long("length")
                .value_name("N")
                .help("Longueur du mot de passe (défaut 20)"),
        )
        .arg(
            Arg::new("charset")
                .long("charset")
                .value_name("CLASSES")
                .help("Classes de caractères (défaut « lud »)"),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .value_name("CARACTERES")
                .help("Caractères à retirer"),
        )
        .arg(
            Arg::new("no-ambiguous")
                .long("no-ambiguous")
                .action(ArgAction::SetTrue)
                .help("Retire les caractères ambigus"),
        )
        .arg(
            Arg::new("min-digits")
                .long("min-digits")
                .value_name("N")
                .help("Minimum de chiffres exigé par le site"),
        )
        .arg(
            Arg::new("min-symbols")
                .long("min-symbols")
                .value_name("N")
                .help("Minimum de symboles exigé par le site"),
        )
        .arg(
            Arg::new("min-uppercase")
                .long("min-uppercase")
                .value_name("N")
                .help("Minimum de majuscules exigé par le site"),
        )
        .arg(
            Arg::new("show")
                .long("show")
                .action(ArgAction::SetTrue)
                .help("Afficher le secret produit après l'avoir enregistré"),
        )
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

/// `passlock totp`.
pub(crate) fn cmd_totp(
    matches: &ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    if matches.get_flag("list") {
        list_totp(&store);
        return Ok(());
    }

    let raw = matches
        .get_one::<String>("id")
        .ok_or_else(|| CliError("identifiant d'entrée manquant (ou --list)".to_string()))?;
    let id = parse_entry_id(raw)?;

    let entry = store
        .archive()
        .entry(&id)
        .ok_or_else(|| CliError(format!("aucune entrée avec l'identifiant {id}")))?;

    let totp = totp_of(entry)?;

    // L'instant est un paramètre, jamais une lecture cachée : c'est ce qui rend le
    // calcul reproductible et testable.
    let now = match matches.get_one::<String>("at") {
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| CliError(format!("horodatage invalide : « {text} »")))?,
        None => crate::now_seconds(),
    };

    let offset = clock_offset(&store);
    let adjusted = apply_offset(now, offset);

    let code = totp.code(adjusted)?;
    let remaining = totp.remaining(adjusted);

    if matches.get_flag("json") {
        emit_json(&code, remaining, &totp, adjusted, offset);
    } else {
        emit_text(&code, remaining, &totp, adjusted, offset);
    }

    Ok(())
}

/// Liste les entrées portant un TOTP.
///
/// Ne retourne rien : une liste vide n'est pas une erreur, et l'absence d'entrée
/// est signalée sur la sortie d'erreur sans faire échouer la commande.
fn list_totp(store: &passlock_core::store::VaultStore) {
    let mut found = 0_usize;

    for entry in &store.archive().entries {
        if entry.field(TOTP_FIELD_KEY).is_some() {
            let status = if entry.is_trashed() {
                "corbeille"
            } else if entry.archived {
                "archivée"
            } else {
                "active"
            };
            println!("{}  {:<32}  {status}", entry.id, entry.title);
            found += 1;
        }
    }

    if found == 0 {
        eprintln!("Aucune entrée ne porte de champ « {TOTP_FIELD_KEY} ».");
    } else {
        eprintln!("{found} entrée(s) portant un TOTP.");
    }
}

/// Affiche le code en texte.
fn emit_text(code: &Zeroizing<String>, remaining: u32, totp: &Totp, at: u64, offset: i64) {
    // La sortie standard ne porte **que** le code : elle doit rester redirigeable.
    println!("{}", **code);

    if let Some(issuer) = totp.issuer() {
        eprintln!("{issuer} — {}", totp.label());
    } else {
        eprintln!("{}", totp.label());
    }

    eprintln!(
        "  {} chiffres, {}, période {} s, instant {at}",
        totp.digits().count(),
        totp.algorithm().label(),
        totp.period()
    );
    eprintln!("  valable encore {remaining} s");

    if offset != 0 {
        eprintln!(
            "  décalage d'horloge appliqué : {offset:+} s (réglage du coffre \
             « {OFFSET_SETTING_KEY} »)"
        );
    }

    if remaining <= EXPIRY_WARNING_SECONDS {
        eprintln!(
            "  AVERTISSEMENT : ce code expire dans {remaining} s ; attendez le \
             suivant plutôt que de le recopier"
        );
    }

    eprintln!(
        "  rappel : ce code dépend de l'horloge système, que Passlock ne vérifie \
         pas ; s'il est refusé, vérifiez l'heure de la machine"
    );
}

/// Affiche le code en JSON.
///
/// Le JSON ne porte **jamais** de secret à longue durée de vie : ni le secret
/// partagé, ni l'URI `otpauth`.
fn emit_json(code: &Zeroizing<String>, remaining: u32, totp: &Totp, at: u64, offset: i64) {
    println!(
        "{{\"code\":\"{}\",\"remaining\":{remaining},\"digits\":{},\"algorithm\":\"{}\",\
         \"period\":{},\"timestamp\":{at},\"offset\":{offset},\"label\":{},\"issuer\":{}}}",
        json_escape(code),
        totp.digits().count(),
        totp.algorithm().label(),
        totp.period(),
        json_string(Some(totp.label())),
        json_string(totp.issuer()),
    );
}

/// Échappe une chaîne pour un littéral JSON.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Les caractères de contrôle ne devraient pas exister (l'analyse les
            // refuse) ; les échapper ici évite qu'un JSON produit devienne
            // invalide si cette garantie venait à changer.
            c if c.is_control() => out.push_str("\\u0000"),
            c => out.push(c),
        }
    }
    out
}

/// Rend une chaîne optionnelle en littéral JSON.
fn json_string(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("\"{}\"", json_escape(text)),
        None => "null".to_string(),
    }
}

/// Extrait et analyse le TOTP d'une entrée.
fn totp_of(entry: &Entry) -> Result<Totp, CliError> {
    let field = entry.field(TOTP_FIELD_KEY).ok_or_else(|| {
        CliError(format!(
            "l'entrée « {} » ne porte pas de champ « {TOTP_FIELD_KEY} »",
            entry.title
        ))
    })?;
    Ok(Totp::parse_uri(&field.value)?)
}

/// Lit le décalage d'horloge du coffre.
///
/// Le réglage vit dans `Archive::settings`, un sac clé/valeur déjà encodé : le
/// stocker **ne demande aucun changement de format**, donc aucune montée de version.
/// Une valeur illisible est ignorée et signalée comme décalage nul plutôt que de
/// faire échouer la commande : un réglage est un confort, pas une donnée critique.
fn clock_offset(store: &passlock_core::store::VaultStore) -> i64 {
    let Some(field) = store
        .archive()
        .settings
        .iter()
        .find(|field| field.key == OFFSET_SETTING_KEY)
    else {
        return 0;
    };

    let parsed = field.value.trim().parse::<i64>().unwrap_or(0);
    parsed.clamp(-MAX_OFFSET_SECONDS, MAX_OFFSET_SECONDS)
}

/// Applique un décalage à un instant Unix.
///
/// Le décalage est borné à ±3600 s : au-delà, il ne s'agit plus d'une dérive
/// d'horloge mais d'une erreur de configuration, et laisser passer une valeur
/// arbitraire ferait produire des codes sans rapport avec l'heure courante.
fn apply_offset(now: u64, offset: i64) -> u64 {
    if offset >= 0 {
        now.saturating_add(offset.unsigned_abs())
    } else {
        now.saturating_sub(offset.unsigned_abs())
    }
}

/// `passlock entry totp`.
pub(crate) fn cmd_entry_totp(
    matches: &ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let (sub, arguments) = matches
        .subcommand()
        .ok_or_else(|| CliError("sous-commande « entry totp » manquante".to_string()))?;

    match sub {
        "set" => cmd_totp_set(arguments, options, config),
        "new" => cmd_totp_new(arguments, options, config),
        other => Err(CliError(format!(
            "sous-commande « entry totp {other} » inconnue"
        ))),
    }
}

/// `passlock entry totp set`.
fn cmd_totp_set(matches: &ArgMatches, options: GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;

    let id = parse_entry_id(
        matches
            .get_one::<String>("id")
            .ok_or_else(|| CliError("identifiant manquant".to_string()))?,
    )?;

    let totp = if matches.get_flag("uri-stdin") {
        let uri = read_stdin_line()?;
        Totp::parse_uri(&uri)?
    } else {
        // Le secret est demandé par une invite masquée, ou lu sur l'entrée
        // standard. **Jamais** par un argument : un argument est visible dans `ps`.
        let secret = read_password("Secret TOTP (Base32) : ", options.password_stdin)?;
        let text = std::str::from_utf8(secret.expose())
            .map_err(|_| CliError("le secret TOTP doit être du texte Base32".to_string()))?;
        let decoded = passlock_core::encoding::base32_decode(text.trim())?;

        Totp::new(
            decoded.expose(),
            parse_algorithm(matches)?,
            parse_digits(matches)?,
            parse_period(matches)?,
            matches
                .get_one::<String>("account")
                .cloned()
                .unwrap_or_default(),
            matches.get_one::<String>("issuer").cloned(),
        )?
    };

    store_totp(&mut store, &id, &totp)?;

    eprintln!(
        "TOTP associé à l'entrée {id} : {} chiffres, {}, période {} s, secret de \
         {} octets ({} bits)",
        totp.digits().count(),
        totp.algorithm().label(),
        totp.period(),
        totp.secret_len(),
        totp.secret_len() * 8
    );
    Ok(())
}

/// `passlock entry totp new`.
fn cmd_totp_new(matches: &ArgMatches, options: GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;

    let id = parse_entry_id(
        matches
            .get_one::<String>("id")
            .ok_or_else(|| CliError("identifiant manquant".to_string()))?,
    )?;

    let totp = Totp::generate(
        parse_algorithm(matches)?,
        parse_digits(matches)?,
        parse_period(matches)?,
        matches
            .get_one::<String>("account")
            .cloned()
            .unwrap_or_default(),
        matches.get_one::<String>("issuer").cloned(),
    )?;

    store_totp(&mut store, &id, &totp)?;

    eprintln!(
        "Secret TOTP engendré : {} octets, soit {} bits.",
        totp.secret_len(),
        totp.secret_len() * 8
    );
    eprintln!(
        "AVERTISSEMENT : l'URI ci-dessous porte le secret en clair. Elle est \
         destinée à être recopiée sur le service, puis à disparaître de votre écran \
         et de l'historique du terminal."
    );
    // L'URI est la seule sortie de cette commande : c'est elle qui permet
    // l'enrôlement. Elle n'est jamais journalisée, seulement affichée.
    println!("{}", totp.to_uri());
    Ok(())
}

/// Écrit le champ TOTP d'une entrée.
fn store_totp(
    store: &mut passlock_core::store::VaultStore,
    id: &EntryId,
    totp: &Totp,
) -> CliResult {
    let uri = totp.to_uri();
    store.update_entry(id, |entry| {
        let ordinal = u16::try_from(entry.fields.len()).unwrap_or(u16::MAX);
        let field = Field::new(TOTP_FIELD_KEY, FieldKind::Totp, uri.clone(), ordinal)?;
        entry
            .fields
            .retain(|existing| existing.key != TOTP_FIELD_KEY);
        entry.fields.push(field);
        Ok(())
    })?;
    store.save()?;
    Ok(())
}

/// `passlock entry gen`.
pub(crate) fn cmd_entry_gen(
    matches: &ArgMatches,
    options: GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut store = open_store(&path, options, config)?;

    let id = parse_entry_id(
        matches
            .get_one::<String>("id")
            .ok_or_else(|| CliError("identifiant manquant".to_string()))?,
    )?;

    let key = matches
        .get_one::<String>("field")
        .cloned()
        .ok_or_else(|| CliError("clé de champ manquante".to_string()))?;

    if key.is_empty() {
        return Err(CliError("clé de champ vide".to_string()));
    }

    let charset = matches
        .get_one::<String>("charset")
        .map_or("lud", String::as_str);

    let spec = passlock_core::generator::PasswordSpec {
        length: number(matches, "length", 20)?,
        lowercase: charset.contains('l'),
        uppercase: charset.contains('u'),
        digits: charset.contains('d'),
        symbols: charset.contains('s'),
        exclude: matches
            .get_one::<String>("exclude")
            .cloned()
            .unwrap_or_default(),
        exclude_ambiguous: matches.get_flag("no-ambiguous"),
        min_lowercase: 0,
        min_uppercase: number(matches, "min-uppercase", 0)?,
        min_digits: number(matches, "min-digits", 0)?,
        min_symbols: number(matches, "min-symbols", 0)?,
    };

    // Le secret naît ici et va directement dans l'archive : il ne touche ni la
    // ligne de commande, ni un tube, ni un fichier temporaire.
    let generated = passlock_core::generator::generate_password(&spec)?;
    let value = generated.value().to_owned();
    let entropy = generated.entropy();

    store.update_entry(&id, |entry| {
        // La clé est validée par `Field::new` (longueur, valeur) : une clé trop
        // longue est refusée plutôt que tronquée.
        let ordinal = u16::try_from(entry.fields.len()).unwrap_or(u16::MAX);
        let field = Field::new(
            key.clone(),
            crate::infer_field_kind(&key),
            value.clone(),
            ordinal,
        )?;
        entry.fields.retain(|existing| existing.key != key);
        entry.fields.push(field);
        Ok(())
    })?;
    store.save()?;

    eprintln!(
        "Champ « {key} » engendré sur l'entrée {id} : entropie {:.2} bits, bande {}.",
        entropy.bits,
        entropy.band().label()
    );
    eprintln!("  hypothèse : CSPRNG du noyau uniforme et non compromis");

    if matches.get_flag("show") {
        println!("{value}");
    } else {
        eprintln!(
            "  le secret n'est pas affiché ; utilisez « entry show --reveal » pour \
             le consulter"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Analyse un identifiant d'entrée hexadécimal.
fn parse_entry_id(text: &str) -> Result<EntryId, CliError> {
    let trimmed = text.trim();
    if trimmed.len() != 32 {
        return Err(CliError(format!(
            "identifiant invalide : « {trimmed} » (32 caractères hexadécimaux attendus)"
        )));
    }

    let mut bytes = [0_u8; 16];
    for (index, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let pair =
            std::str::from_utf8(chunk).map_err(|_| CliError("identifiant invalide".to_string()))?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| CliError(format!("identifiant invalide : « {trimmed} »")))?;
    }
    Ok(EntryId::from_bytes(bytes))
}

/// Lit l'algorithme demandé.
fn parse_algorithm(matches: &ArgMatches) -> Result<Algorithm, CliError> {
    match matches.get_one::<String>("algorithm") {
        None => Ok(Algorithm::default()),
        Some(text) => Algorithm::parse(text).ok_or_else(|| {
            CliError(format!(
                "algorithme inconnu : « {text} » (attendu SHA1, SHA256 ou SHA512)"
            ))
        }),
    }
}

/// Lit le nombre de chiffres demandé.
fn parse_digits(matches: &ArgMatches) -> Result<Digits, CliError> {
    match matches.get_one::<String>("digits") {
        None => Ok(Digits::default()),
        Some(text) => {
            let value = text
                .parse::<u32>()
                .map_err(|_| CliError(format!("nombre de chiffres invalide : « {text} »")))?;
            Digits::parse(value)
                .ok_or_else(|| CliError(format!("nombre de chiffres hors de {{6, 8}} : {value}")))
        }
    }
}

/// Lit la période demandée.
fn parse_period(matches: &ArgMatches) -> Result<u32, CliError> {
    match matches.get_one::<String>("period") {
        None => Ok(DEFAULT_PERIOD),
        Some(text) => {
            let value = text
                .parse::<u32>()
                .map_err(|_| CliError(format!("période invalide : « {text} »")))?;
            if !(MIN_PERIOD..=MAX_PERIOD).contains(&value) {
                return Err(CliError(format!(
                    "période hors bornes : {value} (attendu {MIN_PERIOD} à {MAX_PERIOD})"
                )));
            }
            Ok(value)
        }
    }
}

/// Lit un paramètre numérique.
fn number(matches: &ArgMatches, name: &str, default: usize) -> Result<usize, CliError> {
    match matches.get_one::<String>(name) {
        None => Ok(default),
        Some(text) => text
            .parse::<usize>()
            .map_err(|_| CliError(format!("« {name} » attend un entier positif"))),
    }
}

/// Lit une ligne sur l'entrée standard.
///
/// Bornée : une URI `otpauth` fait quelques dizaines d'octets, et une entrée
/// hostile ne doit pas faire croître un tampon sans limite.
fn read_stdin_line() -> Result<String, CliError> {
    use std::io::BufRead as _;

    let mut line = String::with_capacity(2048);
    let mut stdin = std::io::stdin().lock();
    let read = stdin
        .read_line(&mut line)
        .map_err(|err| CliError(format!("lecture de l'entrée standard : {err}")))?;

    if read == 0 {
        return Err(CliError(
            "aucune URI reçue sur l'entrée standard".to_string(),
        ));
    }

    if line.len() > passlock_core::totp::MAX_URI_LEN {
        return Err(CliError(format!(
            "URI au-delà de {} octets",
            passlock_core::totp::MAX_URI_LEN
        )));
    }

    Ok(line.trim().to_string())
}
