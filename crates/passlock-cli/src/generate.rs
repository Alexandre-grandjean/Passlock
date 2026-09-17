//! Commandes de génération : mots de passe, phrases de passe, secrets.
//!
//! ## Séparation des flux, décidée
//!
//! Le **secret va sur la sortie standard**, seul, et le **rapport va sur la sortie
//! d'erreur**. Ce n'est pas une coquetterie : `passlock secret > cle.txt` doit
//! écrire exactement le secret dans le fichier, sans commentaire ni bandeau. Le
//! rapport reste visible pour un humain, et disparaît pour un script.
//!
//! ## Aucun secret en argument
//!
//! Aucune de ces commandes n'accepte de secret sur la ligne de commande. Un
//! argument est visible dans `ps` et dans `/proc/<pid>/cmdline`; le projet s'interdit
//! cette voie depuis la phase 1. Pour écrire un secret **dans** le coffre sans le
//! faire transiter par un tube, voir `entry gen`.

use clap::{Arg, ArgAction, ArgMatches, Command};

use passlock_core::entropy::Band;
use passlock_core::generator::{
    self, Composition, DEFAULT_PASSWORD_LEN, DEFAULT_SECRET_BYTES, DEFAULT_SEPARATOR,
    DEFAULT_WORDS, Generated, MAX_PASSWORD_LEN, MAX_SECRET_BYTES, MAX_WORDS, MIN_PASSWORD_LEN,
    MIN_SECRET_BYTES, MIN_WORDS, PassphraseSpec, PasswordSpec, SecretFormat, SecretSpec,
};
use passlock_core::wordlist::{Language, Wordlist};

use crate::CliResult;

/// Nombre de secrets produits au maximum en une invocation.
const MAX_COUNT: usize = 100;

// ---------------------------------------------------------------------------
// Définitions
// ---------------------------------------------------------------------------

/// `passlock generate`.
pub(crate) fn generate_command() -> Command {
    Command::new("generate")
        .about("Engendre un mot de passe")
        .arg(
            Arg::new("length")
                .long("length")
                .short('l')
                .value_name("N")
                .help("Longueur (8 à 1024, défaut 20)"),
        )
        .arg(
            Arg::new("charset")
                .long("charset")
                .value_name("CLASSES")
                .help("Classes de caractères : l=minuscules, u=majuscules, d=chiffres, s=symboles (défaut « lud »)"),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .value_name("CARACTERES")
                .help("Caractères à retirer de l'alphabet"),
        )
        .arg(
            Arg::new("no-ambiguous")
                .long("no-ambiguous")
                .action(ArgAction::SetTrue)
                .help("Retire les caractères ambigus (0 O 1 l I |)"),
        )
        .arg(
            Arg::new("min-lowercase")
                .long("min-lowercase")
                .value_name("N")
                .help("Minimum de minuscules exigé par le site"),
        )
        .arg(
            Arg::new("min-uppercase")
                .long("min-uppercase")
                .value_name("N")
                .help("Minimum de majuscules exigé par le site"),
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
            Arg::new("count")
                .long("count")
                .short('n')
                .value_name("N")
                .help("Nombre de mots de passe à produire"),
        )
}

/// `passlock passphrase`.
pub(crate) fn passphrase_command() -> Command {
    Command::new("passphrase")
        .about("Engendre une phrase de passe à partir d'une liste de mots")
        .arg(
            Arg::new("words")
                .long("words")
                .short('w')
                .value_name("N")
                .help("Nombre de mots (3 à 24, défaut 6)"),
        )
        .arg(
            Arg::new("language")
                .long("language")
                .value_name("LANGUE")
                .help("Liste embarquée : fr (défaut) ou en"),
        )
        .arg(
            Arg::new("separator")
                .long("separator")
                .value_name("SEP")
                .help("Séparateur entre les mots (défaut « - »)"),
        )
        .arg(
            Arg::new("random-separator")
                .long("random-separator")
                .action(ArgAction::SetTrue)
                .help("Choisir le séparateur au hasard ; les bits correspondants sont comptés"),
        )
        .arg(
            Arg::new("wordlist")
                .long("wordlist")
                .value_name("FICHIER")
                .help("Utiliser une liste personnalisée à la place d'une liste embarquée"),
        )
        .arg(
            Arg::new("letters-only")
                .long("letters-only")
                .action(ArgAction::SetTrue)
                .help("Écarter les entrées sans lettre (chiffres et ponctuation Diceware)"),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .short('n')
                .value_name("N")
                .help("Nombre de phrases à produire"),
        )
}

/// `passlock secret`.
pub(crate) fn secret_command() -> Command {
    Command::new("secret")
        .about("Engendre un secret arbitraire (clé d'API, jeton, code de récupération)")
        .arg(
            Arg::new("bytes")
                .long("bytes")
                .short('b')
                .value_name("N")
                .help("Matière aléatoire : octets, ou symboles pour le format alphanumerique (8 à 1024, défaut 32)"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .value_name("FORMAT")
                .help("hex (défaut), base32, base64url, alphanumerique"),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .short('g')
                .value_name("N")
                .help("Regrouper la sortie par blocs de N symboles, séparés par des tirets"),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .short('n')
                .value_name("N")
                .help("Nombre de secrets à produire"),
        )
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

/// `passlock generate`.
pub(crate) fn cmd_generate(matches: &ArgMatches) -> CliResult {
    let length = parse_number(matches, "length", DEFAULT_PASSWORD_LEN)?;
    let charset = matches
        .get_one::<String>("charset")
        .map_or("lud", String::as_str);

    let spec = PasswordSpec {
        length,
        lowercase: charset.contains('l'),
        uppercase: charset.contains('u'),
        digits: charset.contains('d'),
        symbols: charset.contains('s'),
        exclude: matches
            .get_one::<String>("exclude")
            .cloned()
            .unwrap_or_default(),
        exclude_ambiguous: matches.get_flag("no-ambiguous"),
        min_lowercase: parse_number(matches, "min-lowercase", 0)?,
        min_uppercase: parse_number(matches, "min-uppercase", 0)?,
        min_digits: parse_number(matches, "min-digits", 0)?,
        min_symbols: parse_number(matches, "min-symbols", 0)?,
    };

    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&length) {
        return Err(crate::CliError(format!(
            "longueur hors bornes : {length} (attendu {MIN_PASSWORD_LEN} à {MAX_PASSWORD_LEN})"
        )));
    }

    emit_many(matches, || generator::generate_password(&spec))
}

/// `passlock passphrase`.
pub(crate) fn cmd_passphrase(matches: &ArgMatches) -> CliResult {
    let words = parse_number(matches, "words", DEFAULT_WORDS)?;
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
        return Err(crate::CliError(format!(
            "nombre de mots hors bornes : {words} (attendu {MIN_WORDS} à {MAX_WORDS})"
        )));
    }

    let letters_only = matches.get_flag("letters-only");

    // La liste personnalisée est construite une fois et vit jusqu'à la fin de la
    // commande ; la liste embarquée est statique.
    // La liste personnalisée doit vivre aussi longtemps que la référence qui la
    // désigne : sa liaison est donc déclarée **avant** le choix, et non dans la
    // branche qui la crée.
    let custom;
    let wordlist: &Wordlist = if let Some(path) = matches.get_one::<String>("wordlist") {
        custom = Wordlist::from_file(std::path::Path::new(path), letters_only)?;
        &custom
    } else {
        let language = match matches.get_one::<String>("language") {
            Some(text) => Language::parse(text).ok_or_else(|| {
                crate::CliError(format!("langue inconnue : « {text} » (attendu fr ou en)"))
            })?,
            None => Language::DicewareFrench,
        };
        Wordlist::embedded(language, letters_only)?
    };

    let spec = PassphraseSpec {
        words,
        separator: matches
            .get_one::<String>("separator")
            .cloned()
            .unwrap_or_else(|| DEFAULT_SEPARATOR.to_owned()),
        random_separator: matches.get_flag("random-separator"),
        wordlist,
    };

    emit_many(matches, || generator::generate_passphrase(&spec))
}

/// `passlock secret`.
pub(crate) fn cmd_secret(matches: &ArgMatches) -> CliResult {
    let bytes = parse_number(matches, "bytes", DEFAULT_SECRET_BYTES)?;
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&bytes) {
        return Err(crate::CliError(format!(
            "taille hors bornes : {bytes} (attendu {MIN_SECRET_BYTES} à {MAX_SECRET_BYTES})"
        )));
    }

    let format = match matches.get_one::<String>("format") {
        Some(text) => SecretFormat::parse(text).ok_or_else(|| {
            crate::CliError(format!(
                "format inconnu : « {text} » (attendu hex, base32, base64url ou alphanumerique)"
            ))
        })?,
        None => SecretFormat::default(),
    };

    let spec = SecretSpec {
        bytes,
        format,
        groups: parse_number(matches, "groups", 0)?,
    };

    emit_many(matches, || generator::generate_secret(&spec))
}

/// Produit `count` secrets, écrit chacun sur la sortie standard, et un rapport
/// sur la sortie d'erreur.
fn emit_many<F>(matches: &ArgMatches, produce: F) -> CliResult
where
    F: Fn() -> passlock_core::error::Result<Generated>,
{
    let count = parse_number(matches, "count", 1)?;
    if count == 0 || count > MAX_COUNT {
        return Err(crate::CliError(format!(
            "nombre de secrets hors bornes : {count} (attendu 1 à {MAX_COUNT})"
        )));
    }

    let mut last: Option<Generated> = None;

    for _ in 0..count {
        let generated = produce()?;
        // Sortie standard : le secret, et rien d'autre.
        println!("{}", generated.value());
        last = Some(generated);
    }

    if let Some(generated) = last.as_ref() {
        report(generated, count);
    }

    Ok(())
}

/// Écrit le rapport d'entropie sur la sortie d'erreur.
///
/// ## Ce que ce rapport dit, et ce qu'il ne dit pas
///
/// Il donne un **nombre de bits calculé** et une **bande de politique**. Il ne
/// donne **aucune** estimation de durée de cassage : une telle estimation exige des
/// hypothèses sur le matériel de l'attaquant que ce projet ne peut pas vérifier, et
/// un chiffre inventé dans un gestionnaire de mots de passe est un mensonge aux
/// conséquences réelles.
///
/// L'hypothèse dont dépend le chiffre est rappelée **à chaque fois**. Un nombre de
/// bits affiché sans son hypothèse se lit comme une garantie.
fn report(generated: &Generated, count: usize) {
    let entropy = generated.entropy();

    eprintln!("{}", describe(generated.composition()));

    if entropy.cost_bits < 0.0 {
        eprintln!(
            "  entropie sans contrainte {:.2} bits ; contrainte {:.2} bit ; retenu {:.2} bits",
            entropy.unconstrained_bits, entropy.cost_bits, entropy.bits
        );
    } else {
        eprintln!("  entropie {:.2} bits", entropy.bits);
    }

    eprintln!(
        "  bande : {} (plancher {} bits)",
        band_label(entropy.band()),
        entropy.floor_bits()
    );

    if count > 1 {
        eprintln!("  {count} secrets produits");
    }

    // L'hypothèse, répétée à chaque affichage.
    eprintln!("  hypothèse : CSPRNG du noyau uniforme et non compromis");

    if entropy.band() == Band::Insufficient {
        eprintln!(
            "  AVERTISSEMENT : cette entropie est sous le seuil retenu par ce projet \
             (64 bits)"
        );
    }

    // Le canal de sortie est le maillon faible de tout générateur.
    eprintln!(
        "  rappel : la sortie standard peut être conservée par le terminal ou un \
         journal de session ; redirigez-la vers un fichier si nécessaire"
    );
}

/// Décrit la composition sous forme lisible.
fn describe(composition: Composition) -> String {
    match composition {
        Composition::Password { length, alphabet } => {
            format!("mot de passe de {length} caractères sur un alphabet de {alphabet} symboles")
        }
        Composition::Passphrase {
            words,
            list_size,
            separator_choices,
        } => {
            if separator_choices > 1 {
                format!(
                    "phrase de {words} mots d'une liste de {list_size} entrées, \
                     séparateur choisi parmi {separator_choices}"
                )
            } else {
                format!(
                    "phrase de {words} mots d'une liste de {list_size} entrées, \
                     séparateur fixe (aucun apport d'entropie)"
                )
            }
        }
        Composition::Secret {
            bytes,
            symbols,
            alphabet,
        } => format!(
            "secret de {symbols} symboles sur un alphabet de {alphabet}, \
             à partir de {bytes} unités d'aléa"
        ),
    }
}

/// Libellé français d'une bande.
fn band_label(band: Band) -> &'static str {
    band.label()
}

/// Lit un paramètre numérique.
fn parse_number(
    matches: &ArgMatches,
    name: &str,
    default: usize,
) -> Result<usize, crate::CliError> {
    match matches.get_one::<String>(name) {
        None => Ok(default),
        Some(text) => text.parse::<usize>().map_err(|_| {
            crate::CliError(format!(
                "« {name} » attend un entier positif, reçu « {text} »"
            ))
        }),
    }
}
