//! Commandes `export` et `import` : échange CSV canonique.
//!
//! # Ce que ces commandes manipulent
//!
//! Du **texte en clair**. L'export écrit toutes les entrées, leurs champs, leurs
//! dossiers et leurs tags dans un fichier lisible par n'importe quel outil. C'est une
//! fuite délibérée et massive : elle n'a lieu que sur demande explicite, et **jamais
//! par défaut sur la sortie standard**. La destination est donc choisie : `--output`
//! pour un fichier, `--stdout` pour un tube.
//!
//! Aucun secret n'est demandé en argument de commande : le mot de passe maître l'est
//! par l'invite habituelle — ou sur l'entrée standard avec `--password-stdin`, ce qui
//! interdit alors de faire venir le CSV par le même canal.
//!
//! # L'import est transactionnel
//!
//! Tout est analysé et validé **avant** la moindre écriture, et une seule écriture du
//! coffre est déclenchée, à la fin. Un import qui échoue ne laisse donc **aucune
//! modification persistante** — ni entrée, ni dossier, ni tag.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use passlock_core::portability;
use passlock_core::vault::VaultConfig;

use passlock_platform::fs;

use crate::{
    CliError, CliResult, GlobalOptions, now_seconds, open_store, vault_argument, vault_path,
};

/// Sous-commande `export`.
pub(crate) fn export_command() -> Command {
    Command::new("export")
        .about("Exporte le coffre au format CSV canonique — en clair")
        .long_about(
            "Écrit toutes les entrées, leurs champs, leurs dossiers et leurs tags dans \
             un CSV déterministe.

             **Le contenu est en clair.** Le format ne conserve ni les pièces jointes, \
             ni l'historique, ni la corbeille, ni les réglages. Un fichier exporté n'est \
             donc pas une sauvegarde : pour sauvegarder un coffre, utilisez `backup`.

             La destination est obligatoire : `--output` écrit un fichier neuf (jamais \
             écrasé, permissions réservées au propriétaire), `--stdout` écrit vers la \
             sortie standard. Rien n'est écrit par défaut.

             L'export est **reproductible** : deux coffres de même contenu produisent le \
             même fichier, quel que soit l'ordre d'insertion et quels que soient leurs \
             identifiants internes.",
        )
        .arg(vault_argument())
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("FICHIER")
                .help("Écrit l'export dans ce fichier (refusé s'il existe déjà)"),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .action(ArgAction::SetTrue)
                .help("Écrit l'export sur la sortie standard"),
        )
}

/// Sous-commande `import`.
pub(crate) fn import_command() -> Command {
    Command::new("import")
        .about("Importe des entrées depuis un CSV canonique")
        .long_about(
            "Ajoute au coffre les entrées d'un fichier CSV canonique.

             L'import est **transactionnel** : le fichier est entièrement analysé et \
             validé avant toute écriture, et une seule écriture du coffre a lieu à la \
             fin. Un CSV refusé laisse le coffre **strictement inchangé**.

             Les entrées **s'ajoutent** aux données existantes. Les dossiers et les tags \
             de même nom sont réutilisés, jamais dupliqués. Les identifiants internes \
             sont neufs : l'import ne « restaure » pas un coffre, il y verse des entrées.",
        )
        .arg(vault_argument())
        .arg(
            Arg::new("input")
                .long("input")
                .value_name("FICHIER")
                .required(true)
                .help("Fichier CSV à importer"),
        )
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

/// Exporte le coffre.
pub(crate) fn cmd_export(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let to_stdout = matches.get_flag("stdout");
    let output = matches.get_one::<String>("output").map(PathBuf::from);

    if to_stdout == output.is_some() {
        return Err(CliError(
            "précisez exactement l'un des deux : --output <FICHIER> ou --stdout".to_string(),
        ));
    }

    // Export **strictement sans effet** : lecture seule imposée, aucun verrou, aucune
    // sentinelle, aucune migration écrite.
    let read_only = VaultConfig {
        read_only: true,
        ..config.clone()
    };
    let store = open_store(&path, options, &read_only)?;

    let entries = store
        .archive()
        .entries
        .iter()
        .filter(|entry| !entry.is_trashed())
        .count();
    let bytes = portability::export(store.archive())?;

    if let Some(destination) = output {
        write_private(&destination, &bytes)?;
        eprintln!(
            "Export terminé : {entries} entrée(s), {} octet(s) vers {}.",
            bytes.len(),
            destination.display()
        );
        warn_cleartext();
    } else {
        // Le clair part sur la sortie standard, seul.
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(&bytes)?;
        lock.flush()?;
        eprintln!(
            "Export terminé : {entries} entrée(s), {} octet(s).",
            bytes.len()
        );
        warn_cleartext();
    }
    Ok(())
}

/// Importe un CSV dans le coffre.
pub(crate) fn cmd_import(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let input = PathBuf::from(required(matches, "input")?);

    // La borne est appliquée **à la lecture** : un fichier trop gros est refusé avant
    // d'être chargé en mémoire.
    let bytes = fs::read_file(&input, portability::MAX_CSV_BYTES)
        .map_err(|err| CliError(format!("lecture de {} : {err}", input.display())))?;

    let mut store = open_store(&path, options, config)?;

    // Analyse et validation complètes, puis application. Une erreur ici n'a rien écrit.
    let report = portability::import(&mut store, &bytes, now_seconds())?;

    // L'unique écriture. Un échec avant cette ligne laisse le coffre intact.
    store.save()?;

    println!("{} entrée(s) importée(s).", report.entries);
    eprintln!("  {} dossier(s) créé(s)", report.folders_created);
    eprintln!("  {} tag(s) créé(s)", report.tags_created);
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Écrit un fichier neuf : création exclusive, permissions privées, durabilité.
///
/// Même motif que l'écriture d'un fichier-clé : `create_private_file` refuse une cible
/// existante, et le nettoyage ne retire **que** ce que cette fonction a créé.
fn write_private(destination: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let dir = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut file = fs::create_private_file(destination).map_err(|err| {
        CliError(format!(
            "création de {} : {err} — un export n'écrase jamais un fichier existant",
            destination.display()
        ))
    })?;

    let level = match file
        .write_all(bytes)
        .and_then(|()| fs::make_durable(&file, dir))
    {
        Ok(level) => level,
        Err(err) => {
            // Le fichier est bien le nôtre : on l'a créé en exclusif à l'instant.
            let _ = fs::remove_file(destination);
            return Err(CliError(format!(
                "écriture de {} : {err}",
                destination.display()
            )));
        }
    };
    drop(file);

    if !level.directory_entry_is_durable() {
        eprintln!(
            "Avertissement de durabilité : sur cette plateforme, la persistance du **nom**\n\
             de ce fichier n'est pas garantie après une coupure d'alimentation — son contenu\n\
             est synchronisé, pas son entrée de répertoire."
        );
    }
    Ok(())
}

/// Rappelle que l'export est en clair.
fn warn_cleartext() {
    eprintln!(
        "Attention : ce fichier est **en clair**. Il contient vos mots de passe et vos\n\
         secrets sans chiffrement. Rangez-le ou détruisez-le après usage — ce n'est pas\n\
         une sauvegarde."
    );
}

/// Lit un argument obligatoire.
fn required<'a>(matches: &'a clap::ArgMatches, name: &str) -> Result<&'a String, CliError> {
    matches
        .get_one::<String>(name)
        .ok_or_else(|| CliError(format!("argument « {name} » manquant")))
}
