//! Commandes `backup` : créer une sauvegarde, et la tester.
//!
//! # Le geste central
//!
//! Une sauvegarde jamais restaurée n'est pas une sauvegarde : c'est une copie de fichier
//! dont personne ne sait si elle s'ouvre. `backup create` **vérifie donc la copie qu'il
//! vient de faire**, et échoue si elle est incohérente — quitte à la retirer.
//!
//! # Ce que ces commandes ne font pas
//!
//! * **aucune commande de restauration.** Restaurer écrase un coffre vivant, c'est
//!   précisément l'opération qu'il ne faut pas pouvoir déclencher par accident. La
//!   procédure est **documentée** et **rappelée par `backup verify`**, avec les deux
//!   chemins exacts ;
//! * **aucun format nouveau**. Le fichier de sauvegarde *est* un coffre, et son
//!   répertoire de blobs est celui d'un coffre : `info`, `verify` et `attach verify`
//!   l'ouvrent sans une ligne de code supplémentaire.

use std::path::{Path, PathBuf};

use clap::Command;

use passlock_core::backup::{self, Age, Integrity};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

use passlock_platform::fs::Durability;

use crate::{
    CliError, CliResult, GlobalOptions, hex, read_unlock_material, report_diagnostics,
    report_hardening, vault_argument, vault_path,
};

// ---------------------------------------------------------------------------
// Définitions
// ---------------------------------------------------------------------------

/// Sous-commandes de `backup`.
pub(crate) fn command() -> Command {
    Command::new("backup")
        .about("Sauvegarde un coffre, et teste une sauvegarde")
        .long_about(
            "Une sauvegarde est un **couple de chemins** : le fichier de coffre et son \
             répertoire de pièces jointes. Aucun format nouveau, aucune archive : le fichier \
             produit est un coffre, ouvrable par les commandes ordinaires.

             La copie a lieu **sous verrou exclusif** du coffre, puis elle est **vérifiée**. \
             Une sauvegarde que la vérification refuse n'est pas produite : elle est retiree.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .about("Copie le coffre et ses pièces jointes, puis vérifie la copie")
                .arg(vault_argument())
                .arg(
                    clap::Arg::new("destination")
                        .value_name("DESTINATION")
                        .required(true)
                        .help("Chemin du fichier de sauvegarde (doit ne pas exister)"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Teste une sauvegarde : l'ouvre et vérifie ses pièces jointes")
                .long_about(
                    "Ouvre la sauvegarde, décode son archive, et déchiffre **chaque pièce \
                     jointe** pour contrôler son intégrité.

                     **Aucun effet persistant** : le test ne crée aucun fichier, ne répare \
                     aucune permission, n'écrit aucune sentinelle et ne modifie pas la \
                     sauvegarde. C'est une garantie du code, pas une promesse.

                     Deux verdicts **séparés** sont rendus : l'**intégrité** (seule source de \
                     succès ou d'échec) et l'**ancienneté** (une information — restaurer une \
                     sauvegarde ancienne est légitime).",
                )
                .arg(
                    clap::Arg::new("vault")
                        .value_name("SAUVEGARDE")
                        .required(true)
                        .help("Chemin de la sauvegarde à tester"),
                ),
        )
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

/// Aiguille vers les sous-commandes de `backup`.
pub(crate) fn cmd_backup(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    match matches.subcommand() {
        Some(("create", sub)) => cmd_create(sub, options, config),
        Some(("verify", sub)) => cmd_verify(sub, options, config),
        _ => Err(CliError("sous-commande « backup » inconnue".to_string())),
    }
}

fn cmd_create(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let destination = PathBuf::from(
        matches
            .get_one::<String>("destination")
            .ok_or_else(|| CliError("destination manquante".to_string()))?,
    );

    report_hardening(options.hardening);
    let material = read_unlock_material(options)?;

    // **Verrou exclusif**, et ouverture en lecture seule : la sauvegarde ne doit rien
    // écrire au coffre, et doit pourtant en geler l'ensemble {coffre, blobs} pendant
    // qu'elle le copie.
    let locked = VaultConfig {
        read_only: true,
        require_exclusive_lock: true,
        ..config.clone()
    };
    let store = VaultStore::open_with(&path, &material.credentials(), &locked)?;
    report_diagnostics(store.vault());

    let outcome = backup::create(&store, &destination, &material.credentials(), config)?;

    println!("Sauvegarde créée : {}", outcome.destination.display());
    eprintln!("  coffre et {} pièce(s) jointe(s)", outcome.blobs);
    eprintln!("  {} octet(s) copiés au total", outcome.bytes);
    report_durability(outcome.durability);

    if outcome.blobs > 0 {
        eprintln!();
        eprintln!(
            "Les pièces jointes sont dans {}.",
            passlock_core::attachment::blob_dir_for(&outcome.destination).display()
        );
        eprintln!(
            "Les deux chemins forment **un seul** ensemble : copier l'un sans l'autre donne\n\
             une sauvegarde dont les pièces jointes manquent."
        );
    }

    eprintln!();
    eprintln!("La copie a été **vérifiée** avant d'être annoncée : elle s'ouvre, et son");
    eprintln!("archive et ses pièces jointes sont cohérentes.");
    eprintln!();
    eprintln!("Rejouez le test à tout moment :");
    eprintln!("  passlock backup verify {}", outcome.destination.display());
    report_restore_procedure(&outcome.destination);
    Ok(())
}

fn cmd_verify(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let file = vault_path(matches)?;

    report_hardening(options.hardening);
    let material = read_unlock_material(options)?;

    // `backup::verify` force lui-même la lecture seule : ce n'est pas à cet appelant de
    // décider si le test peut écrire quoi que ce soit.
    let report = backup::verify(&file, &material.credentials(), config)?;

    println!("Sauvegarde testée : {}", file.display());
    println!(
        "  coffre {} — génération {}",
        hex(&report.vault_id),
        report.generation
    );
    println!(
        "  {} entrée(s), {} pièce(s) jointe(s), schéma v{}",
        report.entries, report.attachments, report.schema_version
    );
    println!(
        "  dérivation du slot maître : Argon2id, {} Kio, {} itération(s), {} voie(s)",
        report.params_micro.0, report.params_micro.1, report.params_micro.2
    );
    println!();

    // Verdict d'INTÉGRITÉ — la seule source de succès ou d'échec.
    match &report.integrity {
        Integrity::Sound => {
            println!("INTÉGRITÉ : la sauvegarde est complète et cohérente.");
            if report.attachments > 0 {
                println!(
                    "  {} pièce(s) jointe(s) déchiffrée(s) et vérifiée(s) dans {}.",
                    report.attachments,
                    report.blob_dir.display()
                );
            }
        }
        Integrity::Broken { reasons } => {
            println!("INTÉGRITÉ : DÉFAUTS CONSTATÉS");
            for reason in reasons {
                println!("  - {reason}");
            }
        }
    }

    // Verdict d'ANCIENNETÉ — une information, jamais une erreur.
    match &report.age {
        Age::Current => {}
        Age::Older { known, found } => {
            eprintln!();
            eprintln!(
                "ANCIENNETÉ : cette sauvegarde est à la génération {found}, alors que le\n\
                 dernier état connu est {known}."
            );
            eprintln!(
                "  C'est **normal** pour une sauvegarde : elle est forcément antérieure à\n\
                 l'état courant. Restaurer fait réapparaître les entrées supprimées depuis,\n\
                 et l'alerte de retour en arrière se déclenchera à l'ouverture — c'est le\n\
                 comportement voulu, pas une compromission."
            );
        }
        Age::Unknown => {
            eprintln!();
            eprintln!(
                "ANCIENNETÉ : indéterminée — aucune référence pour ce coffre sur cette machine.\n\
                 Ce n'est pas un échec : c'est l'état normal d'une sauvegarde testée ailleurs."
            );
        }
        Age::SentinelCorrupted => {
            eprintln!();
            eprintln!("ANCIENNETÉ : indéterminée — la référence existait mais est inutilisable.");
        }
    }

    if report.migrated_from.is_some() {
        eprintln!();
        eprintln!(
            "Note : cette sauvegarde porte un schéma antérieur ; elle a été migrée **en\n\
             mémoire**. Rien n'a été écrit."
        );
    }

    if report.params_below_recommendation {
        eprintln!();
        eprintln!(
            "Avertissement : les paramètres de dérivation de cette sauvegarde sont plus faibles\n\
             que le profil par défaut actuel. Un attaquant qui obtiendrait le fichier le\n\
             casserait plus vite. `change-password` sur le coffre restauré permet de les durcir."
        );
    }

    report_restore_procedure(&file);

    if report.is_sound() {
        Ok(())
    } else {
        Err(CliError(
            "la sauvegarde présente des défauts d'intégrité ; ce test ne répare rien".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Rappelle la procédure de restauration, avec les deux chemins exacts.
///
/// Elle n'est **pas** exécutable par une commande : écraser un coffre vivant est
/// précisément ce qu'il ne faut pas pouvoir déclencher par accident. Elle est donc
/// documentée, et rappelée là où l'utilisateur en a besoin.
fn report_restore_procedure(backup_path: &Path) {
    let blobs = passlock_core::attachment::blob_dir_for(backup_path);

    eprintln!();
    eprintln!("Restauration — à faire vous-même, en deux copies :");
    eprintln!();
    eprintln!("  cp {} <coffre>", backup_path.display());
    eprintln!("  cp -a {} <coffre>.attachments", blobs.display());
    eprintln!();
    eprintln!(
        "Les deux lignes sont nécessaires : la première seule donne un coffre dont les\n\
         pièces jointes manquent. Si la sauvegarde n'en contient aucune, la seconde est sans\n\
         objet."
    );
    eprintln!();
    eprintln!("Aucune commande ne fait cette copie : écraser un coffre vivant ne doit pas");
    eprintln!("pouvoir être déclenché par une faute de frappe.");
}

/// Signale un niveau de durabilité réduit.
///
/// Une capacité absente n'est **pas** un échec : la sauvegarde est produite normalement.
/// Elle est **annoncée**, parce qu'une garantie absente et tue ne vaut pas mieux qu'une
/// garantie absente.
fn report_durability(durability: Durability) {
    if !durability.directory_entry_is_durable() {
        eprintln!();
        eprintln!(
            "Avertissement de durabilité : sur cette plateforme, la persistance du **nom**\n\
             des fichiers de cette sauvegarde n'est pas garantie après une coupure\n\
             d'alimentation — leur contenu est synchronisé, pas leur entrée de répertoire.\n\
             Vérifiez la sauvegarde avant de compter sur elle."
        );
    }
}
