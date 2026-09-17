//! Commandes `attach` : pièces jointes d'une entrée.
//!
//! # Deux règles qui gouvernent tout ce module
//!
//! **1. La vérification et le ramasse-miettes ne se mélangent pas.** `attach verify`
//! observe et signale ; `attach gc` supprime, et **uniquement** ce que le balayage a
//! classé comme orphelin. Une pièce jointe référencée mais **corrompue** n'est ni
//! orpheline ni absente : elle est présente, donc jamais candidate à la suppression.
//! Sans cette séparation, une corruption deviendrait une perte de données par l'effet
//! d'un outil de maintenance.
//!
//! **2. Aucune E/S directe.** Ce module n'appelle ni `std::fs`, ni `Path::exists`, ni
//! une suppression de fichier : tout passe par les primitives de `passlock-platform`,
//! qui portent les garanties de la phase 1 — marche sans lien symbolique, création
//! exclusive, permissions posées à la création, durabilité rendue et vérifiée. Un
//! raccourci ici contournerait ces garanties sans que rien ne le signale.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use passlock_core::attachment::{self, BlobSweep};
use passlock_core::model::{AttachmentMeta, BlobId, EntryId};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

use passlock_platform::fs;

use crate::{CliError, CliResult, GlobalOptions, hex, open_store, vault_argument, vault_path};

/// Sous-commandes de `attach`.
pub(crate) fn command() -> Command {
    Command::new("attach")
        .about("Gère les pièces jointes chiffrées d'une entrée")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Attache un fichier à une entrée")
                .arg(vault_argument())
                .arg(Arg::new("entry").value_name("ENTRÉE").required(true))
                .arg(Arg::new("file").value_name("FICHIER").required(true))
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("NOM")
                        .help("Nom d'affichage (défaut : nom du fichier)"),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("Liste les pièces jointes")
                .arg(vault_argument())
                .arg(Arg::new("entry").value_name("ENTRÉE")),
        )
        .subcommand(
            Command::new("get")
                .about("Restitue le contenu d'une pièce jointe")
                .long_about(
                    "Écrit le contenu **en clair** vers un fichier.

                     Le contenu n'est publié qu'après vérification complète : une pièce \
                     jointe tronquée ou corrompue ne se présente jamais comme un fichier \
                     complet. Le nom de sortie est refusé s'il existe déjà.

                     La sortie standard n'est pas utilisée par défaut — un binaire sur un \
                     terminal est inutilisable. `--stdout` est explicite.",
                )
                .arg(vault_argument())
                .arg(Arg::new("blob").value_name("BLOB-ID").required(true))
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_name("CHEMIN")
                        .help("Fichier de destination (refusé s'il existe déjà)"),
                )
                .arg(
                    Arg::new("stdout")
                        .long("stdout")
                        .action(ArgAction::SetTrue)
                        .help("Écrit le contenu sur la sortie standard"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Vérifie les pièces jointes, sans rien modifier")
                .long_about(
                    "Déchiffre chaque pièce jointe et contrôle son intégrité : nombre de \
                     morceaux, taille, empreinte de contenu.

                     **Cette commande ne supprime rien et ne répare rien.** Une pièce \
                     jointe absente est signalée comme une incohérence, et un fichier \
                     étranger présent dans le répertoire des blobs est mentionné sans \
                     être touché.",
                )
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("rm")
                .about("Détache une pièce jointe d'une entrée")
                .long_about(
                    "Retire la métadonnée, enregistre le coffre, puis supprime le fichier.

                     L'ordre est celui qui ne peut pas produire d'incohérence : le coffre \
                     cesse de référencer la pièce jointe **avant** que le fichier \
                     disparaisse. Un incident entre les deux laisse un orphelin, que \
                     `attach gc` récupère.",
                )
                .arg(vault_argument())
                .arg(Arg::new("blob").value_name("BLOB-ID").required(true)),
        )
        .subcommand(
            Command::new("gc")
                .about("Supprime les blobs orphelins")
                .long_about(
                    "Supprime les fichiers du répertoire des blobs qu'aucune métadonnée ne \
                     référence.

                     **Aucun blob référencé n'est touché**, même corrompu : un blob \
                     référencé mais illisible est un problème d'intégrité, pas un déchet. \
                     Les fichiers étrangers sont signalés et **jamais supprimés**.

                     La suppression est irréversible, et elle n'est pas physique : les \
                     données peuvent subsister sur le support (SSD, TRIM) et dans toute \
                     sauvegarde déjà écrite.",
                )
                .arg(vault_argument())
                .arg(
                    Arg::new("confirm")
                        .long("confirm")
                        .value_name("IDENTIFIANT")
                        .required(true)
                        .help("Recopiez l'identifiant du coffre affiché par `info`"),
                ),
        )
}

// ---------------------------------------------------------------------------
// Exécution
// ---------------------------------------------------------------------------

/// Aiguille vers les sous-commandes de `attach`.
pub(crate) fn cmd_attachment(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    match matches.subcommand() {
        Some(("add", sub)) => cmd_add(sub, options, config),
        Some(("list", sub)) => cmd_list(sub, options, config),
        Some(("get", sub)) => cmd_get(sub, options, config),
        Some(("verify", sub)) => cmd_verify(sub, options, config),
        Some(("rm", sub)) => cmd_remove(sub, options, config),
        Some(("gc", sub)) => cmd_gc(sub, options, config),
        _ => Err(CliError("sous-commande « attach » inconnue".to_string())),
    }
}

fn cmd_add(matches: &clap::ArgMatches, options: &GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    let entry = entry_id(matches, "entry")?;
    let source = PathBuf::from(required(matches, "file")?);

    // Le nom d'affichage vaut par défaut le nom du fichier : c'est ce que l'utilisateur
    // reconnaîtra. Il n'est **jamais** utilisé comme chemin.
    let name = match matches.get_one::<String>("name") {
        Some(name) => name.clone(),
        None => source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| CliError("le chemin source n'a pas de nom de fichier".to_string()))?,
    };

    let mut store = open_store(&path, options, config)?;
    let meta = store.add_attachment(&entry, &name, &source)?;
    // L'ordre est celui d'`I-BLOB-ORDER` : le blob est déjà durable, la métadonnée
    // n'atteint le disque qu'ici.
    store.save()?;

    println!("Pièce jointe attachée à {entry} : {name}");
    eprintln!(
        "  {} octet(s) en clair, {} morceau(x) de {} Kio",
        meta.size,
        meta.chunk_count,
        meta.chunk_size / 1024
    );
    eprintln!("  identifiant du blob : {}", meta.id.to_hex());
    eprintln!();
    eprintln!(
        "Le contenu est chiffré sous une clé dédiée, séparée du conteneur. Une sauvegarde\n\
         du seul fichier de coffre ne suffit donc pas à préserver cette pièce jointe : la\n\
         sauvegarde devra inclure le répertoire des blobs."
    );
    Ok(())
}

fn cmd_list(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let entry = match matches.get_one::<String>("entry") {
        Some(raw) => Some(parse_entry(raw)?),
        None => None,
    };

    let store = open_store(&path, options, config)?;

    let selected: Vec<&AttachmentMeta> = match entry {
        Some(id) => store.attachments_of(&id),
        None => store.archive().attachments.iter().collect(),
    };

    if selected.is_empty() {
        println!("Aucune pièce jointe.");
        return Ok(());
    }

    println!("{} pièce(s) jointe(s) :\n", selected.len());
    for meta in selected {
        println!(
            "  {} — {}\n     entrée {}, {} octet(s), {} morceau(x), {}",
            meta.id.to_hex(),
            meta.name,
            meta.entry,
            meta.size,
            meta.chunk_count,
            crate::format_timestamp(meta.created_at)
        );
    }
    Ok(())
}

fn cmd_get(matches: &clap::ArgMatches, options: &GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    let id = parse_blob(required(matches, "blob")?)?;
    let to_stdout = matches.get_flag("stdout");
    let output = matches.get_one::<String>("output").map(PathBuf::from);

    if to_stdout == output.is_some() {
        return Err(CliError(
            "précisez exactement l'un des deux : --output <CHEMIN> ou --stdout".to_string(),
        ));
    }

    let store = open_store(&path, options, config)?;
    let meta = store
        .attachment(&id)
        .ok_or_else(|| CliError("pièce jointe inconnue".into()))?;
    let blob = store.blob_path(&id)?;

    let keys = store.vault().subkeys();
    let vault_id = store.vault().header().vault_id;

    if let Some(destination) = output {
        restore_to_file(&blob, meta, keys, &vault_id, &destination)?;
    } else {
        // `--stdout` : le clair part sur la sortie standard, seul.
        let mut reader = attachment::AttachmentReader::open(&blob, meta, keys, &vault_id)?;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        reader.read_all(&mut lock)?;
        lock.flush()?;
    }
    Ok(())
}

fn cmd_verify(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    let keys = store.vault().subkeys();
    let vault_id = store.vault().header().vault_id;
    let mut intact = 0_usize;
    let mut broken: Vec<(BlobId, String)> = Vec::new();

    for meta in &store.archive().attachments {
        match store.blob_path(&meta.id) {
            Ok(blob) => match attachment::verify_blob(&blob, meta, keys, &vault_id) {
                Ok(()) => intact += 1,
                Err(err) => broken.push((meta.id, err.to_string())),
            },
            Err(err) => broken.push((meta.id, err.to_string())),
        }
    }

    let sweep = sweep(&store)?;

    println!(
        "{} pièce(s) jointe(s) : {intact} intacte(s), {} en défaut.",
        store.archive().attachments.len(),
        broken.len()
    );
    for (id, reason) in &broken {
        println!("  DÉFAUT {} — {reason}", id.to_hex());
    }

    // Les trois constats du balayage sont **séparés**, parce qu'ils n'appellent pas la
    // même décision. Aucun n'entraîne de modification : cette commande observe.
    report_sweep(&sweep);

    if !broken.is_empty() || !sweep.is_consistent() {
        return Err(CliError(
            "des incohérences subsistent ; `attach verify` ne répare rien et ne supprime \
             rien"
                .to_string(),
        ));
    }
    Ok(())
}

fn cmd_remove(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let id = parse_blob(required(matches, "blob")?)?;

    let mut store = open_store(&path, options, config)?;
    let meta = store.remove_attachment(&id)?;
    // `I-BLOB-ORDER`, sens inverse : métadonnée **retirée et enregistrée** d'abord,
    // fichier ensuite. Un incident entre les deux laisse un orphelin, jamais une
    // métadonnée sans son blob.
    store.save()?;

    let purged = match store.purge_blob(&id) {
        Ok(()) => true,
        Err(err) => {
            eprintln!(
                "Avertissement : le fichier n'a pas pu être supprimé ({err}). Il devient un\n\
                 orphelin ; `attach gc` le récupérera."
            );
            false
        }
    };

    println!("Pièce jointe détachée : {}", meta.name);
    eprintln!(
        "  blob {}",
        if purged {
            "supprimé"
        } else {
            "laissé en place"
        }
    );
    eprintln!();
    eprintln!(
        "La suppression n'est pas physique : des blocs peuvent subsister sur le support\n\
         (SSD, TRIM) et dans toute sauvegarde déjà écrite."
    );
    Ok(())
}

fn cmd_gc(matches: &clap::ArgMatches, options: &GlobalOptions, config: &VaultConfig) -> CliResult {
    let path = vault_path(matches)?;
    let store = open_store(&path, options, config)?;

    // Confirmation par recopie de l'identifiant du coffre : la seule opération du
    // produit qui retire des fichiers ne doit pas pouvoir être déclenchée par une faute
    // de frappe.
    let expected = hex(&store.vault().header().vault_id);
    if required(matches, "confirm")?.trim() != expected {
        return Err(CliError(
            "la confirmation ne correspond pas à l'identifiant du coffre : rien n'a été \
             supprimé"
                .to_string(),
        ));
    }

    let sweep = sweep(&store)?;

    // On montre **avant** de supprimer, et on ne supprime que la catégorie qui peut
    // l'être.
    report_sweep(&sweep);

    if !sweep.missing.is_empty() {
        eprintln!(
            "Les pièces jointes absentes ci-dessus sont des **erreurs d'intégrité**, pas des\n\
             déchets : il n'y a rien à supprimer, et le coffre les référence toujours."
        );
    }

    let mut removed = 0_usize;
    for name in &sweep.orphans {
        let Some(text) = name.to_str() else {
            return Err(CliError(
                "un nom d'orphelin n'est pas de l'UTF-8 : rien d'autre n'a été supprimé"
                    .to_string(),
            ));
        };
        // Le magasin **revalide** le nom avant toute suppression : cette boucle ne peut
        // donc pas viser un fichier étranger, quoi qu'ait rendu le balayage.
        store.delete_blob_by_name(text)?;
        removed += 1;
    }

    if removed == 0 {
        println!("Aucun blob orphelin à supprimer.");
    } else {
        println!("{removed} blob(s) orphelin(s) supprimé(s).");
        eprintln!();
        eprintln!(
            "La suppression n'est pas physique : des blocs peuvent subsister sur le support\n\
             et dans toute sauvegarde déjà écrite."
        );
    }

    if !sweep.unexpected.is_empty() {
        eprintln!(
            "Les fichiers étrangers ci-dessus n'ont **pas** été supprimés : rien ne prouve\n\
             qu'ils appartiennent à Passlock."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Balaye le répertoire des blobs du magasin.
fn sweep(store: &VaultStore) -> Result<BlobSweep, CliError> {
    Ok(attachment::sweep_blobs(
        &store.attachment_dir(),
        store.archive(),
        store.vault().subkeys(),
        &store.vault().header().vault_id,
    )?)
}

/// Affiche les trois constats du balayage, **séparément**.
fn report_sweep(sweep: &BlobSweep) {
    if sweep.orphans.is_empty() && sweep.unexpected.is_empty() && sweep.missing.is_empty() {
        eprintln!("Le répertoire des blobs est cohérent avec le coffre.");
        return;
    }
    if !sweep.orphans.is_empty() {
        eprintln!("Blobs orphelins (supprimables) : {}", sweep.orphans.len());
    }
    if !sweep.missing.is_empty() {
        eprintln!(
            "Pièces jointes référencées mais ABSENTES : {} — incohérence d'intégrité",
            sweep.missing.len()
        );
        for id in &sweep.missing {
            eprintln!("  {} (fichier introuvable)", id.to_hex());
        }
    }
    if !sweep.unexpected.is_empty() {
        eprintln!(
            "Fichiers étrangers dans le répertoire (jamais supprimés) : {}",
            sweep.unexpected.len()
        );
        for name in &sweep.unexpected {
            eprintln!("  {}", name.to_string_lossy());
        }
    }
}

/// Restitue un blob vers un fichier, **sans jamais publier un contenu partiel**.
///
/// Le clair est écrit dans un fichier temporaire, rendu durable, et **publié seulement
/// après** le verdict de fin de flux. La publication refuse une cible existante :
/// écraser un fichier de l'utilisateur serait une perte de données.
fn restore_to_file(
    blob: &Path,
    meta: &AttachmentMeta,
    keys: &passlock_core::keys::SubKeys,
    vault_id: &[u8; 16],
    destination: &Path,
) -> Result<(), CliError> {
    let temp = temporary_name(destination)?;

    // Création **exclusive** du temporaire : `O_EXCL`. Un nom tiré du générateur du
    // système rend en outre la pré-création impraticable.
    let mut file = fs::create_private_file(&temp).map_err(|err| {
        CliError(format!(
            "création du fichier temporaire {} : {err}",
            temp.display()
        ))
    })?;

    let read = (|| -> Result<(), CliError> {
        let mut reader = attachment::AttachmentReader::open(blob, meta, keys, vault_id)?;
        reader.read_all(&mut file)?;
        Ok(())
    })();

    if let Err(err) = read {
        drop(file);
        // Le temporaire est le nôtre : on le retire. La destination, elle, n'a jamais
        // été touchée.
        let _ = fs::remove_file(&temp);
        return Err(err);
    }

    let durable = fs::make_durable(&file, &parent_of(destination))
        .map_err(|err| CliError(format!("synchronisation du fichier temporaire : {err}")));
    drop(file);
    if let Err(err) = durable {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    if !durable_ok() {
        eprintln!(
            "Avertissement de durabilité : sur cette plateforme, le **nom** du fichier de\n\
             sortie peut ne pas survivre à une coupure d'alimentation. Son contenu, lui, est\n\
             synchronisé."
        );
    }

    // Publication : refuse une cible existante. C'est ici que le contenu devient
    // visible, et seulement s'il est complet.
    if let Err(err) = fs::publish_no_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(CliError(format!(
            "publication vers {} : {err} — la destination n'a pas été modifiée",
            destination.display()
        )));
    }

    println!("Pièce jointe restituée : {}", destination.display());
    eprintln!("  {} octet(s) écrits.", meta.size);
    Ok(())
}

/// Vrai si la plateforme revendique la durabilité de l'entrée de répertoire.
fn durable_ok() -> bool {
    fs::platform_durability().directory_entry_is_durable()
}

/// Nom du fichier temporaire, dans le **même répertoire** que la destination.
///
/// La proximité n'est pas cosmétique : la publication repose sur un lien, qui ne
/// traverse pas les systèmes de fichiers.
fn temporary_name(destination: &Path) -> Result<PathBuf, CliError> {
    let random = passlock_core::rng::array::<8>()?;
    let mut name = destination
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    name.push(format!(".partiel-{}", hex(&random)));

    let parent = parent_of(destination);
    Ok(parent.join(name))
}

/// Répertoire parent, ou le répertoire courant si le chemin n'en porte pas.
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Lit un argument obligatoire.
fn required<'a>(matches: &'a clap::ArgMatches, name: &str) -> Result<&'a String, CliError> {
    matches
        .get_one::<String>(name)
        .ok_or_else(|| CliError(format!("argument « {name} » manquant")))
}

fn entry_id(matches: &clap::ArgMatches, name: &str) -> Result<EntryId, CliError> {
    parse_entry(required(matches, name)?)
}

fn parse_entry(raw: &str) -> Result<EntryId, CliError> {
    EntryId::from_hex(raw.trim()).map_err(|_| {
        CliError(format!(
            "identifiant d'entrée invalide : « {raw} » (attendu : 32 caractères hexadécimaux)"
        ))
    })
}

fn parse_blob(raw: &str) -> Result<BlobId, CliError> {
    BlobId::from_hex(raw.trim()).map_err(|_| {
        CliError(format!(
            "identifiant de pièce jointe invalide : « {raw} » (attendu : 32 caractères \
             hexadécimaux)"
        ))
    })
}
