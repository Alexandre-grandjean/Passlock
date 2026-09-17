//! Commandes `recovery` et `keyfile` : slots supplémentaires du coffre.
//!
//! # Un seul chemin de code
//!
//! Les deux mécanismes — clé de récupération transcrite, fichier-clé sur support
//! amovible — produisent une KEK par **le même chemin** : Argon2id sur le secret du
//! slot, puis HKDF. Ce module ne fait que fournir le matériel et choisir le rôle ; il
//! n'existe pas de chemin d'ouverture parallèle, et donc pas de chemin plus faible.
//!
//! # Ce que ces commandes ne font pas
//!
//! * elles ne rangent **rien** hors du coffre, sauf le fichier-clé que `keyfile new`
//!   écrit à l'emplacement demandé ;
//! * elles ne copient jamais la clé de récupération ailleurs : elle est affichée
//!   **une fois**, et c'est à l'utilisateur de la ranger ;
//! * elles n'acceptent **aucun secret en argument de commande** — la clé de
//!   récupération est lue par une invite masquée ou sur l'entrée standard.

use std::io::Write as _;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use passlock_core::header::SlotLabel;
use passlock_core::kdf::KdfParams;
use passlock_core::recovery::RecoveryKey;
use passlock_core::vault::{Vault, VaultConfig};

use crate::{
    CliError, CliResult, GlobalOptions, UnlockMode, hex, read_unlock_material, report_diagnostics,
    report_hardening, vault_argument, vault_path,
};

/// Longueur d'un fichier-clé : la même que la clé de récupération.
///
/// Un fichier-clé est un support de transport pour 256 bits aléatoires, pas un
/// format différent : lui donner une seconde longueur créerait un second chemin à
/// éprouver pour aucun bénéfice.
const KEY_FILE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Définitions
// ---------------------------------------------------------------------------

/// Sous-commandes de `recovery`.
pub(crate) fn recovery_command() -> Command {
    Command::new("recovery")
        .about("Gère la clé de récupération du coffre")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("new")
                .about("Crée une clé de récupération et l'installe dans le coffre")
                .long_about(
                    "Crée une clé de récupération de 256 bits, l'installe comme slot \
                     supplémentaire, puis l'affiche **une seule fois** sur la sortie standard.

                     La clé n'est écrite nulle part ailleurs : sans elle, et sans le mot de \
                     passe maître, le coffre devient définitivement illisible. Elle doit être \
                     rangée dans un lieu **physiquement distinct** des sauvegardes — une clé \
                     rangée à côté du disque de sauvegarde ne réduit aucun risque et en ajoute un.

                     Chaque slot est un chemin d'entrée supplémentaire : récupérabilité et \
                     résistance au vol varient en sens inverse.",
                )
                .arg(vault_argument())
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Remplace la clé de récupération existante"),
                ),
        )
        .subcommand(
            Command::new("test")
                .about("Vérifie qu'une clé de récupération ouvre réellement le coffre")
                .long_about(
                    "Déverrouille le coffre avec la clé de récupération et rien d'autre.

                     Une clé de récupération jamais essayée n'est pas une clé de récupération : \
                     c'est une chaîne de caractères. Cette commande est la seule façon de savoir \
                     si elle fonctionne avant d'en avoir besoin.",
                )
                .arg(vault_argument()),
        )
        .subcommand(
            Command::new("remove")
                .about("Révoque la clé de récupération")
                .long_about(
                    "Retire le slot de récupération du coffre.

                     Cela ne reprend **pas** une copie déjà faite de la clé : si elle a été \
                     photographiée ou recopiée, elle doit être considérée comme compromise.

                     Cela ne modifie pas non plus les sauvegardes antérieures, qui contiennent \
                     toujours le slot.",
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

/// Sous-commandes de `keyfile`.
pub(crate) fn keyfile_command() -> Command {
    Command::new("keyfile")
        .about("Gère un fichier-clé sur support amovible")
        .long_about(
            "Un fichier-clé est un fichier de 32 octets aléatoires, rangé sur un support \
             amovible. C'est le mécanisme que le ROADMAP appelle « clé matérielle » : la KEK \
             provient du support au lieu d'être dérivée d'une phrase.

             Ce n'est **pas** un facteur de possession inviolable : un fichier se copie. Il \
             doit donc être rangé sur un support distinct du coffre et des sauvegardes, et \
             n'être présent que pendant l'ouverture.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("new")
                .about("Crée un fichier-clé et l'installe dans le coffre")
                .arg(vault_argument())
                .arg(
                    Arg::new("key-file")
                        .long("key-file")
                        .value_name("CHEMIN")
                        .required(true)
                        .help("Emplacement où écrire le fichier-clé (doit être sur un support amovible)"),
                ),
        )
        .subcommand(
            Command::new("test")
                .about("Vérifie qu'un fichier-clé ouvre réellement le coffre")
                .arg(vault_argument())
                .arg(
                    Arg::new("key-file")
                        .long("key-file")
                        .value_name("CHEMIN")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Révoque la clé matérielle")
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

/// Aiguille vers les sous-commandes de `recovery`.
pub(crate) fn cmd_recovery(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    match matches.subcommand() {
        Some(("new", sub)) => cmd_recovery_new(sub, options, config),
        Some(("test", sub)) => cmd_recovery_test(sub, options, config),
        Some(("remove", sub)) => cmd_recovery_remove(sub, options, config),
        _ => Err(CliError("sous-commande « recovery » inconnue".to_string())),
    }
}

/// Aiguille vers les sous-commandes de `keyfile`.
pub(crate) fn cmd_keyfile(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    match matches.subcommand() {
        Some(("new", sub)) => cmd_keyfile_new(sub, options, config),
        Some(("test", sub)) => cmd_keyfile_test(sub, options, config),
        Some(("remove", sub)) => cmd_keyfile_remove(sub, options, config),
        _ => Err(CliError("sous-commande « keyfile » inconnue".to_string())),
    }
}

/// Crée et installe une clé de récupération.
fn cmd_recovery_new(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let force = matches.get_flag("force");

    let key = RecoveryKey::generate()?;
    let mut vault = open_with_master_password(&path, options, config)?;

    if force {
        vault.replace_slot(SlotLabel::Recovery, key.expose(), KdfParams::standard())?;
    } else {
        vault.install_slot(SlotLabel::Recovery, key.expose(), KdfParams::standard())?;
    }

    // ORDRE CRITIQUE : on enregistre **avant** d'afficher la clé. Afficher une clé
    // qui n'a pas été installée donnerait à l'utilisateur une fausse sécurité : il la
    // rangerait, croirait son coffre récupérable, et ne le découvrirait qu'au pire
    // moment.
    vault.save()?;

    // Le secret va sur la sortie standard, seul ; le mode d'emploi sur la sortie
    // d'erreur. `passlock recovery new COFFRE > cle.txt` écrit donc exactement la clé.
    let encoded = key.encode();
    println!("{}", encoded.as_str());

    eprintln!();
    eprintln!("Clé de récupération installée dans {}.", path.display());
    eprintln!(
        "Elle n'est affichée **qu'une fois** : Passlock n'en conserve aucune copie, et\n\
         il n'existe aucun moyen de la retrouver ensuite."
    );
    eprintln!();
    eprintln!("Rangez-la dans un lieu physiquement distinct des sauvegardes — une clé rangée");
    eprintln!("à côté du disque de sauvegarde ne réduit aucun risque et en ajoute un.");
    eprintln!();
    eprintln!(
        "Vérifiez-la maintenant : `passlock recovery test {}`",
        path.display()
    );
    eprintln!(
        "Chaque slot est un chemin d'entrée supplémentaire : la récupérabilité et la\n\
         résistance au vol varient en sens inverse."
    );
    Ok(())
}

/// Vérifie qu'une clé de récupération ouvre le coffre.
fn cmd_recovery_test(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;

    // La commande impose son mode : elle teste une **clé de récupération**, quoi que
    // disent les options globales. `password_stdin` reste honoré, parce qu'il décrit
    // d'où vient la saisie et non ce qu'on saisit.
    let forced = GlobalOptions {
        unlock: UnlockMode::RecoveryKey {
            from_stdin: options.password_stdin,
        },
        ..options.clone()
    };
    let vault = open_vault(&path, &forced, config)?;

    println!(
        "Clé de récupération valide : le coffre {} s'ouvre (génération {}).",
        hex(&vault.header().vault_id),
        vault.generation()
    );
    eprintln!(
        "La clé a été essayée pour de bon : le slot a été désenroulé et le contenu déchiffré."
    );
    Ok(())
}

/// Révoque la clé de récupération.
fn cmd_recovery_remove(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut vault = open_with_master_password(&path, options, config)?;
    require_confirmation(matches, &vault)?;

    vault.revoke_slot(SlotLabel::Recovery)?;
    vault.save()?;

    println!("Clé de récupération révoquée de {}.", path.display());
    eprintln!(
        "Le slot a été retiré du coffre. Une copie déjà faite de la clé n'est PAS reprise :\n\
         si elle a été photographiée ou recopiée, considérez-la comme compromise.\n\
         Les sauvegardes antérieures contiennent toujours ce slot."
    );
    Ok(())
}

/// Crée un fichier-clé et l'installe comme slot matériel.
fn cmd_keyfile_new(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let key_path = matches
        .get_one::<String>("key-file")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| CliError("--key-file est requis".to_string()))?;

    let key = passlock_core::rng::key::<KEY_FILE_LEN>()?;

    // ORDRE CRITIQUE, et inverse de celui de `recovery new`.
    //
    // On écrit d'abord le **fichier**, puis on installe le slot. Si l'installation
    // échoue, l'utilisateur se retrouve avec un fichier-clé inutilisé : un fichier
    // orphelin, qu'il peut supprimer — et il peut recommencer.
    //
    // L'ordre inverse laisserait un **slot sans sa clé** dans le coffre : l'utilisateur
    // croirait disposer d'un moyen de récupération qui n'existe pas. Une promesse non
    // tenue est pire qu'un fichier en trop.
    write_key_file(&key_path, key.expose())?;

    let mut vault = open_with_master_password(&path, options, config)?;
    if vault.slot_labels().contains(&SlotLabel::Hardware) {
        // On nettoie le fichier qu'on vient d'écrire : laisser un fichier-clé qui
        // n'ouvre rien serait un piège.
        let _ = passlock_platform::fs::remove_file(&key_path);
        return Err(CliError(
            "ce coffre porte déjà une clé matérielle ; révoquez-la d'abord avec \
             `keyfile remove`"
                .to_string(),
        ));
    }

    vault.install_slot(SlotLabel::Hardware, key.expose(), KdfParams::standard())?;
    vault.save()?;

    println!("Fichier-clé écrit : {}", key_path.display());
    println!(
        "Clé matérielle installée dans {} (génération {}).",
        path.display(),
        vault.generation()
    );
    eprintln!();
    eprintln!(
        "Le support doit être retiré après usage. Un fichier-clé copié est un secret\n\
         copié : ce n'est pas un facteur de possession inviolable."
    );
    eprintln!(
        "Vérifiez-le : `passlock keyfile test {} --key-file {}`",
        path.display(),
        key_path.display()
    );
    Ok(())
}

/// Vérifie qu'un fichier-clé ouvre le coffre.
fn cmd_keyfile_test(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let key_path = matches
        .get_one::<String>("key-file")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| CliError("--key-file est requis".to_string()))?;

    let forced = GlobalOptions {
        unlock: UnlockMode::KeyFile(key_path.clone()),
        ..options.clone()
    };
    let vault = open_vault(&path, &forced, config)?;

    println!(
        "Fichier-clé valide : le coffre {} s'ouvre (génération {}).",
        hex(&vault.header().vault_id),
        vault.generation()
    );
    eprintln!("Le fichier-clé a été essayé pour de bon, pas seulement relu.");
    Ok(())
}

/// Révoque la clé matérielle.
fn cmd_keyfile_remove(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;
    let mut vault = open_with_master_password(&path, options, config)?;
    require_confirmation(matches, &vault)?;

    vault.revoke_slot(SlotLabel::Hardware)?;
    vault.save()?;

    println!("Clé matérielle révoquée de {}.", path.display());
    eprintln!(
        "Le slot a été retiré du coffre. Le fichier-clé, lui, n'a pas été touché : il ne\n\
         peut simplement plus ouvrir ce coffre. Supprimez-le si vous n'en avez plus besoin."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Ouvre le coffre avec le **mot de passe maître**, quoi que disent les options.
///
/// Installer ou révoquer un slot est une modification du chemin d'accès au coffre :
/// elle exige le mot de passe maître, c'est-à-dire la ré-authentification. Sans cela,
/// quelqu'un disposant d'une clé de récupération pourrait révoquer le mot de passe
/// maître — ou en installer un second.
fn open_with_master_password(
    path: &Path,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> Result<Vault, CliError> {
    let forced = GlobalOptions {
        unlock: UnlockMode::Password,
        ..options.clone()
    };
    open_vault(path, &forced, config)
}

/// Ouvre le coffre et signale les observations d'ouverture.
fn open_vault(
    path: &Path,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> Result<Vault, CliError> {
    report_hardening(options.hardening);
    let material = read_unlock_material(options)?;
    let vault = Vault::open_with(path, &material.credentials(), config)?;
    report_diagnostics(&vault);
    Ok(vault)
}

/// Exige que `--confirm` recopie l'identifiant du coffre.
///
/// Même motif que `entry purge` : retirer un chemin d'accès ne doit pas pouvoir être
/// déclenché par une faute de frappe ou une complétion automatique.
fn require_confirmation(matches: &clap::ArgMatches, vault: &Vault) -> Result<(), CliError> {
    let expected = hex(&vault.header().vault_id);
    let provided = matches
        .get_one::<String>("confirm")
        .ok_or_else(|| CliError("confirmation manquante".to_string()))?;

    if provided.trim() != expected {
        return Err(CliError(
            "la confirmation ne correspond pas à l'identifiant du coffre : rien n'a été \
             modifié"
                .to_string(),
        ));
    }
    Ok(())
}

/// Écrit un fichier-clé : création exclusive, permissions privées, durabilité.
///
/// ## Pourquoi pas `write_atomic`
///
/// `write_atomic` a une **sémantique de remplacement** : il écrase une destination
/// existante. Un fichier-clé doit être **neuf** — écraser celui d'un autre coffre
/// détruirait le seul exemplaire d'une clé encore installée ailleurs. `create_private_file`
/// fournit la création exclusive, sans pré-contrôle d'existence.
///
/// ## Ce que le nettoyage a le droit de supprimer
///
/// **Uniquement ce que cette fonction a créé.** Une version antérieure retirait la
/// cible dès qu'une étape échouait — y compris quand l'échec était « la cible existe
/// déjà ». Elle **détruisait donc le fichier-clé de l'utilisateur** au moment même où
/// elle refusait de l'écraser. Le défaut a été trouvé par
/// `a_key_file_is_never_overwritten` ; la correction consiste à ne rendre le nettoyage
/// atteignable **qu'après** une création réussie.
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use passlock_platform::fs::{create_private_file, make_durable, remove_file};

    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Seule cette étape décide si le fichier est **à nous**. Si elle échoue — parce
    // qu'un fichier existe déjà, par exemple — rien n'a été créé, et rien ne doit être
    // supprimé.
    let mut file = create_private_file(path).map_err(|err| {
        CliError(format!(
            "écriture du fichier-clé {} : {err}",
            path.display()
        ))
    })?;

    let level = match file
        .write_all(bytes)
        .and_then(|()| make_durable(&file, dir))
    {
        Ok(level) => level,
        Err(err) => {
            // Le fichier est bien le nôtre : on l'a créé en exclusif à l'instant. Un
            // fichier-clé tronqué laissé en place serait un piège — il ressemble à une
            // clé sans en être une.
            let _ = remove_file(path);
            return Err(CliError(format!(
                "écriture du fichier-clé {} : {err}",
                path.display()
            )));
        }
    };

    // Le niveau de durabilité est **rendu**, donc jamais ignoré : s'il est réduit, on
    // le dit. C'est la règle du projet — une garantie absente s'annonce.
    if !level.directory_entry_is_durable() {
        eprintln!(
            "Avertissement : sur cette plateforme, Passlock ne peut pas garantir que le\n\
             **nom** du fichier-clé survit à une coupure d'alimentation — son contenu est\n\
             synchronisé, pas son entrée de répertoire. Vérifiez que le fichier est bien\n\
             présent après avoir retiré le support, avant de considérer la clé comme rangée."
        );
    }
    Ok(())
}
