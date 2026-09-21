//! Sauvegardes et test de restauration.
//!
//! # Ce qu'une sauvegarde est — et n'est pas
//!
//! Une sauvegarde est un **couple de chemins** : le fichier de coffre, et son
//! répertoire de blobs. Il n'y a **aucun format nouveau, aucune cryptographie
//! nouvelle, aucun manifeste** : le fichier de sauvegarde *est* un coffre, ouvrable par
//! les commandes ordinaires.
//!
//! Pourquoi pas d'archive unique ni de manifeste : une archive exigerait une dépendance
//! (`zip`, `tar`, `flate2` absents de l'arbre) ou un conteneur maison — c'est-à-dire un
//! **nouveau format cryptographique** ; et un manifeste serait un **second état**,
//! susceptible de diverger du contenu réel, ce que le projet refuse ailleurs (ADR-022).
//!
//! # Ce qui rend l'ensemble cohérent — et ce qui ne le rend pas atomique
//!
//! **Le verrou exclusif**, tenu pendant toute la copie (`VaultConfig::require_exclusive_lock`
//! avec `read_only`). Sans lui, un écrivain concurrent pourrait ajouter une pièce jointe
//! entre la copie du coffre et celle des blobs, et la sauvegarde contiendrait un coffre
//! référençant un blob absent.
//!
//! Ce qui **n'est pas** revendiqué : **aucune atomicité de destination**. Le couple est
//! fait de deux chemins indépendants, et l'écriture se fait **en place** (pas de couple
//! temporaire + renommage) — c'est le prix de `O_EXCL`, qui ferme toute fenêtre entre le
//! contrôle d'existence et la création.
//!
//! **Trois issues, et deux seulement sont des garanties :**
//!
//! | Issue | Ce qui est garanti |
//! |---|---|
//! | **Succès** | la paire est présente, complète et **vérifiée**. Seule issue qui rend un code de retour 0 |
//! | **Erreur contrôlée** | [`create`] retire **ce qu'il a créé**, et rien d'autre |
//! | **Interruption brutale** | **aucune garantie** : une destination **partielle** peut subsister. Elle doit **échouer** à [`verify`] — c'est ce qui distingue une sauvegarde d'une copie interrompue |
//!
//! Conséquence pratique, énoncée : une destination partielle **occupe le chemin**. Une
//! nouvelle tentative échoue (`O_EXCL`), et le reliquat doit être supprimé explicitement.
//! Écraser silencieusement serait pire que refuser.

use std::path::{Path, PathBuf};

use passlock_platform::fs::{self, Durability};

use crate::attachment;
use crate::error::{Error, Result};
use crate::migrate;
use crate::rollback::RollbackCheck;
use crate::store::VaultStore;
use crate::vault::{Credentials, Vault, VaultConfig};

/// Un fichier à copier, et sa destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMember {
    /// Chemin d'origine.
    pub source: PathBuf,
    /// Chemin dans la sauvegarde.
    pub destination: PathBuf,
    /// Taille, telle qu'observée **sous verrou**, avant toute copie.
    pub size: u64,
}

/// Ce qui constitue une sauvegarde, **énuméré avant toute copie**.
///
/// L'énumération a lieu sous verrou, et la copie est ensuite comparée à cette liste :
/// c'est ce qui permet de constater qu'un membre manque au lieu de produire une
/// sauvegarde incomplète en silence.
#[derive(Debug, Clone)]
pub struct BackupPlan {
    /// Le fichier de coffre.
    pub vault: BackupMember,
    /// Les blobs référencés par l'archive du coffre, dans l'ordre de l'archive.
    pub blobs: Vec<BackupMember>,
    /// Répertoire des blobs de la sauvegarde — absent si le coffre n'a aucune pièce jointe.
    pub blob_dir: Option<PathBuf>,
    /// Identité du coffre, pour le rapport.
    pub vault_id: [u8; 16],
    /// Génération du coffre copié.
    pub generation: u64,
}

impl BackupPlan {
    /// Nombre total d'octets à copier.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.blobs.iter().fold(self.vault.size, |total, member| {
            total.saturating_add(member.size)
        })
    }
}

/// Résultat d'une sauvegarde réussie.
#[derive(Debug)]
pub struct BackupOutcome {
    /// Chemin de la sauvegarde.
    pub destination: PathBuf,
    /// Nombre de blobs copiés.
    pub blobs: usize,
    /// Octets copiés au total.
    pub bytes: u64,
    /// Niveau de durabilité **réellement atteint**.
    pub durability: Durability,
}

/// Verdict d'**intégrité** — la seule source de succès ou d'échec.
#[derive(Debug, PartialEq, Eq)]
pub enum Integrity {
    /// Tout est présent et conforme.
    Sound,
    /// Au moins un défaut, énuméré.
    Broken {
        /// Motifs, dans l'ordre de découverte.
        reasons: Vec<String>,
    },
}

/// Verdict d'**ancienneté** — une information, jamais une erreur.
///
/// Restaurer une sauvegarde ancienne est **légitime**. Le confondre avec une compromission
/// ferait apprendre à ignorer l'alerte de retour en arrière ; le taire ferait perdre la
/// seule détection disponible. Il est donc rendu séparément, et n'influence pas le code de
/// retour.
#[derive(Debug, PartialEq, Eq)]
pub enum Age {
    /// Au moins aussi récent que le dernier état connu.
    Current,
    /// Antérieur au dernier état connu.
    Older {
        /// Génération enregistrée dans la sentinelle.
        known: u64,
        /// Génération lue dans la sauvegarde.
        found: u64,
    },
    /// Aucune référence : impossible de conclure. Ce n'est **pas** un échec.
    Unknown,
    /// La sentinelle existait mais était inutilisable.
    SentinelCorrupted,
}

/// Rapport de test de restauration.
#[derive(Debug)]
pub struct RestoreReport {
    /// Verdict d'intégrité.
    pub integrity: Integrity,
    /// Verdict d'ancienneté.
    pub age: Age,
    /// Identité du coffre sauvegardé.
    pub vault_id: [u8; 16],
    /// Génération du coffre sauvegardé.
    pub generation: u64,
    /// Schéma du corps, tel que lu.
    pub schema_version: u16,
    /// Schéma antérieur détecté : la migration a eu lieu **en mémoire**, rien n'a été écrit.
    pub migrated_from: Option<u16>,
    /// Nombre d'entrées.
    pub entries: usize,
    /// Nombre de pièces jointes référencées.
    pub attachments: usize,
    /// Paramètres de dérivation du slot maître, tels que lus dans le fichier.
    pub params_micro: (u32, u32, u32),
    /// Paramètres sous la recommandation : une sauvegarde ancienne fige d'anciennes valeurs.
    pub params_below_recommendation: bool,
    /// Répertoire de blobs attendu, tel qu'il a été déduit du chemin.
    pub blob_dir: PathBuf,
}

impl RestoreReport {
    /// Vrai si la sauvegarde est exploitable.
    #[must_use]
    pub const fn is_sound(&self) -> bool {
        matches!(self.integrity, Integrity::Sound)
    }
}

// ---------------------------------------------------------------------------
// Création
// ---------------------------------------------------------------------------

/// Énumère ce qu'une sauvegarde devra contenir.
///
/// À appeler **sous verrou** : c'est ce qui garantit que la liste ne changera pas
/// pendant la copie.
///
/// # Erreurs
/// * [`Error::Internal`] si la dérivation d'un nom de blob échoue ;
/// * [`Error::Io`] si la taille d'un membre ne peut pas être lue.
pub fn plan(store: &VaultStore, destination: &Path) -> Result<BackupPlan> {
    let vault_id = store.vault().header().vault_id;
    let source = store.path().to_path_buf();
    let size = fs::open_read(&source)?.metadata()?.len();

    let mut blobs = Vec::new();
    let blob_dir = if store.archive().attachments.is_empty() {
        None
    } else {
        let target = attachment::blob_dir_for(destination);
        for meta in &store.archive().attachments {
            let from = store.blob_path(&meta.id)?;
            let name = attachment::blob_file_name(store.vault().subkeys(), &vault_id, meta.id)?;
            let observed = fs::open_read(&from)?.metadata()?.len();
            blobs.push(BackupMember {
                source: from,
                destination: target.join(name),
                size: observed,
            });
        }
        Some(target)
    };

    Ok(BackupPlan {
        vault: BackupMember {
            source,
            destination: destination.to_path_buf(),
            size,
        },
        blobs,
        blob_dir,
        vault_id,
        generation: store.vault().generation(),
    })
}

/// Crée une sauvegarde, **puis la vérifie**, et ne réussit que si elle est intègre.
///
/// # Le verrou
///
/// L'appelant doit avoir ouvert le magasin avec `read_only` **et**
/// `require_exclusive_lock`. Le verrou est ce qui gèle l'ensemble pendant la copie : sans
/// lui, une pièce jointe ajoutée entre la copie du coffre et celle des blobs produirait
/// une sauvegarde incohérente.
///
/// # Ce qui est supprimé, et ce qui ne l'est jamais
///
/// En cas d'échec — copie ou vérification — cette fonction retire **ce qu'elle a créé** :
/// les fichiers copiés et le répertoire de blobs qu'elle a créé. Jamais rien d'autre : la
/// destination ne préexistait pas, `O_EXCL` le garantit.
///
/// # Erreurs
/// * [`Error::Io`] avec `AlreadyExists` si la destination existe déjà ;
/// * [`Error::Corrupted`] si la vérification de la copie échoue — la sauvegarde est alors
///   retirée, et rien de trompeur ne subsiste.
pub fn create(
    store: &VaultStore,
    destination: &Path,
    credentials: &Credentials<'_>,
    config: &VaultConfig,
) -> Result<BackupOutcome> {
    let plan = plan(store, destination)?;

    // Ce qui a été **réellement créé** par cette session, et rien d'autre. Le
    // nettoyage ne s'appuie pas sur le plan : il s'appuie sur ce qui existe par notre
    // fait. Un répertoire de blobs préexistant, ou un fichier qu'une autre session a
    // laissé, ne sont donc jamais retirés.
    let mut created = Created::new();

    if let Err(err) = copy_all(&plan, &mut created) {
        created.discard();
        return Err(err);
    }

    // Vérification **immédiate**. Une sauvegarde non vérifiée n'est pas produite : la
    // vérifier plus tard est précisément ce qu'on ne fait pas.
    match verify(destination, credentials, config) {
        Ok(report) if report.is_sound() => Ok(BackupOutcome {
            destination: destination.to_path_buf(),
            blobs: plan.blobs.len(),
            bytes: plan.total_bytes(),
            durability: created.durability,
        }),
        Ok(_) => {
            // La copie existe, elle est lisible, et elle est **incohérente** : on la
            // retire plutôt que de laisser quelque chose qui ressemble à une sauvegarde.
            created.discard();
            Err(Error::Corrupted {
                reason: "la sauvegarde copiée n'est pas intègre",
            })
        }
        Err(err) => {
            created.discard();
            Err(err)
        }
    }
}

/// Ce qu'une session de copie a **créé**, et ce qu'elle peut donc retirer.
///
/// **NOTE DE CORRECTION.** Une version antérieure nettoyait d'après le **plan** : elle
/// retirait `blob_dir` dès qu'il figurait au plan, sans savoir si la session l'avait créé.
/// Un répertoire `.attachments/` **préexistant et vide** — celui d'une sauvegarde
/// antérieure, par exemple — aurait donc été supprimé par un `backup create` qui échoue
/// avant même de l'utiliser. Le nettoyage s'appuie désormais sur les créations
/// effectivement réussies.
struct Created {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    durability: Durability,
}

impl Created {
    /// Rien n'a encore été créé, et le niveau de durabilité part de ce que la plateforme
    /// **déclare** : chaque opération le fait ensuite descendre au lieu de le remonter.
    fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
            durability: fs::platform_durability(),
        }
    }

    /// Retire ce qui a été créé, dans l'ordre inverse de la création.
    ///
    /// Les échecs de nettoyage sont ignorés : l'erreur d'origine est la cause première, et
    /// c'est elle qui doit être signalée, pas un échec de ménage qui la masquerait.
    fn discard(&self) {
        for path in self.files.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for path in self.dirs.iter().rev() {
            let _ = fs::remove_dir(path);
        }
    }
}

/// Copie tous les membres du plan, en **enregistrant chaque création réussie**.
///
/// # Erreurs
/// Toute erreur de fichier. L'appelant retire alors ce qui a été créé.
fn copy_all(plan: &BackupPlan, created: &mut Created) -> Result<()> {
    // Le fichier de coffre d'abord : s'il échoue, rien d'autre n'a été écrit.
    created.durability = lower(created.durability, copy_member(&plan.vault, created)?);

    if let Some(dir) = &plan.blob_dir {
        // `mkdirat` est le contrôle d'existence : un `AlreadyExists` signifie que le
        // répertoire existait **déjà**, donc qu'il n'est **pas** à nous — et il n'est
        // alors pas enregistré comme créé.
        match fs::create_dir_private(dir) {
            Ok(level) => {
                created.dirs.push(dir.clone());
                created.durability = lower(created.durability, level);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(Error::Io(err)),
        }
        for member in &plan.blobs {
            created.durability = lower(created.durability, copy_member(member, created)?);
        }
    }
    Ok(())
}

/// Copie **en flux**, sans charger le fichier entier en mémoire.
///
/// La destination est créée en **exclusif** : elle ne peut donc pas exister, et rien ne
/// peut être écrasé. Un échec laisse un fichier partiel, que l'appelant retire — et il le
/// retire parce qu'il l'a **créé**, pas parce qu'il figurait au plan.
fn copy_member(member: &BackupMember, created: &mut Created) -> Result<Durability> {
    let mut source = fs::open_read(&member.source)?;
    let mut destination =
        fs::create_private_file(&member.destination).map_err(|err| describe_create(err, member))?;
    created.files.push(member.destination.clone());

    let copied = std::io::copy(&mut source, &mut destination).map_err(Error::Io)?;
    if copied != member.size {
        return Err(Error::Corrupted {
            reason: "la taille du fichier a changé pendant la copie",
        });
    }

    let durability = fs::make_durable(&destination, &parent_of(&member.destination))?;
    Ok(durability)
}

/// Rend le motif d'un échec de création lisible.
///
/// Aucun contrôle préalable n'a lieu : c'est la création elle-même qui échoue, et le
/// message ne fait que nommer la cause la plus fréquente. Un `path_exists` en amont
/// rouvrirait la fenêtre que `O_EXCL` ferme.
fn describe_create(err: std::io::Error, member: &BackupMember) -> Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        return Error::InvalidInput {
            reason: "le répertoire de destination n'existe pas",
        };
    }
    if err.kind() == std::io::ErrorKind::AlreadyExists {
        return Error::InvalidInput {
            reason: "la destination existe déjà ; elle n'est jamais écrasée",
        };
    }
    let _ = member;
    Error::Io(err)
}

/// Rend le niveau de durabilité le plus **faible** des deux.
///
/// `DirectoryEntrySynced` est plus fort que `FileOnly` : l'ensemble ne peut pas prétendre
/// à mieux que son maillon le plus faible.
fn lower(left: Durability, right: Durability) -> Durability {
    if left == Durability::DirectoryEntrySynced && right == Durability::DirectoryEntrySynced {
        Durability::DirectoryEntrySynced
    } else {
        Durability::FileOnly
    }
}

/// Répertoire parent, ou le répertoire courant.
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

// ---------------------------------------------------------------------------
// Test de restauration
// ---------------------------------------------------------------------------

/// Teste une sauvegarde : ouvre la copie, décode son archive, et vérifie **chaque pièce
/// jointe** référencée.
///
/// # Aucun effet persistant
///
/// L'ouverture est **forcée en lecture seule**, et le verrou n'est **pas** pris :
///
/// * pas de fichier `<sauvegarde>.lock` ;
/// * pas de réparation des permissions du fichier testé ;
/// * pas d'écriture de sentinelle ;
/// * aucune écriture du coffre.
///
/// Ce n'est pas une discipline d'appelant : le `config` reçu est **écrasé** ici, de sorte
/// qu'aucun appelant ne puisse obtenir un effet persistant, même par distraction.
///
/// # Migration
///
/// Une sauvegarde écrite par une version antérieure est migrée **en mémoire**, et le
/// rapport l'indique. **Rien n'est écrit.**
///
/// # Erreurs
/// * [`Error::UnlockFailed`], [`Error::Corrupted`]… si le fichier n'est pas une sauvegarde
///   exploitable — une destination partielle échoue **ici** ;
/// * jamais d'erreur pour un simple défaut d'intégrité : le verdict est dans le rapport,
///   et c'est l'appelant qui décide.
pub fn verify(
    path: &Path,
    credentials: &Credentials<'_>,
    config: &VaultConfig,
) -> Result<RestoreReport> {
    // Lecture seule imposée, verrou refusé : la garantie est ici, pas chez l'appelant.
    let read_only = VaultConfig {
        read_only: true,
        require_exclusive_lock: false,
        ..config.clone()
    };

    let mut vault = Vault::open_with(path, credentials, &read_only)?;

    let vault_id = vault.header().vault_id;
    let generation = vault.generation();
    let schema_version = vault.schema_version();
    let migrated_from = vault.diagnostics().migrated_from;
    let age = match vault.diagnostics().rollback {
        RollbackCheck::Consistent => Age::Current,
        RollbackCheck::Rollback { known, found } => Age::Older { known, found },
        RollbackCheck::NoSentinel if vault.diagnostics().sentinel_corrupted => {
            Age::SentinelCorrupted
        }
        RollbackCheck::NoSentinel => Age::Unknown,
    };
    let params = vault.header().master_slot().map_or((0, 0, 0), |slot| {
        (
            slot.params.m_cost_kib(),
            slot.params.t_cost(),
            slot.params.p_cost(),
        )
    });
    let params_below = vault
        .header()
        .master_slot()
        .is_some_and(|slot| slot.params.is_below_recommendation());

    // Le corps est **pris** : le coffre n'en garde aucune copie, et le buffer est effacé
    // au `Drop` de la valeur rendue.
    let (version, body) = vault.take_body();
    let created_at = vault.header().created_at;
    let archive = migrate::decode_any(version, &body, created_at)?.archive;
    drop(body);

    let blob_dir = attachment::blob_dir_for(path);
    let mut reasons = Vec::new();

    let subkeys = vault.subkeys();
    for meta in &archive.attachments {
        let blob = match attachment::blob_file_name(subkeys, &vault_id, meta.id) {
            Ok(name) => blob_dir.join(name),
            Err(err) => {
                reasons.push(format!("{} : {err}", meta.id.to_hex()));
                continue;
            }
        };
        if let Err(err) = attachment::verify_blob(&blob, meta, subkeys, &vault_id) {
            reasons.push(format!(
                "{} ({} octet(s)) : {err}",
                meta.id.to_hex(),
                meta.size
            ));
        }
    }

    // Un répertoire de blobs **attendu mais absent** est un défaut, pas un silence.
    if !archive.attachments.is_empty() && !fs::path_exists(&blob_dir) {
        reasons.push(format!(
            "le répertoire de pièces jointes est absent : {}",
            blob_dir.display()
        ));
    }

    let integrity = if reasons.is_empty() {
        Integrity::Sound
    } else {
        Integrity::Broken { reasons }
    };

    Ok(RestoreReport {
        integrity,
        age,
        vault_id,
        generation,
        schema_version,
        migrated_from,
        entries: archive.entries.len(),
        attachments: archive.attachments.len(),
        params_micro: params,
        params_below_recommendation: params_below,
        blob_dir,
    })
}
