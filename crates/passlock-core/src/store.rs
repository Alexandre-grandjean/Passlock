//! Magasin du coffre : le modèle de données au-dessus du moteur cryptographique.
//!
//! # Ce que ce module possède
//!
//! Un [`VaultStore`] détient **à la fois** le [`Vault`] (cryptographie, conteneur,
//! fichier) et l'[`Archive`] (le modèle de données déchiffré). Il ne les expose
//! jamais séparément, ce qui garantit qu'on ne peut pas modifier le modèle sans
//! pouvoir l'enregistrer, ni enregistrer autre chose que le modèle courant.
//!
//! # Modèle de concurrence
//!
//! **Propriété unique, aucune synchronisation interne.** Les mutations prennent
//! `&mut self` : le vérificateur d'emprunts rend la mutation concurrente impossible
//! à *compiler*, pas seulement déconseillée.
//!
//! Un `Arc<Mutex<VaultStore>>` serait un contresens : il autoriserait deux
//! enregistrements entrelacés et des mutations dont l'ordre dépendrait de
//! l'ordonnanceur. L'interface graphique (phase 6) possédera le magasin sur un fil
//! et communiquera par messages — cette contrainte lui est imposée dès maintenant.
//!
//! # Transactions
//!
//! Chaque opération **valide puis applique**. Sur erreur, l'archive est inchangée.
//! La granularité transactionnelle est le couple « une mutation, un `save()` » :
//! l'écriture du conteneur est déjà tout-ou-rien, et rien de plus fin ne serait
//! utile.
//!
//! # Fenêtre d'exposition d'un plantage
//!
//! Les mutations non enregistrées sont perdues. C'est le contrat, et il doit être
//! dit à l'utilisateur. `is_dirty()` et `save_if_dirty()` existent pour que la
//! politique d'enregistrement automatique soit **testable sans interface**.

use zeroize::Zeroizing;

use std::path::{Path, PathBuf};

use passlock_platform::fs::{self, Durability};

use crate::archive;
use crate::attachment;
use crate::error::{Error, Result};
use crate::migrate;
use crate::model::{
    Archive, AttachmentMeta, AuditEvent, AuditKind, BlobId, Entry, EntryId, Folder, FolderId,
    MAX_ATTACHMENT_NAME_LEN, MAX_ATTACHMENTS, MAX_AUDIT_EVENTS, MAX_FOLDER_DEPTH, MAX_NAME_LEN,
    Revision, Tag, TagId,
};
use crate::rollback::now_unix;
use crate::vault::{Credentials, Diagnostics, Vault, VaultConfig};

/// Nombre de tirages d'un nom de blob avant d'abandonner.
///
/// Le nom est un HMAC tronqué à 128 bits : au-delà de quelques tirages, une collision
/// répétée ne relève plus du hasard mais d'un adversaire qui occupe les noms, ou d'un
/// défaut. On s'arrête alors avec une erreur franche plutôt que de boucler.
const MAX_BLOB_NAME_ATTEMPTS: u32 = 8;

/// Vérifie que le niveau de durabilité **obtenu** est celui que la plateforme déclare.
///
/// `platform_durability` est ce qui est **rapporté à l'utilisateur** à l'ouverture ;
/// `make_durable` rend ce qui a été **réellement obtenu**. S'ils divergent, le rapport
/// mentirait : c'est un défaut du programme, jamais une condition d'exploitation.
fn check_durability(level: Durability) -> Result<()> {
    if level == fs::platform_durability() {
        Ok(())
    } else {
        Err(Error::Internal {
            invariant: "le niveau de durabilité obtenu diffère de celui déclaré par la plateforme",
        })
    }
}

/// Un coffre ouvert, avec son modèle de données.
pub struct VaultStore {
    vault: Vault,
    archive: Archive,
    dirty: bool,
}

impl VaultStore {
    /// Crée un coffre neuf.
    ///
    /// # Erreurs
    /// Voir [`Vault::create`].
    pub fn create(path: &Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
        let vault = Vault::create(path, password, config)?;
        let mut store = Self {
            vault,
            archive: Archive::new(now_unix()),
            dirty: false,
        };

        // Le coffre est enregistré **immédiatement** avec une archive vide.
        //
        // Sans cela, `Vault::create` laisserait un fichier déclarant le schéma
        // courant avec un corps vide : un coffre cohérent en apparence, mais dont
        // l'ouverture dépendrait d'un cas particulier du décodeur. Écrire tout de
        // suite rend le fichier **auto-cohérent** — ce qu'il contient correspond à ce
        // qu'il annonce — et fait échouer une création sur un système de fichiers
        // défaillant au moment de la création, plutôt qu'à la première utilisation.
        store.save()?;
        Ok(store)
    }

    /// Ouvre un coffre existant avec son mot de passe maître.
    ///
    /// Raccourci du cas courant : délègue à [`VaultStore::open_with`]. Les clés de
    /// récupération et les fichiers-clés passent par `open_with` directement.
    ///
    /// # Erreurs
    /// Voir [`VaultStore::open_with`].
    pub fn open(path: &Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
        Self::open_with(path, &Credentials::Password(password), config)
    }

    /// Ouvre un coffre existant avec un matériel d'ouverture quelconque, et décode
    /// son modèle.
    ///
    /// # Migration
    ///
    /// Si le coffre porte un schéma antérieur, la migration s'applique **en
    /// mémoire** et le magasin est marqué modifié : la nouvelle forme sera écrite au
    /// prochain enregistrement. Rien n'est écrit ici — une ouverture en lecture seule
    /// ne doit rien modifier.
    ///
    /// # Un seul chemin
    ///
    /// Le matériel d'ouverture ne change **rien** à ce qui suit : décodage, migration
    /// et diagnostics sont identiques quel que soit le slot utilisé. C'est ce qui
    /// garantit qu'un coffre ouvert par une clé de récupération se comporte comme un
    /// coffre ouvert par mot de passe.
    ///
    /// # Erreurs
    /// Voir [`Vault::open_with`], plus les erreurs de décodage du corps.
    pub fn open_with(
        path: &Path,
        credentials: &Credentials<'_>,
        config: &VaultConfig,
    ) -> Result<Self> {
        let mut vault = Vault::open_with(path, credentials, config)?;

        // Le corps est **déplacé** : le coffre n'en conserve aucune copie, et le
        // `Zeroizing` efface le buffer dès qu'il n'est plus utile.
        let (version, body) = vault.take_body();
        let created_at = vault.header().created_at;

        let migrated = migrate::decode_any(version, &body, created_at)?;
        drop(body);

        let dirty = migrated.from.is_some();
        vault.set_migrated_from(migrated.from);

        Ok(Self {
            vault,
            archive: migrated.archive,
            dirty,
        })
    }

    /// Enregistre le modèle sur le disque.
    ///
    /// # Erreurs
    /// [`Error::ReadOnly`] si le coffre est ouvert en lecture seule, plus les erreurs
    /// d'encodage et d'écriture.
    pub fn save(&mut self) -> Result<()> {
        if self.vault.is_read_only() {
            return Err(Error::ReadOnly);
        }

        let encoded: Zeroizing<Vec<u8>> = archive::encode(&self.archive)?;

        // Le corps contient le coffre entier en clair : il est transféré au coffre,
        // qui l'effacera après l'avoir chiffré.
        self.vault.set_body(encoded.to_vec());
        self.vault.save()?;
        self.dirty = false;
        Ok(())
    }

    /// Vrai si des modifications n'ont pas été enregistrées.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Enregistre si nécessaire.
    ///
    /// Existe pour que la politique d'enregistrement automatique d'une interface
    /// soit décidée **en dehors** du magasin, et donc testable sans interface.
    ///
    /// # Erreurs
    /// Propage les erreurs de [`VaultStore::save`], et [`Error::ReadOnly`] si le
    /// coffre est en lecture seule et qu'il y a des modifications à écrire — un
    /// abandon silencieux serait pire qu'un refus.
    pub fn save_if_dirty(&mut self) -> Result<bool> {
        if !self.dirty {
            return Ok(false);
        }
        if self.vault.is_read_only() {
            return Err(Error::ReadOnly);
        }
        self.save()?;
        Ok(true)
    }

    /// Modèle de données, en lecture.
    #[must_use]
    pub const fn archive(&self) -> &Archive {
        &self.archive
    }

    /// Observations faites à l'ouverture.
    #[must_use]
    pub fn diagnostics(&self) -> &Diagnostics {
        self.vault.diagnostics()
    }

    /// Header du coffre.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Chemin du coffre.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.vault.path()
    }

    // -----------------------------------------------------------------------
    // Entrées
    // -----------------------------------------------------------------------

    /// Ajoute une entrée.
    ///
    /// L'entrée est **validée avant** d'être insérée : une référence vers un dossier
    /// ou un tag inexistant est refusée, jamais silencieusement acceptée. Sans cette
    /// vérification, une entrée pourrait devenir invisible — rattachée à un dossier
    /// qui n'existe pas.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si une référence est pendante,
    /// [`Error::MalformedLength`] si l'entrée dépasse une borne.
    pub fn add_entry(&mut self, entry: Entry) -> Result<EntryId> {
        self.check_references(&entry)?;
        entry.validate()?;

        let id = entry.id;
        self.archive.entries.push(entry);
        self.record(AuditKind::EntryCreated, Some(id));
        self.dirty = true;
        Ok(id)
    }

    /// Modifie une entrée, en conservant son état antérieur dans l'historique.
    ///
    /// # Atomicité
    ///
    /// La mutation est appliquée sur une **copie** de l'entrée, validée, puis
    /// substituée. Si la closure échoue — ou si l'entrée résultante est invalide —
    /// l'archive est **inchangée**. Sans cette précaution, une modification refusée
    /// laisserait une entrée à moitié modifiée.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si l'entrée est introuvable ou si la mutation produit
    /// une référence pendante.
    pub fn update_entry<F>(&mut self, id: &EntryId, mutate: F) -> Result<u32>
    where
        F: FnOnce(&mut Entry) -> Result<()>,
    {
        let index = self.entry_index(id)?;
        let now = now_unix();

        // Copie de travail. `Entry` n'est pas `Clone` — délibérément, pour que
        // dupliquer du contenu secret soit toujours un acte explicite et repérable en
        // relecture. C'est le motif « valider puis appliquer » : on modifie une copie,
        // on la valide, et on ne la substitue qu'en cas de succès.
        let previous = self.archive.entries[index].duplicate();

        let mut working = self.archive.entries[index].duplicate();
        mutate(&mut working)?;
        self.check_references(&working)?;
        working.validate()?;

        working.revision = working.revision.saturating_add(1);
        working.updated_at = now;

        // L'état antérieur entre dans l'historique, puis la rétention s'applique.
        let mut snapshot = previous;
        snapshot.history.clear();
        working.history.push(Revision { at: now, snapshot });
        migrate::truncate_history(&mut working, now);

        self.archive.entries[index] = working;
        self.record(AuditKind::EntryUpdated, Some(*id));
        self.dirty = true;
        Ok(self.archive.entries[index].revision)
    }

    /// Met une entrée à la corbeille.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si l'entrée est introuvable.
    pub fn trash_entry(&mut self, id: &EntryId) -> Result<()> {
        let index = self.entry_index(id)?;
        if self.archive.entries[index].is_trashed() {
            return Ok(());
        }

        self.archive.entries[index].trashed_at = Some(now_unix());
        self.record(AuditKind::EntryTrashed, Some(*id));
        self.dirty = true;
        Ok(())
    }

    /// Restaure une entrée depuis la corbeille.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si l'entrée est introuvable.
    pub fn restore_entry(&mut self, id: &EntryId) -> Result<()> {
        let index = self.entry_index(id)?;
        if self.archive.entries[index].trashed_at.take().is_none() {
            return Ok(());
        }

        self.record(AuditKind::EntryRestored, Some(*id));
        self.dirty = true;
        Ok(())
    }

    /// Supprime définitivement une entrée, **historique compris**.
    ///
    /// # Ce que cette opération ne fait pas
    ///
    /// Elle n'a aucun effet sur les **sauvegardes déjà écrites** : une copie
    /// antérieure du coffre contient toujours l'entrée. C'est inévitable, et cela
    /// doit être dit à l'utilisateur au moment de la suppression plutôt que découvert
    /// plus tard.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si l'entrée est introuvable.
    pub fn purge_entry(&mut self, id: &EntryId) -> Result<()> {
        let index = self.entry_index(id)?;
        self.archive.entries.remove(index);

        // Les pièces jointes de l'entrée deviennent orphelines : leurs métadonnées
        // sont retirées ici, la suppression des blobs sur disque relève de la couche
        // qui les gère (phase ultérieure).
        self.archive.attachments.retain(|meta| meta.entry != *id);

        self.record(AuditKind::EntryPurged, Some(*id));
        self.dirty = true;
        Ok(())
    }

    /// Vide la corbeille.
    ///
    /// Retourne le nombre d'entrées supprimées.
    ///
    /// # Erreurs
    /// Propage les erreurs de [`VaultStore::purge_entry`].
    pub fn empty_trash(&mut self) -> Result<usize> {
        let doomed: Vec<EntryId> = self
            .archive
            .entries
            .iter()
            .filter(|entry| entry.is_trashed())
            .map(|entry| entry.id)
            .collect();

        let count = doomed.len();
        for id in doomed {
            self.purge_entry(&id)?;
        }
        Ok(count)
    }

    /// Purge l'historique d'une entrée.
    ///
    /// # Conséquences, à énoncer
    ///
    /// Les versions antérieures disparaissent **de ce coffre**, et nulle part
    /// ailleurs : ni des sauvegardes déjà écrites, ni d'un éventuel support
    /// synchronisé. L'utilisateur doit le savoir au moment où il purge, pas après.
    ///
    /// Retourne le nombre de révisions supprimées.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si l'entrée est introuvable.
    pub fn purge_history(&mut self, id: &EntryId) -> Result<usize> {
        let index = self.entry_index(id)?;
        let removed = self.archive.entries[index].history.len();
        self.archive.entries[index].history.clear();

        if removed > 0 {
            self.record(AuditKind::HistoryPurged, Some(*id));
            self.dirty = true;
        }
        Ok(removed)
    }

    // -----------------------------------------------------------------------
    // Dossiers et tags
    // -----------------------------------------------------------------------

    /// Ajoute un dossier.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si le parent est introuvable, si la profondeur
    /// maximale est dépassée, ou si un dossier de ce nom existe déjà au même niveau.
    pub fn add_folder(&mut self, name: &str, parent: Option<FolderId>) -> Result<FolderId> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::MalformedLength {
                reason: "nom de dossier invalide",
            });
        }

        if let Some(parent_id) = parent {
            let depth = self.folder_depth(&parent_id)?;
            if depth >= MAX_FOLDER_DEPTH {
                return Err(Error::InvalidHeader {
                    reason: "profondeur maximale de dossiers atteinte",
                });
            }
        }

        if self
            .archive
            .folders
            .iter()
            .any(|folder| folder.parent == parent && folder.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::InvalidHeader {
                reason: "un dossier de ce nom existe déjà à ce niveau",
            });
        }

        let id = FolderId::generate()?;
        self.archive.folders.push(Folder {
            id,
            name: name.to_string(),
            parent,
            ordinal: 0,
        });
        self.dirty = true;
        Ok(id)
    }

    /// Ajoute un tag.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si un tag de ce nom existe déjà.
    pub fn add_tag(&mut self, name: &str) -> Result<TagId> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::MalformedLength {
                reason: "nom de tag invalide",
            });
        }

        if self
            .archive
            .tags
            .iter()
            .any(|tag| tag.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::InvalidHeader {
                reason: "un tag de ce nom existe déjà",
            });
        }

        let id = TagId::generate()?;
        self.archive.tags.push(Tag {
            id,
            name: name.to_string(),
        });
        self.dirty = true;
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Pièces jointes
    // -----------------------------------------------------------------------

    /// Répertoire des blobs de ce coffre.
    ///
    /// La règle de nommage est **unique** (`attachment::blob_dir_for`) et partagée par
    /// le coffre vivant, la sauvegarde et la vérification : elle n'est jamais devinée.
    #[must_use]
    pub fn attachment_dir(&self) -> PathBuf {
        attachment::blob_dir_for(self.path())
    }

    /// Chemin du fichier d'un blob.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si la dérivation du nom échoue.
    pub fn blob_path(&self, id: &BlobId) -> Result<PathBuf> {
        Ok(self.attachment_dir().join(self.blob_name(id)?))
    }

    /// Nom de fichier dérivé d'un blob.
    fn blob_name(&self, id: &BlobId) -> Result<String> {
        attachment::blob_file_name(self.vault.subkeys(), &self.vault.header().vault_id, *id)
    }

    /// Pièces jointes d'une entrée, dans l'ordre de l'archive.
    #[must_use]
    pub fn attachments_of(&self, entry: &EntryId) -> Vec<&AttachmentMeta> {
        self.archive
            .attachments
            .iter()
            .filter(|meta| meta.entry == *entry)
            .collect()
    }

    /// Pièce jointe par identifiant.
    #[must_use]
    pub fn attachment(&self, id: &BlobId) -> Option<&AttachmentMeta> {
        self.archive.attachments.iter().find(|meta| meta.id == *id)
    }

    /// Ajoute une pièce jointe, en écrivant son blob **avant** d'enregistrer sa
    /// métadonnée.
    ///
    /// # Ordre, et pourquoi il est imposé ici
    ///
    /// `I-BLOB-ORDER`. La séquence est : scellement → durabilité du blob → **puis**
    /// ajout de la métadonnée, laquelle n'atteint le disque qu'au prochain
    /// [`VaultStore::save`]. Un incident entre les deux laisse donc un **orphelin** —
    /// invisible et inoffensif, récupérable par `attach gc`. L'ordre inverse
    /// produirait une métadonnée sans son fichier, c'est-à-dire une **promesse non
    /// tenue** : le coffre annoncerait une pièce jointe que `attach get` ne pourrait pas
    /// restituer.
    ///
    /// # Collision de nom
    ///
    /// Le nom de fichier est un HMAC **tronqué à 128 bits** : une collision est
    /// improbable, jamais impossible. `O_EXCL` reste la garantie ultime — il refuse
    /// d'écraser quoi que ce soit, y compris un fichier étranger déposé au même nom.
    /// En cas de collision, un **nouvel identifiant** est tiré et le nom recalculé,
    /// jusqu'à [`MAX_BLOB_NAME_ATTEMPTS`] fois. Ce cas n'est jamais supposé impossible.
    ///
    /// # Erreurs
    /// * [`Error::ReadOnly`] sur un coffre ouvert en lecture seule ;
    /// * [`Error::InvalidHeader`] si l'entrée n'existe pas, ou s'il y a déjà
    ///   [`MAX_ATTACHMENTS`] pièces jointes ;
    /// * [`Error::MalformedLength`] si le nom est vide ou trop long ;
    /// * [`Error::InvalidInput`] si la source dépasse la taille maximale, ou change de
    ///   taille pendant la lecture ;
    /// * [`Error::Io`] pour toute erreur de fichier.
    pub fn add_attachment(
        &mut self,
        entry: &EntryId,
        name: &str,
        source: &Path,
    ) -> Result<AttachmentMeta> {
        if self.vault.is_read_only() {
            return Err(Error::ReadOnly);
        }

        // Toutes les vérifications **avant** d'écrire quoi que ce soit sur le disque.
        if self.archive.entry(entry).is_none() {
            return Err(Error::InvalidHeader {
                reason: "pièce jointe rattachée à une entrée inexistante",
            });
        }
        if name.is_empty() || name.len() > MAX_ATTACHMENT_NAME_LEN {
            return Err(Error::MalformedLength {
                reason: "nom de pièce jointe invalide",
            });
        }
        if self.archive.attachments.len() >= MAX_ATTACHMENTS {
            return Err(Error::InvalidHeader {
                reason: "trop de pièces jointes",
            });
        }

        let mut origin = fs::open_read(source)?;
        let size = origin.metadata()?.len();
        if size > attachment::MAX_ATTACHMENT_BYTES {
            return Err(Error::InvalidInput {
                reason: "pièce jointe au-delà de la taille maximale",
            });
        }

        let dir = self.attachment_dir();
        Self::ensure_attachment_dir(&dir)?;

        let vault_id = self.vault.header().vault_id;
        let sealed = self.seal_new_blob(&dir, &vault_id, size, &mut origin)?;

        let meta = AttachmentMeta {
            id: sealed.header.blob_id,
            entry: *entry,
            name: name.to_string(),
            size: sealed.header.plaintext_size,
            chunk_size: sealed.header.chunk_size,
            chunk_count: sealed.header.chunk_count,
            created_at: now_unix(),
            content_mac: sealed.content_mac,
        };

        // `AuditKind` est un ensemble **fermé** à valeurs d'octets fixes : y ajouter une
        // variante rendrait tout coffre écrit par ce binaire illisible par l'ancien
        // (ADR-025). Rien n'est donc ajouté — et `EntryUpdated` décrit exactement ce qui
        // vient de se passer : l'entrée a changé.
        let stored = meta.duplicate();
        self.archive.attachments.push(meta);
        self.record(AuditKind::EntryUpdated, Some(*entry));
        self.dirty = true;
        Ok(stored)
    }

    /// Retire la métadonnée d'une pièce jointe, **sans toucher au fichier**.
    ///
    /// # Ordre
    ///
    /// `I-BLOB-ORDER`, sens inverse : la métadonnée d'abord, le fichier ensuite — ou
    /// jamais, s'il devient un orphelin. L'appelant peut enchaîner sur
    /// [`VaultStore::save`] puis [`VaultStore::purge_blob`], ce qui donne l'ordre
    /// attendu : le coffre ne référence plus le blob **avant** que le fichier
    /// disparaisse. Si le processus s'arrête entre les deux, il reste un orphelin.
    ///
    /// # Erreurs
    /// [`Error::ReadOnly`], ou [`Error::InvalidHeader`] si l'identifiant est inconnu.
    /// Retirer une pièce jointe déjà absente échoue explicitement : c'est une opération
    /// qui libère un fichier, et viser une cible absente signale une erreur de cible.
    pub fn remove_attachment(&mut self, id: &BlobId) -> Result<AttachmentMeta> {
        if self.vault.is_read_only() {
            return Err(Error::ReadOnly);
        }
        let index = self
            .archive
            .attachments
            .iter()
            .position(|meta| meta.id == *id)
            .ok_or(Error::InvalidHeader {
                reason: "pièce jointe inconnue",
            })?;

        let meta = self.archive.attachments.remove(index);
        self.record(AuditKind::EntryUpdated, Some(meta.entry));
        self.dirty = true;
        Ok(meta)
    }

    /// Supprime physiquement le fichier d'un blob.
    ///
    /// # Quand l'appeler
    ///
    /// **Après** [`VaultStore::remove_attachment`] **et** [`VaultStore::save`]. C'est
    /// l'ordre `I-BLOB-ORDER` en suppression : le coffre ne référence plus le blob avant
    /// que le fichier disparaisse. Appelée dans l'autre sens, elle produirait une
    /// métadonnée sans son fichier — une promesse non tenue.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si la dérivation du nom échoue, [`Error::Io`] si la
    /// suppression échoue. Un échec laisse un **orphelin**, que `attach gc` récupère :
    /// ce n'est jamais une incohérence.
    pub fn purge_blob(&self, id: &BlobId) -> Result<()> {
        self.delete_blob_by_name(&self.blob_name(id)?)
    }

    /// Supprime un fichier du répertoire des blobs, **par son nom**.
    ///
    /// # Pourquoi par nom, et pas par chemin
    ///
    /// Un chemin arbitraire laisserait la suppression sortir du répertoire des blobs.
    /// Le nom est ici **revalidé** (`is_blob_name`) avant toute opération, et il est
    /// résolu **relativement au répertoire des blobs** : cette méthode ne peut donc pas
    /// viser un fichier étranger ni un autre répertoire, quoi que lui passe l'appelant.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si le nom ne peut pas être un nom de blob.
    pub fn delete_blob_by_name(&self, name: &str) -> Result<()> {
        if !attachment::is_blob_name(name) {
            return Err(Error::InvalidInput {
                reason: "ce nom ne peut pas être celui d'un blob",
            });
        }
        fs::remove_file(&self.attachment_dir().join(name))?;
        Ok(())
    }

    /// Crée le répertoire des blobs s'il n'existe pas encore.
    ///
    /// `mkdirat` **est** le contrôle d'existence : il n'y a donc **aucun**
    /// `path_exists` préalable, et donc aucune fenêtre entre la vérification et la
    /// création. Un `AlreadyExists` signifie simplement qu'un autre appel l'a créé —
    /// ce n'est pas une erreur.
    fn ensure_attachment_dir(dir: &Path) -> Result<()> {
        match fs::create_dir_private(dir) {
            Ok(level) => check_durability(level),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(Error::Io(err)),
        }
    }

    /// Écrit un blob neuf sous un nom **libre**, et le rend durable.
    ///
    /// # Pourquoi une boucle
    ///
    /// Le nom est un HMAC tronqué à 128 bits : une collision est improbable, **jamais
    /// impossible**. `create_private_file` repose sur `O_EXCL`, qui refuse d'écraser
    /// quoi que ce soit — y compris un fichier étranger déposé au même nom. En cas de
    /// collision, un nouvel identifiant est tiré et le nom recalculé. Rien n'est jamais
    /// écrasé, et le cas n'est jamais supposé impossible.
    ///
    /// La collision est détectée **avant** de lire la source : réessayer ne consomme
    /// donc pas le flux, et la nouvelle tentative lit bien l'intégralité de l'entrée.
    fn seal_new_blob(
        &self,
        dir: &Path,
        vault_id: &[u8; 16],
        size: u64,
        source: &mut std::fs::File,
    ) -> Result<attachment::SealedBlob> {
        for _ in 0..MAX_BLOB_NAME_ATTEMPTS {
            let id = BlobId::generate()?;
            let name = attachment::blob_file_name(self.vault.subkeys(), vault_id, id)?;
            let path = dir.join(&name);

            let mut file = match fs::create_private_file(&path) {
                Ok(file) => file,
                // Collision de nom, ou fichier étranger au même nom : on retire un
                // identifiant et on recommence. Jamais d'écrasement.
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(Error::Io(err)),
            };

            let sealed = match attachment::seal_blob(
                id,
                vault_id,
                self.vault.subkeys(),
                size,
                source,
                &mut file,
            ) {
                Ok(sealed) => sealed,
                Err(err) => {
                    // Le fichier est le nôtre : on l'a créé en exclusif à l'instant.
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(err);
                }
            };

            let level = match fs::make_durable(&file, dir) {
                Ok(level) => level,
                Err(err) => {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(Error::Io(err));
                }
            };
            drop(file);
            check_durability(level)?;

            return Ok(sealed);
        }

        Err(Error::Internal {
            invariant: "aucun nom de blob libre après plusieurs tirages",
        })
    }

    // -----------------------------------------------------------------------
    // Journal de sécurité
    // -----------------------------------------------------------------------

    /// Consigne un événement dans le journal.
    ///
    /// # Ce qu'un événement ne contient jamais
    ///
    /// Aucune valeur d'entrée, aucun titre, aucune clé : le type [`AuditKind`] est un
    /// ensemble **fermé**, et le sujet est un identifiant aléatoire. Il n'existe donc
    /// aucun chemin par lequel un contenu pourrait entrer dans le journal.
    ///
    /// Le journal est **circulaire** : au-delà de [`MAX_AUDIT_EVENTS`], les plus
    /// anciens événements sont retirés. Un journal non borné ferait grossir le coffre
    /// indéfiniment au fil des ouvertures.
    pub fn record(&mut self, kind: AuditKind, subject: Option<EntryId>) {
        self.archive.audit.push(AuditEvent {
            at: now_unix(),
            kind,
            subject,
        });

        if self.archive.audit.len() > MAX_AUDIT_EVENTS {
            let excess = self.archive.audit.len() - MAX_AUDIT_EVENTS;
            self.archive.audit.drain(..excess);
        }
        self.dirty = true;
    }

    /// Journal de sécurité.
    #[must_use]
    pub fn audit(&self) -> &[AuditEvent] {
        &self.archive.audit
    }

    /// Enregistre un événement **sans** marquer le coffre comme modifié.
    ///
    /// Sert aux événements d'ouverture : consigner un déverrouillage dans le journal
    /// permanent rendrait **toute** ouverture modifiante, et forcerait une écriture
    /// pour une simple consultation. Le compromis est explicite : le journal conserve
    /// les actions, pas les consultations.
    pub fn record_without_dirty(&mut self, kind: AuditKind, subject: Option<EntryId>) {
        let was_dirty = self.dirty;
        self.record(kind, subject);
        self.dirty = was_dirty;
    }

    // -----------------------------------------------------------------------
    // Détails d'implémentation
    // -----------------------------------------------------------------------

    /// Retrouve l'index d'une entrée.
    fn entry_index(&self, id: &EntryId) -> Result<usize> {
        self.archive
            .entries
            .iter()
            .position(|entry| entry.id == *id)
            .ok_or(Error::InvalidHeader {
                reason: "entrée introuvable",
            })
    }

    /// Vérifie que les références d'une entrée existent.
    fn check_references(&self, entry: &Entry) -> Result<()> {
        if entry
            .folder
            .is_some_and(|folder| !self.archive.folders.iter().any(|other| other.id == folder))
        {
            return Err(Error::InvalidHeader {
                reason: "dossier référencé inexistant",
            });
        }
        for tag in &entry.tags {
            if !self.archive.tags.iter().any(|other| other.id == *tag) {
                return Err(Error::InvalidHeader {
                    reason: "tag référencé inexistant",
                });
            }
        }
        Ok(())
    }

    /// Profondeur d'un dossier, bornée.
    fn folder_depth(&self, id: &FolderId) -> Result<usize> {
        let mut depth = 0;
        let mut current = Some(*id);

        while let Some(folder_id) = current {
            depth += 1;
            if depth > MAX_FOLDER_DEPTH {
                return Err(Error::InvalidHeader {
                    reason: "profondeur de dossiers excessive ou cycle",
                });
            }
            current = self
                .archive
                .folders
                .iter()
                .find(|folder| folder.id == folder_id)
                .and_then(|folder| folder.parent);
        }
        Ok(depth)
    }
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultStore")
            .field("path", &self.vault.path())
            .field("archive", &self.archive)
            .field("dirty", &self.dirty)
            .field("migrated_from", &self.vault.diagnostics().migrated_from)
            .finish_non_exhaustive()
    }
}
