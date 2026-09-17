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

use crate::archive;
use crate::error::{Error, Result};
use crate::migrate;
use crate::model::{
    Archive, AuditEvent, AuditKind, Entry, EntryId, Folder, FolderId, MAX_AUDIT_EVENTS,
    MAX_FOLDER_DEPTH, MAX_NAME_LEN, Revision, Tag, TagId,
};
use crate::rollback::now_unix;
use crate::vault::{Credentials, Diagnostics, Vault, VaultConfig};

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
    pub fn create(path: &std::path::Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
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
    pub fn open(path: &std::path::Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
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
        path: &std::path::Path,
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
    pub fn path(&self) -> &std::path::Path {
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
