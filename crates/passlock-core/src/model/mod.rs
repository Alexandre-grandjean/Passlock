//! Modèle de données du coffre.
//!
//! # Principes
//!
//! 1. **Champs clé-valeur typés, pas de schéma figé par type d'entrée.** Un `Login`
//!    et une `SecureNote` ne diffèrent que par leurs champs. Ajouter un type
//!    d'entrée — ou un champ personnalisé — ne change donc **ni le format ni le code
//!    de sérialisation**.
//! 2. **Identifiants aléatoires**, jamais dérivés d'un contenu (voir `ids.rs`).
//! 3. **Tout ce qui est stocké est déchiffré quelque part.** Il n'y a pas de champ
//!    « moins sensible » : la distinction secret/non-secret portée par
//!    [`Field::concealed`] est une indication **d'affichage**, pas une garantie de
//!    stockage.
//! 4. **Rien n'est stocké qui puisse être calculé.** Ce qui est volontairement absent
//!    est listé dans `docs/DATA_MODEL.md`.
//! 5. **Aucune structure récursive.** Une [`Revision`] contient un instantané dont
//!    l'historique est **obligatoirement vide** — c'est ce qui borne la profondeur à
//!    un niveau et empêche un corps forgé de provoquer un épuisement de pile. Cet
//!    invariant est vérifié au décodage.

mod ids;
mod wipe;

pub use ids::{BlobId, EntryId, FolderId, TagId};

use std::fmt;

use wipe::{Wipe, impl_wipe_on_drop};

// ---------------------------------------------------------------------------
// Bornes du format.
//
// TOUTES sont vérifiées **avant** allocation, à l'encodage comme au décodage.
// Elles ne sont pas là pour limiter l'utilisateur : elles délimitent ce qu'un corps
// forgé peut faire tenter au décodeur.
// ---------------------------------------------------------------------------

/// Nombre maximal d'entrées.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Nombre maximal de dossiers.
pub const MAX_FOLDERS: usize = 4096;
/// Nombre maximal de tags.
pub const MAX_TAGS: usize = 4096;
/// Nombre maximal d'événements de journal conservés.
pub const MAX_AUDIT_EVENTS: usize = 1_000;
/// Nombre maximal de champs dans une entrée.
pub const MAX_FIELDS_PER_ENTRY: usize = 256;
/// Nombre maximal de tags sur une entrée.
pub const MAX_TAGS_PER_ENTRY: usize = 64;
/// Nombre maximal de révisions conservées par entrée.
pub const MAX_HISTORY_PER_ENTRY: usize = 50;
/// Profondeur maximale de l'arborescence de dossiers.
pub const MAX_FOLDER_DEPTH: usize = 8;
/// Longueur maximale d'un titre ou d'un sous-titre.
pub const MAX_TITLE_LEN: usize = 1024;
/// Longueur maximale du nom d'un dossier ou d'un tag.
pub const MAX_NAME_LEN: usize = 256;
/// Longueur maximale d'une clé de champ.
pub const MAX_FIELD_KEY_LEN: usize = 128;
/// Longueur maximale d'une valeur de champ.
pub const MAX_FIELD_VALUE_LEN: usize = 64 * 1024;
/// Nombre maximal de pièces jointes référencées.
pub const MAX_ATTACHMENTS: usize = 4096;
/// Longueur maximale du nom d'origine d'une pièce jointe.
pub const MAX_ATTACHMENT_NAME_LEN: usize = 512;

// Tailles encodées **minimales** d'un enregistrement, utilisées par
// `bytes::Reader::count` pour vérifier qu'un compte lu dans le corps est
// physiquement compatible avec les octets restants. Toute modification du layout
// doit les mettre à jour — un test les confronte à l'encodage réel.
pub(crate) const MIN_ENCODED_ENTRY: usize = 82;
// 4 (longueur de clé) + 1 (clé minimale : une clé vide est refusée) + 1 (type)
// + 2 (ordre) + 1 (drapeaux) + 4 (longueur de valeur) = 13.
//
// NOTE : une première valeur de 12 omettait l'octet de clé minimal. Une constante
// **trop basse** est le cas dangereux : elle rend la borne d'allocation plus
// permissive qu'elle ne devrait l'être. Le test
// `the_minimum_encoded_sizes_match_the_encoder` compare chaque constante à
// l'encodage réellement produit, précisément pour attraper ce sens d'erreur.
pub(crate) const MIN_ENCODED_FIELD: usize = 13;
pub(crate) const MIN_ENCODED_FOLDER: usize = 38;
pub(crate) const MIN_ENCODED_TAG: usize = 20;
pub(crate) const MIN_ENCODED_REVISION: usize = 12;
pub(crate) const MIN_ENCODED_ATTACHMENT: usize = 92;
pub(crate) const MIN_ENCODED_AUDIT_EVENT: usize = 25;

/// Type d'entrée.
///
/// Ensemble **fermé** : un octet inconnu est refusé au décodage plutôt que
/// silencieusement rangé dans une catégorie fourre-tout. Un type ajouté dans une
/// version future produira une erreur explicite au lieu d'une perte de données
/// silencieuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum EntryKind {
    #[default]
    Login,
    SecureNote,
    CreditCard,
    Identity,
    ApiKey,
    SshKey,
    Wifi,
    PasskeyMetadata,
    Custom,
}

impl EntryKind {
    /// Toutes les variantes, pour l'énumération exhaustive des tests.
    pub const ALL: [Self; 9] = [
        Self::Login,
        Self::SecureNote,
        Self::CreditCard,
        Self::Identity,
        Self::ApiKey,
        Self::SshKey,
        Self::Wifi,
        Self::PasskeyMetadata,
        Self::Custom,
    ];

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::SecureNote => 2,
            Self::CreditCard => 3,
            Self::Identity => 4,
            Self::ApiKey => 5,
            Self::SshKey => 6,
            Self::Wifi => 7,
            Self::PasskeyMetadata => 8,
            Self::Custom => 9,
        }
    }

    /// Décode un type d'entrée.
    ///
    /// # Erreurs
    /// [`crate::error::Error::InvalidHeader`] si l'octet est inconnu.
    pub fn from_u8(value: u8) -> crate::error::Result<Self> {
        match value {
            1 => Ok(Self::Login),
            2 => Ok(Self::SecureNote),
            3 => Ok(Self::CreditCard),
            4 => Ok(Self::Identity),
            5 => Ok(Self::ApiKey),
            6 => Ok(Self::SshKey),
            7 => Ok(Self::Wifi),
            8 => Ok(Self::PasskeyMetadata),
            9 => Ok(Self::Custom),
            _ => Err(crate::error::Error::InvalidHeader {
                reason: "type d'entrée inconnu",
            }),
        }
    }

    /// Libellé destiné à l'affichage.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Login => "identifiant",
            Self::SecureNote => "note sécurisée",
            Self::CreditCard => "carte bancaire",
            Self::Identity => "identité",
            Self::ApiKey => "clé d'API",
            Self::SshKey => "clé SSH",
            Self::Wifi => "réseau Wi-Fi",
            Self::PasskeyMetadata => "passkey (métadonnées)",
            Self::Custom => "personnalisé",
        }
    }
}

/// Type de valeur portée par un champ.
///
/// Sert à l'affichage et au masquage, **pas** à la protection : la valeur est
/// chiffrée de la même façon quel que soit son type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum FieldKind {
    #[default]
    Text,
    Secret,
    Url,
    Multiline,
    Email,
    Totp,
    Number,
    Date,
    Pin,
    Custom,
}

impl FieldKind {
    pub const ALL: [Self; 10] = [
        Self::Text,
        Self::Secret,
        Self::Url,
        Self::Multiline,
        Self::Email,
        Self::Totp,
        Self::Number,
        Self::Date,
        Self::Pin,
        Self::Custom,
    ];

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Secret => 2,
            Self::Url => 3,
            Self::Multiline => 4,
            Self::Email => 5,
            Self::Totp => 6,
            Self::Number => 7,
            Self::Date => 8,
            Self::Pin => 9,
            Self::Custom => 10,
        }
    }

    /// # Erreurs
    /// [`crate::error::Error::InvalidHeader`] si l'octet est inconnu.
    pub fn from_u8(value: u8) -> crate::error::Result<Self> {
        match value {
            1 => Ok(Self::Text),
            2 => Ok(Self::Secret),
            3 => Ok(Self::Url),
            4 => Ok(Self::Multiline),
            5 => Ok(Self::Email),
            6 => Ok(Self::Totp),
            7 => Ok(Self::Number),
            8 => Ok(Self::Date),
            9 => Ok(Self::Pin),
            10 => Ok(Self::Custom),
            _ => Err(crate::error::Error::InvalidHeader {
                reason: "type de champ inconnu",
            }),
        }
    }

    /// Libellé destiné à l'affichage.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "texte",
            Self::Secret => "secret",
            Self::Url => "url",
            Self::Multiline => "texte long",
            Self::Email => "courriel",
            Self::Totp => "totp",
            Self::Number => "nombre",
            Self::Date => "date",
            Self::Pin => "code",
            Self::Custom => "personnalisé",
        }
    }

    /// Vrai si la valeur doit être masquée par défaut à l'affichage.
    #[must_use]
    pub const fn is_concealed_by_default(self) -> bool {
        matches!(self, Self::Secret | Self::Pin | Self::Totp)
    }
}

/// Un champ d'une entrée.
pub struct Field {
    /// Nom du champ : `password`, `totp`, `url`… ou une clé libre pour un champ
    /// personnalisé.
    pub key: String,
    /// Nature de la valeur, pour l'affichage.
    pub kind: FieldKind,
    /// Contenu du champ.
    pub value: String,
    /// Ordre d'affichage, utilisé pour rendre l'encodage déterministe.
    pub ordinal: u16,
    /// Masquage à l'affichage. Indication d'interface **et non** de stockage.
    pub concealed: bool,
}

impl Field {
    /// Construit un champ.
    ///
    /// # Erreurs
    /// [`crate::error::Error::MalformedLength`] si la clé ou la valeur dépassent
    /// leur borne.
    pub fn new(
        key: impl Into<String>,
        kind: FieldKind,
        value: impl Into<String>,
        ordinal: u16,
    ) -> crate::error::Result<Self> {
        let key = key.into();
        let value = value.into();

        if key.len() > MAX_FIELD_KEY_LEN {
            return Err(crate::error::Error::MalformedLength {
                reason: "clé de champ au-delà de la longueur maximale",
            });
        }
        if value.len() > MAX_FIELD_VALUE_LEN {
            return Err(crate::error::Error::MalformedLength {
                reason: "valeur de champ au-delà de la longueur maximale",
            });
        }

        Ok(Self {
            concealed: kind.is_concealed_by_default(),
            key,
            kind,
            value,
            ordinal,
        })
    }
}

impl Wipe for Field {
    fn wipe(&mut self) {
        self.key.wipe();
        self.value.wipe();
        // Les champs scalaires ne portent aucun contenu : le type, l'ordre et le
        // masquage sont des métadonnées d'affichage. Seul le **texte** est effacé,
        // parce que seul le texte transporte du contenu.
    }
}
impl_wipe_on_drop!(Field);

/// Un instantané d'entrée pris avant une modification.
///
/// # Invariant structurel
///
/// `snapshot.history` **doit** être vide. C'est ce qui rend la structure
/// non récursive : sans cette règle, un corps forgé pourrait imbriquer des
/// révisions à l'infini et provoquer un épuisement de pile au décodage. Le décodeur
/// **refuse** tout instantané dont l'historique n'est pas vide.
pub struct Revision {
    /// Date de la révision, en secondes depuis l'époque Unix.
    pub at: u64,
    /// État de l'entrée avant la modification.
    pub snapshot: Entry,
}

impl Wipe for Revision {
    fn wipe(&mut self) {
        self.snapshot.wipe();
    }
}
impl_wipe_on_drop!(Revision);

/// Une entrée du coffre.
pub struct Entry {
    pub id: EntryId,
    pub kind: EntryKind,
    pub title: String,
    /// Texte secondaire affiché dans les listes (nom d'utilisateur, domaine…).
    pub subtitle: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Date de mise à la corbeille ; `None` si l'entrée est active.
    pub trashed_at: Option<u64>,
    pub archived: bool,
    pub favorite: bool,
    /// Exige une réauthentification avant toute révélation.
    ///
    /// Indication d'interface : elle ne change rien au stockage, qui est déjà
    /// chiffré. Elle sera appliquée par la couche qui affiche (phase 6).
    pub sensitive: bool,
    pub folder: Option<FolderId>,
    pub tags: Vec<TagId>,
    pub fields: Vec<Field>,
    /// Numéro de révision, incrémenté à chaque modification.
    pub revision: u32,
    pub history: Vec<Revision>,
}

impl Entry {
    /// Construit une entrée vide.
    ///
    /// # Erreurs
    /// Propage l'échec du générateur d'identifiants, et refuse un titre hors bornes.
    pub fn new(kind: EntryKind, title: impl Into<String>, now: u64) -> crate::error::Result<Self> {
        let title = title.into();
        if title.len() > MAX_TITLE_LEN {
            return Err(crate::error::Error::MalformedLength {
                reason: "titre au-delà de la longueur maximale",
            });
        }

        Ok(Self {
            id: EntryId::generate()?,
            kind,
            title,
            subtitle: String::new(),
            created_at: now,
            updated_at: now,
            trashed_at: None,
            archived: false,
            favorite: false,
            sensitive: false,
            folder: None,
            tags: Vec::new(),
            fields: Vec::new(),
            revision: 1,
            history: Vec::new(),
        })
    }

    /// Duplique l'entrée, **explicitement**.
    ///
    /// # Pourquoi une méthode nommée plutôt que `Clone`
    ///
    /// `Entry` n'implémente délibérément pas `Clone`, pour la même raison que les
    /// types de clés de `secret.rs` : dupliquer du contenu secret doit être un acte
    /// **visible**, jamais l'effet de bord d'un `.clone()` oublié au détour d'un
    /// remaniement. Une méthode nommée `duplicate` se repère en relecture ; un
    /// `#[derive(Clone)]` ne se repère pas.
    ///
    /// L'usage prévu est le motif « valider puis appliquer » de
    /// [`crate::store::VaultStore::update_entry`] : on modifie une copie, on la
    /// valide, et on ne la substitue qu'en cas de succès.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            subtitle: self.subtitle.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            trashed_at: self.trashed_at,
            archived: self.archived,
            favorite: self.favorite,
            sensitive: self.sensitive,
            folder: self.folder,
            tags: self.tags.clone(),
            fields: self
                .fields
                .iter()
                .map(|field| Field {
                    key: field.key.clone(),
                    kind: field.kind,
                    value: field.value.clone(),
                    ordinal: field.ordinal,
                    concealed: field.concealed,
                })
                .collect(),
            revision: self.revision,
            // Les instantanés d'historique sont dupliqués récursivement — leur
            // profondeur est bornée à un niveau, donc la récursion est finie.
            history: self
                .history
                .iter()
                .map(|revision| Revision {
                    at: revision.at,
                    snapshot: revision.snapshot.duplicate(),
                })
                .collect(),
        }
    }

    /// Vrai si l'entrée est à la corbeille.
    #[must_use]
    pub const fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// Vrai si l'entrée est active : ni à la corbeille, ni archivée.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.trashed_at.is_none() && !self.archived
    }

    /// Retourne la valeur d'un champ, par sa clé.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.key == key)
    }

    /// Vérifie les invariants de l'entrée.
    ///
    /// Appelée avant tout encodage : une entrée qui les viole produirait une archive
    /// que notre propre décodeur refuserait, ce qui est préférable à une archive
    /// acceptée puis mal interprétée — mais autant le détecter au plus tôt.
    ///
    /// # Erreurs
    /// [`crate::error::Error::MalformedLength`] ou
    /// [`crate::error::Error::InvalidHeader`] selon la violation.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::Error;

        if self.title.len() > MAX_TITLE_LEN || self.subtitle.len() > MAX_TITLE_LEN {
            return Err(Error::MalformedLength {
                reason: "titre ou sous-titre au-delà de la longueur maximale",
            });
        }
        if self.fields.len() > MAX_FIELDS_PER_ENTRY {
            return Err(Error::MalformedLength {
                reason: "trop de champs dans une entrée",
            });
        }
        if self.tags.len() > MAX_TAGS_PER_ENTRY {
            return Err(Error::MalformedLength {
                reason: "trop de tags sur une entrée",
            });
        }
        if self.history.len() > MAX_HISTORY_PER_ENTRY {
            return Err(Error::MalformedLength {
                reason: "historique au-delà de la rétention maximale",
            });
        }

        for field in &self.fields {
            if field.key.is_empty() {
                return Err(Error::InvalidHeader {
                    reason: "clé de champ vide",
                });
            }
            if field.key.len() > MAX_FIELD_KEY_LEN || field.value.len() > MAX_FIELD_VALUE_LEN {
                return Err(Error::MalformedLength {
                    reason: "clé ou valeur de champ au-delà de la longueur maximale",
                });
            }
        }

        // Une entrée à la corbeille doit porter une date, et réciproquement.
        if self.trashed_at.is_some_and(|at| at == 0) {
            return Err(Error::InvalidHeader {
                reason: "date de mise à la corbeille invalide",
            });
        }

        Ok(())
    }
}

impl Wipe for Entry {
    fn wipe(&mut self) {
        self.title.wipe();
        self.subtitle.wipe();
        self.tags.wipe();
        self.fields.wipe();
        self.history.wipe();
    }
}
impl_wipe_on_drop!(Entry);

/// Un dossier.
pub struct Folder {
    pub id: FolderId,
    pub name: String,
    /// Dossier parent ; `None` pour un dossier racine.
    pub parent: Option<FolderId>,
    pub ordinal: u16,
}

impl Wipe for Folder {
    fn wipe(&mut self) {
        self.name.wipe();
    }
}
impl_wipe_on_drop!(Folder);

/// Un tag.
pub struct Tag {
    pub id: TagId,
    pub name: String,
}

impl Wipe for Tag {
    fn wipe(&mut self) {
        self.name.wipe();
    }
}
impl_wipe_on_drop!(Tag);

/// Métadonnées d'une pièce jointe.
///
/// Présentes au format dès la phase 2 pour que l'archive les accueille sans
/// rupture, alors que les pièces jointes ne sont pas encore implémentées.
pub struct AttachmentMeta {
    pub id: BlobId,
    pub entry: EntryId,
    /// Nom d'origine, **conservé pour l'affichage uniquement**. Il n'est jamais
    /// utilisé comme chemin : le fichier sur disque porte un nom dérivé de `id`.
    pub name: String,
    /// Taille du clair, en octets.
    pub size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub created_at: u64,
    /// `HMAC(K_index, contenu en clair)` : détecte la substitution d'un blob entier,
    /// que les tags par morceau ne détecteraient pas.
    pub content_mac: [u8; 32],
}

impl AttachmentMeta {
    /// Copie explicitement les métadonnées d'une pièce jointe.
    ///
    /// **NOTE DE CORRECTION.** Le commentaire de `content_mac` ci-dessus disait
    /// « `HMAC(K_index, contenu en clair)` ». La définition exacte est plus étroite, et
    /// elle est celle qu'implémente `attachment.rs` :
    ///
    /// ```text
    /// HMAC(K_index, "passlock/v1/attachment-content-mac"
    ///              ‖ vault_id ‖ blob_id ‖ taille ‖ clair)
    /// ```
    ///
    /// La liaison au coffre, au blob et à la taille rend le MAC **non rejouable** d'un
    /// blob, d'un coffre ou d'une taille à un autre. Ce n'est pas la correction d'une
    /// faille démontrée — l'AAD des morceaux lie déjà ces valeurs — mais une défense en
    /// profondeur, et surtout une valeur **auto-descriptive** là où le commentaire
    /// initial en laissait l'interprétation ouverte.
    ///
    /// # Pourquoi une méthode nommée plutôt que `Clone`
    ///
    /// Même raison que `Entry::duplicate` : dupliquer des métadonnées doit rester un
    /// acte **visible en relecture**. Un `#[derive(Clone)]` se serait propagé sans
    /// qu'on le remarque ; `duplicate()` se repère.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            id: self.id,
            entry: self.entry,
            name: self.name.clone(),
            size: self.size,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            created_at: self.created_at,
            content_mac: self.content_mac,
        }
    }
}

impl Wipe for AttachmentMeta {
    fn wipe(&mut self) {
        self.name.wipe();
        self.content_mac.wipe();
    }
}
impl_wipe_on_drop!(AttachmentMeta);

/// Nature d'un événement du journal de sécurité.
///
/// Ensemble **fermé** : le journal ne consigne que ce qui est énuméré ici, ce qui
/// interdit d'y écrire un contenu libre — et donc d'y faire fuiter un secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditKind {
    Unlock,
    Lock,
    EntryCreated,
    EntryUpdated,
    EntryTrashed,
    EntryRestored,
    EntryPurged,
    HistoryPurged,
    VaultSaved,
    PasswordChanged,
    Migration,
    RollbackDetected,
    ReadOnlyRefused,
}

impl AuditKind {
    pub const ALL: [Self; 13] = [
        Self::Unlock,
        Self::Lock,
        Self::EntryCreated,
        Self::EntryUpdated,
        Self::EntryTrashed,
        Self::EntryRestored,
        Self::EntryPurged,
        Self::HistoryPurged,
        Self::VaultSaved,
        Self::PasswordChanged,
        Self::Migration,
        Self::RollbackDetected,
        Self::ReadOnlyRefused,
    ];

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Unlock => 1,
            Self::Lock => 2,
            Self::EntryCreated => 3,
            Self::EntryUpdated => 4,
            Self::EntryTrashed => 5,
            Self::EntryRestored => 6,
            Self::EntryPurged => 7,
            Self::HistoryPurged => 8,
            Self::VaultSaved => 9,
            Self::PasswordChanged => 10,
            Self::Migration => 11,
            Self::RollbackDetected => 12,
            Self::ReadOnlyRefused => 13,
        }
    }

    /// # Erreurs
    /// [`crate::error::Error::InvalidHeader`] si l'octet est inconnu.
    pub fn from_u8(value: u8) -> crate::error::Result<Self> {
        match value {
            1 => Ok(Self::Unlock),
            2 => Ok(Self::Lock),
            3 => Ok(Self::EntryCreated),
            4 => Ok(Self::EntryUpdated),
            5 => Ok(Self::EntryTrashed),
            6 => Ok(Self::EntryRestored),
            7 => Ok(Self::EntryPurged),
            8 => Ok(Self::HistoryPurged),
            9 => Ok(Self::VaultSaved),
            10 => Ok(Self::PasswordChanged),
            11 => Ok(Self::Migration),
            12 => Ok(Self::RollbackDetected),
            13 => Ok(Self::ReadOnlyRefused),
            _ => Err(crate::error::Error::InvalidHeader {
                reason: "type d'événement de journal inconnu",
            }),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlock => "déverrouillage",
            Self::Lock => "verrouillage",
            Self::EntryCreated => "entrée créée",
            Self::EntryUpdated => "entrée modifiée",
            Self::EntryTrashed => "entrée mise à la corbeille",
            Self::EntryRestored => "entrée restaurée",
            Self::EntryPurged => "entrée supprimée définitivement",
            Self::HistoryPurged => "historique purgé",
            Self::VaultSaved => "coffre enregistré",
            Self::PasswordChanged => "mot de passe maître modifié",
            Self::Migration => "migration de schéma",
            Self::RollbackDetected => "retour en arrière détecté",
            Self::ReadOnlyRefused => "écriture refusée en lecture seule",
        }
    }
}

/// Un événement du journal de sécurité.
///
/// # Ce qu'un événement ne contient jamais
///
/// Aucune valeur d'entrée, aucun titre, aucune clé. Le journal consigne **qu'un**
/// événement a eu lieu, à telle date, sur tel identifiant — jamais **ce qui** y
/// figurait. Le type de sujet est un [`EntryId`], qui est un identifiant aléatoire
/// et non un contenu.
pub struct AuditEvent {
    pub at: u64,
    pub kind: AuditKind,
    /// Entrée concernée, si l'événement en vise une.
    pub subject: Option<EntryId>,
}

impl Wipe for AuditEvent {
    fn wipe(&mut self) {
        // Aucun texte : un événement ne porte qu'une date, un type fermé et un
        // identifiant aléatoire. Cette méthode existe pour satisfaire le contrat du
        // trait, et son absence de contenu est un choix, pas un oubli.
    }
}
impl_wipe_on_drop!(AuditEvent);

/// Contenu déchiffré du coffre.
///
/// C'est la seule structure qui survit durablement en mémoire. Son `Drop` efface
/// donc **tout** ce qu'elle contient.
#[derive(Default)]
pub struct Archive {
    pub created_at: u64,
    pub folders: Vec<Folder>,
    pub tags: Vec<Tag>,
    pub entries: Vec<Entry>,
    pub attachments: Vec<AttachmentMeta>,
    pub audit: Vec<AuditEvent>,
    /// Réglages propres au coffre (politique d'historique, préférences).
    pub settings: Vec<Field>,
}

impl Archive {
    /// Archive vide, à la date donnée.
    #[must_use]
    pub fn new(created_at: u64) -> Self {
        // Construction explicite : `..Self::default()` est interdit sur un type
        // qui implémente `Drop`, puisque la syntaxe déplacerait les champs restants.
        Self {
            created_at,
            folders: Vec::new(),
            tags: Vec::new(),
            entries: Vec::new(),
            attachments: Vec::new(),
            audit: Vec::new(),
            settings: Vec::new(),
        }
    }

    /// Nombre d'entrées actives.
    #[must_use]
    pub fn active_entry_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.is_active())
            .count()
    }

    /// Retrouve une entrée par son identifiant.
    #[must_use]
    pub fn entry(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == *id)
    }

    /// Vérifie les invariants de l'archive entière.
    ///
    /// Au-delà des bornes, cette méthode vérifie les **références croisées** : un
    /// dossier parent inexistant, un tag référencé inexistant, une entrée rattachée
    /// à un dossier absent. Une référence invalide est une **erreur**, jamais un
    /// `Option` silencieusement vide — une donnée rattachée à rien disparaîtrait
    /// sans que personne ne s'en aperçoive.
    ///
    /// # Erreurs
    /// [`crate::error::Error::InvalidHeader`] si une référence est pendante,
    /// [`crate::error::Error::MalformedLength`] si une borne est franchie.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::Error;

        if self.folders.len() > MAX_FOLDERS
            || self.tags.len() > MAX_TAGS
            || self.entries.len() > MAX_ENTRIES
            || self.attachments.len() > MAX_ATTACHMENTS
            || self.audit.len() > MAX_AUDIT_EVENTS
        {
            return Err(Error::MalformedLength {
                reason: "section au-delà de sa borne",
            });
        }

        for folder in &self.folders {
            if folder.name.len() > MAX_NAME_LEN {
                return Err(Error::MalformedLength {
                    reason: "nom de dossier au-delà de la longueur maximale",
                });
            }
            if let Some(parent) = folder.parent {
                if parent == folder.id {
                    return Err(Error::InvalidHeader {
                        reason: "un dossier ne peut pas être son propre parent",
                    });
                }
                if !self.folders.iter().any(|other| other.id == parent) {
                    return Err(Error::InvalidHeader {
                        reason: "dossier parent inexistant",
                    });
                }
            }
        }

        if self.detect_folder_cycle() {
            return Err(Error::InvalidHeader {
                reason: "cycle dans l'arborescence des dossiers",
            });
        }

        for tag in &self.tags {
            if tag.name.len() > MAX_NAME_LEN {
                return Err(Error::MalformedLength {
                    reason: "nom de tag au-delà de la longueur maximale",
                });
            }
        }

        for entry in &self.entries {
            entry.validate()?;

            if let Some(folder) = entry
                .folder
                .filter(|folder| !self.folders.iter().any(|other| other.id == *folder))
            {
                let _ = folder;
                return Err(Error::InvalidHeader {
                    reason: "entrée rattachée à un dossier inexistant",
                });
            }
            for tag in &entry.tags {
                if !self.tags.iter().any(|other| other.id == *tag) {
                    return Err(Error::InvalidHeader {
                        reason: "entrée portant un tag inexistant",
                    });
                }
            }
        }

        for attachment in &self.attachments {
            if attachment.name.len() > MAX_ATTACHMENT_NAME_LEN {
                return Err(Error::MalformedLength {
                    reason: "nom de pièce jointe au-delà de la longueur maximale",
                });
            }
            if attachment.chunk_size == 0 || attachment.chunk_count == 0 {
                return Err(Error::InvalidHeader {
                    reason: "métadonnées de pièce jointe incohérentes",
                });
            }
            if !self
                .entries
                .iter()
                .any(|entry| entry.id == attachment.entry)
            {
                return Err(Error::InvalidHeader {
                    reason: "pièce jointe rattachée à une entrée inexistante",
                });
            }
        }

        Ok(())
    }

    /// Détecte un cycle dans l'arborescence des dossiers.
    ///
    /// Un cycle provoquerait une boucle infinie partout où l'on remonte les parents.
    /// La détection est bornée par `MAX_FOLDER_DEPTH` : au-delà, il y a
    /// nécessairement un cycle, sans avoir à suivre la chaîne indéfiniment.
    fn detect_folder_cycle(&self) -> bool {
        for folder in &self.folders {
            let mut current = folder.parent;
            let mut steps = 0;
            while let Some(parent) = current {
                steps += 1;
                if steps > MAX_FOLDER_DEPTH {
                    return true;
                }
                match self.folders.iter().find(|other| other.id == parent) {
                    Some(found) => current = found.parent,
                    None => break,
                }
            }
        }
        false
    }
}

impl Wipe for Archive {
    fn wipe(&mut self) {
        self.folders.wipe();
        self.tags.wipe();
        self.entries.wipe();
        self.attachments.wipe();
        self.audit.wipe();
        self.settings.wipe();
    }
}
impl_wipe_on_drop!(Archive);

// ---------------------------------------------------------------------------
// `Debug` rédacteur.
//
// # Pourquoi aucune dérivation
//
// `#[derive(Debug)]` sur ces types afficherait les titres, les noms de dossiers et
// les valeurs de champs — c'est-à-dire **le contenu du coffre**. Un `{:?}` laissé
// dans un message de journal, une trace de panique ou un rapport de bogue
// suffirait alors à faire fuiter des secrets, sans qu'aucune relecture ne le
// remarque.
//
// Chaque implémentation ci-dessous affiche donc la **structure** — identifiants,
// types, compteurs, longueurs — et jamais le texte. C'est la même règle qu'en
// phase 1 sur les types de clés, appliquée à un modèle qui contient beaucoup plus
// de texte.
//
// Corollaire assumé : `{:?}` ne suffit plus pour diagnostiquer un problème de
// contenu. C'est délibéré — un outil de diagnostic qui afficherait le contenu
// serait précisément le défaut qu'on cherche à éviter.
// ---------------------------------------------------------------------------

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("key", &self.key)
            .field("kind", &self.kind)
            .field("ordinal", &self.ordinal)
            .field("concealed", &self.concealed)
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Revision")
            .field("at", &self.at)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("trashed_at", &self.trashed_at)
            .field("archived", &self.archived)
            .field("favorite", &self.favorite)
            .field("sensitive", &self.sensitive)
            .field("folder", &self.folder)
            .field("tag_count", &self.tags.len())
            .field("field_count", &self.fields.len())
            .field("history_count", &self.history.len())
            .field("title_len", &self.title.len())
            .field("subtitle_len", &self.subtitle.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Folder")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("ordinal", &self.ordinal)
            .field("name_len", &self.name.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tag")
            .field("id", &self.id)
            .field("name_len", &self.name.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AttachmentMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentMeta")
            .field("id", &self.id)
            .field("entry", &self.entry)
            .field("size", &self.size)
            .field("chunk_size", &self.chunk_size)
            .field("chunk_count", &self.chunk_count)
            .field("created_at", &self.created_at)
            .field("name_len", &self.name.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEvent")
            .field("at", &self.at)
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Archive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Archive")
            .field("created_at", &self.created_at)
            .field("folders", &self.folders.len())
            .field("tags", &self.tags.len())
            .field("entries", &self.entries.len())
            .field("attachments", &self.attachments.len())
            .field("audit", &self.audit.len())
            .field("settings", &self.settings.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kind_round_trips_and_is_closed() {
        for kind in EntryKind::ALL {
            assert_eq!(EntryKind::from_u8(kind.to_u8()).expect("relecture"), kind);
        }
        assert!(EntryKind::from_u8(0).is_err());
        assert!(EntryKind::from_u8(10).is_err());
        assert!(EntryKind::from_u8(255).is_err());
    }

    #[test]
    fn field_kind_round_trips_and_is_closed() {
        for kind in FieldKind::ALL {
            assert_eq!(FieldKind::from_u8(kind.to_u8()).expect("relecture"), kind);
        }
        assert!(FieldKind::from_u8(0).is_err());
        assert!(FieldKind::from_u8(11).is_err());
    }

    #[test]
    fn audit_kind_round_trips_and_is_closed() {
        for kind in AuditKind::ALL {
            assert_eq!(AuditKind::from_u8(kind.to_u8()).expect("relecture"), kind);
        }
        assert!(AuditKind::from_u8(0).is_err());
        assert!(AuditKind::from_u8(14).is_err());
    }

    #[test]
    fn secret_ish_field_kinds_are_concealed_by_default() {
        assert!(FieldKind::Secret.is_concealed_by_default());
        assert!(FieldKind::Pin.is_concealed_by_default());
        assert!(FieldKind::Totp.is_concealed_by_default());
        assert!(!FieldKind::Text.is_concealed_by_default());
        assert!(!FieldKind::Url.is_concealed_by_default());
    }

    #[test]
    fn building_a_field_refuses_oversized_input() {
        let long_key = "k".repeat(MAX_FIELD_KEY_LEN + 1);
        assert!(Field::new(long_key, FieldKind::Text, "v", 0).is_err());

        let long_value = "v".repeat(MAX_FIELD_VALUE_LEN + 1);
        assert!(Field::new("k", FieldKind::Text, long_value, 0).is_err());

        // Les bornes exactes doivent être acceptées.
        let key = "k".repeat(MAX_FIELD_KEY_LEN);
        assert!(Field::new(key, FieldKind::Text, "v", 0).is_ok());
    }

    #[test]
    fn building_an_entry_refuses_an_oversized_title() {
        assert!(Entry::new(EntryKind::Login, "t".repeat(MAX_TITLE_LEN + 1), 0).is_err());
        assert!(Entry::new(EntryKind::Login, "t".repeat(MAX_TITLE_LEN), 0).is_ok());
    }

    #[test]
    fn a_fresh_entry_is_active_and_not_trashed() {
        let entry = Entry::new(EntryKind::Login, "exemple", 1_700_000_000).expect("création");
        assert!(entry.is_active());
        assert!(!entry.is_trashed());
        assert_eq!(entry.revision, 1);
        assert!(entry.history.is_empty());
    }

    #[test]
    fn validation_refuses_a_dangling_folder_reference() {
        let mut archive = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "orpheline", 0).expect("création");
        entry.folder = Some(FolderId::generate().expect("aléa"));
        archive.entries.push(entry);

        assert!(
            archive.validate().is_err(),
            "une entrée rattachée à un dossier inexistant doit être refusée"
        );
    }

    #[test]
    fn validation_refuses_a_dangling_tag_reference() {
        let mut archive = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "orpheline", 0).expect("création");
        entry.tags.push(TagId::generate().expect("aléa"));
        archive.entries.push(entry);

        assert!(archive.validate().is_err());
    }

    #[test]
    fn validation_refuses_a_folder_pointing_to_itself() {
        let mut archive = Archive::new(0);
        let id = FolderId::generate().expect("aléa");
        archive.folders.push(Folder {
            id,
            name: "boucle".to_string(),
            parent: Some(id),
            ordinal: 0,
        });

        assert!(archive.validate().is_err());
    }

    #[test]
    fn validation_detects_a_folder_cycle() {
        let mut archive = Archive::new(0);
        let first = FolderId::generate().expect("aléa");
        let second = FolderId::generate().expect("aléa");

        archive.folders.push(Folder {
            id: first,
            name: "a".to_string(),
            parent: Some(second),
            ordinal: 0,
        });
        archive.folders.push(Folder {
            id: second,
            name: "b".to_string(),
            parent: Some(first),
            ordinal: 0,
        });

        assert!(
            archive.validate().is_err(),
            "un cycle de dossiers doit être détecté"
        );
    }

    #[test]
    fn validation_accepts_a_coherent_archive() {
        let mut archive = Archive::new(1_700_000_000);
        let folder = FolderId::generate().expect("aléa");
        let tag = TagId::generate().expect("aléa");

        archive.folders.push(Folder {
            id: folder,
            name: "travail".to_string(),
            parent: None,
            ordinal: 0,
        });
        archive.tags.push(Tag {
            id: tag,
            name: "important".to_string(),
        });

        let mut entry = Entry::new(EntryKind::Login, "exemple", 1_700_000_000).expect("création");
        entry.folder = Some(folder);
        entry.tags.push(tag);
        entry
            .fields
            .push(Field::new("password", FieldKind::Secret, "s3cr3t", 0).expect("champ"));
        archive.entries.push(entry);

        archive.validate().expect("archive cohérente");
        assert_eq!(archive.active_entry_count(), 1);
    }

    #[test]
    fn wiping_an_archive_reaches_every_string() {
        let mut archive = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "titre secret", 0).expect("création");
        entry
            .fields
            .push(Field::new("password", FieldKind::Secret, "valeur secrète", 0).expect("champ"));
        archive.entries.push(entry);
        archive.folders.push(Folder {
            id: FolderId::generate().expect("aléa"),
            name: "dossier secret".to_string(),
            parent: None,
            ordinal: 0,
        });

        archive.wipe();

        assert!(archive.entries.is_empty());
        assert!(archive.folders.is_empty());
        assert!(archive.tags.is_empty());
        assert!(archive.settings.is_empty());
    }
}
