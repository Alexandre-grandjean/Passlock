//! Codec binaire de l'archive — le corps déchiffré du coffre.
//!
//! # Pourquoi un format explicite plutôt qu'une bibliothèque
//!
//! Même raisonnement qu'en phase 1 pour le header du conteneur, appliqué à une
//! structure bien plus large. L'archive est **la plus grosse donnée non fiable que
//! le programme traite** : elle est authentifiée par le tag AEAD, donc un tiers ne
//! peut pas la modifier, mais elle peut provenir d'une **autre implémentation**,
//! d'une **version future**, ou d'un **défaut de notre propre encodeur**.
//!
//! L'authentification garantit qu'elle n'a pas été altérée par un adversaire ; elle
//! ne garantit **pas** qu'elle est bien formée. C'est pourquoi le décodeur applique
//! les mêmes règles qu'un analyseur d'entrée hostile.
//!
//! # L'invariant qui compte
//!
//! > Aucune allocation n'est dimensionnée par une valeur lue dans le corps avant
//! > que cette valeur n'ait été confrontée aux octets réellement disponibles.
//!
//! Toute lecture de compte passe par [`crate::bytes::Reader::count`], qui vérifie
//! `count × taille_minimale_d_un_enregistrement ≤ octets_restants` avec
//! `checked_mul`. Un corps déclarant quatre milliards d'entrées dans cent octets
//! est donc refusé **avant** toute tentative de réservation.
//!
//! # Déterminisme
//!
//! L'encodage ne comporte aucune structure associative : les sections suivent
//! l'ordre des `Vec`, les champs leur `ordinal`. Deux archives équivalentes
//! produisent des octets identiques, ce qui rend le format testable par simple
//! comparaison — et c'est aussi ce qui rend l'AAD du conteneur non ambiguë.
//!
//! # Répartition des responsabilités avec `validate`
//!
//! Le décodeur garantit la **forme** : structure, bornes, UTF-8, absence de
//! récursion. [`crate::model::Archive::validate`] garantit la **cohérence** :
//! références croisées, cycles de dossiers, invariants métier. Les deux sont
//! appelées, dans cet ordre, par [`decode`].

use zeroize::Zeroizing;

use crate::bytes::{Reader, Writer};
use crate::error::{Error, Result};
use crate::model::{
    Archive, AttachmentMeta, AuditEvent, AuditKind, BlobId, Entry, EntryId, EntryKind, Field,
    FieldKind, Folder, FolderId, MAX_ATTACHMENTS, MAX_AUDIT_EVENTS, MAX_ENTRIES, MAX_FIELD_KEY_LEN,
    MAX_FIELD_VALUE_LEN, MAX_FOLDERS, MAX_HISTORY_PER_ENTRY, MAX_NAME_LEN, MAX_TAGS,
    MAX_TAGS_PER_ENTRY, MAX_TITLE_LEN, MIN_ENCODED_ATTACHMENT, MIN_ENCODED_AUDIT_EVENT,
    MIN_ENCODED_ENTRY, MIN_ENCODED_FIELD, MIN_ENCODED_FOLDER, MIN_ENCODED_REVISION,
    MIN_ENCODED_TAG, Revision, Tag, TagId,
};

/// Signature de l'archive.
pub const ARCHIVE_MAGIC: [u8; 4] = *b"ARC2";

/// Version de schéma produite par ce binaire.
pub const ARCHIVE_VERSION: u16 = 2;

/// Taille de la partie fixe de l'archive : en-tête + comptes de section.
const ARCHIVE_HEADER_LEN: usize = 40;

/// Bits de drapeau actuellement définis pour une entrée.
const ENTRY_FLAG_FAVORITE: u8 = 0b0000_0001;
const ENTRY_FLAG_ARCHIVED: u8 = 0b0000_0010;
const ENTRY_FLAG_SENSITIVE: u8 = 0b0000_0100;
const ENTRY_FLAG_KNOWN: u8 = ENTRY_FLAG_FAVORITE | ENTRY_FLAG_ARCHIVED | ENTRY_FLAG_SENSITIVE;

/// Bits de drapeau définis pour un champ.
const FIELD_FLAG_CONCEALED: u8 = 0b0000_0001;
const FIELD_FLAG_KNOWN: u8 = FIELD_FLAG_CONCEALED;

// ---------------------------------------------------------------------------
// Encodage
// ---------------------------------------------------------------------------

/// Encode une archive.
///
/// Le résultat contient du **contenu déchiffré** : il est retourné dans un
/// [`Zeroizing`], de sorte qu'un appelant ne puisse pas en obtenir un `Vec<u8>` nu
/// par inadvertance.
///
/// # Erreurs
/// * [`Error::MalformedLength`] si une borne est franchie ;
/// * [`Error::InvalidHeader`] si un invariant de cohérence est violé.
///
/// Les invariants sont vérifiés **avant** l'encodage : produire une archive que
/// notre propre décodeur refuserait serait un défaut silencieux, découvert
/// seulement à la réouverture du coffre.
pub fn encode(archive: &Archive) -> Result<Zeroizing<Vec<u8>>> {
    archive.validate()?;

    let mut writer = Writer::with_capacity(estimate_size(archive));

    writer.bytes(&ARCHIVE_MAGIC);
    writer.u16_be(ARCHIVE_VERSION);
    writer.u16_be(0);
    writer.u64_be(archive.created_at);

    // Les comptes sont écrits en tête, ce qui les rend bornables à la lecture.
    writer.count(archive.folders.len(), MAX_FOLDERS, "trop de dossiers")?;
    writer.count(archive.tags.len(), MAX_TAGS, "trop de tags")?;
    writer.count(archive.entries.len(), MAX_ENTRIES, "trop d'entrées")?;
    writer.count(
        archive.attachments.len(),
        MAX_ATTACHMENTS,
        "trop de pièces jointes",
    )?;
    writer.count(
        archive.audit.len(),
        MAX_AUDIT_EVENTS,
        "journal au-delà de sa borne",
    )?;
    writer.count(
        archive.settings.len(),
        crate::model::MAX_FIELDS_PER_ENTRY,
        "trop de réglages",
    )?;

    for folder in &archive.folders {
        encode_folder(&mut writer, folder)?;
    }
    for tag in &archive.tags {
        encode_tag(&mut writer, tag)?;
    }
    for entry in &archive.entries {
        encode_entry(&mut writer, entry)?;
    }
    for attachment in &archive.attachments {
        encode_attachment(&mut writer, attachment)?;
    }
    for event in &archive.audit {
        encode_audit_event(&mut writer, event);
    }
    for setting in &archive.settings {
        encode_field(&mut writer, setting)?;
    }

    Ok(writer.finish())
}

/// Estime la taille encodée, pour éviter les réallocations.
///
/// Une estimation n'est pas une borne : l'encodage reste borné par les vérifications
/// de chaque champ. Une sous-estimation provoque simplement une réallocation.
fn estimate_size(archive: &Archive) -> usize {
    let mut size = ARCHIVE_HEADER_LEN;

    for folder in &archive.folders {
        size += MIN_ENCODED_FOLDER + folder.name.len();
    }
    for tag in &archive.tags {
        size += MIN_ENCODED_TAG + tag.name.len();
    }
    for entry in &archive.entries {
        size += MIN_ENCODED_ENTRY + entry.title.len() + entry.subtitle.len();
        size += entry.tags.len() * 16;
        for field in &entry.fields {
            size += MIN_ENCODED_FIELD + field.key.len() + field.value.len();
        }
        size += entry.history.len() * MIN_ENCODED_REVISION;
        // Les instantanés sont estimés grossièrement : leur contenu exact serait
        // coûteux à reparcourir, et une sous-estimation n'est pas un défaut.
        size += entry.history.iter().map(|_| 256).sum::<usize>();
    }
    for attachment in &archive.attachments {
        size += MIN_ENCODED_ATTACHMENT + attachment.name.len();
    }
    size += archive.audit.len() * MIN_ENCODED_AUDIT_EVENT;
    for setting in &archive.settings {
        size += MIN_ENCODED_FIELD + setting.key.len() + setting.value.len();
    }

    size
}

fn encode_folder(writer: &mut Writer, folder: &Folder) -> Result<()> {
    writer.id(folder.id.as_bytes());
    writer.text(
        &folder.name,
        MAX_NAME_LEN,
        "nom de dossier au-delà de sa borne",
    )?;
    match folder.parent {
        Some(parent) => writer.id(parent.as_bytes()),
        None => writer.id(&[0_u8; 16]),
    }
    writer.u16_be(folder.ordinal);
    Ok(())
}

fn encode_tag(writer: &mut Writer, tag: &Tag) -> Result<()> {
    writer.id(tag.id.as_bytes());
    writer.text(&tag.name, MAX_NAME_LEN, "nom de tag au-delà de sa borne")
}

fn encode_field(writer: &mut Writer, field: &Field) -> Result<()> {
    writer.text(
        &field.key,
        MAX_FIELD_KEY_LEN,
        "clé de champ au-delà de sa borne",
    )?;
    writer.u8(field.kind.to_u8());
    writer.u16_be(field.ordinal);
    writer.u8(if field.concealed {
        FIELD_FLAG_CONCEALED
    } else {
        0
    });
    writer.text(
        &field.value,
        MAX_FIELD_VALUE_LEN,
        "valeur de champ au-delà de sa borne",
    )
}

fn encode_entry(writer: &mut Writer, entry: &Entry) -> Result<()> {
    writer.id(entry.id.as_bytes());
    writer.u8(entry.kind.to_u8());

    let mut flags = 0_u8;
    if entry.favorite {
        flags |= ENTRY_FLAG_FAVORITE;
    }
    if entry.archived {
        flags |= ENTRY_FLAG_ARCHIVED;
    }
    if entry.sensitive {
        flags |= ENTRY_FLAG_SENSITIVE;
    }
    writer.u8(flags);

    writer.u32_be(entry.revision);
    writer.u64_be(entry.created_at);
    writer.u64_be(entry.updated_at);
    // Zéro signifie « pas à la corbeille » : une date de 1970 n'a pas de sens pour
    // une mise à la corbeille, la convention est donc sans ambiguïté.
    writer.u64_be(entry.trashed_at.unwrap_or(0));
    match entry.folder {
        Some(folder) => writer.id(folder.as_bytes()),
        None => writer.id(&[0_u8; 16]),
    }

    writer.text(&entry.title, MAX_TITLE_LEN, "titre au-delà de sa borne")?;
    writer.text(
        &entry.subtitle,
        MAX_TITLE_LEN,
        "sous-titre au-delà de sa borne",
    )?;

    writer.count(
        entry.tags.len(),
        MAX_TAGS_PER_ENTRY,
        "trop de tags sur une entrée",
    )?;
    for tag in &entry.tags {
        writer.id(tag.as_bytes());
    }

    writer.count(
        entry.fields.len(),
        crate::model::MAX_FIELDS_PER_ENTRY,
        "trop de champs dans une entrée",
    )?;
    for field in &entry.fields {
        encode_field(writer, field)?;
    }

    writer.count(
        entry.history.len(),
        MAX_HISTORY_PER_ENTRY,
        "historique au-delà de sa borne",
    )?;
    for revision in &entry.history {
        // L'instantané est écrit avec son propre historique **vide** : c'est ce qui
        // borne la profondeur de la structure à un niveau, et donc ce qui empêche un
        // corps forgé de provoquer un épuisement de pile.
        let mut snapshot = Writer::new();
        encode_entry(&mut snapshot, &revision.snapshot)?;
        let bytes = snapshot.finish();

        writer.u64_be(revision.at);
        writer.count(
            bytes.len(),
            MAX_ARCHIVE_LEN,
            "instantané au-delà de sa borne",
        )?;
        writer.bytes(&bytes);
    }

    Ok(())
}

fn encode_attachment(writer: &mut Writer, attachment: &AttachmentMeta) -> Result<()> {
    writer.id(attachment.id.as_bytes());
    writer.id(attachment.entry.as_bytes());
    writer.text(
        &attachment.name,
        crate::model::MAX_ATTACHMENT_NAME_LEN,
        "nom de pièce jointe au-delà de sa borne",
    )?;
    writer.u64_be(attachment.size);
    writer.u32_be(attachment.chunk_size);
    writer.u32_be(attachment.chunk_count);
    writer.u64_be(attachment.created_at);
    writer.bytes(&attachment.content_mac);
    Ok(())
}

fn encode_audit_event(writer: &mut Writer, event: &AuditEvent) {
    writer.u64_be(event.at);
    writer.u8(event.kind.to_u8());
    match event.subject {
        Some(subject) => writer.id(subject.as_bytes()),
        None => writer.id(&[0_u8; 16]),
    }
}

/// Taille maximale acceptée pour une archive encodée.
///
/// Cohérente avec [`crate::container::MAX_VAULT_BYTES`] : une archive plus grande que
/// le conteneur qui la porte est nécessairement le produit d'un encodage fautif.
pub const MAX_ARCHIVE_LEN: usize = crate::container::MAX_VAULT_BYTES / 2;

// ---------------------------------------------------------------------------
// Décodage
// ---------------------------------------------------------------------------

/// Décode une archive.
///
/// # Ordre des vérifications
///
/// 1. **forme** : signature, version, champs réservés, bornes, comptes compatibles
///    avec les octets restants, UTF-8 ;
/// 2. **cohérence** : références croisées, cycles, invariants métier
///    ([`Archive::validate`]).
///
/// Aucune allocation n'est dimensionnée par une valeur du corps avant l'étape 1.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la forme est invalide,
/// [`Error::InvalidHeader`] si la cohérence est rompue, y compris pour un type
/// d'entrée ou un type de champ inconnu.
pub fn decode(body: &[u8]) -> Result<Archive> {
    if body.len() > MAX_ARCHIVE_LEN {
        return Err(Error::MalformedLength {
            reason: "archive au-delà de la taille maximale admise",
        });
    }

    let mut reader = Reader::new(body);

    if reader.slice(ARCHIVE_MAGIC.len(), "signature d'archive tronquée")? != ARCHIVE_MAGIC {
        return Err(Error::InvalidHeader {
            reason: "signature d'archive absente",
        });
    }

    let version = reader.u16_be("version d'archive tronquée")?;
    if version != ARCHIVE_VERSION {
        return Err(Error::InvalidHeader {
            reason: "version de schéma d'archive non supportée",
        });
    }

    if reader.u16_be("zone réservée tronquée")? != 0 {
        return Err(Error::InvalidHeader {
            reason: "zone réservée de l'archive non nulle",
        });
    }

    let created_at = reader.u64_be("date de création tronquée")?;

    // Les comptes sont lus **avant** tout parcours, et chacun est confronté aux
    // octets restants. C'est le point où un corps hostile est arrêté.
    let folder_count = reader.count(
        MAX_FOLDERS,
        MIN_ENCODED_FOLDER,
        "compte de dossiers invalide",
    )?;
    let tag_count = reader.count(MAX_TAGS, MIN_ENCODED_TAG, "compte de tags invalide")?;
    let entry_count = reader.count(MAX_ENTRIES, MIN_ENCODED_ENTRY, "compte d'entrées invalide")?;
    let attachment_count = reader.count(
        MAX_ATTACHMENTS,
        MIN_ENCODED_ATTACHMENT,
        "compte de pièces jointes invalide",
    )?;
    let audit_count = reader.count(
        MAX_AUDIT_EVENTS,
        MIN_ENCODED_AUDIT_EVENT,
        "compte d'événements invalide",
    )?;
    let settings_count = reader.count(
        crate::model::MAX_FIELDS_PER_ENTRY,
        MIN_ENCODED_FIELD,
        "compte de réglages invalide",
    )?;

    // C'est ici que `with_capacity` est autorisé : les comptes ont été vérifiés.
    let mut archive = Archive::new(created_at);
    archive.folders.reserve_exact(folder_count);
    archive.tags.reserve_exact(tag_count);
    archive.entries.reserve_exact(entry_count);
    archive.attachments.reserve_exact(attachment_count);
    archive.audit.reserve_exact(audit_count);
    archive.settings.reserve_exact(settings_count);

    for _ in 0..folder_count {
        archive.folders.push(decode_folder(&mut reader)?);
    }
    for _ in 0..tag_count {
        archive.tags.push(decode_tag(&mut reader)?);
    }
    for _ in 0..entry_count {
        archive.entries.push(decode_entry(&mut reader, 0)?);
    }
    for _ in 0..attachment_count {
        archive.attachments.push(decode_attachment(&mut reader)?);
    }
    for _ in 0..audit_count {
        archive.audit.push(decode_audit_event(&mut reader)?);
    }
    for _ in 0..settings_count {
        archive.settings.push(decode_field(&mut reader)?);
    }

    reader.expect_consumed("octets excédentaires à la fin de l'archive")?;

    // Cohérence métier : références croisées, cycles, invariants.
    archive.validate()?;

    Ok(archive)
}

fn decode_folder(reader: &mut Reader<'_>) -> Result<Folder> {
    let id = FolderId::from_bytes(reader.id("identifiant de dossier tronqué")?);
    let name = reader.text(MAX_NAME_LEN, "nom de dossier au-delà de sa borne")?;
    let parent = FolderId::from_bytes(reader.id("dossier parent tronqué")?);
    let ordinal = reader.u16_be("ordre de dossier tronqué")?;

    Ok(Folder {
        id,
        name,
        parent: if parent.is_nil() { None } else { Some(parent) },
        ordinal,
    })
}

fn decode_tag(reader: &mut Reader<'_>) -> Result<Tag> {
    let id = TagId::from_bytes(reader.id("identifiant de tag tronqué")?);
    let name = reader.text(MAX_NAME_LEN, "nom de tag au-delà de sa borne")?;
    Ok(Tag { id, name })
}

fn decode_field(reader: &mut Reader<'_>) -> Result<Field> {
    let key = reader.text(MAX_FIELD_KEY_LEN, "clé de champ au-delà de sa borne")?;
    let kind = FieldKind::from_u8(reader.u8("type de champ tronqué")?)?;
    let ordinal = reader.u16_be("ordre de champ tronqué")?;
    let flags = reader.u8("drapeaux de champ tronqués")?;

    if flags & !FIELD_FLAG_KNOWN != 0 {
        return Err(Error::InvalidHeader {
            reason: "drapeaux de champ inconnus",
        });
    }

    let value = reader.text(MAX_FIELD_VALUE_LEN, "valeur de champ au-delà de sa borne")?;

    if key.is_empty() {
        return Err(Error::InvalidHeader {
            reason: "clé de champ vide",
        });
    }

    Ok(Field {
        key,
        kind,
        value,
        ordinal,
        concealed: flags & FIELD_FLAG_CONCEALED != 0,
    })
}

/// Décode une entrée.
///
/// `depth` vaut 0 pour une entrée de premier niveau et 1 pour l'instantané d'une
/// révision. Toute profondeur supérieure est **refusée** : c'est la barrière qui
/// rend la structure non récursive et empêche un corps forgé d'épuiser la pile.
fn decode_entry(reader: &mut Reader<'_>, depth: u8) -> Result<Entry> {
    const MAX_DEPTH: u8 = 1;
    if depth > MAX_DEPTH {
        return Err(Error::InvalidHeader {
            reason: "profondeur d'imbrication d'entrée excessive",
        });
    }

    let id = EntryId::from_bytes(reader.id("identifiant d'entrée tronqué")?);
    let kind = EntryKind::from_u8(reader.u8("type d'entrée tronqué")?)?;
    let flags = reader.u8("drapeaux d'entrée tronqués")?;

    if flags & !ENTRY_FLAG_KNOWN != 0 {
        return Err(Error::InvalidHeader {
            reason: "drapeaux d'entrée inconnus",
        });
    }

    let revision = reader.u32_be("numéro de révision tronqué")?;
    let created_at = reader.u64_be("date de création tronquée")?;
    let updated_at = reader.u64_be("date de modification tronquée")?;
    let trashed_at = reader.u64_be("date de mise à la corbeille tronquée")?;
    let folder = FolderId::from_bytes(reader.id("dossier d'entrée tronqué")?);

    let title = reader.text(MAX_TITLE_LEN, "titre au-delà de sa borne")?;
    let subtitle = reader.text(MAX_TITLE_LEN, "sous-titre au-delà de sa borne")?;

    let tag_count = reader.count(
        MAX_TAGS_PER_ENTRY,
        MIN_ENCODED_TAG.min(16),
        "compte de tags d'entrée invalide",
    )?;
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        tags.push(TagId::from_bytes(reader.id("tag d'entrée tronqué")?));
    }

    let field_count = reader.count(
        crate::model::MAX_FIELDS_PER_ENTRY,
        MIN_ENCODED_FIELD,
        "compte de champs invalide",
    )?;
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        fields.push(decode_field(reader)?);
    }

    let history_count = reader.count(
        MAX_HISTORY_PER_ENTRY,
        MIN_ENCODED_REVISION,
        "compte de révisions invalide",
    )?;
    let mut history = Vec::with_capacity(history_count);
    for _ in 0..history_count {
        let at = reader.u64_be("date de révision tronquée")?;
        let len =
            usize::try_from(reader.u32_be("longueur d'instantané tronquée")?).map_err(|_| {
                Error::MalformedLength {
                    reason: "longueur d'instantané non représentable",
                }
            })?;
        if len > reader.remaining() {
            return Err(Error::MalformedLength {
                reason: "instantané au-delà des octets disponibles",
            });
        }

        let mut nested = reader.sub_reader(len, "instantané tronqué")?;
        let snapshot = decode_entry(&mut nested, depth + 1)?;
        nested.expect_consumed("octets excédentaires dans un instantané")?;

        // L'invariant qui borne la profondeur. Un instantané qui contiendrait
        // lui-même un historique permettrait une imbrication arbitraire.
        if !snapshot.history.is_empty() {
            return Err(Error::InvalidHeader {
                reason: "l'instantané d'une révision ne peut pas contenir d'historique",
            });
        }

        history.push(Revision { at, snapshot });
    }

    Ok(Entry {
        id,
        kind,
        title,
        subtitle,
        created_at,
        updated_at,
        trashed_at: if trashed_at == 0 {
            None
        } else {
            Some(trashed_at)
        },
        archived: flags & ENTRY_FLAG_ARCHIVED != 0,
        favorite: flags & ENTRY_FLAG_FAVORITE != 0,
        sensitive: flags & ENTRY_FLAG_SENSITIVE != 0,
        folder: if folder.is_nil() { None } else { Some(folder) },
        tags,
        fields,
        revision,
        history,
    })
}

fn decode_attachment(reader: &mut Reader<'_>) -> Result<AttachmentMeta> {
    let id = BlobId::from_bytes(reader.id("identifiant de pièce jointe tronqué")?);
    let entry = EntryId::from_bytes(reader.id("entrée de pièce jointe tronquée")?);
    let name = reader.text(
        crate::model::MAX_ATTACHMENT_NAME_LEN,
        "nom de pièce jointe au-delà de sa borne",
    )?;
    let size = reader.u64_be("taille de pièce jointe tronquée")?;
    let chunk_size = reader.u32_be("taille de morceau tronquée")?;
    let chunk_count = reader.u32_be("nombre de morceaux tronqué")?;
    let created_at = reader.u64_be("date de pièce jointe tronquée")?;
    let content_mac = reader.array::<32>("empreinte de pièce jointe tronquée")?;

    Ok(AttachmentMeta {
        id,
        entry,
        name,
        size,
        chunk_size,
        chunk_count,
        created_at,
        content_mac,
    })
}

fn decode_audit_event(reader: &mut Reader<'_>) -> Result<AuditEvent> {
    let at = reader.u64_be("date d'événement tronquée")?;
    let kind = AuditKind::from_u8(reader.u8("type d'événement tronqué")?)?;
    let subject = EntryId::from_bytes(reader.id("sujet d'événement tronqué")?);

    Ok(AuditEvent {
        at,
        kind,
        subject: if subject.is_nil() {
            None
        } else {
            Some(subject)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MAX_FOLDER_DEPTH;

    /// Construit une archive représentative de tous les cas.
    fn sample_archive() -> Archive {
        let mut archive = Archive::new(1_700_000_000);

        let root = FolderId::generate().expect("aléa");
        let child = FolderId::generate().expect("aléa");
        archive.folders.push(Folder {
            id: root,
            name: "racine".to_string(),
            parent: None,
            ordinal: 0,
        });
        archive.folders.push(Folder {
            id: child,
            name: "dossier accentué : éàü".to_string(),
            parent: Some(root),
            ordinal: 1,
        });

        let tag = TagId::generate().expect("aléa");
        archive.tags.push(Tag {
            id: tag,
            name: "important".to_string(),
        });

        let mut entry = Entry::new(EntryKind::Login, "exemple.com", 1_700_000_000).expect("entrée");
        entry.subtitle = "utilisateur@exemple.com".to_string();
        entry.favorite = true;
        entry.sensitive = true;
        entry.folder = Some(child);
        entry.tags.push(tag);
        entry
            .fields
            .push(Field::new("username", FieldKind::Text, "utilisateur", 0).expect("champ"));
        entry
            .fields
            .push(Field::new("password", FieldKind::Secret, "s3cr3t-Ünïcödé", 1).expect("champ"));
        archive.entries.push(entry);

        archive.audit.push(AuditEvent {
            at: 1_700_000_001,
            kind: AuditKind::Unlock,
            subject: None,
        });
        archive.audit.push(AuditEvent {
            at: 1_700_000_002,
            kind: AuditKind::EntryCreated,
            subject: Some(archive.entries[0].id),
        });

        archive
            .settings
            .push(Field::new("history_days", FieldKind::Number, "90", 0).expect("champ"));

        archive
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let original = sample_archive();
        let encoded = encode(&original).expect("encodage");
        let decoded = decode(&encoded).expect("décodage");

        assert_eq!(decoded.created_at, original.created_at);
        assert_eq!(decoded.folders.len(), original.folders.len());
        assert_eq!(decoded.folders[1].name, "dossier accentué : éàü");
        assert_eq!(decoded.folders[1].parent, original.folders[1].parent);
        assert_eq!(decoded.tags.len(), 1);
        assert_eq!(decoded.entries.len(), 1);

        let entry = &decoded.entries[0];
        assert_eq!(entry.id, original.entries[0].id);
        assert_eq!(entry.kind, EntryKind::Login);
        assert!(entry.favorite);
        assert!(entry.sensitive);
        assert!(!entry.archived);
        assert_eq!(entry.folder, original.entries[0].folder);
        assert_eq!(entry.tags, original.entries[0].tags);
        assert_eq!(entry.fields.len(), 2);
        assert_eq!(entry.fields[1].value, "s3cr3t-Ünïcödé");
        assert_eq!(entry.fields[1].kind, FieldKind::Secret);
        assert!(entry.fields[1].concealed);

        assert_eq!(decoded.audit.len(), 2);
        assert_eq!(decoded.audit[1].subject, Some(original.entries[0].id));
        assert_eq!(decoded.settings.len(), 1);
    }

    #[test]
    fn encoding_is_deterministic() {
        let archive = sample_archive();
        assert_eq!(
            encode(&archive).expect("a").as_slice(),
            encode(&archive).expect("b").as_slice()
        );
    }

    #[test]
    fn an_empty_archive_round_trips() {
        let archive = Archive::new(42);
        let decoded = decode(&encode(&archive).expect("encodage")).expect("décodage");

        assert_eq!(decoded.created_at, 42);
        assert!(decoded.entries.is_empty());
        assert!(decoded.folders.is_empty());
    }

    #[test]
    fn history_round_trips_with_its_snapshot() {
        let mut archive = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "avant", 1).expect("entrée");
        entry
            .fields
            .push(Field::new("password", FieldKind::Secret, "ancien", 0).expect("champ"));

        let mut previous = Entry::new(EntryKind::Login, "avant", 1).expect("instantané");
        previous.id = entry.id;
        previous.fields.push(
            Field::new("password", FieldKind::Secret, "encore-plus-ancien", 0).expect("champ"),
        );

        entry.history.push(Revision {
            at: 1,
            snapshot: previous,
        });
        archive.entries.push(entry);

        let decoded = decode(&encode(&archive).expect("encodage")).expect("décodage");
        assert_eq!(decoded.entries[0].history.len(), 1);
        assert_eq!(decoded.entries[0].history[0].snapshot.title, "avant");
        assert_eq!(
            decoded.entries[0].history[0].snapshot.fields[0].value,
            "encore-plus-ancien"
        );
    }

    #[test]
    fn every_single_byte_mutation_is_either_refused_or_round_trips() {
        // Parcours exhaustif. La propriété : aucune mutation ne doit paniquer, et
        // toute archive acceptée doit se ré-encoder à l'identique — un décodage qui
        // accepte une forme que l'encodage ne reproduit pas rendrait le format
        // ambigu.
        let archive = sample_archive();
        let encoded = encode(&archive).expect("encodage");

        for index in 0..encoded.len() {
            let mut mutated = encoded.to_vec();
            mutated[index] ^= 0x01;

            if let Ok(decoded) = decode(&mutated) {
                let reencoded = encode(&decoded).expect("ré-encodage");
                assert_eq!(
                    reencoded.as_slice(),
                    mutated.as_slice(),
                    "décodage non fidèle à l'offset {index}"
                );
            }
        }
    }

    #[test]
    fn every_truncation_is_refused() {
        let encoded = encode(&sample_archive()).expect("encodage");
        for len in 0..encoded.len() {
            assert!(
                decode(&encoded[..len]).is_err(),
                "troncature à {len} octets acceptée"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut encoded = encode(&sample_archive()).expect("encodage").to_vec();
        encoded.push(0);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn a_hostile_section_count_is_refused_before_allocating() {
        // LE test de l'invariant central. Un compte de quatre milliards dans une
        // archive de quelques centaines d'octets doit être refusé **sans** qu'aucune
        // réservation n'ait été tentée.
        let encoded = encode(&sample_archive()).expect("encodage");

        // Offsets des comptes : 16 (dossiers), 20 (tags), 24 (entrées),
        // 28 (pièces jointes), 32 (journal), 36 (réglages).
        // `MAX_ENTRIES` tient sur 32 bits, ce que le format exige : la conversion est
        // sûre, et le test le vérifie plutôt que de la supposer.
        let over_max_entries =
            u32::try_from(MAX_ENTRIES).expect("MAX_ENTRIES doit tenir sur 32 bits") + 1;

        for (offset, label) in [
            (16_usize, "dossiers"),
            (20, "tags"),
            (24, "entrées"),
            (28, "pièces jointes"),
            (32, "journal"),
            (36, "réglages"),
        ] {
            for value in [u32::MAX, 1_000_000_000, over_max_entries] {
                let mut hostile = encoded.to_vec();
                hostile[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
                assert!(
                    decode(&hostile).is_err(),
                    "un compte de {value} {label} a été accepté"
                );
            }
        }
    }

    #[test]
    fn a_count_just_beyond_what_the_bytes_allow_is_refused() {
        // Frontière fine : le compte est sous la borne déclarée mais incompatible
        // avec les octets réellement présents. C'est le cas qu'une vérification de
        // borne seule laisserait passer.
        let encoded = encode(&sample_archive()).expect("encodage");

        for offset in [16_usize, 20, 24, 28, 32, 36] {
            let mut hostile = encoded.to_vec();
            // Un compte juste au-dessus de ce que les octets restants permettent.
            let remaining = hostile.len() - offset - 4;
            let too_many = u32::try_from(remaining + 1).unwrap_or(u32::MAX);
            hostile[offset..offset + 4].copy_from_slice(&too_many.to_be_bytes());
            assert!(
                decode(&hostile).is_err(),
                "un compte de {too_many} (reste {remaining} octets) a été accepté"
            );
        }
    }

    #[test]
    fn an_unknown_entry_kind_is_refused() {
        let mut archive = Archive::new(0);
        archive
            .entries
            .push(Entry::new(EntryKind::Login, "x", 0).expect("entrée"));

        let encoded = encode(&archive).expect("encodage");
        let mut hostile = encoded.to_vec();
        // kind se trouve juste après les 40 octets d'en-tête, puis l'identifiant
        // de 16 octets.
        hostile[ARCHIVE_HEADER_LEN + 16] = 200;
        assert!(
            decode(&hostile).is_err(),
            "un type d'entrée inconnu a été accepté"
        );
    }

    #[test]
    fn unknown_entry_flags_are_refused() {
        let mut archive = Archive::new(0);
        archive
            .entries
            .push(Entry::new(EntryKind::Login, "x", 0).expect("entrée"));

        let encoded = encode(&archive).expect("encodage");
        let mut hostile = encoded.to_vec();
        hostile[ARCHIVE_HEADER_LEN + 17] = 0b1000_0000;
        assert!(
            decode(&hostile).is_err(),
            "des drapeaux inconnus ont été acceptés"
        );
    }

    #[test]
    fn invalid_utf8_in_a_title_is_refused() {
        let mut archive = Archive::new(0);
        archive
            .entries
            .push(Entry::new(EntryKind::Login, "abc", 0).expect("entrée"));

        let encoded = encode(&archive).expect("encodage");
        // Le titre suit l'en-tête, l'identifiant, le type, les drapeaux et les dates.
        // On cherche la séquence « abc » et on corrompt son premier octet.
        let position = encoded
            .windows(3)
            .position(|window| window == b"abc")
            .expect("titre introuvable");

        let mut hostile = encoded.to_vec();
        hostile[position] = 0xFF;
        assert!(
            decode(&hostile).is_err(),
            "de l'UTF-8 invalide a été accepté"
        );
    }

    #[test]
    fn a_nested_history_in_a_snapshot_is_refused() {
        // Construit à la main une archive dont l'instantané contient lui-même un
        // historique : c'est l'invariant qui borne la profondeur. Le décodeur doit
        // le refuser, sans quoi un corps forgé pourrait imbriquer indéfiniment.
        //
        // On encode une entrée avec un historique, puis on réinjecte ce même
        // encodage comme instantané.
        let archive = sample_archive();
        let encoded = encode(&archive).expect("encodage");

        // L'archive de référence n'a pas d'historique : on en construit une qui en a,
        // puis on vérifie que le décodage d'un instantané non vide échoue.
        let mut with_history = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "courante", 0).expect("entrée");
        let mut snapshot = Entry::new(EntryKind::Login, "instantané", 0).expect("instantané");
        snapshot.id = entry.id;
        // Un historique **dans l'instantané** : c'est ce qui doit être refusé.
        snapshot.history.push(Revision {
            at: 0,
            snapshot: Entry::new(EntryKind::Login, "trop profond", 0).expect("entrée"),
        });
        entry.history.push(Revision { at: 1, snapshot });
        with_history.entries.push(entry);

        // L'encodage doit déjà refuser : `validate` borne la rétention, et
        // l'encodeur écrit un instantané dont l'historique n'est pas vide.
        let outcome = encode(&with_history);
        match outcome {
            Err(_) => {}
            Ok(bytes) => {
                // Si l'encodage a réussi, le décodage doit refuser.
                assert!(
                    decode(&bytes).is_err(),
                    "un instantané contenant un historique a été accepté"
                );
            }
        }
        let _ = encoded;
    }

    #[test]
    fn a_dangling_entry_reference_is_refused() {
        // Une entrée rattachée à un dossier absent doit être refusée à la
        // **cohérence**, pas silencieusement acceptée avec un dossier vide.
        let mut archive = Archive::new(0);
        let mut entry = Entry::new(EntryKind::Login, "orpheline", 0).expect("entrée");
        let ghost = FolderId::generate().expect("aléa");
        entry.folder = Some(ghost);
        archive.entries.push(entry);

        // L'encodage refuse déjà, puisque `validate` est appelé en amont.
        assert!(
            encode(&archive).is_err(),
            "l'encodage d'une archive incohérente doit être refusé"
        );
    }

    #[test]
    fn folder_depth_beyond_the_limit_is_refused() {
        let mut archive = Archive::new(0);
        let mut parent: Option<FolderId> = None;

        for level in 0..=MAX_FOLDER_DEPTH + 1 {
            let id = FolderId::generate().expect("aléa");
            archive.folders.push(Folder {
                id,
                name: format!("niveau {level}"),
                parent,
                ordinal: 0,
            });
            parent = Some(id);
        }

        assert!(
            archive.validate().is_err(),
            "une profondeur de dossiers excessive doit être refusée"
        );
    }

    #[test]
    fn a_hostile_archive_length_is_refused_before_reading() {
        let oversized = vec![0_u8; MAX_ARCHIVE_LEN + 1];
        assert!(matches!(
            decode(&oversized),
            Err(Error::MalformedLength { .. })
        ));
    }

    #[test]
    fn empty_and_tiny_bodies_never_panic() {
        for candidate in [
            Vec::new(),
            vec![0_u8],
            vec![0_u8; ARCHIVE_HEADER_LEN - 1],
            vec![0_u8; ARCHIVE_HEADER_LEN],
            b"ARC2".to_vec(),
        ] {
            assert!(decode(&candidate).is_err());
        }
    }

    #[test]
    fn a_future_schema_version_is_refused_explicitly() {
        let mut encoded = encode(&Archive::new(0)).expect("encodage").to_vec();
        encoded[4..6].copy_from_slice(&99_u16.to_be_bytes());
        assert!(matches!(decode(&encoded), Err(Error::InvalidHeader { .. })));
    }

    #[test]
    fn the_minimum_encoded_sizes_match_the_encoder() {
        // Les constantes `MIN_ENCODED_*` servent à borner les comptes **avant**
        // allocation. Si l'encodeur produisait un enregistrement plus court que sa
        // constante, la borne serait trop permissive et laisserait passer des
        // allocations excessives. Ce test les confronte à la réalité.
        let mut writer = Writer::new();
        // Champ minimal **valide** : clé d'un octet (une clé vide est refusée par
        // `validate`) et valeur vide.
        encode_field(
            &mut writer,
            &Field::new("k", FieldKind::Text, "", 0).expect("champ"),
        )
        .expect("encodage");
        assert_eq!(
            writer.len(),
            MIN_ENCODED_FIELD,
            "MIN_ENCODED_FIELD ne correspond plus à l'encodage réel"
        );

        let mut writer = Writer::new();
        encode_tag(
            &mut writer,
            &Tag {
                id: TagId::nil(),
                name: String::new(),
            },
        )
        .expect("encodage");
        assert_eq!(writer.len(), MIN_ENCODED_TAG);

        let mut writer = Writer::new();
        encode_folder(
            &mut writer,
            &Folder {
                id: FolderId::nil(),
                name: String::new(),
                parent: None,
                ordinal: 0,
            },
        )
        .expect("encodage");
        assert_eq!(writer.len(), MIN_ENCODED_FOLDER);

        let mut writer = Writer::new();
        let minimal = Entry {
            id: EntryId::nil(),
            kind: EntryKind::Login,
            title: String::new(),
            subtitle: String::new(),
            created_at: 0,
            updated_at: 0,
            trashed_at: None,
            archived: false,
            favorite: false,
            sensitive: false,
            folder: None,
            tags: Vec::new(),
            fields: Vec::new(),
            revision: 0,
            history: Vec::new(),
        };
        encode_entry(&mut writer, &minimal).expect("encodage");
        assert_eq!(
            writer.len(),
            MIN_ENCODED_ENTRY,
            "MIN_ENCODED_ENTRY ne correspond plus à l'encodage réel"
        );

        let mut writer = Writer::new();
        encode_audit_event(
            &mut writer,
            &AuditEvent {
                at: 0,
                kind: AuditKind::Unlock,
                subject: None,
            },
        );
        assert_eq!(writer.len(), MIN_ENCODED_AUDIT_EVENT);

        let mut writer = Writer::new();
        encode_attachment(
            &mut writer,
            &AttachmentMeta {
                id: BlobId::nil(),
                entry: EntryId::nil(),
                name: String::new(),
                size: 0,
                chunk_size: 0,
                chunk_count: 0,
                created_at: 0,
                content_mac: [0_u8; 32],
            },
        )
        .expect("encodage");
        assert_eq!(writer.len(), MIN_ENCODED_ATTACHMENT);
    }

    #[test]
    fn a_large_archive_round_trips() {
        // Vérifie que rien ne casse à l'échelle : bornes, réallocations, cohérence.
        let mut archive = Archive::new(0);
        let tag = TagId::generate().expect("aléa");
        archive.tags.push(Tag {
            id: tag,
            name: "lot".to_string(),
        });

        for index in 0..2000_u32 {
            let mut entry =
                Entry::new(EntryKind::Login, format!("entrée {index}"), 0).expect("entrée");
            entry.tags.push(tag);
            for field_index in 0..8_u16 {
                entry.fields.push(
                    Field::new(
                        format!("champ{field_index}"),
                        FieldKind::Text,
                        format!("valeur {index}-{field_index}"),
                        field_index,
                    )
                    .expect("champ"),
                );
            }
            archive.entries.push(entry);
        }

        let encoded = encode(&archive).expect("encodage");
        let decoded = decode(&encoded).expect("décodage");

        assert_eq!(decoded.entries.len(), 2000);
        assert_eq!(decoded.entries[1999].title, "entrée 1999");
        assert_eq!(decoded.entries[1999].fields[7].value, "valeur 1999-7");
    }
}
