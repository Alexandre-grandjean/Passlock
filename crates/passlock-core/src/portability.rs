//! Import et export au format CSV canonique.
//!
//! # Ce que ce module produit, et ce qu'il refuse de produire
//!
//! L'export est une projection **textuelle, en clair**, d'un coffre déchiffré. Il ne
//! contient **ni** pièces jointes (les blobs vivent hors du conteneur), **ni**
//! historique, **ni** corbeille, **ni** réglages, **ni** journal, **ni** identifiants
//! internes. Ce qui sort est ce que l'utilisateur reconnaît : ses entrées, leurs
//! champs, leurs dossiers et leurs tags.
//!
//! Le fichier produit est du **texte en clair**. C'est une fuite délibérée et
//! massive : elle est demandée explicitement par l'utilisateur, et le CLI impose un
//! choix explicite de destination plutôt qu'une sortie par défaut.
//!
//! # Le format, en une page
//!
//! Une ligne d'en-tête, puis une ligne par entrée :
//!
//! ```text
//! entry_ref,kind,title,subtitle,folder,tags,fields,favorite,archived,sensitive,created_at,updated_at
//! ```
//!
//! * **`entry_ref`** est attribué **après tri** (`E` + index décimal sur 8 chiffres,
//!   base 1). Il est **hors clé de tri** et **ignoré à l'import** : il n'existe que
//!   pour donner une référence stable et lisible à un humain ou à un outil.
//! * Les **11 autres colonnes** forment la clé de tri, comparées **colonne par
//!   colonne**, bytewise UTF-8, sur leur **forme encodée**.
//! * Les entrées **à la corbeille** ne sont pas exportées ; le drapeau `archived`,
//!   lui, l'est.
//! * Séparateur de champ `,`, séparateur de ligne `\n`, guillemets selon la RFC 4180
//!   (une cellule est citée si elle contient `,`, `"`, `\n` ou `\r` ; `"` y est
//!   doublé). Chaque ligne se termine par `\n`.
//!
//! ## Échappement, par contexte
//!
//! L'échappement est **déterministe**, **strict**, et **contextuel** : un `%XX` n'est
//! valide que là où il a un sens, et **aucune** séquence n'est décodée « au mieux ».
//!
//! | Contexte | Cellules | Règles |
//! |---|---|---|
//! | scalaire | `kind`,`title`,`subtitle`,`favorite`,`archived`,`sensitive`,`created_at`,`updated_at` | `%` → `%25` |
//! | dossier | chaque composant de `folder` (chemin joint par `/`) | `%` → `%25`, `/` → `%2F` |
//! | tag | chaque nom de `tags` (liste jointe par `\|`) | `%` → `%25`, `\|` → `%7C` |
//! | champs | chaque chaîne interne au JSON de `fields` | `%` → `%25` |
//!
//! Le `%` est échappé **en premier**, de sorte qu'un `%` introduit par `%2F` ou
//! `%7C` n'est jamais ré-échappé. L'hexadécimal est **toujours en majuscules** :
//! `%2f` est **refusé**. Un **NUL** est **interdit** dans tout le format. Le
//! **découpage précède le déséchappement** (`/` pour un chemin, `|` pour une liste :
//! un `/` ou un `|` littéral a été échappé à l'export, il ne peut donc pas être pris
//! pour un séparateur).
//!
//! ## La colonne `fields`
//!
//! Chaque entrée porte un nombre variable de champs. Une colonne unique ne peut pas
//! les accueillir « à plat » sans introduire un séparateur interne — ce que le
//! contrat interdit. La cellule est donc une **structure canonique** : un tableau
//! JSON à clés **fixes** et sans espace superflu, dont les chaînes sont d'abord
//! échappées (`%` → `%25`), puis encodées en JSON.
//!
//! ```text
//! fields_cell = "[]" | "[" field ("," field)* "]"
//! field       = "{" "\"key\":" string "," "\"kind\":" string ","
//!                     "\"value\":" string "," "\"ordinal\":" uint ","
//!                     "\"concealed\":" bool "}"
//! uint        = "0" | chiffre non nul chiffre*          (0..65535)
//! bool        = "true" | "false"
//! string      = '"' char* '"'
//! char        = octet UTF-8 sauf  " \ U+0000..U+001F %
//!             | \" | \\ | \b | \f | \n | \r | \t | %25 | \u00XX
//! ```
//!
//! `\u00XX` n'est admis **que** pour un caractère de contrôle C0 que la
//! canonisation représente ainsi : `01`–`07`, `0B`, `0E`–`1F`. Les cinq caractères
//! `08 09 0A 0C 0D` ont un raccourci (`\b \t \n \f \r`) qui est leur **seule** forme
//! canonique ; `\u0000` est **interdit**. Les chiffres hexadécimaux sont **toujours
//! en majuscules**. Une même chaîne n'a donc qu'une seule écriture possible.
//!
//! Les champs sont **ordonnés** par `(ordinal, clé, kind, valeur, concealed)` sur
//! leur forme encodée : deux listes logiquement égales produisent la même cellule,
//! et l'ordre de départ n'influence rien.
//!
//! # Pourquoi le déterminisme tient
//!
//! L'export ne consulte **jamais** un identifiant interne : le tri se fait sur le
//! contenu encodé, et `entry_ref` est attribué d'après le rang. Le codec `fields`
//! est **bijectif** sur sa forme canonique, et les autres colonnes le sont aussi
//! (échappement inversible, chemin reconstruit par `/`, tags retriés). Ce qui n'est
//! pas exporté — `EntryId`, `revision`, `ordinal` de dossier, historique, corbeille,
//! pièces jointes, réglages — n'entre dans aucune cellule **et n'influence pas le
//! comparateur**. L'ordre d'insertion et les identifiants sont donc sans effet :
//!
//! ```text
//! export → import → export   =   octet pour octet identique
//! ```
//!
//! # Bornes : rejeter **avant** d'allouer
//!
//! L'import construit et valide tout en mémoire avant le moindre enregistrement. Un
//! fichier hostile ne doit donc pas pouvoir imposer une allocation arbitraire : la
//! taille du fichier est refusée **avant lecture**, et chaque enregistrement et
//! chaque cellule sont bornés **pendant** l'analyse.

use std::fmt::Write as _;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::{
    Archive, Entry, EntryKind, Field, FieldKind, FolderId, MAX_ENTRIES, MAX_FIELDS_PER_ENTRY,
    MAX_FOLDER_DEPTH, MAX_NAME_LEN, MAX_TAGS_PER_ENTRY, TagId,
};
use crate::store::VaultStore;

/// Taille maximale d'un fichier CSV, en octets.
///
/// Égale à la borne d'un coffre ([`crate::container::MAX_VAULT_BYTES`]) : un export
/// qu'on ne pourrait pas réimporter n'aurait pas de sens. Le fichier est refusé
/// **avant** d'être lu en entier.
pub const MAX_CSV_BYTES: usize = 512 * 1024 * 1024;

/// Taille maximale d'un enregistrement (une ligne), en octets.
///
/// Très au-dessus de ce que le modèle peut produire : la cellule `fields` la plus
/// grosse possible — 256 champs de 64 Kio, échappés — reste sous cette borne.
pub const MAX_CSV_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Taille maximale d'une cellule, en octets.
pub const MAX_CSV_CELL_BYTES: usize = 64 * 1024 * 1024;

/// Nombre maximal d'entrées importables.
///
/// Aligné sur la borne du modèle : au-delà, l'archive elle-même serait refusée.
pub const MAX_IMPORT_ENTRIES: usize = MAX_ENTRIES;

/// Nombre maximal de champs par entrée importée.
pub const MAX_IMPORT_FIELDS_PER_ENTRY: usize = MAX_FIELDS_PER_ENTRY;

/// Nombre de colonnes du format.
pub const COLUMN_COUNT: usize = 12;

/// En-tête canonique, dans l'ordre.
pub const HEADER: [&str; COLUMN_COUNT] = [
    "entry_ref",
    "kind",
    "title",
    "subtitle",
    "folder",
    "tags",
    "fields",
    "favorite",
    "archived",
    "sensitive",
    "created_at",
    "updated_at",
];

/// Compte rendu d'un import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportReport {
    /// Nombre d'entrées créées.
    pub entries: usize,
    /// Nombre de dossiers créés (les dossiers existants sont réutilisés).
    pub folders_created: usize,
    /// Nombre de tags créés (les tags existants sont réutilisés).
    pub tags_created: usize,
}

/// Entrée analysée et validée, **pas encore appliquée** au magasin.
///
/// Le type ne dérive pas `Debug` : il porte un titre, des noms de dossiers et de
/// tags — c'est-à-dire du contenu. L'implémentation manuelle n'affiche que des
/// compteurs.
pub struct StagedEntry {
    /// L'entrée elle-même, entièrement validée (`Entry::validate` a réussi).
    pub entry: Entry,
    /// Chemin du dossier, de la racine vers la feuille. Vide si aucun dossier.
    pub folder: Vec<String>,
    /// Noms des tags, tels qu'importés.
    pub tags: Vec<String>,
}

impl std::fmt::Debug for StagedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedEntry")
            .field("kind", &self.entry.kind)
            .field("field_count", &self.entry.fields.len())
            .field("folder_depth", &self.folder.len())
            .field("tag_count", &self.tags.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Contexte d'échappement
// ---------------------------------------------------------------------------

/// Contexte d'un échappement : ce qui a le droit d'être échappé, et comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// Cellule scalaire : seul `%` est échappé.
    Scalar,
    /// Composant de chemin de dossier : `%` et `/`.
    FolderComponent,
    /// Nom de tag : `%` et `|`.
    Tag,
    /// Chaîne interne au JSON de `fields` : seul `%`.
    FieldsString,
}

/// Erreur d'entrée invalide, avec un motif statique.
const fn invalid(reason: &'static str) -> Error {
    Error::InvalidInput { reason }
}

/// Erreur de dépassement de borne, avec un motif statique.
const fn too_long(reason: &'static str) -> Error {
    Error::MalformedLength { reason }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Exporte un coffre déchiffré au format CSV canonique.
///
/// Le résultat est du **texte en clair**, renvoyé dans un buffer auto-effaçable.
///
/// # Erreurs
/// * [`Error::InvalidInput`] si un contenu exporté contient un octet NUL, interdit
///   par le format ;
/// * [`Error::MalformedLength`] si une cellule, une ligne ou le fichier dépasse sa
///   borne (cas inatteignable pour une archive respectant le modèle) ;
/// * [`Error::Internal`] si l'archive est incohérente (tag ou dossier référencé
///   introuvable) — ce qui ne peut arriver qu'après un décodage pourtant validé.
pub fn export(archive: &Archive) -> Result<Zeroizing<Vec<u8>>> {
    // Une ligne par entrée active ou archivée ; la corbeille est exclue.
    let mut rows: Vec<[String; 11]> = Vec::with_capacity(archive.entries.len());
    for entry in &archive.entries {
        if entry.is_trashed() {
            continue;
        }
        rows.push(encode_row(archive, entry)?);
    }

    // Le tri porte sur les 11 colonnes exportables, dans l'ordre ordinal des
    // colonnes, bytewise UTF-8. `entry_ref` n'en fait pas partie : il sera attribué
    // d'après le rang, une fois l'ordre fixé.
    rows.sort();

    let mut out = String::new();
    out.push_str(&HEADER.join(","));
    out.push('\n');

    for (index, row) in rows.iter().enumerate() {
        let mut record = String::new();
        // `E` + 8 chiffres : `rows.len()` est borné par `MAX_ENTRIES` (10⁶), donc la
        // largeur est toujours suffisante.
        let _ = write!(record, "E{:08}", index + 1);
        for cell in row {
            if cell.len() > MAX_CSV_CELL_BYTES {
                return Err(too_long("cellule CSV au-delà de la taille maximale"));
            }
            record.push(',');
            quote_into(&mut record, cell);
        }
        if record.len() > MAX_CSV_LINE_BYTES {
            return Err(too_long("enregistrement CSV au-delà de la taille maximale"));
        }
        out.push_str(&record);
        out.push('\n');
        if out.len() > MAX_CSV_BYTES {
            return Err(too_long("export CSV au-delà de la taille maximale"));
        }
    }

    Ok(Zeroizing::new(out.into_bytes()))
}

/// Encode les 11 colonnes exportables d'une entrée.
fn encode_row(archive: &Archive, entry: &Entry) -> Result<[String; 11]> {
    Ok([
        escape(entry_kind_name(entry.kind), Context::Scalar)?,
        escape(&entry.title, Context::Scalar)?,
        escape(&entry.subtitle, Context::Scalar)?,
        encode_folder_path(archive, entry)?,
        encode_tags(archive, entry)?,
        encode_fields(&entry.fields)?,
        bool_text(entry.favorite).to_string(),
        bool_text(entry.archived).to_string(),
        bool_text(entry.sensitive).to_string(),
        entry.created_at.to_string(),
        entry.updated_at.to_string(),
    ])
}

/// Chemin du dossier d'une entrée, composants échappés et joints par `/`.
fn encode_folder_path(archive: &Archive, entry: &Entry) -> Result<String> {
    let Some(leaf) = entry.folder else {
        return Ok(String::new());
    };

    // Remontée vers la racine. Bornée par la profondeur maximale : l'archive est
    // validée au décodage, donc un dépassement signalerait une incohérence interne.
    let mut names: Vec<&str> = Vec::new();
    let mut current = Some(leaf);
    let mut steps = 0_usize;
    while let Some(id) = current {
        steps += 1;
        if steps > MAX_FOLDER_DEPTH {
            return Err(Error::Internal {
                invariant: "arborescence de dossiers plus profonde que la borne admise",
            });
        }
        let folder = archive
            .folders
            .iter()
            .find(|folder| folder.id == id)
            .ok_or(Error::Internal {
                invariant: "dossier référencé introuvable à l'export",
            })?;
        names.push(&folder.name);
        current = folder.parent;
    }
    names.reverse();

    let mut out = String::new();
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        push_escaped(&mut out, name, Context::FolderComponent)?;
    }
    Ok(out)
}

/// Noms de tags échappés, triés et dédupliqués, joints par `|`.
///
/// Triés par nom **encodé**, puis dédupliqués : une entrée qui référencerait deux
/// fois le même tag ne doit pas produire `a|a`, que l'import refuserait.
fn encode_tags(archive: &Archive, entry: &Entry) -> Result<String> {
    let mut names: Vec<String> = Vec::with_capacity(entry.tags.len());
    for id in &entry.tags {
        let tag = archive
            .tags
            .iter()
            .find(|tag| tag.id == *id)
            .ok_or(Error::Internal {
                invariant: "tag référencé introuvable à l'export",
            })?;
        names.push(escape(&tag.name, Context::Tag)?);
    }
    names.sort();
    names.dedup();
    Ok(names.join("|"))
}

/// Encode la liste des champs en structure canonique.
fn encode_fields(fields: &[Field]) -> Result<String> {
    if fields.is_empty() {
        return Ok("[]".to_string());
    }

    // Forme encodée de chaque champ, pour un tri déterministe sur la forme finale.
    let mut items: Vec<(u16, String, String, String, bool)> = Vec::with_capacity(fields.len());
    for field in fields {
        items.push((
            field.ordinal,
            json_string(&field.key)?,
            json_string(field_kind_name(field.kind))?,
            json_string(&field.value)?,
            field.concealed,
        ));
    }
    items.sort();

    let mut out = String::from("[");
    for (index, (ordinal, key, kind, value, concealed)) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"key\":");
        out.push_str(key);
        out.push_str(",\"kind\":");
        out.push_str(kind);
        out.push_str(",\"value\":");
        out.push_str(value);
        out.push_str(",\"ordinal\":");
        out.push_str(&ordinal.to_string());
        out.push_str(",\"concealed\":");
        out.push_str(bool_text(*concealed));
        out.push('}');
    }
    out.push(']');
    Ok(out)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Analyse et valide un CSV **sans toucher au magasin**.
///
/// Toute la validation ne dépendant pas de l'état du coffre a lieu ici : structure
/// du CSV, nombre de colonnes, échappements, structure des champs, types, bornes et
/// invariants d'entrée. Le résultat peut ensuite être appliqué par [`import`].
///
/// # Erreurs
/// [`Error::InvalidInput`] pour tout défaut de format,
/// [`Error::MalformedLength`] pour un dépassement de borne.
pub fn stage(bytes: &[u8], now: u64) -> Result<Vec<StagedEntry>> {
    let rows = parse_csv(bytes)?;
    let mut rows = rows.into_iter();

    let header = rows.next().ok_or_else(|| invalid("en-tête CSV absent"))?;
    if header.len() != COLUMN_COUNT
        || header
            .iter()
            .zip(HEADER.iter())
            .any(|(found, want)| found != want)
    {
        return Err(invalid("en-tête CSV inattendu"));
    }

    let mut staged = Vec::new();
    for row in rows {
        if staged.len() >= MAX_IMPORT_ENTRIES {
            return Err(too_long("trop d'entrées à importer"));
        }
        staged.push(decode_row(&row, now)?);
    }
    Ok(staged)
}

/// Importe un CSV dans un magasin ouvert en écriture.
///
/// # Transaction
///
/// L'analyse a lieu **avant** toute mutation (voir [`stage`]). L'application peut
/// ensuite échouer sur un invariant du magasin (doublon de dossier, profondeur,
/// borne de section) ; dans ce cas **rien n'est enregistré**, puisque l'unique
/// [`VaultStore::save`] est laissé à l'appelant. Une erreur d'import ne laisse donc
/// **aucune modification persistante**.
///
/// # Erreurs
/// Celles de [`stage`], plus celles de [`VaultStore::add_folder`],
/// [`VaultStore::add_tag`] et [`VaultStore::add_entry`].
pub fn import(store: &mut VaultStore, bytes: &[u8], now: u64) -> Result<ImportReport> {
    let staged = stage(bytes, now)?;
    apply(store, staged)
}

/// Applique des entrées déjà validées.
fn apply(store: &mut VaultStore, staged: Vec<StagedEntry>) -> Result<ImportReport> {
    let mut report = ImportReport {
        entries: 0,
        folders_created: 0,
        tags_created: 0,
    };

    for staged in staged {
        let folder = resolve_folder(store, &staged.folder, &mut report)?;
        let mut tags = Vec::with_capacity(staged.tags.len());
        for name in &staged.tags {
            tags.push(resolve_tag(store, name, &mut report)?);
        }

        let mut entry = staged.entry;
        entry.folder = folder;
        entry.tags = tags;

        store.add_entry(entry)?;
        report.entries += 1;
    }

    Ok(report)
}

/// Retrouve ou crée le dossier correspondant à un chemin, de la racine vers la feuille.
fn resolve_folder(
    store: &mut VaultStore,
    path: &[String],
    report: &mut ImportReport,
) -> Result<Option<FolderId>> {
    let mut parent: Option<FolderId> = None;
    for name in path {
        // Recherche insensible à la casse, comme la règle d'unicité du magasin.
        let existing = store
            .archive()
            .folders
            .iter()
            .find(|folder| folder.parent == parent && folder.name.eq_ignore_ascii_case(name))
            .map(|folder| folder.id);

        let id = if let Some(id) = existing {
            id
        } else {
            let id = store.add_folder(name, parent)?;
            report.folders_created += 1;
            id
        };
        parent = Some(id);
    }
    Ok(parent)
}

/// Retrouve ou crée le tag portant ce nom.
fn resolve_tag(store: &mut VaultStore, name: &str, report: &mut ImportReport) -> Result<TagId> {
    let existing = store
        .archive()
        .tags
        .iter()
        .find(|tag| tag.name.eq_ignore_ascii_case(name))
        .map(|tag| tag.id);

    if let Some(id) = existing {
        Ok(id)
    } else {
        let id = store.add_tag(name)?;
        report.tags_created += 1;
        Ok(id)
    }
}

/// Décode une ligne de données en entrée validée.
fn decode_row(row: &[String], now: u64) -> Result<StagedEntry> {
    if row.len() != COLUMN_COUNT {
        return Err(invalid("nombre de colonnes invalide"));
    }

    if !is_entry_ref(&row[0]) {
        return Err(invalid("référence d'entrée mal formée"));
    }

    let kind = entry_kind_from_name(&unescape(&row[1], Context::Scalar)?)?;
    let title = unescape(&row[2], Context::Scalar)?;
    let subtitle = unescape(&row[3], Context::Scalar)?;
    let folder = decode_folder(&row[4])?;
    let tags = decode_tags(&row[5])?;
    let fields = decode_fields(&row[6])?;
    let favorite = parse_bool(&row[7])?;
    let archived = parse_bool(&row[8])?;
    let sensitive = parse_bool(&row[9])?;
    let created_at = parse_u64(&row[10])?;
    let updated_at = parse_u64(&row[11])?;

    // `Entry::new` valide la longueur du titre ; les autres invariants sont vérifiés
    // par `Entry::validate`, qui borne titre, sous-titre, nombre de champs, clés
    // vides et longueurs de champ. On réutilise ces validations plutôt que d'en
    // écrire de parallèles.
    let mut entry = Entry::new(kind, title, now)?;
    entry.subtitle = subtitle;
    entry.created_at = created_at;
    entry.updated_at = updated_at;
    entry.favorite = favorite;
    entry.archived = archived;
    entry.sensitive = sensitive;
    entry.fields = fields;
    entry.validate()?;

    Ok(StagedEntry {
        entry,
        folder,
        tags,
    })
}

/// Décode le chemin de dossier : découpage sur `/`, **puis** déséchappement.
fn decode_folder(cell: &str) -> Result<Vec<String>> {
    if cell.is_empty() {
        return Ok(Vec::new());
    }

    let mut parts = Vec::new();
    for component in cell.split('/') {
        if component.is_empty() {
            return Err(invalid("composant de dossier vide"));
        }
        let name = unescape(component, Context::FolderComponent)?;
        if name.len() > MAX_NAME_LEN {
            return Err(too_long("nom de dossier au-delà de la longueur maximale"));
        }
        parts.push(name);
    }
    if parts.len() > MAX_FOLDER_DEPTH {
        return Err(invalid("profondeur de dossier au-delà de la limite"));
    }
    Ok(parts)
}

/// Décode la liste de tags : découpage sur `|`, **puis** déséchappement.
fn decode_tags(cell: &str) -> Result<Vec<String>> {
    if cell.is_empty() {
        return Ok(Vec::new());
    }

    let mut tags: Vec<String> = Vec::new();
    for raw in cell.split('|') {
        if raw.is_empty() {
            return Err(invalid("nom de tag vide"));
        }
        let name = unescape(raw, Context::Tag)?;
        if name.len() > MAX_NAME_LEN {
            return Err(too_long("nom de tag au-delà de la longueur maximale"));
        }
        // Deux noms égaux à la casse près désigneraient le même tag : ce doublon ne
        // peut pas provenir d'un export canonique.
        if tags
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            return Err(invalid("tag répété dans une entrée"));
        }
        tags.push(name);
    }
    if tags.len() > MAX_TAGS_PER_ENTRY {
        return Err(too_long("trop de tags sur une entrée"));
    }
    Ok(tags)
}

// ---------------------------------------------------------------------------
// Décodage de la colonne `fields`
// ---------------------------------------------------------------------------

/// Curseur d'octets, utilisé par l'analyseur de la structure `fields`.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> Result<()> {
        match self.bump() {
            Some(found) if found == byte => Ok(()),
            _ => Err(invalid("structure des champs mal formée")),
        }
    }

    fn expect_lit(&mut self, literal: &[u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(literal.len())
            .ok_or_else(|| invalid("structure des champs mal formée"))?;
        if self.bytes.get(self.pos..end) == Some(literal) {
            self.pos = end;
            Ok(())
        } else {
            Err(invalid("structure des champs mal formée"))
        }
    }

    /// Décodes une chaîne JSON **canonique**.
    ///
    /// N'accepte que les échappements que l'écrivain produit : `\"`, `\\`, `\b`,
    /// `\f`, `\n`, `\r`, `\t`, et `\u00XX` pour les C0 sans raccourci. Un caractère
    /// de contrôle brut, un `\u` non canonique ou un chiffre hexadécimal minuscule
    /// sont refusés.
    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self
                .bump()
                .ok_or_else(|| invalid("chaîne JSON non terminée"))?;
            match byte {
                b'"' => break,
                b'\\' => {
                    let esc = self
                        .bump()
                        .ok_or_else(|| invalid("échappement JSON incomplet"))?;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(0x0A),
                        b'r' => out.push(0x0D),
                        b't' => out.push(0x09),
                        b'u' => {
                            let digits = [
                                self.bump().ok_or_else(|| invalid("\\u incomplet"))?,
                                self.bump().ok_or_else(|| invalid("\\u incomplet"))?,
                                self.bump().ok_or_else(|| invalid("\\u incomplet"))?,
                                self.bump().ok_or_else(|| invalid("\\u incomplet"))?,
                            ];
                            out.push(u_escape_value(digits)?);
                        }
                        _ => return Err(invalid("échappement JSON inconnu")),
                    }
                }
                0x00..=0x1F => {
                    return Err(invalid("caractère de contrôle brut dans une chaîne JSON"));
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).map_err(|_| invalid("chaîne de champ non UTF-8"))
    }

    fn parse_u16(&mut self) -> Result<u16> {
        let start = self.pos;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits = &self.bytes[start..self.pos];
        if digits.is_empty() {
            return Err(invalid("nombre attendu"));
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(invalid("nombre avec un zéro de tête"));
        }
        let mut value: u32 = 0;
        for &digit in digits {
            value = value * 10 + u32::from(digit - b'0');
            if value > u32::from(u16::MAX) {
                return Err(invalid("nombre hors bornes"));
            }
        }
        Ok(u16::try_from(value).unwrap_or(u16::MAX))
    }

    fn parse_bool(&mut self) -> Result<bool> {
        if self.bytes.get(self.pos..self.pos + 4) == Some(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.bytes.get(self.pos..self.pos + 5) == Some(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(invalid("booléen attendu (true ou false)"))
        }
    }
}

/// Valeur d'un `\u00XX` : uniquement un C0 que la canonisation écrit ainsi.
fn u_escape_value(digits: [u8; 4]) -> Result<u8> {
    if digits[0] != b'0' || digits[1] != b'0' {
        return Err(invalid("échappement \\u non canonique"));
    }
    let high = hex_upper_value(digits[2]).ok_or_else(|| {
        invalid("chiffre hexadécimal invalide ou minuscule dans un échappement \\u")
    })?;
    let low = hex_upper_value(digits[3]).ok_or_else(|| {
        invalid("chiffre hexadécimal invalide ou minuscule dans un échappement \\u")
    })?;
    let code = high * 16 + low;
    // `00` est interdit (NUL) ; `08 09 0A 0C 0D` ont un raccourci qui est leur seule
    // forme canonique ; au-delà de `1F`, ce n'est plus un C0.
    if code == 0 || code > 0x1F || matches!(code, 0x08 | 0x09 | 0x0A | 0x0C | 0x0D) {
        return Err(invalid("échappement \\u non canonique"));
    }
    Ok(code)
}

/// Valeur hexadécimale d'un chiffre **majuscule**.
const fn hex_upper_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Décode la cellule `fields` en liste de champs.
fn decode_fields(cell: &str) -> Result<Vec<Field>> {
    let mut cursor = Cursor::new(cell.as_bytes());
    cursor.expect(b'[')?;

    let mut fields = Vec::new();
    if cursor.peek() == Some(b']') {
        cursor.bump();
    } else {
        loop {
            if fields.len() >= MAX_IMPORT_FIELDS_PER_ENTRY {
                return Err(too_long("trop de champs dans une entrée"));
            }
            fields.push(decode_field(&mut cursor)?);
            match cursor
                .bump()
                .ok_or_else(|| invalid("structure des champs non terminée"))?
            {
                b',' => {}
                b']' => break,
                _ => return Err(invalid("séparateur attendu entre les champs")),
            }
        }
    }

    if !cursor.is_empty() {
        return Err(invalid("contenu résiduel après la structure des champs"));
    }
    Ok(fields)
}

/// Décode un objet champ, à clés fixes et dans l'ordre canonique.
fn decode_field(cursor: &mut Cursor<'_>) -> Result<Field> {
    cursor.expect(b'{')?;

    cursor.expect_lit(b"\"key\":")?;
    let key = unescape(&cursor.parse_string()?, Context::FieldsString)?;

    cursor.expect_lit(b",\"kind\":")?;
    let kind = field_kind_from_name(&cursor.parse_string()?)?;

    cursor.expect_lit(b",\"value\":")?;
    let value = unescape(&cursor.parse_string()?, Context::FieldsString)?;

    cursor.expect_lit(b",\"ordinal\":")?;
    let ordinal = cursor.parse_u16()?;

    cursor.expect_lit(b",\"concealed\":")?;
    let concealed = cursor.parse_bool()?;

    cursor.expect(b'}')?;

    // `Field::new` fixe `concealed` d'après le type ; on restaure ensuite la valeur
    // exacte lue, pour que l'aller-retour soit fidèle.
    let mut field = Field::new(key, kind, value, ordinal)?;
    field.concealed = concealed;
    Ok(field)
}

// ---------------------------------------------------------------------------
// Analyse CSV (RFC 4180, stricte et bornée)
// ---------------------------------------------------------------------------

/// État d'un champ pendant l'analyse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellState {
    Start,
    Unquoted,
    Quoted,
    AfterQuote,
    ExpectLf,
}

/// Analyse un CSV en lignes de cellules, en appliquant les bornes.
fn parse_csv(bytes: &[u8]) -> Result<Vec<Vec<String>>> {
    if bytes.len() > MAX_CSV_BYTES {
        return Err(too_long("fichier CSV au-delà de la taille maximale"));
    }
    if bytes.contains(&0) {
        return Err(invalid(
            "le fichier contient un octet NUL, interdit par le format",
        ));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("le CSV n'est pas de l'UTF-8 valide"))?;

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut state = CellState::Start;
    let mut record_len = 0_usize;

    for ch in text.chars() {
        record_len = record_len.saturating_add(ch.len_utf8());
        if record_len > MAX_CSV_LINE_BYTES {
            return Err(too_long("enregistrement CSV au-delà de la taille maximale"));
        }

        match state {
            CellState::Start => match ch {
                '"' => state = CellState::Quoted,
                ',' => finish_field(&mut row, &mut field)?,
                '\n' => {
                    finish_field(&mut row, &mut field)?;
                    finish_row(&mut rows, &mut row);
                    check_row_count(rows.len())?;
                    record_len = 0;
                }
                '\r' => state = CellState::ExpectLf,
                _ => {
                    field.push(ch);
                    state = CellState::Unquoted;
                }
            },
            CellState::Unquoted => match ch {
                ',' => {
                    finish_field(&mut row, &mut field)?;
                    state = CellState::Start;
                }
                '\n' => {
                    finish_field(&mut row, &mut field)?;
                    finish_row(&mut rows, &mut row);
                    check_row_count(rows.len())?;
                    record_len = 0;
                    state = CellState::Start;
                }
                '\r' => state = CellState::ExpectLf,
                '"' => {
                    return Err(invalid("guillemet au milieu d'un champ non cité"));
                }
                _ => field.push(ch),
            },
            CellState::Quoted => match ch {
                '"' => state = CellState::AfterQuote,
                _ => field.push(ch),
            },
            CellState::AfterQuote => match ch {
                '"' => {
                    field.push('"');
                    state = CellState::Quoted;
                }
                ',' => {
                    finish_field(&mut row, &mut field)?;
                    state = CellState::Start;
                }
                '\n' => {
                    finish_field(&mut row, &mut field)?;
                    finish_row(&mut rows, &mut row);
                    check_row_count(rows.len())?;
                    record_len = 0;
                    state = CellState::Start;
                }
                '\r' => state = CellState::ExpectLf,
                _ => return Err(invalid("caractère après la fermeture d'un champ cité")),
            },
            CellState::ExpectLf => {
                if ch != '\n' {
                    return Err(invalid("retour chariot sans saut de ligne"));
                }
                finish_field(&mut row, &mut field)?;
                finish_row(&mut rows, &mut row);
                check_row_count(rows.len())?;
                record_len = 0;
                state = CellState::Start;
            }
        }
    }

    match state {
        CellState::Quoted => return Err(invalid("champ cité non terminé")),
        CellState::ExpectLf => return Err(invalid("retour chariot en fin de fichier")),
        _ => {}
    }

    // Dernière ligne sans saut de ligne final. Après une ligne complète, l'état est
    // `Start` et rien n'est en attente : on ne fabrique pas de ligne vide.
    if !(state == CellState::Start && field.is_empty() && row.is_empty()) {
        finish_field(&mut row, &mut field)?;
        finish_row(&mut rows, &mut row);
        check_row_count(rows.len())?;
    }

    Ok(rows)
}

fn finish_field(row: &mut Vec<String>, field: &mut String) -> Result<()> {
    if field.len() > MAX_CSV_CELL_BYTES {
        return Err(too_long("cellule CSV au-delà de la taille maximale"));
    }
    row.push(std::mem::take(field));
    Ok(())
}

fn finish_row(rows: &mut Vec<Vec<String>>, row: &mut Vec<String>) {
    rows.push(std::mem::take(row));
}

/// Borne le nombre de lignes : l'en-tête compris.
fn check_row_count(rows: usize) -> Result<()> {
    if rows > MAX_IMPORT_ENTRIES.saturating_add(1) {
        return Err(too_long("trop de lignes dans le fichier CSV"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Échappement et déséchappement
// ---------------------------------------------------------------------------

/// Échappe un texte selon son contexte, et refuse un NUL.
fn escape(text: &str, context: Context) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    push_escaped(&mut out, text, context)?;
    Ok(out)
}

/// Échappe `text` et l'ajoute à `out`.
fn push_escaped(out: &mut String, text: &str, context: Context) -> Result<()> {
    for ch in text.chars() {
        match ch {
            '\0' => {
                return Err(invalid(
                    "un contenu exporté contient un octet NUL, interdit par le format",
                ));
            }
            '%' => out.push_str("%25"),
            '/' if context == Context::FolderComponent => out.push_str("%2F"),
            '|' if context == Context::Tag => out.push_str("%7C"),
            _ => out.push(ch),
        }
    }
    Ok(())
}

/// Déséchappe un texte selon son contexte, strictement.
///
/// Seules sont admises les séquences **autorisées dans ce contexte**, en
/// **hexadécimal majuscule** : `%25` partout, `%2F` en composant de dossier, `%7C`
/// en tag. Tout le reste — séquence inconnue, incomplète, ou minuscule — échoue.
fn unescape(text: &str, context: Context) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '\0' => {
                return Err(invalid(
                    "un contenu contient un octet NUL, interdit par le format",
                ));
            }
            '%' => {
                let high = chars.next();
                let low = chars.next();
                match (high, low) {
                    (Some('2'), Some('5')) => out.push('%'),
                    (Some('2'), Some('F')) if context == Context::FolderComponent => out.push('/'),
                    (Some('7'), Some('C')) if context == Context::Tag => out.push('|'),
                    _ => {
                        return Err(invalid(
                            "séquence d'échappement inconnue, incomplète ou non autorisée \
                             dans ce contexte",
                        ));
                    }
                }
            }
            _ => out.push(ch),
        }
    }
    Ok(out)
}

/// Écrit une cellule, citée si nécessaire (RFC 4180).
fn quote_into(out: &mut String, cell: &str) {
    let needs_quote = cell
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\n' | b'\r'));
    if !needs_quote {
        out.push_str(cell);
        return;
    }

    out.push('"');
    for ch in cell.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    out.push('"');
}

/// Encodes une chaîne en chaîne JSON canonique, `%` échappé au préalable.
fn json_string(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\0' => {
                return Err(invalid(
                    "un contenu exporté contient un octet NUL, interdit par le format",
                ));
            }
            '%' => out.push_str("%25"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let code = control as u8;
                out.push_str("\\u00");
                out.push(hex_upper(code >> 4));
                out.push(hex_upper(code & 0x0F));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

const fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

// ---------------------------------------------------------------------------
// Petits analyseurs et tables
// ---------------------------------------------------------------------------

/// Vrai si la référence a la forme canonique `E` suivie de 8 chiffres.
fn is_entry_ref(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 9 && bytes[0] == b'E' && bytes[1..].iter().all(u8::is_ascii_digit)
}

/// Analyse un booléen canonique.
fn parse_bool(text: &str) -> Result<bool> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid("booléen attendu (true ou false)")),
    }
}

/// Analyse un entier décimal canonique (`u64`), sans zéro de tête.
fn parse_u64(text: &str) -> Result<u64> {
    if text.is_empty() || text.len() > 20 {
        return Err(invalid("horodatage invalide"));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(invalid("horodatage avec un zéro de tête"));
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("horodatage non décimal"));
    }
    text.parse::<u64>()
        .map_err(|_| invalid("horodatage hors bornes"))
}

const fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Nom canonique d'un type d'entrée.
const fn entry_kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Login => "login",
        EntryKind::SecureNote => "secure_note",
        EntryKind::CreditCard => "credit_card",
        EntryKind::Identity => "identity",
        EntryKind::ApiKey => "api_key",
        EntryKind::SshKey => "ssh_key",
        EntryKind::Wifi => "wifi",
        EntryKind::PasskeyMetadata => "passkey_metadata",
        EntryKind::Custom => "custom",
    }
}

/// Type d'entrée correspondant à un nom canonique.
fn entry_kind_from_name(name: &str) -> Result<EntryKind> {
    Ok(match name {
        "login" => EntryKind::Login,
        "secure_note" => EntryKind::SecureNote,
        "credit_card" => EntryKind::CreditCard,
        "identity" => EntryKind::Identity,
        "api_key" => EntryKind::ApiKey,
        "ssh_key" => EntryKind::SshKey,
        "wifi" => EntryKind::Wifi,
        "passkey_metadata" => EntryKind::PasskeyMetadata,
        "custom" => EntryKind::Custom,
        _ => return Err(invalid("type d'entrée inconnu")),
    })
}

/// Nom canonique d'un type de champ.
const fn field_kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Secret => "secret",
        FieldKind::Url => "url",
        FieldKind::Multiline => "multiline",
        FieldKind::Email => "email",
        FieldKind::Totp => "totp",
        FieldKind::Number => "number",
        FieldKind::Date => "date",
        FieldKind::Pin => "pin",
        FieldKind::Custom => "custom",
    }
}

/// Type de champ correspondant à un nom canonique.
fn field_kind_from_name(name: &str) -> Result<FieldKind> {
    Ok(match name {
        "text" => FieldKind::Text,
        "secret" => FieldKind::Secret,
        "url" => FieldKind::Url,
        "multiline" => FieldKind::Multiline,
        "email" => FieldKind::Email,
        "totp" => FieldKind::Totp,
        "number" => FieldKind::Number,
        "date" => FieldKind::Date,
        "pin" => FieldKind::Pin,
        "custom" => FieldKind::Custom,
        _ => return Err(invalid("type de champ inconnu")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_respects_context() {
        assert_eq!(escape("a%b", Context::Scalar).expect("ok"), "a%25b");
        assert_eq!(
            escape("a/b", Context::FolderComponent).expect("ok"),
            "a%2Fb"
        );
        // `/` n'est pas échappé hors d'un composant de dossier.
        assert_eq!(escape("a/b", Context::Scalar).expect("ok"), "a/b");
        assert_eq!(escape("a|b", Context::Tag).expect("ok"), "a%7Cb");
        assert_eq!(escape("a|b", Context::Scalar).expect("ok"), "a|b");
    }

    #[test]
    fn escaping_rejects_nul() {
        assert!(escape("a\0b", Context::Scalar).is_err());
    }

    #[test]
    fn unescaping_is_strict() {
        assert_eq!(unescape("a%25b", Context::Scalar).expect("ok"), "a%b");
        assert_eq!(
            unescape("a%2Fb", Context::FolderComponent).expect("ok"),
            "a/b"
        );
        assert_eq!(unescape("a%7Cb", Context::Tag).expect("ok"), "a|b");

        // Contexte interdit.
        assert!(unescape("a%2Fb", Context::Scalar).is_err());
        assert!(unescape("a%7Cb", Context::FolderComponent).is_err());
        // Minuscules interdites.
        assert!(unescape("a%2fb", Context::FolderComponent).is_err());
        assert!(unescape("a%25b", Context::Scalar).is_ok());
        // Inconnue, incomplète.
        assert!(unescape("a%41", Context::Scalar).is_err());
        assert!(unescape("a%2", Context::Scalar).is_err());
        assert!(unescape("a%", Context::Scalar).is_err());
        // NUL.
        assert!(unescape("a\0b", Context::Scalar).is_err());
    }

    #[test]
    fn json_string_is_canonical() {
        assert_eq!(json_string("abc").expect("ok"), "\"abc\"");
        assert_eq!(json_string("a%b").expect("ok"), "\"a%25b\"");
        assert_eq!(json_string("a\"b").expect("ok"), "\"a\\\"b\"");
        assert_eq!(json_string("a\\b").expect("ok"), "\"a\\\\b\"");
        assert_eq!(json_string("a\nb").expect("ok"), "\"a\\nb\"");
        assert_eq!(json_string("a\u{0B}b").expect("ok"), "\"a\\u000Bb\"");
        assert!(json_string("a\0b").is_err());
    }

    #[test]
    fn fields_cell_round_trips() {
        let fields = vec![
            Field::new("password", FieldKind::Secret, "Tr0p%S3cr3t", 0).expect("champ"),
            Field::new("url", FieldKind::Url, "https://ex.com/a|b", 1).expect("champ"),
        ];
        let cell = encode_fields(&fields).expect("encodage");
        assert_eq!(
            cell,
            "[{\"key\":\"password\",\"kind\":\"secret\",\"value\":\"Tr0p%25S3cr3t\",\
             \"ordinal\":0,\"concealed\":true},{\"key\":\"url\",\"kind\":\"url\",\
             \"value\":\"https://ex.com/a|b\",\"ordinal\":1,\"concealed\":false}]"
        );

        let decoded = decode_fields(&cell).expect("décodage");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].key, "password");
        assert_eq!(decoded[0].value, "Tr0p%S3cr3t");
        assert!(decoded[0].concealed);
        assert_eq!(decoded[1].value, "https://ex.com/a|b");
    }

    #[test]
    fn field_order_is_independent_of_input_order() {
        let mut first = vec![
            Field::new("b", FieldKind::Text, "2", 1).expect("champ"),
            Field::new("a", FieldKind::Text, "1", 0).expect("champ"),
            Field::new("c", FieldKind::Text, "3", 1).expect("champ"),
        ];
        let encoded_first = encode_fields(&first).expect("ok");

        first.reverse();
        let encoded_second = encode_fields(&first).expect("ok");
        assert_eq!(encoded_first, encoded_second);
    }

    #[test]
    fn decode_fields_rejects_non_canonical_forms() {
        // Ordre de clés inversé.
        assert!(decode_fields("[{\"kind\":\"text\",\"key\":\"a\",\"value\":\"v\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // Espace superflu.
        assert!(decode_fields("[ {\"key\":\"a\",\"kind\":\"text\",\"value\":\"v\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // Zéro de tête.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"v\",\"ordinal\":00,\"concealed\":false}]").is_err());
        // Booléen non canonique.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"v\",\"ordinal\":0,\"concealed\":TRUE}]").is_err());
        // Type de champ inconnu.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"bogus\",\"value\":\"v\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // Contenu résiduel.
        assert!(decode_fields("[]x").is_err());
        // \\u0000 interdit.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"\\u0000\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // \\u non canonique.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"\\u0041\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // \\u minuscule refusé.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"\\u000b\",\"ordinal\":0,\"concealed\":false}]").is_err());
        // % interdit dans une chaîne de champ.
        assert!(decode_fields("[{\"key\":\"a\",\"kind\":\"text\",\"value\":\"%2F\",\"ordinal\":0,\"concealed\":false}]").is_err());
    }

    #[test]
    fn csv_quoting_round_trips_through_the_parser() {
        let cells = [
            "simple",
            "avec, virgule",
            "avec \"guillemet\"",
            "avec\nsaut",
        ];
        let mut record = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index > 0 {
                record.push(',');
            }
            quote_into(&mut record, cell);
        }
        record.push('\n');

        let rows = parse_csv(record.as_bytes()).expect("analyse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], cells);
    }

    #[test]
    fn the_parser_rejects_malformed_csv() {
        // Guillemet au milieu d'un champ non cité.
        assert!(parse_csv(b"a\"b,c\n").is_err());
        // Champ cité non terminé.
        assert!(parse_csv(b"\"abc\n").is_err());
        // Caractère après fermeture.
        assert!(parse_csv(b"\"abc\"x\n").is_err());
        // CR sans LF.
        assert!(parse_csv(b"a\rb\n").is_err());
        // NUL.
        assert!(parse_csv(b"a\0b\n").is_err());
    }

    #[test]
    fn empty_input_has_no_header() {
        assert!(stage(b"", 0).is_err());
    }

    #[test]
    fn a_wrong_header_is_refused() {
        assert!(stage(b"a,b,c\n", 0).is_err());
    }

    #[test]
    fn header_alone_is_an_empty_import() {
        let mut bytes = String::new();
        bytes.push_str(&HEADER.join(","));
        bytes.push('\n');
        let staged = stage(bytes.as_bytes(), 0).expect("ok");
        assert!(staged.is_empty());
    }

    #[test]
    fn kind_names_round_trip() {
        for kind in EntryKind::ALL {
            assert_eq!(
                entry_kind_from_name(entry_kind_name(kind)).expect("ok"),
                kind
            );
        }
        for kind in FieldKind::ALL {
            assert_eq!(
                field_kind_from_name(field_kind_name(kind)).expect("ok"),
                kind
            );
        }
    }

    #[test]
    fn canonical_u64_is_enforced() {
        assert_eq!(parse_u64("0").expect("ok"), 0);
        assert_eq!(parse_u64("1700000000").expect("ok"), 1_700_000_000);
        assert!(parse_u64("00").is_err());
        assert!(parse_u64("").is_err());
        assert!(parse_u64("1 ").is_err());
        assert!(parse_u64("-1").is_err());
        assert!(parse_u64("99999999999999999999999999").is_err());
    }
}
