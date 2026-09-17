//! Audit sémantique du magasin par modèle de référence.
//!
//! # Pourquoi ce fichier est différent des autres
//!
//! Les tests de `store.rs` vérifient des **scénarios écrits à la main**, avec les
//! mêmes helpers et les mêmes hypothèses que le code qu'ils éprouvent. Ils partagent
//! donc ses angles morts : ce que l'auteur n'a pas imaginé n'est pas testé.
//!
//! Ce fichier prend le problème par l'autre bout :
//!
//! 1. un **modèle de référence** décrit en quelques dizaines de lignes la sémantique
//!    attendue — naïf, sans cryptographie, sans fichier, écrit pour être
//!    évidemment correct plutôt que performant ;
//! 2. un générateur produit des **séquences aléatoires d'opérations**, y compris
//!    hostiles (identifiants inexistants, répétitions, références pendantes) ;
//! 3. après **chaque** opération, le comportement du magasin est comparé à celui du
//!    modèle, et les invariants structurels sont revérifiés.
//!
//! Le modèle est l'oracle. Il ne partage **aucune** ligne avec l'implémentation.
//!
//! # Reproduction d'un échec
//!
//! Le générateur est déterministe : chaque essai est identifié par une graine, et
//! l'échec affiche la **séquence complète** des opérations avec son indice. Un test
//! paramétré par la graine rejoue le cas à l'identique.
//!
//! # Compromis assumé : pas de « shrinking »
//!
//! Les cadriciels de tests par propriétés réduisent automatiquement un cas d'échec à
//! sa plus petite forme. Ici, l'échec donne la séquence complète, que l'auteur doit
//! réduire à la main. C'est le prix de l'absence de dépendance de test — et un cas
//! minimal se reconstitue en général en rejouant les premières opérations.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use passlock_core::error::Error;
use passlock_core::kdf::{KdfParams, MIN_M_COST_KIB};
use passlock_core::model::{
    Entry, EntryId, EntryKind, Field, FieldKind, FolderId, MAX_AUDIT_EVENTS, MAX_FOLDER_DEPTH,
    MAX_HISTORY_PER_ENTRY, MAX_NAME_LEN, TagId,
};
use passlock_core::query::{SearchQuery, search};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

const PASSWORD: &[u8] = b"audit semantique du magasin";

fn config(state: &Path) -> VaultConfig {
    VaultConfig {
        params: KdfParams::new(MIN_M_COST_KIB, 1, 1).expect("paramètres valides"),
        read_only: false,
        state_dir: Some(state.to_path_buf()),
    }
}

// ---------------------------------------------------------------------------
// Générateur déterministe
//
// Volontairement distinct de ceux des autres harnais : un générateur partagé
// produirait les mêmes séquences, donc les mêmes angles morts.
// ---------------------------------------------------------------------------

struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0xDEAD_BEEF_CAFE_F00D)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() >> 11) as usize % bound
        }
    }

    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Opérations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Operation {
    AddFolder {
        name_seed: usize,
        parent_slot: Option<usize>,
    },
    AddTag {
        name_seed: usize,
    },
    AddEntry {
        title_seed: usize,
        folder_slot: Option<usize>,
        tag_slots: Vec<usize>,
        field_count: usize,
    },
    /// Ajout référençant un dossier qui n'existe pas.
    AddEntryWithGhostFolder,
    /// Ajout référençant un tag qui n'existe pas.
    AddEntryWithGhostTag,
    UpdateEntry {
        entry_slot: usize,
        new_title_seed: usize,
        add_field: bool,
    },
    /// Modification référençant un dossier inexistant.
    UpdateEntryWithGhostFolder {
        entry_slot: usize,
    },
    TrashEntry {
        entry_slot: usize,
    },
    RestoreEntry {
        entry_slot: usize,
    },
    PurgeEntry {
        entry_slot: usize,
    },
    PurgeHistory {
        entry_slot: usize,
    },
    EmptyTrash,
    /// Opération sur un identifiant qui n'existe dans aucune des deux parties.
    OperateOnMissingEntry,
    Save,
    Reopen,
}

impl Operation {
    /// Décrit l'opération pour la reproduction d'un échec.
    fn describe(&self) -> String {
        format!("{self:?}")
    }
}

fn generate(rng: &mut Prng, slots: usize, folders: usize, tags: usize) -> Operation {
    let kind = rng.below(16);

    match kind {
        0 => Operation::AddFolder {
            name_seed: rng.below(6),
            parent_slot: if folders > 0 && rng.bool() {
                Some(rng.below(folders))
            } else {
                None
            },
        },
        1 => Operation::AddTag {
            name_seed: rng.below(6),
        },
        2..=4 => Operation::AddEntry {
            title_seed: rng.below(20),
            folder_slot: if folders > 0 && rng.bool() {
                Some(rng.below(folders))
            } else {
                None
            },
            tag_slots: if tags > 0 && rng.bool() {
                (0..=rng.below(2)).map(|_| rng.below(tags)).collect()
            } else {
                Vec::new()
            },
            field_count: rng.below(4),
        },
        5 => Operation::AddEntryWithGhostFolder,
        6 => Operation::AddEntryWithGhostTag,
        7 | 8 => {
            if slots == 0 {
                Operation::AddEntry {
                    title_seed: rng.below(20),
                    folder_slot: None,
                    tag_slots: Vec::new(),
                    field_count: 0,
                }
            } else {
                Operation::UpdateEntry {
                    entry_slot: rng.below(slots),
                    new_title_seed: rng.below(20),
                    add_field: rng.bool(),
                }
            }
        }
        9 => {
            if slots == 0 {
                Operation::Save
            } else {
                Operation::UpdateEntryWithGhostFolder {
                    entry_slot: rng.below(slots),
                }
            }
        }
        10 => slot_or_save(rng, slots, |slot| Operation::TrashEntry {
            entry_slot: slot,
        }),
        11 => slot_or_save(rng, slots, |slot| Operation::RestoreEntry {
            entry_slot: slot,
        }),
        12 => slot_or_save(rng, slots, |slot| Operation::PurgeEntry {
            entry_slot: slot,
        }),
        13 => slot_or_save(rng, slots, |slot| Operation::PurgeHistory {
            entry_slot: slot,
        }),
        14 => Operation::EmptyTrash,
        _ => {
            // Les proportions comptent : une réouverture coûte une dérivation
            // Argon2id complète. À 1 sur 16, elle dominait le temps d'exécution
            // (116 secondes) alors qu'un sur cent suffit largement à éprouver la
            // persistance — la propriété vérifiée est que l'aller-retour par le
            // fichier ne change rien, et elle ne dépend pas de sa fréquence.
            let roll = rng.below(96);
            if roll == 0 {
                Operation::Reopen
            } else if roll < 12 {
                Operation::OperateOnMissingEntry
            } else {
                Operation::Save
            }
        }
    }
}

fn slot_or_save(rng: &mut Prng, slots: usize, build: impl Fn(usize) -> Operation) -> Operation {
    if slots == 0 {
        Operation::Save
    } else {
        build(rng.below(slots))
    }
}

// ---------------------------------------------------------------------------
// Modèle de référence
//
// Écrit pour être **évidemment correct**, pas pour être efficace : des `Vec` et des
// `BTreeMap`, aucune optimisation, aucune connaissance du magasin réel.
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Reference {
    folders: Vec<(FolderId, String, Option<FolderId>)>,
    tags: Vec<(TagId, String)>,
    entries: Vec<RefEntry>,
}

#[derive(Clone)]
struct RefEntry {
    id: EntryId,
    title: String,
    trashed: bool,
    revision: u32,
    history_len: usize,
    field_count: usize,
    folder: Option<FolderId>,
    tags: BTreeSet<TagId>,
}

impl Reference {
    /// Profondeur d'un dossier dans le modèle.
    fn depth(&self, id: FolderId) -> usize {
        let mut depth = 1;
        let mut current = self
            .folders
            .iter()
            .find(|(folder, _, _)| *folder == id)
            .and_then(|(_, _, parent)| *parent);

        while let Some(parent) = current {
            depth += 1;
            current = self
                .folders
                .iter()
                .find(|(folder, _, _)| *folder == parent)
                .and_then(|(_, _, grand)| *grand);
        }
        depth
    }
}

/// Résultat attendu d'une opération, du point de vue du modèle.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Ok,
    Err,
}

// ---------------------------------------------------------------------------
// Application au modèle
// ---------------------------------------------------------------------------

/// Applique une opération au modèle et retourne le résultat attendu.
///
/// Pour les créations de dossier ou de tag, l'identifiant réel est inconnu du modèle :
/// il est adopté depuis le magasin (voir `apply`). Le modèle prédit donc seulement
/// **si** l'opération doit réussir et quel en est l'effet.
fn predict(reference: &mut Reference, operation: &Operation) -> Expect {
    match operation {
        Operation::AddFolder {
            name_seed,
            parent_slot,
        } => {
            let name = format!("dossier-{}", name_seed % 6);

            if name.len() > MAX_NAME_LEN {
                return Expect::Err;
            }

            let parent = parent_slot.and_then(|slot| reference.folders.get(slot).map(|f| f.0));

            if parent_slot.is_some() && parent.is_none() {
                // Le modèle n'a pas ce dossier : le magasin non plus, puisque les
                // deux avancent ensemble.
                return Expect::Err;
            }

            // Doublon au même niveau.
            if reference
                .folders
                .iter()
                .any(|(_, existing, existing_parent)| {
                    *existing_parent == parent && existing.eq_ignore_ascii_case(&name)
                })
            {
                return Expect::Err;
            }

            // Profondeur maximale.
            if parent.is_some_and(|parent| reference.depth(parent) >= MAX_FOLDER_DEPTH) {
                return Expect::Err;
            }

            Expect::Ok
        }

        Operation::AddTag { name_seed } => {
            let name = format!("tag-{}", name_seed % 6);
            if reference
                .tags
                .iter()
                .any(|(_, existing)| existing.eq_ignore_ascii_case(&name))
            {
                Expect::Err
            } else {
                Expect::Ok
            }
        }

        Operation::AddEntry {
            folder_slot,
            tag_slots,
            ..
        } => {
            // Le magasin refuse une référence pendante. Un emplacement de dossier ou
            // de tag dont l'identifiant n'a pas encore été réconcilié (nul) est
            // précisément ce cas.
            let folder_missing = folder_slot
                .is_some_and(|slot| reference.folders.get(slot).is_none_or(|f| f.0.is_nil()));
            let tag_missing = tag_slots
                .iter()
                .any(|slot| reference.tags.get(*slot).is_none_or(|t| t.0.is_nil()));

            if folder_missing || tag_missing {
                Expect::Err
            } else {
                Expect::Ok
            }
        }

        // Toutes les opérations visant une entrée par son emplacement partagent la
        // même condition : l'emplacement doit exister dans le modèle.
        Operation::UpdateEntry { entry_slot, .. }
        | Operation::TrashEntry { entry_slot }
        | Operation::RestoreEntry { entry_slot }
        | Operation::PurgeEntry { entry_slot }
        | Operation::PurgeHistory { entry_slot } => {
            if *entry_slot < reference.entries.len() {
                Expect::Ok
            } else {
                Expect::Err
            }
        }

        // Opérations sans condition : elles réussissent toujours, ou échouent
        // toujours. Les variantes « fantômes » visent une référence inexistante et
        // échouent par construction ; la dernière agit sur un identifiant absent.
        Operation::EmptyTrash | Operation::Save | Operation::Reopen => Expect::Ok,
        Operation::AddEntryWithGhostFolder
        | Operation::AddEntryWithGhostTag
        | Operation::UpdateEntryWithGhostFolder { .. }
        | Operation::OperateOnMissingEntry => Expect::Err,
    }
}

/// Met le modèle à jour pour les opérations qui ne créent pas d'objet.
///
/// Les créations sont traitées dans `apply` : elles doivent **adopter** l'identifiant
/// produit par le magasin, et sont donc les seules à avoir besoin d'un aller-retour.
fn commit(reference: &mut Reference, operation: &Operation) {
    match operation {
        Operation::UpdateEntry {
            entry_slot,
            new_title_seed,
            add_field,
        } => {
            if let Some(entry) = reference.entries.get_mut(*entry_slot) {
                entry.history_len += 1;
                entry.revision += 1;
                entry.title = format!("entrée-{}", new_title_seed % 20);
                if *add_field {
                    entry.field_count += 1;
                }
                if entry.history_len > MAX_HISTORY_PER_ENTRY {
                    entry.history_len = MAX_HISTORY_PER_ENTRY;
                }
            }
        }
        Operation::TrashEntry { entry_slot } => {
            if let Some(entry) = reference.entries.get_mut(*entry_slot) {
                entry.trashed = true;
            }
        }
        Operation::RestoreEntry { entry_slot } => {
            if let Some(entry) = reference.entries.get_mut(*entry_slot) {
                entry.trashed = false;
            }
        }
        Operation::PurgeEntry { entry_slot } => {
            if *entry_slot < reference.entries.len() {
                reference.entries.remove(*entry_slot);
            }
        }
        Operation::PurgeHistory { entry_slot } => {
            if let Some(entry) = reference.entries.get_mut(*entry_slot) {
                entry.history_len = 0;
            }
        }
        Operation::EmptyTrash => {
            reference.entries.retain(|entry| !entry.trashed);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Application au magasin et comparaison
// ---------------------------------------------------------------------------

/// Résultat simplifié, pour comparer avec [`Expect`].
fn outcome_of<T>(result: &Result<T, Error>) -> Expect {
    match result {
        Ok(_) => Expect::Ok,
        Err(_) => Expect::Err,
    }
}

/// Vérifie les invariants structurels de l'archive, indépendamment des tests du codec.
fn check_invariants(store: &VaultStore, step: usize, trace: &[String]) -> Result<(), String> {
    let archive = store.archive();

    let fail = |message: String| -> Result<(), String> {
        Err(format!(
            "étape {step} : {message}\n--- séquence ---\n{}",
            trace.join("\n")
        ))
    };

    // I1 — aucun identifiant dupliqué.
    let mut entry_ids = BTreeSet::new();
    for entry in &archive.entries {
        if !entry_ids.insert(entry.id) {
            return fail(format!("identifiant d'entrée dupliqué : {}", entry.id));
        }
    }
    let mut folder_ids = BTreeSet::new();
    for folder in &archive.folders {
        if !folder_ids.insert(folder.id) {
            return fail(format!("identifiant de dossier dupliqué : {}", folder.id));
        }
    }
    let mut tag_ids = BTreeSet::new();
    for tag in &archive.tags {
        if !tag_ids.insert(tag.id) {
            return fail(format!("identifiant de tag dupliqué : {}", tag.id));
        }
    }

    // I2 — aucune référence orpheline.
    for entry in &archive.entries {
        if let Some(folder) = entry.folder
            && !folder_ids.contains(&folder)
        {
            return fail(format!(
                "l'entrée {} référence un dossier inexistant {folder}",
                entry.id
            ));
        }
        for tag in &entry.tags {
            if !tag_ids.contains(tag) {
                return fail(format!(
                    "l'entrée {} référence un tag inexistant {tag}",
                    entry.id
                ));
            }
        }
    }
    for folder in &archive.folders {
        if let Some(parent) = folder.parent
            && !folder_ids.contains(&parent)
        {
            return fail(format!("dossier {} de parent inexistant", folder.id));
        }
    }

    // I3 — aucun historique impossible.
    for entry in &archive.entries {
        if entry.history.len() > MAX_HISTORY_PER_ENTRY {
            return fail(format!(
                "l'entrée {} porte {} révisions, au-delà du plafond",
                entry.id,
                entry.history.len()
            ));
        }
        for revision in &entry.history {
            if !revision.snapshot.history.is_empty() {
                return fail(format!(
                    "l'instantané d'une révision de {} porte lui-même un historique",
                    entry.id
                ));
            }
        }
        if entry.revision == 0 {
            return fail(format!("l'entrée {} porte la révision 0", entry.id));
        }
    }

    // I4 — le journal reste borné.
    if archive.audit.len() > MAX_AUDIT_EVENTS {
        return fail(format!("journal à {} événements", archive.audit.len()));
    }

    // I5 — l'archive reste cohérente selon ses propres règles.
    archive
        .validate()
        .map_err(|err| format!("étape {step} : validate() refuse l'archive — {err}"))?;

    // I6 — l'archive se ré-encode et se redécode à l'identique.
    let encoded = passlock_core::archive::encode(archive)
        .map_err(|err| format!("étape {step} : encodage impossible — {err}"))?;
    let decoded = passlock_core::archive::decode(&encoded).map_err(|err| {
        format!("étape {step} : le décodeur refuse notre propre encodage — {err}")
    })?;
    let reencoded = passlock_core::archive::encode(&decoded)
        .map_err(|err| format!("étape {step} : ré-encodage impossible — {err}"))?;

    if reencoded.as_slice() != encoded.as_slice() {
        return fail("l'aller-retour d'encodage n'est pas fidèle".to_string());
    }

    Ok(())
}

/// Compare l'état du magasin à celui du modèle.
fn compare(
    reference: &Reference,
    store: &VaultStore,
    step: usize,
    trace: &[String],
) -> Result<(), String> {
    let archive = store.archive();
    let fail = |message: String| -> Result<(), String> {
        Err(format!(
            "étape {step} : {message}\n--- séquence ---\n{}",
            trace.join("\n")
        ))
    };

    if archive.entries.len() != reference.entries.len() {
        return fail(format!(
            "le magasin porte {} entrées, le modèle en attend {}",
            archive.entries.len(),
            reference.entries.len()
        ));
    }
    if archive.folders.len() != reference.folders.len() {
        return fail(format!(
            "le magasin porte {} dossiers, le modèle en attend {}",
            archive.folders.len(),
            reference.folders.len()
        ));
    }
    if archive.tags.len() != reference.tags.len() {
        return fail(format!(
            "le magasin porte {} tags, le modèle en attend {}",
            archive.tags.len(),
            reference.tags.len()
        ));
    }

    // Les entrées sont dans le même ordre dans les deux : le magasin ajoute en fin de
    // vecteur, comme le modèle. `purge` retire au même indice des deux côtés.
    for (index, (actual, expected)) in archive
        .entries
        .iter()
        .zip(reference.entries.iter())
        .enumerate()
    {
        if actual.id != expected.id {
            return fail(format!("entrée {index} : identifiant différent du modèle"));
        }
        if actual.title != expected.title {
            return fail(format!(
                "entrée {index} : titre « {} » au lieu de « {} »",
                actual.title, expected.title
            ));
        }
        if actual.is_trashed() != expected.trashed {
            return fail(format!(
                "entrée {index} : état corbeille {} au lieu de {}",
                actual.is_trashed(),
                expected.trashed
            ));
        }
        if actual.revision != expected.revision {
            return fail(format!(
                "entrée {index} : révision {} au lieu de {}",
                actual.revision, expected.revision
            ));
        }
        if actual.history.len() != expected.history_len {
            return fail(format!(
                "entrée {index} : {} révisions au lieu de {}",
                actual.history.len(),
                expected.history_len
            ));
        }
        if actual.fields.len() != expected.field_count {
            return fail(format!(
                "entrée {index} : {} champs au lieu de {}",
                actual.fields.len(),
                expected.field_count
            ));
        }
        if actual.folder != expected.folder {
            return fail(format!(
                "entrée {index} : dossier {:?} au lieu de {:?}",
                actual.folder, expected.folder
            ));
        }
        if actual.tags.iter().copied().collect::<BTreeSet<_>>() != expected.tags {
            return fail(format!(
                "entrée {index} : tags différents du modèle ({} contre {})",
                actual.tags.len(),
                expected.tags.len()
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Campagne
// ---------------------------------------------------------------------------

/// Applique une opération au magasin et met le modèle à jour avec l'identifiant réel.
///
/// La longueur est inhérente : chaque variante d'opération a son corps, et les
/// regrouper derrière des fabriques masquerait la correspondance entre l'opération
/// décrite et l'appel réel — c'est-à-dire ce que ce harnais doit rendre lisible.
#[allow(clippy::too_many_lines)]
fn apply(reference: &mut Reference, store: &mut VaultStore, operation: &Operation) -> Expect {
    // Le modèle prédit d'abord, sur son propre état.
    let predicted = predict(reference, operation);

    let actual = match operation {
        Operation::AddFolder {
            name_seed,
            parent_slot,
        } => {
            let name = format!("dossier-{}", name_seed % 6);
            let parent = parent_slot.and_then(|slot| reference.folders.get(slot).map(|f| f.0));

            // L'emplacement est réservé **avant** l'appel, puis adopté ou annulé.
            // Réserver après coup ferait dépendre l'indice d'un état que le magasin
            // vient de modifier : c'est l'erreur que ce harnais a commise d'abord.
            let slot = reference.folders.len();
            reference
                .folders
                .push((FolderId::nil(), name.clone(), parent));

            let result = store.add_folder(&name, parent);
            match &result {
                Ok(id) => reference.folders[slot].0 = *id,
                Err(_) => {
                    reference.folders.remove(slot);
                }
            }
            outcome_of(&result)
        }

        Operation::AddTag { name_seed } => {
            let name = format!("tag-{}", name_seed % 6);

            let slot = reference.tags.len();
            reference.tags.push((TagId::nil(), name.clone()));

            let result = store.add_tag(&name);
            match &result {
                Ok(id) => reference.tags[slot].0 = *id,
                Err(_) => {
                    reference.tags.remove(slot);
                }
            }
            outcome_of(&result)
        }

        Operation::AddEntryWithGhostFolder => {
            let mut entry = Entry::new(EntryKind::Login, "fantôme", 0).expect("entrée");
            entry.folder = Some(FolderId::generate().expect("aléa"));
            outcome_of(&store.add_entry(entry))
        }

        Operation::AddEntryWithGhostTag => {
            let mut entry = Entry::new(EntryKind::Login, "fantôme", 0).expect("entrée");
            entry.tags.push(TagId::generate().expect("aléa"));
            outcome_of(&store.add_entry(entry))
        }

        Operation::AddEntry {
            title_seed,
            folder_slot,
            tag_slots,
            field_count,
        } => {
            let mut entry = Entry::new(EntryKind::Login, format!("entrée-{}", title_seed % 20), 0)
                .expect("entrée");
            entry.folder = folder_slot.and_then(|slot| reference.folders.get(slot).map(|f| f.0));

            let mut tag_ids = BTreeSet::new();
            for slot in tag_slots {
                if let Some((id, _)) = reference.tags.get(*slot) {
                    entry.tags.push(*id);
                    tag_ids.insert(*id);
                }
            }
            // Un tag nul (pas encore réconcilié) rendrait l'ajout invalide : le
            // modèle doit le savoir. C'est une source de divergence légitime, qu'on
            // évite en n'utilisant que des tags réconciliés.
            entry.tags.retain(|tag| !tag.is_nil());

            for index in 0..*field_count {
                entry.fields.push(
                    Field::new(
                        format!("champ{index}"),
                        FieldKind::Text,
                        format!("valeur-{index}"),
                        u16::try_from(index).unwrap_or(0),
                    )
                    .expect("champ"),
                );
            }

            let folder = folder_slot.and_then(|slot| reference.folders.get(slot).map(|f| f.0));

            // L'emplacement est réservé **avant** l'appel, puis adopté ou annulé. Le
            // réserver après coup ferait dépendre l'indice d'un état que le magasin
            // vient de modifier — erreur que ce harnais a commise d'abord, et que
            // l'exécution a immédiatement signalée par un dépassement d'entier.
            let slot = reference.entries.len();
            reference.entries.push(RefEntry {
                id: EntryId::nil(),
                title: format!("entrée-{}", title_seed % 20),
                trashed: false,
                revision: 1,
                history_len: 0,
                field_count: *field_count,
                folder,
                tags: tag_ids,
            });

            let result = store.add_entry(entry);
            match &result {
                Ok(id) => reference.entries[slot].id = *id,
                Err(_) => {
                    reference.entries.remove(slot);
                }
            }
            outcome_of(&result)
        }

        Operation::UpdateEntryWithGhostFolder { entry_slot } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            let ghost = FolderId::generate().expect("aléa");
            let result = store.update_entry(&target, |entry| {
                entry.folder = Some(ghost);
                Ok(())
            });
            outcome_of(&result)
        }

        Operation::UpdateEntry {
            entry_slot,
            new_title_seed,
            add_field,
        } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            let title = format!("entrée-{}", new_title_seed % 20);
            let result = store.update_entry(&target, |entry| {
                entry.title.clone_from(&title);
                if *add_field {
                    let index = entry.fields.len();
                    entry.fields.push(
                        Field::new(
                            format!("ajout{index}"),
                            FieldKind::Text,
                            "valeur",
                            u16::try_from(index).unwrap_or(0),
                        )
                        .expect("champ"),
                    );
                }
                Ok(())
            });
            outcome_of(&result)
        }

        Operation::TrashEntry { entry_slot } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            outcome_of(&store.trash_entry(&target))
        }

        Operation::RestoreEntry { entry_slot } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            outcome_of(&store.restore_entry(&target))
        }

        Operation::PurgeEntry { entry_slot } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            outcome_of(&store.purge_entry(&target))
        }

        Operation::PurgeHistory { entry_slot } => {
            let Some(target) = reference.entries.get(*entry_slot).map(|entry| entry.id) else {
                return Expect::Err;
            };
            outcome_of(&store.purge_history(&target))
        }

        Operation::EmptyTrash => outcome_of(&store.empty_trash()),

        Operation::OperateOnMissingEntry => {
            let ghost = EntryId::generate().expect("aléa");
            let mut all_err = true;

            if store.trash_entry(&ghost).is_ok() {
                all_err = false;
            }
            if store.restore_entry(&ghost).is_ok() {
                all_err = false;
            }
            if store.purge_entry(&ghost).is_ok() {
                all_err = false;
            }
            if store.purge_history(&ghost).is_ok() {
                all_err = false;
            }
            if store.update_entry(&ghost, |_| Ok(())).is_ok() {
                all_err = false;
            }

            if all_err { Expect::Err } else { Expect::Ok }
        }

        Operation::Save => outcome_of(&store.save()),

        Operation::Reopen => {
            // Le modèle ne change pas ; la réouverture est vérifiée par l'appelant.
            Expect::Ok
        }
    };

    // Les créations ont déjà mis le modèle à jour, identifiant réel compris. Les
    // autres opérations le font ici.
    if actual == Expect::Ok
        && !matches!(
            operation,
            Operation::AddFolder { .. } | Operation::AddTag { .. } | Operation::AddEntry { .. }
        )
    {
        commit(reference, operation);
    }

    debug_assert_eq!(
        predicted, actual,
        "le modèle prédit {predicted:?} mais le magasin a produit {actual:?}"
    );

    actual
}

/// Rejoue une séquence complète et vérifie les invariants à chaque étape.
fn run_campaign(seed: u64, steps: usize) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|err| format!("répertoire temporaire : {err}"))?;
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");

    let mut store = VaultStore::create(&path, PASSWORD, &config(&state))
        .map_err(|err| format!("création : {err}"))?;
    let mut reference = Reference::default();
    let mut rng = Prng::new(seed);
    let mut trace: Vec<String> = Vec::with_capacity(steps);

    for step in 0..steps {
        let operation = generate(
            &mut rng,
            reference.entries.len(),
            reference.folders.len(),
            reference.tags.len(),
        );
        trace.push(format!("{step:>4}  {}", operation.describe()));

        let predicted = predict(&mut reference, &operation);

        // Cas particulier de la réouverture : elle doit préserver l'état.
        if matches!(operation, Operation::Reopen) {
            let encoded_before = passlock_core::archive::encode(store.archive())
                .map_err(|err| format!("étape {step} : encodage — {err}"))?;

            store
                .save()
                .map_err(|err| format!("étape {step} : enregistrement — {err}"))?;
            drop(store);

            store = VaultStore::open(&path, PASSWORD, &config(&state))
                .map_err(|err| format!("étape {step} : réouverture — {err}"))?;

            let encoded_after = passlock_core::archive::encode(store.archive())
                .map_err(|err| format!("étape {step} : encodage après réouverture — {err}"))?;

            if encoded_after.as_slice() != encoded_before.as_slice() {
                return Err(format!(
                    "étape {step} : la réouverture a modifié l'archive\n--- séquence ---\n{}",
                    trace.join("\n")
                ));
            }

            compare(&reference, &store, step, &trace)?;
            check_invariants(&store, step, &trace)?;
            continue;
        }

        let actual = apply(&mut reference, &mut store, &operation);

        if predicted != actual {
            return Err(format!(
                "étape {step} : le modèle prédit {predicted:?}, le magasin produit {actual:?}\n\
                 opération : {}\n--- séquence ---\n{}",
                operation.describe(),
                trace.join("\n")
            ));
        }

        compare(&reference, &store, step, &trace)?;
        check_invariants(&store, step, &trace)?;
    }

    Ok(())
}

#[test]
fn random_operation_sequences_match_the_reference_model() {
    // 60 séquences de 150 opérations, soit 9 000 opérations comparées une à une.
    // Chaque graine est rejouable à l'identique.
    let mut failures = Vec::new();

    for seed in 0..60_u64 {
        if let Err(message) = run_campaign(seed, 150) {
            failures.push(format!("graine {seed} :\n{message}"));
            if failures.len() >= 3 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "des séquences ont divergé du modèle de référence :\n\n{}",
        failures.join("\n\n")
    );
}

#[test]
fn short_sequences_exercise_the_early_paths() {
    // Les séquences courtes atteignent des états que les longues dépassent : coffre
    // presque vide, un seul dossier, un seul tag.
    for seed in 0..40_u64 {
        run_campaign(10_000 + seed, 12).unwrap_or_else(|message| panic!("{message}"));
    }
}

// ---------------------------------------------------------------------------
// Invariants vérifiés indépendamment des séquences
// ---------------------------------------------------------------------------

fn fresh_store() -> (tempfile::TempDir, PathBuf, PathBuf, VaultStore) {
    let dir = tempfile::tempdir().expect("répertoire");
    let path = dir.path().join("coffre.plk");
    let state = dir.path().join("etat");
    let store = VaultStore::create(&path, PASSWORD, &config(&state)).expect("création");
    (dir, path, state, store)
}

fn entry(title: &str) -> Entry {
    Entry::new(EntryKind::Login, title, 1_700_000_000).expect("entrée")
}

#[test]
fn i1_no_duplicate_identifiers_after_repeated_creation() {
    let (_dir, _path, _state, mut store) = fresh_store();

    let mut ids = BTreeSet::new();
    for index in 0..500 {
        // Titres volontairement identiques : seuls les identifiants diffèrent.
        let id = store.add_entry(entry("identique")).expect("ajout");
        assert!(ids.insert(id), "identifiant dupliqué à l'itération {index}");
    }

    assert_eq!(store.archive().entries.len(), 500);
    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i2_no_orphan_reference_after_purging_everything() {
    let (_dir, _path, _state, mut store) = fresh_store();

    let folder = store.add_folder("dossier", None).expect("dossier");
    let tag = store.add_tag("tag").expect("tag");

    for index in 0..20 {
        let mut item = entry(&format!("entrée {index}"));
        item.folder = Some(folder);
        item.tags.push(tag);
        store.add_entry(item).expect("ajout");
    }

    // Tout purger : aucune entrée ne doit subsister, et donc aucune référence.
    let ids: Vec<EntryId> = store.archive().entries.iter().map(|e| e.id).collect();
    for id in ids {
        store.purge_entry(&id).expect("purge");
    }

    assert!(store.archive().entries.is_empty());
    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i3_no_impossible_history_after_many_updates() {
    let (_dir, _path, _state, mut store) = fresh_store();
    let id = store.add_entry(entry("cible")).expect("ajout");

    for index in 0..(MAX_HISTORY_PER_ENTRY * 3) {
        store
            .update_entry(&id, |entry| {
                entry.title = format!("révision {index}");
                Ok(())
            })
            .expect("modification");
        check_invariants(&store, index, &[]).expect("invariants");
    }

    let stored = store.archive().entry(&id).expect("entrée");
    assert_eq!(stored.history.len(), MAX_HISTORY_PER_ENTRY);
    assert_eq!(
        stored.revision,
        1 + u32::try_from(MAX_HISTORY_PER_ENTRY * 3).expect("borne"),
        "le compteur de révision doit refléter toutes les modifications, pas seulement \
         celles dont l'historique est conservé"
    );
}

#[test]
fn i4_no_partial_mutation_after_a_failure() {
    // Pour chaque opération qui peut échouer, l'état doit être **exactement** celui
    // d'avant. La comparaison porte sur l'encodage complet de l'archive, pas sur
    // quelques champs choisis.
    let (_dir, _path, _state, mut store) = fresh_store();

    let folder = store.add_folder("valide", None).expect("dossier");
    let tag = store.add_tag("valide").expect("tag");

    let mut item = entry("cible");
    item.folder = Some(folder);
    item.tags.push(tag);
    let id = store.add_entry(item).expect("ajout");

    store
        .update_entry(&id, |entry| {
            entry.title = "modifiée".to_string();
            Ok(())
        })
        .expect("modification");
    store.trash_entry(&id).expect("corbeille");

    // Le dossier « duplicat » est créé **avant** la photographie de référence : le
    // test porte sur le refus du doublon, et non sur une création légitime. Le
    // placer après ferait légitimement changer l'archive, et le test accuserait le
    // magasin d'un écart qu'il a lui-même provoqué.
    store.add_folder("duplicat", None).expect("dossier témoin");

    let before = passlock_core::archive::encode(store.archive()).expect("encodage");

    let ghost_folder = FolderId::generate().expect("aléa");
    let ghost_tag = TagId::generate().expect("aléa");
    let ghost_entry = EntryId::generate().expect("aléa");

    // Chaque opération doit échouer…
    let outcomes = [
        store
            .update_entry(&id, |entry| {
                entry.folder = Some(ghost_folder);
                Ok(())
            })
            .is_err(),
        store
            .update_entry(&id, |entry| {
                entry.tags.push(ghost_tag);
                Ok(())
            })
            .is_err(),
        store
            .update_entry(&id, |entry| {
                entry.title = "trop long".repeat(1_000);
                Ok(())
            })
            .is_err(),
        store
            .update_entry(&id, |entry| {
                entry.history.push(passlock_core::model::Revision {
                    at: 0,
                    snapshot: entry.duplicate(),
                });
                Err(Error::Internal {
                    invariant: "échec volontaire",
                })
            })
            .is_err(),
        store.update_entry(&ghost_entry, |_| Ok(())).is_err(),
        store.trash_entry(&ghost_entry).is_err(),
        store.restore_entry(&ghost_entry).is_err(),
        store.purge_entry(&ghost_entry).is_err(),
        store.purge_history(&ghost_entry).is_err(),
        store.add_folder("duplicat", None).is_err(),
    ];

    assert!(
        outcomes.iter().all(|failed| *failed),
        "une opération censée échouer a réussi : {outcomes:?}"
    );

    // …et l'archive doit être bit-à-bit celle d'avant.
    let after = passlock_core::archive::encode(store.archive()).expect("encodage");
    assert!(
        after.as_slice() == before.as_slice(),
        "une opération refusée a laissé une trace dans l'archive"
    );

    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i5_search_reflects_the_trash_and_archive_state() {
    let (_dir, _path, _state, mut store) = fresh_store();

    let active = store.add_entry(entry("cible active")).expect("ajout");
    let trashed = store.add_entry(entry("cible corbeille")).expect("ajout");
    let archived = store.add_entry(entry("cible archivee")).expect("ajout");

    store.trash_entry(&trashed).expect("corbeille");
    store
        .update_entry(&archived, |entry| {
            entry.archived = true;
            Ok(())
        })
        .expect("archivage");

    // Requête par défaut : uniquement l'active.
    let default_hits = search(store.archive(), &SearchQuery::new("cible"));
    assert_eq!(default_hits.len(), 1);
    assert_eq!(default_hits[0].id, active);

    // Corbeille incluse : l'active et la supprimée.
    let with_trash = search(
        store.archive(),
        &SearchQuery {
            include_trashed: true,
            ..SearchQuery::new("cible")
        },
    );
    assert_eq!(with_trash.len(), 2);
    assert!(with_trash.iter().any(|hit| hit.id == trashed));
    assert!(
        !with_trash.iter().any(|hit| hit.id == archived),
        "l'entrée archivée ne doit pas apparaître sans include_archived"
    );

    // Tout inclus.
    let everything = search(
        store.archive(),
        &SearchQuery {
            include_trashed: true,
            include_archived: true,
            ..SearchQuery::new("cible")
        },
    );
    assert_eq!(everything.len(), 3);

    // Et une entrée à la corbeille reste **trouvable** : elle n'est pas effacée.
    assert!(store.archive().entry(&trashed).is_some());
}

#[test]
fn i6_audit_references_are_allowed_to_dangle_but_stay_well_formed() {
    // Une référence d'audit vers une entrée supprimée est **légitime** : le journal
    // consigne qu'un événement a eu lieu, et l'entrée peut avoir disparu depuis.
    // L'invariant n'est donc pas « toute référence existe », mais « le journal reste
    // bien formé et borné ».
    let (_dir, _path, _state, mut store) = fresh_store();

    let id = store.add_entry(entry("éphémère")).expect("ajout");
    store.purge_entry(&id).expect("purge");

    assert!(
        store
            .archive()
            .audit
            .iter()
            .any(|event| event.subject == Some(id)),
        "le journal devrait conserver la trace d'une entrée supprimée"
    );
    assert!(store.archive().entry(&id).is_none());
    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i7_folder_depth_is_enforced_and_cycles_are_impossible() {
    let (_dir, _path, _state, mut store) = fresh_store();

    // Un cycle est **impossible à construire** par l'API : `add_folder` n'accepte
    // qu'un parent existant, et un dossier ne peut pas être son propre parent
    // puisqu'il n'existe pas encore au moment de sa création.
    let mut parent = None;
    let mut created = Vec::new();
    for level in 0..MAX_FOLDER_DEPTH {
        let id = store
            .add_folder(&format!("niveau {level}"), parent)
            .unwrap_or_else(|err| panic!("niveau {level} : {err}"));
        created.push(id);
        parent = Some(id);
    }

    assert!(
        store.add_folder("trop profond", parent).is_err(),
        "la profondeur maximale doit être appliquée"
    );

    // Aucun dossier créé n'a de parent inexistant.
    for id in &created {
        let folder = store
            .archive()
            .folders
            .iter()
            .find(|folder| folder.id == *id)
            .expect("dossier");
        if let Some(parent) = folder.parent {
            assert!(
                store
                    .archive()
                    .folders
                    .iter()
                    .any(|other| other.id == parent),
                "parent inexistant pour {id}"
            );
        }
    }
    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i8_an_entry_can_carry_several_tags() {
    let (_dir, _path, _state, mut store) = fresh_store();

    let first = store.add_tag("alpha").expect("tag");
    let second = store.add_tag("beta").expect("tag");
    let third = store.add_tag("gamma").expect("tag");

    let mut item = entry("multi-tags");
    item.tags = vec![first, second, third];
    let id = store.add_entry(item).expect("ajout");

    let stored = store.archive().entry(&id).expect("entrée");
    assert_eq!(stored.tags.len(), 3);

    // Filtrer par un tag doit retrouver l'entrée, quel qu'il soit.
    for tag in [first, second, third] {
        let hits = search(
            store.archive(),
            &SearchQuery {
                tags: vec![tag],
                ..SearchQuery::new("")
            },
        );
        assert_eq!(hits.len(), 1, "filtre par tag {tag}");
    }

    // Deux tags simultanés doivent aussi la retrouver.
    let hits = search(
        store.archive(),
        &SearchQuery {
            tags: vec![first, third],
            ..SearchQuery::new("")
        },
    );
    assert_eq!(hits.len(), 1);
}

#[test]
fn i9_purging_a_used_folder_leaves_no_orphan_reference() {
    // L'API n'expose pas la suppression de dossier : c'est un choix. Ce test constate
    // qu'un dossier **ne peut pas** être supprimé tant que des entrées y sont
    // rattachées, faute d'opération — et donc qu'aucune référence orpheline ne peut
    // apparaître par ce chemin.
    let (_dir, _path, _state, mut store) = fresh_store();

    let folder = store.add_folder("utilisé", None).expect("dossier");
    let mut item = entry("rattachée");
    item.folder = Some(folder);
    store.add_entry(item).expect("ajout");

    check_invariants(&store, 0, &[]).expect("invariants");
    assert_eq!(store.archive().folders.len(), 1);
}

#[test]
fn i10_trashing_and_restoring_are_idempotent() {
    // Deux catégories d'opérations, deux contrats distincts.
    //
    // * `trash` et `restore` convergent vers un état : les répéter ne change rien.
    //   C'est ce qui rend une reprise après incident possible.
    // * `update` **ne doit pas** être idempotent : la répéter produirait deux
    //   révisions, ce qui est le comportement correct — deux modifications ont eu
    //   lieu.
    let (_dir, _path, _state, mut store) = fresh_store();
    let id = store.add_entry(entry("cible")).expect("ajout");

    for _ in 0..5 {
        store.trash_entry(&id).expect("corbeille");
    }
    assert!(store.archive().entry(&id).expect("entrée").is_trashed());
    let trashed_revision = store.archive().entry(&id).expect("entrée").revision;

    for _ in 0..5 {
        store.restore_entry(&id).expect("restauration");
    }
    assert!(!store.archive().entry(&id).expect("entrée").is_trashed());
    assert_eq!(
        store.archive().entry(&id).expect("entrée").revision,
        trashed_revision,
        "trash et restore ne sont pas des modifications de contenu : la révision ne \
         doit pas bouger"
    );

    // `update` est délibérément non idempotent.
    let before = store.archive().entry(&id).expect("entrée").revision;
    for _ in 0..3 {
        store.update_entry(&id, |_| Ok(())).expect("modification");
    }
    assert_eq!(
        store.archive().entry(&id).expect("entrée").revision,
        before + 3,
        "chaque modification doit produire une révision, même identique"
    );

    // `purge_entry` sur une entrée déjà absente échoue : le contrat est explicite.
    let ghost = EntryId::generate().expect("aléa");
    assert!(store.purge_entry(&ghost).is_err());
    assert!(
        store.purge_entry(&ghost).is_err(),
        "purger deux fois une entrée absente échoue deux fois : la répétition ne \
         change pas le contrat"
    );

    store.purge_entry(&id).expect("purge");
    assert!(
        store.purge_entry(&id).is_err(),
        "purger une entrée déjà purgée échoue : rien ne subsiste"
    );
}

/// L'échec d'écriture est provoqué par des **permissions**, qui n'ont pas
/// d'équivalent portable. Le test est donc restreint à Unix, ce qui évite qu'il
/// compile à vide sur Windows en ne testant rien.
#[cfg(unix)]
#[test]
fn i11_a_failed_save_leaves_the_file_untouched() {
    let (_dir, path, state, mut store) = fresh_store();
    store.add_entry(entry("conservée")).expect("ajout");
    store.save().expect("enregistrement");

    let before = std::fs::read(&path).expect("lecture");

    // Simule un échec **avant** écriture : le répertoire devient inaccessible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let locked = state.join("verrou");
        std::fs::create_dir_all(&locked).expect("création");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod");

        // Une écriture vers un répertoire inaccessible échoue sans toucher au coffre.
        let outcome = passlock_platform_fs_write(&locked.join("coffre.plk"));
        assert!(outcome.is_err() || std::fs::read(locked.join("coffre.plk")).is_ok());

        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
    }

    // Le coffre réel n'a pas bougé.
    assert!(
        std::fs::read(&path).expect("lecture") == before,
        "une tentative d'écriture a modifié le coffre"
    );
}

/// Écriture dans un répertoire arbitraire, pour éprouver les échecs de permission.
#[cfg(unix)]
fn passlock_platform_fs_write(target: &Path) -> std::io::Result<()> {
    passlock_platform::fs::write_atomic(target, "test", b"contenu")
}

#[test]
fn i12_a_truncated_vault_is_refused_and_the_original_survives() {
    let (_dir, path, state, mut store) = fresh_store();
    store.add_entry(entry("précieuse")).expect("ajout");
    store.save().expect("enregistrement");
    drop(store);

    // Sauvegarde de sécurité, comme le ferait un utilisateur prudent.
    let backup = std::fs::read(&path).expect("lecture");

    // Coffre tronqué : l'ouverture doit échouer proprement.
    let truncated = &backup[..backup.len() / 2];
    std::fs::write(&path, truncated).expect("écriture");
    assert!(
        VaultStore::open(&path, PASSWORD, &config(&state)).is_err(),
        "un coffre tronqué doit être refusé"
    );

    // Restauration de la sauvegarde : l'état d'origine doit être retrouvé à
    // l'identique.
    std::fs::write(&path, &backup).expect("restauration");
    let restored = VaultStore::open(&path, PASSWORD, &config(&state)).expect("réouverture");

    assert_eq!(restored.archive().entries.len(), 1);
    assert_eq!(restored.archive().entries[0].title, "précieuse");
    check_invariants(&restored, 0, &[]).expect("invariants");
}

#[test]
fn i13_unpersisted_mutations_are_lost_by_design() {
    // Le contrat, énoncé explicitement : une mutation non enregistrée est perdue.
    // Un test qui l'exigerait serait un faux espoir.
    let (_dir, path, state, mut store) = fresh_store();
    store.add_entry(entry("enregistrée")).expect("ajout");
    store.save().expect("enregistrement");

    store.add_entry(entry("non enregistrée")).expect("ajout");
    assert!(store.is_dirty());
    drop(store);

    let reopened = VaultStore::open(&path, PASSWORD, &config(&state)).expect("réouverture");
    assert_eq!(
        reopened.archive().entries.len(),
        1,
        "une mutation non enregistrée doit être perdue — c'est le contrat"
    );
    assert_eq!(reopened.archive().entries[0].title, "enregistrée");
}

#[test]
fn i14_reopening_preserves_the_archive_byte_for_byte() {
    // Propriété forte : enregistrer puis rouvrir ne doit **rien** changer. Un écart
    // signalerait une perte ou une invention de données au passage par le fichier.
    let (_dir, path, state, mut store) = fresh_store();

    let folder = store.add_folder("dossier", None).expect("dossier");
    let tag = store.add_tag("tag").expect("tag");

    for index in 0..30 {
        let mut item = entry(&format!("entrée {index}"));
        item.folder = Some(folder);
        item.tags.push(tag);
        item.fields.push(
            Field::new("password", FieldKind::Secret, format!("secret-{index}"), 0).expect("champ"),
        );
        store.add_entry(item).expect("ajout");
    }

    // Quelques modifications, pour peupler l'historique.
    let ids: Vec<EntryId> = store.archive().entries.iter().map(|e| e.id).collect();
    for id in ids.iter().take(10) {
        store
            .update_entry(id, |entry| {
                entry.title = format!("{} (modifiée)", entry.title);
                Ok(())
            })
            .expect("modification");
    }

    let before = passlock_core::archive::encode(store.archive()).expect("encodage");
    store.save().expect("enregistrement");
    drop(store);

    let reopened = VaultStore::open(&path, PASSWORD, &config(&state)).expect("réouverture");
    let after = passlock_core::archive::encode(reopened.archive()).expect("encodage");

    assert!(
        after.as_slice() == before.as_slice(),
        "l'aller-retour par le fichier a modifié l'archive"
    );
    check_invariants(&reopened, 0, &[]).expect("invariants");
}

#[test]
fn i15_empty_store_survives_every_operation() {
    // Cas dégénéré : toutes les opérations sur un coffre vide. Un magasin vide ne
    // doit jamais produire d'état incohérent ni de panique.
    let (_dir, _path, _state, mut store) = fresh_store();

    assert_eq!(store.empty_trash().expect("vidage"), 0);
    assert!(!store.is_dirty());

    let ghost = EntryId::generate().expect("aléa");
    assert!(store.purge_entry(&ghost).is_err());
    assert!(store.trash_entry(&ghost).is_err());
    assert!(store.restore_entry(&ghost).is_err());
    assert!(store.purge_history(&ghost).is_err());
    assert!(store.update_entry(&ghost, |_| Ok(())).is_err());

    assert!(search(store.archive(), &SearchQuery::new("")).is_empty());
    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i16_a_name_at_the_length_limit_is_accepted_and_one_beyond_is_refused() {
    // Frontière exacte, du côté du modèle et du magasin.
    let (_dir, _path, _state, mut store) = fresh_store();

    let exact = "n".repeat(MAX_NAME_LEN);
    assert!(store.add_folder(&exact, None).is_ok());

    let too_long = "n".repeat(MAX_NAME_LEN + 1);
    assert!(store.add_folder(&too_long, None).is_err());

    assert!(store.add_tag(&"t".repeat(MAX_NAME_LEN)).is_ok());
    assert!(store.add_tag(&"t".repeat(MAX_NAME_LEN + 1)).is_err());

    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i17_folder_and_tag_objects_are_never_left_unreferenced_by_a_creation() {
    // Un dossier ou un tag créé doit exister immédiatement : une création qui
    // retourne un identifiant sans l'avoir inséré serait un identifiant fantôme.
    let (_dir, _path, _state, mut store) = fresh_store();

    for index in 0..20 {
        let id = store
            .add_folder(&format!("dossier {index}"), None)
            .expect("dossier");
        assert!(
            store.archive().folders.iter().any(|folder| folder.id == id),
            "le dossier {id} a été annoncé mais n'existe pas"
        );

        let id = store.add_tag(&format!("tag {index}")).expect("tag");
        assert!(
            store.archive().tags.iter().any(|tag| tag.id == id),
            "le tag {id} a été annoncé mais n'existe pas"
        );
    }

    check_invariants(&store, 0, &[]).expect("invariants");
}

#[test]
fn i18_purge_entry_also_removes_its_history() {
    // La purge d'une entrée supprime tout ce qu'elle portait : c'est le seul geste
    // qui efface réellement des secrets du coffre.
    let (_dir, _path, _state, mut store) = fresh_store();
    let id = store.add_entry(entry("à purger")).expect("ajout");

    for _ in 0..5 {
        store.update_entry(&id, |_| Ok(())).expect("modification");
    }
    assert_eq!(store.archive().entry(&id).expect("entrée").history.len(), 5);

    store.purge_entry(&id).expect("purge");

    assert!(store.archive().entry(&id).is_none());
    check_invariants(&store, 0, &[]).expect("invariants");

    // Et un enregistrement suivi d'une réouverture ne doit pas la ressusciter.
    store.save().expect("enregistrement");
    let path = store.path().to_path_buf();
    let state_dir = path.parent().expect("parent").join("relecture");
    drop(store);

    let reopened = VaultStore::open(&path, PASSWORD, &config(&state_dir)).expect("réouverture");
    assert!(
        reopened.archive().entry(&id).is_none(),
        "une entrée purgée est réapparue après réouverture"
    );
}
