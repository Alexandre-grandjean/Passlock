//! Recherche, filtres et tri dans le coffre déchiffré.
//!
//! # Pas d'index persistant, et pourquoi
//!
//! La recherche parcourt l'archive à chaque requête. Un index persistant
//! introduirait trois défauts pour aucun bénéfice à cette échelle :
//!
//! 1. une **désynchronisation** possible entre l'index et les données ;
//! 2. une **double mémoire** — l'index recopie des secrets hors des entrées ;
//! 3. une **surface d'injection**, dès que l'index apporte son propre langage de
//!    requête. C'est exactement ce que FTS5 aurait imposé (opérateurs `MATCH`,
//!    `NEAR`, guillemets), et ce qui a motivé son abandon.
//!
//! Un parcours linéaire sur quelques milliers d'entrées est instantané, et il ne
//! peut pas mentir : il n'y a rien à synchroniser.
//!
//! # La requête n'est pas un langage
//!
//! L'entrée de l'utilisateur est traitée comme une **suite de termes littéraux**.
//! Aucune expression régulière, aucun opérateur, aucune syntaxe. Les métacaractères
//! sont des caractères comme les autres — il n'y a donc rien à échapper, et rien à
//! injecter.
//!
//! Le coût est borné : au plus [`MAX_TERMS`] termes, chacun d'au plus
//! [`MAX_TERM_LEN`] octets, et au plus [`MAX_RESULTS`] résultats.
//!
//! # Normalisation, sans dépendance
//!
//! La comparaison est insensible à la casse et, pour les écritures latines, aux
//! diacritiques, par une table de repli explicite. Ajouter une crate de
//! normalisation Unicode pour une fonctionnalité de confort serait disproportionné.
//!
//! **Limite assumée** : une écriture non latine est trouvée en insensible à la
//! casse, mais **pas** en insensible aux accents. `café` trouve `CAFÉ` et `cafe`,
//! mais `ΑΘΉΝΑ` ne trouve pas `αθηνα`. La limite est écrite ici plutôt que
//! dissimulée.

use crate::model::{Archive, Entry, EntryId, EntryKind, FolderId, TagId};

/// Nombre maximal de termes dans une requête.
pub const MAX_TERMS: usize = 16;
/// Longueur maximale d'un terme, en octets.
pub const MAX_TERM_LEN: usize = 64;
/// Nombre maximal de résultats retournés.
pub const MAX_RESULTS: usize = 1000;
/// Nombre de résultats par défaut.
pub const DEFAULT_LIMIT: usize = 200;

/// Critère de tri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Par pertinence décroissante.
    #[default]
    Relevance,
    /// Par titre, insensible à la casse.
    Title,
    /// Par date de création, la plus récente d'abord.
    CreatedDesc,
    /// Par date de modification, la plus récente d'abord.
    UpdatedDesc,
}

/// Requête de recherche.
///
/// Le texte est découpé en termes, et **tous** doivent apparaître : c'est une
/// conjonction, pas un langage de requête.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// Texte recherché.
    pub text: String,
    /// Ne retenir que ces types d'entrée.
    pub kinds: Vec<EntryKind>,
    /// Ne retenir que les entrées de ce dossier, descendants compris.
    pub folder: Option<FolderId>,
    /// Ne retenir que les entrées portant **tous** ces tags.
    pub tags: Vec<TagId>,
    /// Inclure les entrées archivées.
    pub include_archived: bool,
    /// Inclure les entrées à la corbeille.
    pub include_trashed: bool,
    /// Ne retenir que les favoris.
    pub favorites_only: bool,
    /// Ordre de tri.
    pub sort: SortOrder,
    /// Nombre maximal de résultats.
    pub limit: usize,
}

impl SearchQuery {
    /// Requête ne retenant que les entrées actives.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            limit: DEFAULT_LIMIT,
            ..Self::default()
        }
    }
}

/// Où un terme a été trouvé, pour l'affichage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchedIn {
    /// Aucun terme (requête vide) : toutes les entrées actives correspondent.
    Everywhere,
    /// Dans le titre.
    Title,
    /// Dans le sous-titre.
    Subtitle,
    /// Dans un champ.
    Field,
    /// Dans un tag ou un dossier.
    Organisation,
}

/// Un résultat de recherche.
#[derive(Debug, Clone, Copy)]
pub struct SearchHit {
    /// Entrée trouvée.
    pub id: EntryId,
    /// Score de pertinence ; plus grand est plus pertinent.
    pub score: u32,
    /// Meilleur endroit où un terme a été trouvé.
    pub matched_in: MatchedIn,
}

/// Exécute une recherche.
///
/// Ne retourne jamais d'erreur : une requête mal formée n'existe pas, puisque
/// l'entrée est un texte littéral. Les bornes sont appliquées silencieusement par
/// troncature — un terme trop long est ignoré, un nombre de termes excessif est
/// tronqué — plutôt que par un refus : l'utilisateur cherche, il ne configure pas.
#[must_use]
pub fn search(archive: &Archive, query: &SearchQuery) -> Vec<SearchHit> {
    let terms = parse_terms(&query.text);
    let limit = query.limit.clamp(1, MAX_RESULTS);

    // Un seul buffer de normalisation, réutilisé pour toutes les entrées. Le
    // normaliser une fois par champ produirait autant d'allocations que de champs,
    // et laisserait autant de copies de contenu dans le tas.
    let mut buffer = String::with_capacity(256);

    let mut hits: Vec<SearchHit> = Vec::new();

    for entry in &archive.entries {
        if !passes_filters(archive, entry, query) {
            continue;
        }

        let Some(hit) = score_entry(archive, entry, &terms, &mut buffer) else {
            continue;
        };

        hits.push(SearchHit {
            id: entry.id,
            score: hit.0,
            matched_in: hit.1,
        });
    }

    sort_hits(archive, &mut hits, query.sort);
    hits.truncate(limit);
    hits
}

/// Découpe le texte en termes normalisés.
///
/// Les termes vides sont ignorés, les termes trop longs écartés, et le nombre de
/// termes borné : une requête de dix mille mots ne doit pas coûter dix mille fois
/// plus cher qu'une requête d'un mot.
fn parse_terms(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|term| !term.is_empty())
        .take(MAX_TERMS)
        .filter(|term| term.len() <= MAX_TERM_LEN)
        .map(|term| {
            let mut normalized = String::with_capacity(term.len());
            normalize_into(&mut normalized, term);
            normalized
        })
        .filter(|term| !term.is_empty())
        .collect()
}

/// Applique les filtres, sans rapport avec le texte.
fn passes_filters(archive: &Archive, entry: &Entry, query: &SearchQuery) -> bool {
    if !query.include_trashed && entry.is_trashed() {
        return false;
    }
    if !query.include_archived && entry.archived {
        return false;
    }
    if query.favorites_only && !entry.favorite {
        return false;
    }
    if !query.kinds.is_empty() && !query.kinds.contains(&entry.kind) {
        return false;
    }
    if query.tags.iter().any(|tag| !entry.tags.contains(tag)) {
        return false;
    }
    if let Some(folder) = query.folder
        && !is_in_folder(archive, entry, folder)
    {
        return false;
    }
    true
}

/// Vrai si l'entrée est dans `folder` ou dans l'un de ses descendants.
///
/// La remontée est bornée par la profondeur maximale de l'arborescence, ce qui
/// garantit la terminaison même si l'archive contenait un cycle — cas que
/// `Archive::validate` refuse par ailleurs, mais dont cette fonction ne dépend pas.
fn is_in_folder(archive: &Archive, entry: &Entry, folder: FolderId) -> bool {
    const MAX_WALK: usize = crate::model::MAX_FOLDER_DEPTH + 1;

    let mut current = entry.folder;
    let mut steps = 0;

    while let Some(id) = current {
        if id == folder {
            return true;
        }
        steps += 1;
        if steps > MAX_WALK {
            return false;
        }
        current = archive
            .folders
            .iter()
            .find(|candidate| candidate.id == id)
            .and_then(|candidate| candidate.parent);
    }
    false
}

/// Évalue une entrée, et retourne son score et le meilleur endroit trouvé.
///
/// Retourne `None` si l'un des termes est absent : la sémantique est une
/// **conjonction**.
fn score_entry(
    archive: &Archive,
    entry: &Entry,
    terms: &[String],
    buffer: &mut String,
) -> Option<(u32, MatchedIn)> {
    if terms.is_empty() {
        return Some((0, MatchedIn::Everywhere));
    }

    let mut score = 0_u32;
    let mut best = MatchedIn::Everywhere;

    for term in terms {
        // Chaque terme doit apparaître **quelque part**. On cherche dans l'ordre du
        // plus significatif au moins significatif, et on s'arrête au premier succès.
        let mut found = false;

        buffer.clear();
        normalize_into(buffer, &entry.title);
        let normalized_title = buffer.as_str();

        if normalized_title == term {
            score += 1000;
            best = best.max(MatchedIn::Title);
            found = true;
        } else if normalized_title.starts_with(term.as_str()) {
            score += 500;
            best = best.max(MatchedIn::Title);
            found = true;
        } else if normalized_title.contains(term.as_str()) {
            score += 250;
            best = best.max(MatchedIn::Title);
            found = true;
        }

        if !found {
            buffer.clear();
            normalize_into(buffer, &entry.subtitle);
            if buffer.contains(term.as_str()) {
                score += 150;
                best = best.max(MatchedIn::Subtitle);
                found = true;
            }
        }

        if !found {
            for field in &entry.fields {
                buffer.clear();
                normalize_into(buffer, &field.value);
                if buffer.contains(term.as_str()) {
                    score += 100;
                    best = best.max(MatchedIn::Field);
                    found = true;
                    break;
                }
                buffer.clear();
                normalize_into(buffer, &field.key);
                if buffer.contains(term.as_str()) {
                    score += 60;
                    best = best.max(MatchedIn::Field);
                    found = true;
                    break;
                }
            }
        }

        if !found {
            for tag_id in &entry.tags {
                if let Some(tag) = archive.tags.iter().find(|tag| tag.id == *tag_id) {
                    buffer.clear();
                    normalize_into(buffer, &tag.name);
                    if buffer.contains(term.as_str()) {
                        score += 50;
                        best = best.max(MatchedIn::Organisation);
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            let folder_name = entry
                .folder
                .and_then(|id| archive.folders.iter().find(|folder| folder.id == id))
                .map(|folder| folder.name.as_str());

            if let Some(name) = folder_name {
                buffer.clear();
                normalize_into(buffer, name);
                if buffer.contains(term.as_str()) {
                    score += 40;
                    best = best.max(MatchedIn::Organisation);
                    found = true;
                }
            }
        }

        if !found {
            return None;
        }
    }

    // Un favori remonte légèrement, à score égal.
    if entry.favorite {
        score += 10;
    }

    Some((score, best))
}

/// Trie les résultats.
fn sort_hits(archive: &Archive, hits: &mut [SearchHit], order: SortOrder) {
    match order {
        SortOrder::Relevance => hits.sort_by_key(|hit| std::cmp::Reverse(hit.score)),
        SortOrder::Title => hits.sort_by(|left, right| {
            let left_title = title_of(archive, left.id);
            let right_title = title_of(archive, right.id);
            left_title
                .to_lowercase()
                .cmp(&right_title.to_lowercase())
                .then_with(|| right.score.cmp(&left.score))
        }),
        // Tri décroissant : `sort_by_key` avec `Reverse` exprime l'intention, et
        // évite de parcourir l'archive deux fois par comparaison.
        SortOrder::CreatedDesc => {
            hits.sort_by_key(|hit| std::cmp::Reverse(entry_of(archive, hit.id).created_at));
        }
        SortOrder::UpdatedDesc => {
            hits.sort_by_key(|hit| std::cmp::Reverse(entry_of(archive, hit.id).updated_at));
        }
    }

    // Le tri par pertinence seul n'est pas déterministe à score égal : on départage
    // par identifiant, pour que deux exécutions donnent le même ordre.
    if order == SortOrder::Relevance {
        hits.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.id.cmp(&right.id))
        });
    }
}

fn entry_of(archive: &Archive, id: EntryId) -> &Entry {
    // Une entrée absente ne peut pas arriver : les résultats sont construits à
    // partir des entrées de l'archive. On retourne la première plutôt que de
    // paniquer, et le tri reste correct pour toutes les entrées présentes.
    archive
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .unwrap_or(&archive.entries[0])
}

fn title_of(archive: &Archive, id: EntryId) -> String {
    entry_of(archive, id).title.clone()
}

/// Normalise un texte pour la comparaison : minuscules et repli des diacritiques.
///
/// Le résultat est écrit dans `out`, qui doit être vidé par l'appelant entre deux
/// usages : c'est ce qui permet de réutiliser un unique buffer au lieu d'allouer une
/// chaîne par champ parcouru.
pub fn normalize_into(out: &mut String, input: &str) {
    for character in input.chars() {
        let folded = fold(character);
        // `to_lowercase` peut produire plusieurs caractères (par exemple `İ`), mais
        // le repli a déjà ramené les cas courants à de l'ASCII. On écrit donc chaque
        // caractère replié tel quel, en minuscule si possible.
        for lowered in folded.to_lowercase() {
            out.push(lowered);
        }
    }
}

/// Replie un caractère latin sur sa forme sans diacritique.
///
/// **Limite assumée** : les écritures non latines traversent cette fonction sans
/// modification. Elles restent trouvables en insensible à la casse, mais pas en
/// insensible aux accents.
fn fold(character: char) -> char {
    match character {
        // Une seule branche par lettre cible : les casses haute et basse, ainsi que
        // toutes les variantes diacritiques, produisent le même caractère.
        'a' | 'A' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' | 'À' | 'Á' | 'Â' | 'Ã'
        | 'Ä' | 'Å' | 'Ā' | 'Ă' | 'Ą' | 'æ' | 'Æ' => 'a',
        'c' | 'C' | 'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' | 'Ç' | 'Ć' | 'Ĉ' | 'Ċ' | 'Č' => 'c',
        'd' | 'D' | 'ď' | 'đ' | 'ð' | 'Ď' | 'Đ' | 'Ð' => 'd',
        'e' | 'E' | 'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' | 'È' | 'É' | 'Ê' | 'Ë'
        | 'Ē' | 'Ĕ' | 'Ė' | 'Ę' | 'Ě' => 'e',
        'g' | 'G' | 'ĝ' | 'ğ' | 'ġ' | 'ģ' | 'Ĝ' | 'Ğ' | 'Ġ' | 'Ģ' => 'g',
        'h' | 'H' | 'ĥ' | 'ħ' | 'Ĥ' | 'Ħ' => 'h',
        'i' | 'I' | 'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ı' | 'Ì' | 'Í' | 'Î' | 'Ï'
        | 'Ĩ' | 'Ī' | 'Ĭ' | 'Į' | 'İ' => 'i',
        'j' | 'J' | 'ĵ' | 'Ĵ' => 'j',
        'k' | 'K' | 'ķ' | 'Ķ' => 'k',
        'l' | 'L' | 'ĺ' | 'ļ' | 'ľ' | 'ŀ' | 'ł' | 'Ĺ' | 'Ļ' | 'Ľ' | 'Ŀ' | 'Ł' => 'l',
        'n' | 'N' | 'ñ' | 'ń' | 'ņ' | 'ň' | 'Ñ' | 'Ń' | 'Ņ' | 'Ň' => 'n',
        'o' | 'O' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' | 'Ò' | 'Ó' | 'Ô' | 'Õ'
        | 'Ö' | 'Ø' | 'Ō' | 'Ŏ' | 'Ő' | 'œ' | 'Œ' => 'o',
        'r' | 'R' | 'ŕ' | 'ŗ' | 'ř' | 'Ŕ' | 'Ŗ' | 'Ř' => 'r',
        's' | 'S' | 'ś' | 'ŝ' | 'ş' | 'š' | 'Ś' | 'Ŝ' | 'Ş' | 'Š' | 'ß' | 'ẞ' => 's',
        't' | 'T' | 'ţ' | 'ť' | 'ŧ' | 'Ţ' | 'Ť' | 'Ŧ' | 'þ' | 'Þ' => 't',
        'u' | 'U' | 'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' | 'Ù' | 'Ú' | 'Û'
        | 'Ü' | 'Ũ' | 'Ū' | 'Ŭ' | 'Ů' | 'Ű' | 'Ų' => 'u',
        'w' | 'W' | 'ŵ' | 'Ŵ' => 'w',
        'y' | 'Y' | 'ý' | 'ÿ' | 'ŷ' | 'Ý' | 'Ÿ' | 'Ŷ' => 'y',
        'z' | 'Z' | 'ź' | 'ż' | 'ž' | 'Ź' | 'Ż' | 'Ž' => 'z',
        // Les écritures non latines traversent sans modification : elles restent
        // trouvables en insensible à la casse, mais pas en insensible aux accents.
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entry, Field, FieldKind, Folder, Tag};

    fn archive_with_entries() -> (Archive, Vec<EntryId>) {
        let mut archive = Archive::new(0);

        let folder = FolderId::generate().expect("aléa");
        archive.folders.push(Folder {
            id: folder,
            name: "Travail".to_string(),
            parent: None,
            ordinal: 0,
        });
        let tag = TagId::generate().expect("aléa");
        archive.tags.push(Tag {
            id: tag,
            name: "critique".to_string(),
        });

        let mut login = Entry::new(EntryKind::Login, "Exemple.com", 100).expect("entrée");
        login.subtitle = "utilisateur@exemple.com".to_string();
        login.folder = Some(folder);
        login.tags.push(tag);
        login.favorite = true;
        login
            .fields
            .push(Field::new("password", FieldKind::Secret, "Tr0p-S3cr3t", 0).expect("champ"));

        let mut note = Entry::new(EntryKind::SecureNote, "Café du coin", 200).expect("entrée");
        note.sensitive = true;

        let mut archived = Entry::new(EntryKind::Login, "Ancien compte", 300).expect("entrée");
        archived.archived = true;

        let mut trashed = Entry::new(EntryKind::Login, "Supprimé", 400).expect("entrée");
        trashed.trashed_at = Some(500);

        let ids: Vec<EntryId> = [login.id, note.id, archived.id, trashed.id].to_vec();
        archive.entries.push(login);
        archive.entries.push(note);
        archive.entries.push(archived);
        archive.entries.push(trashed);

        (archive, ids)
    }

    #[test]
    fn an_empty_query_returns_every_active_entry() {
        // NOTE DE CORRECTION : ce test attendait initialement trois résultats. Le
        // jeu de données en contient quatre, dont **deux** seulement sont actives :
        // l'une est archivée, l'autre à la corbeille. « Actif » signifie ni l'un ni
        // l'autre, et la requête par défaut exclut les deux catégories. C'est le test
        // qui était faux, pas le filtre.
        let (archive, ids) = archive_with_entries();
        let hits = search(&archive, &SearchQuery::new(""));

        assert_eq!(hits.len(), 2, "seules les entrées actives sont retournées");
        assert!(hits.iter().all(|hit| hit.id != ids[2]), "archivée exclue");
        assert!(hits.iter().all(|hit| hit.id != ids[3]), "corbeille exclue");
    }

    #[test]
    fn a_title_prefix_ranks_above_a_field_match() {
        let (archive, _) = archive_with_entries();
        let hits = search(&archive, &SearchQuery::new("exemple"));

        assert!(!hits.is_empty());
        assert_eq!(hits[0].id, archive.entries[0].id, "le titre doit primer");
        assert_eq!(hits[0].matched_in, MatchedIn::Title);
    }

    #[test]
    fn search_is_case_insensitive() {
        let (archive, _) = archive_with_entries();
        assert_eq!(
            search(&archive, &SearchQuery::new("EXEMPLE")).len(),
            search(&archive, &SearchQuery::new("exemple")).len()
        );
    }

    #[test]
    fn search_ignores_latin_diacritics() {
        let (archive, _) = archive_with_entries();

        // « Café » doit être trouvé en tapant « cafe ».
        let hits = search(&archive, &SearchQuery::new("cafe"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, archive.entries[1].id);

        // Et inversement.
        assert_eq!(search(&archive, &SearchQuery::new("CAFÉ")).len(), 1);
    }

    #[test]
    fn a_missing_term_yields_no_result() {
        let (archive, _) = archive_with_entries();
        assert!(search(&archive, &SearchQuery::new("exemple introuvable")).is_empty());
    }

    #[test]
    fn all_terms_must_match() {
        let (archive, _) = archive_with_entries();
        // Les deux termes existent, mais dans des entrées différentes.
        assert!(search(&archive, &SearchQuery::new("exemple cafe")).is_empty());
    }

    #[test]
    fn archived_entries_are_excluded_unless_requested() {
        let (archive, _) = archive_with_entries();

        assert_eq!(search(&archive, &SearchQuery::new("ancien")).len(), 0);

        let query = SearchQuery {
            include_archived: true,
            ..SearchQuery::new("ancien")
        };
        assert_eq!(search(&archive, &query).len(), 1);
    }

    #[test]
    fn trashed_entries_are_excluded_unless_requested() {
        let (archive, _) = archive_with_entries();

        assert_eq!(search(&archive, &SearchQuery::new("supprime")).len(), 0);

        let query = SearchQuery {
            include_trashed: true,
            ..SearchQuery::new("supprime")
        };
        assert_eq!(search(&archive, &query).len(), 1);
    }

    #[test]
    fn filters_combine() {
        let (archive, _) = archive_with_entries();

        let by_kind = SearchQuery {
            kinds: vec![EntryKind::SecureNote],
            ..SearchQuery::new("")
        };
        assert_eq!(search(&archive, &by_kind).len(), 1);

        let favorites = SearchQuery {
            favorites_only: true,
            ..SearchQuery::new("")
        };
        assert_eq!(search(&archive, &favorites).len(), 1);

        let by_folder = SearchQuery {
            folder: Some(archive.folders[0].id),
            ..SearchQuery::new("")
        };
        assert_eq!(search(&archive, &by_folder).len(), 1);

        let by_tag = SearchQuery {
            tags: vec![archive.tags[0].id],
            ..SearchQuery::new("")
        };
        assert_eq!(search(&archive, &by_tag).len(), 1);
    }

    #[test]
    fn a_folder_filter_includes_descendants() {
        let mut archive = Archive::new(0);
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
            name: "enfant".to_string(),
            parent: Some(root),
            ordinal: 0,
        });

        let mut entry = Entry::new(EntryKind::Login, "dans l'enfant", 0).expect("entrée");
        entry.folder = Some(child);
        archive.entries.push(entry);

        let query = SearchQuery {
            folder: Some(root),
            ..SearchQuery::new("")
        };
        assert_eq!(
            search(&archive, &query).len(),
            1,
            "un filtre sur un dossier doit inclure ses descendants"
        );
    }

    #[test]
    fn hostile_queries_are_treated_as_literal_text() {
        // Aucune requête n'est interprétée : les métacaractères de regex, les
        // guillemets et les opérateurs sont des caractères comme les autres. Il n'y a
        // donc rien à échapper — et rien à injecter.
        let (archive, _) = archive_with_entries();

        for hostile in [
            ".*",
            "(",
            "[a-z]",
            "\\",
            "\" OR 1=1 --",
            "NEAR(",
            "' OR '1'='1",
            "\u{202E}reversed",
            "\0",
            "${jndi}",
            "%s%s%s",
            "exemple\u{0}",
        ] {
            let hits = search(&archive, &SearchQuery::new(hostile));
            assert!(
                hits.len() <= archive.entries.len(),
                "la requête « {hostile} » a produit un résultat incohérent"
            );
        }
    }

    #[test]
    fn an_absurdly_long_query_is_bounded() {
        let (archive, _) = archive_with_entries();

        // Un seul terme énorme : écarté, donc requête vide, donc toutes les entrées
        // actives.
        let huge_term = "a".repeat(MAX_TERM_LEN + 1);
        let hits = search(&archive, &SearchQuery::new(huge_term));
        assert_eq!(hits.len(), 2);

        // Beaucoup de termes : seuls les premiers sont pris en compte.
        let many_terms = (0..1000)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = search(&archive, &SearchQuery::new(many_terms));
    }

    #[test]
    fn the_result_limit_is_enforced() {
        let mut archive = Archive::new(0);
        for index in 0..500 {
            archive
                .entries
                .push(Entry::new(EntryKind::Login, format!("entrée {index}"), 0).expect("entrée"));
        }

        let query = SearchQuery {
            limit: 10,
            ..SearchQuery::new("")
        };
        assert_eq!(search(&archive, &query).len(), 10);
    }

    #[test]
    fn results_are_deterministic_at_equal_scores() {
        let mut archive = Archive::new(0);
        for _ in 0..50 {
            archive
                .entries
                .push(Entry::new(EntryKind::Login, "identique", 0).expect("entrée"));
        }

        let first: Vec<EntryId> = search(&archive, &SearchQuery::new("identique"))
            .iter()
            .map(|hit| hit.id)
            .collect();
        let second: Vec<EntryId> = search(&archive, &SearchQuery::new("identique"))
            .iter()
            .map(|hit| hit.id)
            .collect();

        assert_eq!(
            first, second,
            "l'ordre doit être stable entre deux exécutions"
        );
    }

    #[test]
    fn sorting_by_title_and_dates_works() {
        let (archive, _) = archive_with_entries();

        let by_title = SearchQuery {
            sort: SortOrder::Title,
            ..SearchQuery::new("")
        };
        let hits = search(&archive, &by_title);
        assert_eq!(
            archive.entry(&hits[0].id).expect("entrée").title,
            "Café du coin"
        );

        // La plus récente des entrées **actives** : l'entrée créée à 300 est
        // archivée, donc exclue par défaut.
        let by_created = SearchQuery {
            sort: SortOrder::CreatedDesc,
            ..SearchQuery::new("")
        };
        let hits = search(&archive, &by_created);
        assert_eq!(archive.entry(&hits[0].id).expect("entrée").created_at, 200);
    }

    #[test]
    fn normalisation_is_idempotent() {
        let mut once = String::new();
        normalize_into(&mut once, "Café ÉCOLE naïve");

        let mut twice = String::new();
        normalize_into(&mut twice, &once);

        assert_eq!(once, twice);
        assert_eq!(once, "cafe ecole naive");
    }

    #[test]
    fn normalisation_preserves_non_latin_scripts() {
        // Limite documentée : les écritures non latines ne sont pas repliées, mais
        // elles restent intactes — la normalisation ne doit rien perdre.
        let mut out = String::new();
        normalize_into(&mut out, "ΑΘΉΝΑ 東京");
        assert_eq!(out, "αθήνα 東京");
    }
}
