//! Listes de mots pour les phrases de passe.
//!
//! ## Deux listes embarquées, deux provenances
//!
//! | Liste | Source | Entrées | Licence |
//! |---|---|---|---|
//! | EFF (anglais) | `eff_large_wordlist.txt`, Electronic Frontier Foundation | 7776 | CC BY |
//! | Diceware français | `diceware-fr-5-jets.txt`, Christophe-Marie Duquesne | 7776 | CC-BY-3.0 |
//!
//! Les fichiers sont embarqués **verbatim**, tels que téléchargés depuis leur
//! source. Leur provenance et leur empreinte restent donc vérifiables par un tiers
//! qui télécharge l'original — voir `data/wordlists/ATTRIBUTION.md` et le test
//! d'empreinte dans `tests/wordlist_integrity.rs`.
//!
//! ## Une liste tierce est une donnée non fiable
//!
//! Au même titre qu'une entrée importée. Le chargement est donc **borné** et la
//! validation est **fermée** : format, longueur, unicité, absence de caractère de
//! contrôle. En cas d'échec, le générateur **refuse de produire**.
//!
//! ## L'entropie dépend de la liste réellement utilisée
//!
//! `H = mots × log₂(W)` où `W` est la taille de la liste **effective**. Un filtrage
//! change `W`, donc change l'entropie. Ce module expose donc la taille réelle et
//! jamais une constante supposée : une liste personnalisée de 300 mots donne
//! `log₂(300)`, pas `log₂(7776)`.
//!
//! ## Ce que la validation ne couvre pas
//!
//! Le **compte**, le **format**, l'**unicité** et l'**empreinte** sont vérifiés. La
//! *qualité linguistique* de ces listes et l'absence de biais dans leur construction
//! d'origine ne le sont pas, et ne peuvent pas l'être depuis ce projet.

use std::path::Path;
use std::sync::OnceLock;

use crate::error::{Error, Result};

/// Nombre d'entrées des deux listes embarquées.
///
/// Vaut `6⁵ = 7776` : le format Diceware associe cinq jets de dé à un mot.
pub const EMBEDDED_WORD_COUNT: usize = 7776;

/// Longueur maximale d'un mot accepté.
pub const MAX_WORD_LEN: usize = 64;

/// Taille maximale d'un fichier de liste fourni par l'utilisateur.
pub const MAX_WORDLIST_BYTES: usize = 4 * 1024 * 1024;

/// Nombre maximal d'entrées d'une liste fournie par l'utilisateur.
pub const MAX_CUSTOM_WORDS: usize = 1_000_000;

/// Liste EFF, verbatim.
const EFF_LARGE: &str = include_str!("../data/wordlists/eff_large_wordlist.txt");

/// Liste Diceware française, verbatim.
const DICEWARE_FR: &str = include_str!("../data/wordlists/diceware-fr-5-jets.txt");

/// Langue d'une liste embarquée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// Liste EFF, mots anglais.
    EffEnglish,
    /// Liste Diceware française.
    DicewareFrench,
}

impl Language {
    /// Nom lisible, pour l'affichage.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EffEnglish => "anglais (liste EFF)",
            Self::DicewareFrench => "français (liste Diceware)",
        }
    }

    /// Analyse un nom de langue.
    ///
    /// Accepte les formes courtes `en` et `fr`, utilisées par l'interface.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "en" | "eff" | "anglais" => Some(Self::EffEnglish),
            "fr" | "diceware" | "francais" | "français" => Some(Self::DicewareFrench),
            _ => None,
        }
    }

    /// Texte brut de la liste embarquée.
    ///
    /// Exposé pour que l'empreinte et le nombre de lignes de la source restent
    /// vérifiables depuis les tests, sans dupliquer le contenu.
    #[must_use]
    pub const fn raw(self) -> &'static str {
        match self {
            Self::EffEnglish => EFF_LARGE,
            Self::DicewareFrench => DICEWARE_FR,
        }
    }
}

/// Origine d'une liste, conservée pour l'affichage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Liste embarquée dans le binaire.
    Embedded(Language),
    /// Liste fournie par l'utilisateur.
    CustomFile,
}

/// Liste de mots validée.
#[derive(Debug)]
pub struct Wordlist {
    words: Vec<String>,
    origin: Origin,
    letters_only: bool,
}

impl Wordlist {
    /// Retourne une liste embarquée, mise en cache.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si la liste **compilée dans le binaire** ne passe pas sa
    /// propre validation. Ce cas signale une construction corrompue, pas une
    /// condition d'exploitation — mais il produit une erreur, jamais une panique.
    pub fn embedded(language: Language, letters_only: bool) -> Result<&'static Self> {
        static CACHE: [OnceLock<Wordlist>; 4] = [const { OnceLock::new() }; 4];

        let slot = &CACHE[cache_index(language, letters_only)];
        if let Some(list) = slot.get() {
            return Ok(list);
        }

        // Une course entre deux fils ferait parser deux fois et n'en conserverait
        // qu'une : l'autre est simplement libérée. Sans conséquence.
        let parsed = parse_literal(language.raw(), Origin::Embedded(language), letters_only)
            .map_err(|_| Error::Internal {
                invariant: "liste de mots embarquée invalide : construction corrompue",
            })?;

        Ok(slot.get_or_init(|| parsed))
    }

    /// Charge une liste depuis un fichier fourni par l'utilisateur.
    ///
    /// Le fichier accepte deux formes par ligne : le mot seul, ou une clé suivie
    /// d'une blanche et du mot (`11111\tmot`, le format Diceware d'origine). Les
    /// blancs multiples sont tolérés.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si le fichier dépasse [`MAX_WORDLIST_BYTES`], s'il
    /// n'est pas de l'UTF-8 valide, s'il ne contient aucun mot, ou si une ligne est
    /// mal formée.
    /// [`Error::Io`] si la lecture échoue.
    pub fn from_file(path: &Path, letters_only: bool) -> Result<Self> {
        // Borne **avant** lecture. Un fichier plus gros que la limite n'est jamais
        // chargé en mémoire.
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_WORDLIST_BYTES as u64 {
            return Err(Error::InvalidInput {
                reason: "fichier de liste de mots au-delà de la taille maximale admise",
            });
        }

        let bytes = std::fs::read(path)?;

        // Seconde vérification : le fichier a pu grandir entre `metadata` et
        // `read`. C'est le même enchaînement que la lecture d'un coffre, et la même
        // raison de le refaire.
        if bytes.len() > MAX_WORDLIST_BYTES {
            return Err(Error::InvalidInput {
                reason: "fichier de liste de mots au-delà de la taille maximale admise",
            });
        }

        let text = String::from_utf8(bytes).map_err(|_| Error::InvalidInput {
            reason: "fichier de liste de mots non conforme à UTF-8",
        })?;

        parse_literal(&text, Origin::CustomFile, letters_only)
    }

    /// Nombre de mots **effectivement utilisables**.
    ///
    /// C'est cette valeur, et non une constante, qui détermine l'entropie.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Vrai si la liste est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Origine de la liste.
    #[must_use]
    pub const fn origin(&self) -> Origin {
        self.origin
    }

    /// Vrai si le filtrage « lettres seulement » a été appliqué.
    #[must_use]
    pub const fn is_letters_only(&self) -> bool {
        self.letters_only
    }

    /// Mot à un index donné.
    #[must_use]
    pub fn word(&self, index: usize) -> Option<&str> {
        self.words.get(index).map(String::as_str)
    }

    /// Vrai si **au moins un mot** de la liste contient ce caractère.
    ///
    /// Sert au générateur de phrases de passe : un séparateur qui apparaît dans un
    /// mot rend la concaténation **ambiguë**, donc `n × log₂(W)` **surestime**
    /// l'espace réel. Voir [`crate::generator::generate_passphrase`].
    #[must_use]
    pub fn contains(&self, needle: char) -> bool {
        self.words.iter().any(|word| word.contains(needle))
    }

    /// Vrai si **aucun** mot ne contient ce caractère.
    #[must_use]
    pub fn is_free_of(&self, needle: char) -> bool {
        !self.contains(needle)
    }

    /// Vrai si **au moins un mot** contient cette séquence.
    ///
    /// Version textuelle de [`Wordlist::contains`], pour un séparateur de plusieurs
    /// caractères.
    #[must_use]
    pub fn contains_sequence(&self, needle: &str) -> bool {
        !needle.is_empty() && self.words.iter().any(|word| word.contains(needle))
    }
}

/// Index dans le cache : langue × filtre.
const fn cache_index(language: Language, letters_only: bool) -> usize {
    let base = match language {
        Language::EffEnglish => 0,
        Language::DicewareFrench => 2,
    };
    base + if letters_only { 1 } else { 0 }
}

/// Analyse et valide le texte d'une liste.
fn parse_literal(text: &str, origin: Origin, letters_only: bool) -> Result<Wordlist> {
    let max_words = match origin {
        Origin::Embedded(_) => EMBEDDED_WORD_COUNT,
        Origin::CustomFile => MAX_CUSTOM_WORDS,
    };

    let mut words: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (number, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        // Forme acceptée : « mot » ou « clé<blancs>mot ». Les blancs multiples et
        // les tabulations sont absorbés par `split_whitespace`.
        let mut parts = line.split_whitespace();
        let first = parts.next().ok_or(Error::InvalidInput {
            reason: "liste de mots : ligne vide inattendue",
        })?;
        let word = match parts.next() {
            Some(second) => second,
            // Un seul champ : c'est le mot, sans clé.
            None => first,
        };

        if parts.next().is_some() {
            return Err(Error::InvalidInput {
                reason: "liste de mots : ligne à plus de deux champs",
            });
        }

        let _ = number;
        validate_word(word)?;

        if letters_only && !word.bytes().any(|byte| byte.is_ascii_alphabetic()) {
            continue;
        }

        // Un doublon réduit silencieusement l'espace réel : le tirage deviendrait
        // non uniforme sans que rien ne le signale. C'est un refus, pas un
        // avertissement.
        if !seen.insert(word.to_owned()) {
            return Err(Error::InvalidInput {
                reason: "liste de mots : mot dupliqué",
            });
        }

        words.push(word.to_owned());

        if words.len() > max_words {
            return Err(Error::InvalidInput {
                reason: "liste de mots : nombre d'entrées au-delà de la limite",
            });
        }
    }

    if words.is_empty() {
        return Err(Error::InvalidInput {
            reason: "liste de mots vide : aucune phrase de passe ne peut être engendrée",
        });
    }

    Ok(Wordlist {
        words,
        origin,
        letters_only,
    })
}

/// Valide un mot.
///
/// Les caractères de contrôle sont refusés : une liste est une donnée tierce, et
/// un mot portant une séquence d'échappement s'afficherait dans un terminal. Le
/// refus a lieu ici, à l'entrée, pour protéger tous les affichages à venir.
fn validate_word(word: &str) -> Result<()> {
    if word.is_empty() {
        return Err(Error::InvalidInput {
            reason: "liste de mots : mot vide",
        });
    }
    if word.len() > MAX_WORD_LEN {
        return Err(Error::InvalidInput {
            reason: "liste de mots : mot au-delà de la longueur maximale admise",
        });
    }
    if word.chars().any(char::is_control) {
        return Err(Error::InvalidInput {
            reason: "liste de mots : caractère de contrôle dans un mot",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_embedded_lists_load_with_the_expected_count() {
        for language in [Language::EffEnglish, Language::DicewareFrench] {
            let list = Wordlist::embedded(language, false).expect("liste embarquée");
            assert_eq!(
                list.len(),
                EMBEDDED_WORD_COUNT,
                "{:?} : {} entrées au lieu de {EMBEDDED_WORD_COUNT}",
                language,
                list.len()
            );
            assert!(!list.is_empty());
            assert_eq!(list.origin(), Origin::Embedded(language));
        }
    }

    /// Le filtrage doit réduire la liste, et le nombre obtenu doit être celui qui
    /// sert au calcul d'entropie — pas une constante supposée.
    #[test]
    fn the_letters_only_filter_shrinks_the_french_list_only() {
        let eff_all = Wordlist::embedded(Language::EffEnglish, false).expect("liste");
        let eff_letters = Wordlist::embedded(Language::EffEnglish, true).expect("liste");
        assert_eq!(
            eff_all.len(),
            eff_letters.len(),
            "la liste EFF ne contient que des mots : le filtre ne doit rien retirer"
        );

        let fr_all = Wordlist::embedded(Language::DicewareFrench, false).expect("liste");
        let fr_letters = Wordlist::embedded(Language::DicewareFrench, true).expect("liste");

        // La liste française contient des entrées Diceware authentiques qui ne
        // portent pas de lettre — chiffres et ponctuation de la méthode d'origine.
        // Le filtre les retire, et le compte change : c'est ce compte-là qui doit
        // servir à l'entropie.
        assert!(
            fr_letters.len() < fr_all.len(),
            "le filtre n'a rien retiré : {} contre {}",
            fr_letters.len(),
            fr_all.len()
        );
        assert_eq!(fr_all.len(), EMBEDDED_WORD_COUNT);
        assert!(fr_letters.len() > 7000, "filtrage excessif");

        // Tous les mots conservés portent bien une lettre.
        for index in 0..fr_letters.len() {
            let word = fr_letters.word(index).expect("mot");
            assert!(
                word.bytes().any(|b| b.is_ascii_alphabetic()),
                "« {word} » ne porte aucune lettre mais a été conservé"
            );
        }
    }

    #[test]
    fn embedded_lists_are_cached_and_stable() {
        let first = Wordlist::embedded(Language::EffEnglish, false).expect("liste");
        let second = Wordlist::embedded(Language::EffEnglish, false).expect("liste");
        assert!(
            std::ptr::eq(first, second),
            "la liste n'est pas mise en cache"
        );
    }

    #[test]
    fn every_embedded_word_is_usable() {
        for language in [Language::EffEnglish, Language::DicewareFrench] {
            let list = Wordlist::embedded(language, false).expect("liste");
            for index in 0..list.len() {
                let word = list.word(index).expect("mot");
                assert!(!word.is_empty(), "{language:?} index {index}");
                assert!(word.len() <= MAX_WORD_LEN);
                assert!(!word.chars().any(char::is_control));
                assert!(!word.chars().any(char::is_whitespace));
            }
            // L'index au-delà de la fin ne doit pas paniquer.
            assert!(list.word(list.len()).is_none());
        }
    }

    #[test]
    fn no_embedded_list_contains_a_duplicate() {
        for language in [Language::EffEnglish, Language::DicewareFrench] {
            let list = Wordlist::embedded(language, false).expect("liste");
            let unique: std::collections::HashSet<&str> =
                (0..list.len()).filter_map(|i| list.word(i)).collect();
            assert_eq!(
                unique.len(),
                list.len(),
                "{language:?} : {} doublons",
                list.len() - unique.len()
            );
        }
    }

    #[test]
    fn language_names_are_recognised() {
        assert_eq!(Language::parse("fr"), Some(Language::DicewareFrench));
        assert_eq!(Language::parse("FR"), Some(Language::DicewareFrench));
        assert_eq!(Language::parse("en"), Some(Language::EffEnglish));
        assert_eq!(Language::parse("eff"), Some(Language::EffEnglish));
        assert_eq!(Language::parse("de"), None);
        assert_eq!(Language::parse(""), None);
    }

    // -- Listes fournies par l'utilisateur ---------------------------------

    fn write_temp(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("liste.txt");
        std::fs::write(&path, content).expect("écriture");
        (dir, path)
    }

    #[test]
    fn a_custom_list_is_accepted_in_both_shapes() {
        // Mot seul.
        let (_dir, path) = write_temp("alpha\nbeta\ngamma\n");
        let list = Wordlist::from_file(&path, false).expect("chargement");
        assert_eq!(list.len(), 3);
        assert_eq!(list.origin(), Origin::CustomFile);

        // Forme Diceware : clé, blanche, mot.
        let (_dir, path) = write_temp("11111\talpha\n11112\tbeta\n11113\tgamma\n");
        let list = Wordlist::from_file(&path, false).expect("chargement");
        assert_eq!(list.len(), 3);
        assert_eq!(list.word(0), Some("alpha"));

        // Espaces multiples et tabulations mélangés.
        let (_dir, path) = write_temp("11111   alpha\n11112\t\tbeta\n");
        let list = Wordlist::from_file(&path, false).expect("chargement");
        assert_eq!(list.len(), 2);
        assert_eq!(list.word(1), Some("beta"));
    }

    #[test]
    fn a_custom_list_with_duplicates_is_refused() {
        let (_dir, path) = write_temp("alpha\nbeta\nalpha\n");
        assert!(
            Wordlist::from_file(&path, false).is_err(),
            "un doublon doit être refusé : il fausserait l'entropie annoncée"
        );
    }

    #[test]
    fn a_malformed_custom_list_is_refused() {
        for content in ["", "\n\n\n", "alpha beta gamma\n", "alpha\n\x07beta\n"] {
            let (_dir, path) = write_temp(content);
            assert!(
                Wordlist::from_file(&path, false).is_err(),
                "contenu {content:?} devrait être refusé"
            );
        }
    }

    #[test]
    fn an_oversized_custom_list_is_refused_before_reading() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("enorme.txt");
        let word = "a".repeat(MAX_WORD_LEN);
        let line = format!("{word}\n");
        let count = MAX_WORDLIST_BYTES / line.len() + 2;
        std::fs::write(&path, line.repeat(count)).expect("écriture");

        assert!(matches!(
            Wordlist::from_file(&path, false),
            Err(Error::InvalidInput { .. })
        ));
    }

    #[test]
    fn a_custom_list_of_one_word_is_usable_but_obviously_weak() {
        let (_dir, path) = write_temp("unique\n");
        let list = Wordlist::from_file(&path, false).expect("chargement");
        assert_eq!(list.len(), 1);
        // Une liste d'un mot donne 0 bit par mot : le calcul d'entropie le dira, et
        // c'est au générateur de refuser ou d'avertir, pas à ce module.
        assert_eq!(list.word(0), Some("unique"));
    }

    #[test]
    fn a_missing_file_reports_an_io_error() {
        let outcome = Wordlist::from_file(Path::new("/inexistant/liste.txt"), false);
        assert!(matches!(outcome, Err(Error::Io(_))));
    }

    #[test]
    fn the_cache_index_is_injective() {
        let mut indices = std::collections::HashSet::new();
        for language in [Language::EffEnglish, Language::DicewareFrench] {
            for letters_only in [false, true] {
                assert!(
                    indices.insert(cache_index(language, letters_only)),
                    "collision de cache pour {language:?} / {letters_only}"
                );
            }
        }
        assert_eq!(indices.len(), 4);
    }
}
