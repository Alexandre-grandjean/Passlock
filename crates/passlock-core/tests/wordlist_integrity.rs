//! Intégrité et provenance des listes de mots embarquées.
//!
//! ## Pourquoi ce fichier existe
//!
//! Une liste de mots embarquée est du **contenu tiers** dont dépend directement
//! l'entropie annoncée : `H = mots × log₂(W)`. Si le fichier embarqué différait de
//! sa source — troncature, modification, remplacement — l'entropie annoncée
//! deviendrait fausse **sans qu'aucun autre test ne s'en aperçoive**, puisque tous
//! les autres tests s'appuient sur la liste telle qu'elle est compilée.
//!
//! Ce fichier rompt cette circularité en figeant :
//!
//! - l'**empreinte SHA-256** des octets de chaque source ;
//! - la **taille exacte** en octets ;
//! - le **nombre exact** de lignes.
//!
//! Un tiers peut donc télécharger l'original à l'URL documentée dans
//! `data/wordlists/ATTRIBUTION.md` et vérifier lui-même que rien n'a bougé.
//!
//! ## Ce que ce fichier ne vérifie pas
//!
//! L'empreinte prouve que le fichier **est bien celui téléchargé**, pas qu'il est
//! de bonne qualité. La qualité linguistique des listes et l'absence de biais dans
//! leur construction d'origine ne sont pas vérifiables depuis ce projet.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

use passlock_core::wordlist::{EMBEDDED_WORD_COUNT, Language};
use sha2::{Digest, Sha256};

/// Empreinte SHA-256 en hexadécimal minuscule.
///
/// L'écriture dans un `String` ne peut pas échouer : le résultat est donc
/// délibérément ignoré, et non « géré ».
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Empreintes des fichiers **tels que téléchargés**, épinglées le 2026-09-16.
///
/// Relevées sur les octets de `Language::raw()`, qui est la décodification UTF-8
/// du fichier embarqué verbatim. Les deux listes étant purement ASCII, ces octets
/// sont exactement ceux du fichier d'origine.
const EFF_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";
const DICEWARE_FR_SHA256: &str = "49ef76a9379fed2781db30d08c1bd2ed3ccec9b13d372f183c42b2e97a95bd8b";

#[test]
fn the_english_list_matches_its_upstream_checksum() {
    let raw = Language::EffEnglish.raw();
    assert_eq!(
        sha256_hex(raw.as_bytes()),
        EFF_SHA256,
        "la liste EFF embarquée ne correspond plus à sa source : l'entropie \
         annoncée pour les phrases de passe anglaises n'est plus fondée"
    );
    assert_eq!(raw.len(), 108_800, "taille de la liste EFF");
    assert_eq!(raw.lines().count(), EMBEDDED_WORD_COUNT);
}

#[test]
fn the_french_list_matches_its_upstream_checksum() {
    let raw = Language::DicewareFrench.raw();
    assert_eq!(
        sha256_hex(raw.as_bytes()),
        DICEWARE_FR_SHA256,
        "la liste française embarquée ne correspond plus à sa source : l'entropie \
         annoncée pour les phrases de passe françaises n'est plus fondée"
    );
    assert_eq!(raw.len(), 91_466, "taille de la liste française");
    assert_eq!(raw.lines().count(), EMBEDDED_WORD_COUNT);
}

/// Les deux listes doivent être **purement ASCII**.
///
/// Ce n'est pas une curiosité : un mot accentué demanderait une saisie composée sur
/// un clavier étranger, et la normalisation Unicode (NFC ou NFD) fait qu'une même
/// lettre accentuée peut s'écrire de deux façons. Deux encodages distincts du même
/// mot compteraient comme deux entrées, ou pire, échoueraient à correspondre lors
/// d'une saisie. L'ASCII supprime la question.
#[test]
fn both_lists_are_pure_ascii() {
    for language in [Language::EffEnglish, Language::DicewareFrench] {
        let raw = language.raw();
        assert!(
            raw.is_ascii(),
            "la liste {language:?} contient des caractères non ASCII"
        );
    }
}

/// Les clés Diceware doivent former exactement l'ensemble `11111` à `66666`.
///
/// C'est la vérification la plus forte sur la **structure** de ces fichiers : une
/// troncature, une ligne dupliquée ou une clé hors du jeu de cinq dés est détectée
/// immédiatement, indépendamment du nombre total de lignes.
#[test]
fn the_dice_keys_cover_exactly_the_five_dice_space() {
    let digits = ['1', '2', '3', '4', '5', '6'];
    let mut expected = std::collections::HashSet::new();
    for a in digits {
        for b in digits {
            for c in digits {
                for d in digits {
                    for e in digits {
                        expected.insert(format!("{a}{b}{c}{d}{e}"));
                    }
                }
            }
        }
    }
    assert_eq!(expected.len(), EMBEDDED_WORD_COUNT);

    for language in [Language::EffEnglish, Language::DicewareFrench] {
        let mut found = std::collections::HashSet::new();
        for line in language.raw().lines() {
            let key = line
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("ligne vide dans {language:?}"));
            assert!(
                found.insert(key.to_owned()),
                "clé dupliquée « {key} » dans {language:?}"
            );
        }

        let missing: Vec<&String> = expected.difference(&found).collect();
        let extra: Vec<&String> = found.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{language:?} : {} clés manquantes, {} clés hors du jeu de dés",
            missing.len(),
            extra.len()
        );
    }
}

/// Le nombre de mots utilisables est celui qui sert au calcul d'entropie.
///
/// Ce test fige les deux valeurs pour qu'un changement de liste — même anodin en
/// apparence — se traduise par un écart visible plutôt que par une entropie
/// silencieusement fausse.
#[test]
fn the_usable_word_counts_are_pinned() {
    use passlock_core::wordlist::Wordlist;

    let eff = Wordlist::embedded(Language::EffEnglish, false).expect("liste");
    assert_eq!(
        eff.len(),
        7776,
        "liste EFF : toutes les entrées portent des lettres"
    );

    let fr = Wordlist::embedded(Language::DicewareFrench, false).expect("liste");
    assert_eq!(fr.len(), 7776, "liste française complète");

    let fr_letters = Wordlist::embedded(Language::DicewareFrench, true).expect("liste");
    assert_eq!(
        fr_letters.len(),
        7536,
        "liste française filtrée : les entrées Diceware sans lettre (chiffres et \
         ponctuation de la méthode d'origine) sont retirées, et c'est ce nombre qui \
         détermine l'entropie"
    );
}
