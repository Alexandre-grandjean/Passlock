//! Intégrité et provenance de la liste des suffixes publics embarquée.
//!
//! ## Pourquoi ce fichier existe
//!
//! La PSL est du **contenu tiers** dont dépend le calcul du domaine enregistrable
//! (eTLD+1). Si le fichier embarqué différait de sa source — troncature,
//! modification, remplacement — les regroupements de domaines deviendraient faux
//! **sans qu'aucun autre test ne s'en aperçoive**, puisque les autres tests
//! s'appuient sur la liste telle qu'elle est compilée.
//!
//! Ce fichier rompt cette circularité en figeant :
//!
//! - l'**empreinte SHA-256** des octets embarqués ;
//! - la **taille exacte** en octets ;
//! - le **nombre exact** de lignes ;
//! - la présence des deux sections (ICANN et PRIVATE).
//!
//! Un tiers peut donc télécharger l'original au commit documenté dans
//! `data/public-suffix-list/ATTRIBUTION.md` et vérifier lui-même que rien n'a bougé.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

use passlock_core::psl;
use sha2::{Digest, Sha256};

/// Empreinte SHA-256 en hexadécimal minuscule.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Empreinte du fichier **tel que téléchargé**, épinglée le 2026-09-20.
///
/// Relevée sur les octets de [`psl::raw_list`], qui est le contenu du fichier
/// embarqué verbatim (`include_str!`).
const PSL_SHA256: &str = "d3fba7b2934b0e1b9c958baf42bef85107b53cd0115ff7e81a7e61c7119a36d0";

/// Taille du fichier amont, en octets.
const PSL_BYTES: usize = 334_227;

/// Nombre de lignes du fichier amont (comptage `wc -l`).
const PSL_LINES: usize = 16_481;

/// Commit amont dont le fichier est issu.
const PSL_COMMIT: &str = "645b36c9a51ff0b3718df0ba02f6570aa6921632";

#[test]
fn the_embedded_list_matches_its_upstream_checksum() {
    let raw = psl::raw_list();
    assert_eq!(
        sha256_hex(raw.as_bytes()),
        PSL_SHA256,
        "la PSL embarquée ne correspond plus à sa source (commit {PSL_COMMIT}) : \
         mettez à jour l'empreinte DANS CE TEST et dans ATTRIBUTION.md, par un commit revu"
    );
}

#[test]
fn the_embedded_list_has_the_expected_size_and_lines() {
    let raw = psl::raw_list();
    assert_eq!(raw.len(), PSL_BYTES, "taille de la PSL embarquée");
    assert_eq!(raw.lines().count(), PSL_LINES, "nombre de lignes de la PSL");
}

#[test]
fn both_sections_are_present() {
    let raw = psl::raw_list();
    // Les deux sections — ICANN **et** PRIVATE — sont utilisées : leur présence est
    // une propriété voulue, pas un détail.
    for marker in [
        "// ===BEGIN ICANN DOMAINS===",
        "// ===BEGIN PRIVATE DOMAINS===",
        "// ===END PRIVATE DOMAINS===",
    ] {
        assert!(raw.contains(marker), "repère de section absent : {marker}");
    }
}

/// La liste mêle des règles en A-label et en U-label : le parseur les normalise.
/// Ce test vérifie que les deux formes sont bien présentes dans la source, pour que
/// la normalisation reste **nécessaire** et ne devienne pas un code mort.
#[test]
fn the_source_mixes_a_labels_and_u_labels() {
    let mut a_labels = 0_usize;
    let mut u_labels = 0_usize;
    for line in psl::raw_list().lines() {
        let rule = line.trim();
        if rule.is_empty() || rule.starts_with("//") {
            continue;
        }
        if rule.is_ascii() {
            a_labels += 1;
        } else {
            u_labels += 1;
        }
    }
    assert!(a_labels > 1000, "règles ASCII attendues en nombre");
    assert!(
        u_labels > 0,
        "la liste doit encore contenir des règles U-label à normaliser"
    );
}

#[test]
fn the_file_has_lf_endings_only() {
    assert!(
        !psl::raw_list().contains('\r'),
        "fins de ligne CR détectées : le fichier doit rester verbatim en LF"
    );
}
