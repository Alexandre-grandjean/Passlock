//! Tests de l'étape 5.1 : centre de sécurité (six indicateurs).
//!
//! # Ce qui est éprouvé ici, et que rien d'autre n'éprouve
//!
//! Le module `security` lit le modèle et n'écrit rien. Ces tests vérifient, par
//! l'API **publique**, les propriétés qui comptent pour l'utilisateur :
//!
//! | Invariant | Ce qu'il protège |
//! |---|---|
//! | `I-SEC-DETERMINISTIC` | l'ordre des résultats ne dépend pas de l'insertion |
//! | `I-SEC-NO-SECRET` | aucune valeur ni empreinte ne sort |
//! | `I-SEC-SCOPE` | exactement six indicateurs, aucune écriture |
//! | `I-SEC-EXPIRY` | bornes de la fenêtre, motifs d'indétermination |
//! | `I-SEC-REUSE` | ≥ 2 entrées distinctes, Secret+Pin, Totp exclu |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use passlock_core::keys::KEY_LEN;
use passlock_core::model::{Archive, Entry, EntryId, EntryKind, Field, FieldKind};
use passlock_core::secret::Key;
use passlock_core::security::{
    self, CivilDate, DEFAULT_EXPIRY_WINDOW_DAYS, EXPIRES_AT_KEY, ExpiryState, ExpiryUnknown,
    StrengthBand, WEAK_ENTRY_MIN_LEN,
};

const NOW: u64 = 1_700_000_000;

fn index_key() -> Key<KEY_LEN> {
    Key::from_array([0x5A; KEY_LEN])
}

fn field(key: &str, kind: FieldKind, value: &str, ordinal: u16) -> Field {
    Field::new(key, kind, value, ordinal).expect("champ")
}

fn login(title: &str, fields: Vec<Field>) -> Entry {
    let mut entry = Entry::new(EntryKind::Login, title, NOW).expect("entrée");
    entry.fields = fields;
    entry
}

fn ids_sorted(ids: &[EntryId]) -> bool {
    ids.windows(2).all(|pair| pair[0] <= pair[1])
}

// ---------------------------------------------------------------------------
// I-SEC-SCOPE — le rapport couvre exactement six indicateurs
// ---------------------------------------------------------------------------

#[test]
fn the_report_has_six_indicators_and_no_global_score() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "same", 0)],
    ));
    archive.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, "same", 0)],
    ));

    let report =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");

    assert_eq!(report.reuse.len(), 1);
    assert_eq!(report.age.len(), 2);
    assert_eq!(report.strengths.len(), 2);
    assert_eq!(report.weak.len(), 2);
    assert_eq!(report.missing_totp.len(), 2);
    assert_eq!(report.expiry.len(), 2);

    // Aucun agrégat global : le rapport porte les six listes et rien de composite.
    // (Le mot « score » apparaît légitimement dans le motif `LowHeuristicScore`,
    // qui qualifie un champ, pas le coffre.)
    let rendered = format!("{report:?}");
    for aggregate in ["percent", "pourcent", "global", "ratio", "note_globale"] {
        assert!(
            !rendered.to_lowercase().contains(aggregate),
            "agrégat « {aggregate} » dans le rapport : {rendered}"
        );
    }
    for indicator in [
        "reuse",
        "age",
        "strengths",
        "weak",
        "missing_totp",
        "expiry",
    ] {
        assert!(
            rendered.contains(indicator),
            "indicateur « {indicator} » absent"
        );
    }
}

// ---------------------------------------------------------------------------
// I-SEC-NO-SECRET — rien de secret ne sort
// ---------------------------------------------------------------------------

#[test]
fn no_value_or_fingerprint_escapes_the_report() {
    let marker = "MARQUEUR-CONFIDENTIEL-DE-TEST";
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, marker, 0)],
    ));
    archive.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, marker, 0)],
    ));

    let report =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");
    let rendered = format!("{report:?}");

    assert!(
        !rendered.contains(marker),
        "valeur secrète exposée : {rendered}"
    );
    // Le groupe de réutilisation ne porte que des références, jamais de valeur.
    assert_eq!(report.reuse[0].entries.len(), 2);
    assert!(
        report.reuse[0]
            .fields
            .iter()
            .all(|reference| reference.kind == FieldKind::Secret)
    );
}

#[test]
fn debug_of_a_reuse_group_shows_ids_but_not_values() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "abcdef", 0)],
    ));
    archive.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, "abcdef", 0)],
    ));
    let report =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");
    let rendered = format!("{:?}", report.reuse[0]);
    assert!(!rendered.contains("abcdef"), "{rendered}");
}

// ---------------------------------------------------------------------------
// I-SEC-DETERMINISTIC — ordre indépendant de l'insertion
// ---------------------------------------------------------------------------

#[test]
fn output_order_is_independent_of_insertion_order() {
    // On construit deux archives peuplées dans un ordre différent : les identifiants
    // diffèrent (aléatoires), mais l'ordre des listes ne doit dépendre que des ids.
    let build = |reverse: bool| {
        let mut entries = vec![
            login("a", vec![field("password", FieldKind::Secret, "one", 0)]),
            login("b", vec![field("password", FieldKind::Secret, "two", 0)]),
            login("c", vec![field("password", FieldKind::Secret, "three", 0)]),
        ];
        if reverse {
            entries.reverse();
        }
        let mut archive = Archive::new(0);
        archive.entries = entries;
        archive
    };

    for reverse in [false, true] {
        let archive = build(reverse);
        let report =
            security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
                .expect("rapport");

        let age_ids: Vec<EntryId> = report.age.iter().map(|info| info.entry).collect();
        assert!(ids_sorted(&age_ids), "ancienneté non triée : {age_ids:?}");

        let strength_keys: Vec<EntryId> = report
            .strengths
            .iter()
            .map(|finding| finding.entry)
            .collect();
        assert!(ids_sorted(&strength_keys));

        let missing = &report.missing_totp;
        assert!(
            ids_sorted(missing),
            "absence de TOTP non triée : {missing:?}"
        );

        let expiry_ids: Vec<EntryId> = report.expiry.iter().map(|report| report.entry).collect();
        assert!(ids_sorted(&expiry_ids));
    }
}

#[test]
fn the_report_is_stable_across_runs() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "same", 0)],
    ));
    archive.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, "same", 0)],
    ));

    let first =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");
    let second =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// I-SEC-REUSE — réutilisation
// ---------------------------------------------------------------------------

#[test]
fn reuse_needs_two_distinct_entries() {
    let mut archive = Archive::new(0);
    // Deux champs identiques dans la **même** entrée : jamais une réutilisation.
    archive.entries.push(login(
        "a",
        vec![
            field("password", FieldKind::Secret, "same", 0),
            field("pin", FieldKind::Pin, "same", 1),
        ],
    ));
    let report =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");
    assert!(report.reuse.is_empty());
}

#[test]
fn reuse_crosses_secret_and_pin_and_ignores_totp() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "1234", 0)],
    ));
    archive
        .entries
        .push(login("b", vec![field("pin", FieldKind::Pin, "1234", 0)]));
    // Un champ TOTP de valeur identique ne doit pas entrer dans un groupe.
    archive
        .entries
        .push(login("c", vec![field("totp", FieldKind::Totp, "1234", 0)]));

    let groups = security::detect_reuse(&archive, &index_key()).expect("détection");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].entries.len(), 2);
    assert!(
        groups[0]
            .fields
            .iter()
            .all(|reference| reference.kind != FieldKind::Totp)
    );
}

#[test]
fn reuse_is_case_sensitive_and_ignores_empty() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "same", 0)],
    ));
    archive.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, "Same", 0)],
    ));
    assert!(
        security::detect_reuse(&archive, &index_key())
            .expect("détection")
            .is_empty(),
        "la comparaison doit être sensible à la casse"
    );

    let mut empty = Archive::new(0);
    empty.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "", 0)],
    ));
    empty.entries.push(login(
        "b",
        vec![field("password", FieldKind::Secret, "", 0)],
    ));
    assert!(
        security::detect_reuse(&empty, &index_key())
            .expect("détection")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// I-SEC-EXPIRY — expiration
// ---------------------------------------------------------------------------

#[test]
fn expiry_is_clock_free_and_uses_the_reference() {
    let reference = CivilDate::new(2026, 6, 15);
    let truth = |value: &str| {
        security::expiry_state(
            &[field(EXPIRES_AT_KEY, FieldKind::Date, value, 0)],
            reference,
            DEFAULT_EXPIRY_WINDOW_DAYS,
        )
    };

    // Bornes : passé, aujourd'hui, +30, +31.
    assert_eq!(truth("2026-06-14"), ExpiryState::Expired);
    assert_eq!(truth("2026-06-15"), ExpiryState::Soon);
    assert_eq!(truth("2026-07-15"), ExpiryState::Soon);
    assert_eq!(truth("2026-07-16"), ExpiryState::Valid);
}

#[test]
fn expiry_reports_each_unknown_reason() {
    let reference = CivilDate::new(2026, 6, 15);
    let window = DEFAULT_EXPIRY_WINDOW_DAYS;

    assert_eq!(
        security::expiry_state(&[], reference, window),
        ExpiryState::Unknown(ExpiryUnknown::Absent)
    );
    assert_eq!(
        security::expiry_state(
            &[field(EXPIRES_AT_KEY, FieldKind::Text, "2026-06-15", 0)],
            reference,
            window
        ),
        ExpiryState::Unknown(ExpiryUnknown::WrongKind)
    );
    assert_eq!(
        security::expiry_state(
            &[field(EXPIRES_AT_KEY, FieldKind::Date, "2026-6-15", 0)],
            reference,
            window
        ),
        ExpiryState::Unknown(ExpiryUnknown::Malformed)
    );
    assert_eq!(
        security::expiry_state(
            &[field(EXPIRES_AT_KEY, FieldKind::Date, "2026-02-30", 0)],
            reference,
            window
        ),
        ExpiryState::Unknown(ExpiryUnknown::Impossible)
    );
    assert_eq!(
        security::expiry_state(
            &[
                field(EXPIRES_AT_KEY, FieldKind::Date, "2026-06-15", 0),
                field(EXPIRES_AT_KEY, FieldKind::Date, "2026-07-01", 1),
            ],
            reference,
            window
        ),
        ExpiryState::Unknown(ExpiryUnknown::Ambiguous)
    );
}

#[test]
fn the_reference_date_is_utc() {
    // Un instant à 01:00 UTC et un instant à 23:59 UTC du même jour donnent le même
    // jour civil ; une seconde avant, c'est la veille.
    let day = CivilDate::new(2026, 6, 15).to_days();
    let midnight = u64::try_from(day * 86_400).expect("secondes");
    let late = midnight + 86_399;

    assert_eq!(
        CivilDate::from_unix_seconds(midnight),
        CivilDate::new(2026, 6, 15)
    );
    assert_eq!(
        CivilDate::from_unix_seconds(late),
        CivilDate::new(2026, 6, 15)
    );
    assert_eq!(
        CivilDate::from_unix_seconds(midnight - 1),
        CivilDate::new(2026, 6, 14)
    );
}

#[test]
fn expiry_in_a_report_uses_the_provided_instant() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field(EXPIRES_AT_KEY, FieldKind::Date, "2026-06-15", 0)],
    ));
    let midday =
        u64::try_from(CivilDate::new(2026, 6, 15).to_days() * 86_400 + 43_200).expect("secondes");

    let report =
        security::run_security_center(&archive, &index_key(), midday, 30).expect("rapport");
    assert_eq!(report.expiry[0].state, ExpiryState::Soon);
    assert_eq!(report.expiry[0].delta_days, Some(0));
    assert_eq!(report.expiry[0].date, Some(CivilDate::new(2026, 6, 15)));
}

// ---------------------------------------------------------------------------
// Ancienneté
// ---------------------------------------------------------------------------

#[test]
fn age_is_deterministic_and_uses_the_instant() {
    let mut archive = Archive::new(0);
    let mut entry = login("a", vec![]);
    entry.updated_at = 1_000_000;
    archive.entries.push(entry);

    let info = security::detect_age(&archive, 1_000_000 + 86_400 * 137);
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].updated_at, 1_000_000);
    assert_eq!(info[0].days_since, 137);

    // Aucune bande : le même résultat est rendu quel que soit l'âge.
    let old = security::detect_age(&archive, 1_000_000 + 86_400 * 10_000);
    assert_eq!(old[0].days_since, 10_000);
}

// ---------------------------------------------------------------------------
// Robustesse et entrées faibles
// ---------------------------------------------------------------------------

#[test]
fn strength_thresholds_and_examples() {
    // Une entrée par cas documenté.
    let cases: [(&str, StrengthBand); 5] = [
        ("1234", StrengthBand::VeryWeak),
        ("password", StrengthBand::VeryWeak),
        ("aaaaaaaaaaaa", StrengthBand::VeryWeak),
        ("abcdefghijklmnopqrst", StrengthBand::Moderate),
        ("aB3!aB3!aB3!aB3!aB3!", StrengthBand::NoStructuralWeakness),
    ];
    for (value, expected) in cases {
        assert_eq!(
            security::estimate_strength(value).band,
            expected,
            "« {value} »"
        );
    }

    // Non-ASCII : indéterminé, mais ce n'est pas une faiblesse en soi.
    let non_ascii = security::estimate_strength("café!");
    assert_eq!(non_ascii.band, StrengthBand::Indeterminate);
    assert!(non_ascii.flags.outside_known_classes);
    assert!(non_ascii.alphabet_observed.is_none());
}

#[test]
fn a_short_secret_is_weak_even_when_indeterminate() {
    // « café! » fait 5 caractères : indéterminé, mais sous la longueur minimale.
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![field("password", FieldKind::Secret, "café!", 0)],
    ));
    let weak = security::detect_weak_entries(&archive);
    assert_eq!(
        weak.len(),
        1,
        "la règle de longueur s'applique indépendamment"
    );
    assert_eq!(weak[0].ordinal, 0);
}

#[test]
fn weak_reports_the_precise_field() {
    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "a",
        vec![
            field("password", FieldKind::Secret, "1234", 0),
            field("pin", FieldKind::Pin, "9999", 5),
            field("title", FieldKind::Text, "x", 1), // non candidat
        ],
    ));
    let weak = security::detect_weak_entries(&archive);
    assert_eq!(weak.len(), 2);
    assert_eq!(weak[0].ordinal, 0);
    assert_eq!(weak[1].ordinal, 5);
    // Chaque champ faible est identifié par entrée + ordinal.
    assert_eq!(weak[0].entry, archive.entries[0].id);
}

#[test]
fn length_threshold_is_eight_characters() {
    let at_threshold = security::estimate_strength("aB3!aB3");
    // 7 caractères, mais 7 plages sur 94 symboles → 45,9 bits : faible par les deux.
    assert!(at_threshold.char_count < WEAK_ENTRY_MIN_LEN);

    let mut archive = Archive::new(0);
    archive.entries.push(login(
        "ok",
        vec![field(
            "password",
            FieldKind::Secret,
            "correct horse battery staple",
            0,
        )],
    ));
    assert!(
        security::detect_weak_entries(&archive).is_empty(),
        "un secret long et varié ne doit pas être signalé"
    );
}

// ---------------------------------------------------------------------------
// Absence de TOTP
// ---------------------------------------------------------------------------

#[test]
fn missing_totp_rule() {
    let mut archive = Archive::new(0);
    let flagged = login(
        "flagged",
        vec![field("password", FieldKind::Secret, "x", 0)],
    );
    let flagged_id = flagged.id;
    archive.entries.push(flagged);

    archive.entries.push(login(
        "has-totp",
        vec![
            field("password", FieldKind::Secret, "x", 0),
            field("totp", FieldKind::Totp, "otpauth://totp/a?secret=AAAA", 1),
        ],
    ));
    archive.entries.push(login("no-secret", vec![]));

    let mut note = Entry::new(EntryKind::SecureNote, "note", NOW).expect("entrée");
    note.fields = vec![field("password", FieldKind::Secret, "x", 0)];
    archive.entries.push(note);

    let missing = security::detect_missing_totp(&archive);
    assert_eq!(missing, vec![flagged_id]);
}

// ---------------------------------------------------------------------------
// Exclusion de la corbeille, inclusion des archivées
// ---------------------------------------------------------------------------

#[test]
fn trash_is_excluded_and_archived_is_included() {
    let mut archive = Archive::new(0);

    let mut archived = login(
        "archived",
        vec![field("password", FieldKind::Secret, "same", 0)],
    );
    archived.archived = true;
    archive.entries.push(archived);

    let active = login(
        "active",
        vec![field("password", FieldKind::Secret, "same", 0)],
    );
    archive.entries.push(active);

    let mut trashed = login(
        "trashed",
        vec![field("password", FieldKind::Secret, "same", 0)],
    );
    trashed.trashed_at = Some(NOW);
    archive.entries.push(trashed);

    let report =
        security::run_security_center(&archive, &index_key(), NOW, DEFAULT_EXPIRY_WINDOW_DAYS)
            .expect("rapport");

    assert_eq!(report.age.len(), 2, "corbeille exclue");
    assert_eq!(
        report.reuse.len(),
        1,
        "archivée incluse dans la réutilisation"
    );
    assert_eq!(report.reuse[0].entries.len(), 2);
}
