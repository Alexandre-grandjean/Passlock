//! Tests de l'étape 5.2 : analyse d'URL locale et PSL.
//!
//! # Ce qui est éprouvé ici
//!
//! L'analyse est **pure** : ces tests ne déverrouillent rien, n'ouvrent aucun
//! fichier et ne touchent à aucun réseau. Ils vérifient les propriétés qui comptent
//! pour l'utilisateur, et **documentent les limites assumées** (motif de
//! sous-domaine trompeur retiré, validité IDNA non établie).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use passlock_core::url::{self, HostKind, MAX_URL_LEN, Motif, UrlVerdict, Verdict};

fn registrable(verdict: &UrlVerdict) -> Option<String> {
    verdict
        .domain
        .as_ref()
        .and_then(|domain| domain.registrable.clone())
}

fn has(verdict: &UrlVerdict, motif: &Motif) -> bool {
    verdict.motifs.iter().any(|found| found == motif)
}

fn has_mixed(verdict: &UrlVerdict) -> bool {
    verdict
        .motifs
        .iter()
        .any(|m| matches!(m, Motif::MixedScriptInLabel { .. }))
}

// ---------------------------------------------------------------------------
// eTLD+1 et sémantique PSL
// ---------------------------------------------------------------------------

#[test]
fn a_plain_domain_is_clean() {
    let verdict = url::analyze("login.exemple.co.uk");
    assert_eq!(verdict.verdict, Verdict::Clean);
    assert_eq!(registrable(&verdict).as_deref(), Some("exemple.co.uk"));
    assert!(verdict.motifs.is_empty(), "{:?}", verdict.motifs);
}

#[test]
fn a_deeply_nested_domain_is_grouped_by_the_real_suffix() {
    // `exemple.co.uk.evil.com` : le domaine enregistrable est `evil.com`. Le motif
    // « sous-domaine trompeur » a été **retiré** de cette version, faute de
    // référence de marque fiable : le verdict reste donc `Clean`.
    let verdict = url::analyze("exemple.co.uk.evil.com");
    assert_eq!(registrable(&verdict).as_deref(), Some("evil.com"));
    assert_eq!(verdict.verdict, Verdict::Clean);
}

#[test]
fn a_private_suffix_separates_tenants() {
    let a = url::analyze("a.github.io");
    let b = url::analyze("b.github.io");
    assert_eq!(a.verdict, Verdict::Clean);
    assert_eq!(registrable(&a).as_deref(), Some("a.github.io"));
    assert_ne!(registrable(&a), registrable(&b));
}

#[test]
fn a_wildcard_suffix_matches_one_label() {
    let verdict = url::analyze("a.ck");
    assert_eq!(
        verdict
            .domain
            .as_ref()
            .and_then(|d| d.public_suffix.clone()),
        Some("a.ck".to_string())
    );
    assert_eq!(registrable(&verdict), None);

    let verdict = url::analyze("b.a.ck");
    assert_eq!(registrable(&verdict).as_deref(), Some("b.a.ck"));
}

#[test]
fn an_exception_suffix_makes_the_host_registrable() {
    let verdict = url::analyze("www.ck");
    assert_eq!(registrable(&verdict).as_deref(), Some("www.ck"));
}

#[test]
fn an_unknown_suffix_is_indeterminate() {
    let verdict = url::analyze("exemple.madeuptld");
    assert_eq!(verdict.verdict, Verdict::Indeterminate);
    assert!(has(&verdict, &Motif::UnknownSuffix));
    assert_eq!(registrable(&verdict).as_deref(), Some("exemple.madeuptld"));
}

// ---------------------------------------------------------------------------
// IDN : conversions, pas validation
// ---------------------------------------------------------------------------

#[test]
fn a_unicode_label_and_its_a_label_agree_and_are_indeterminate() {
    let unicode = url::analyze("münchen.de");
    let a_label = url::analyze("xn--mnchen-3ya.de");

    // Même hôte normalisé, même domaine enregistrable.
    assert_eq!(unicode.host, a_label.host);
    assert_eq!(unicode.host.as_deref(), Some("xn--mnchen-3ya.de"));
    assert_eq!(registrable(&unicode), registrable(&a_label));
    assert_eq!(registrable(&unicode).as_deref(), Some("xn--mnchen-3ya.de"));

    // Mais **la validité IDNA complète n'est pas établie** : jamais `Clean`.
    for verdict in [&unicode, &a_label] {
        assert_eq!(verdict.verdict, Verdict::Indeterminate);
        assert!(has(verdict, &Motif::IdnaNotFullyValidated));
        assert!(
            !has_mixed(verdict),
            "une seule écriture : pas de motif mixte"
        );
    }
    assert_eq!(unicode.host_unicode.as_deref(), Some("münchen.de"));
}

#[test]
fn no_silent_normalization_between_nfc_and_nfd() {
    let composed = url::analyze("münchen.de"); // « ü » = U+00FC
    let decomposed = url::analyze("mu\u{0308}nchen.de"); // « u » + U+0308

    // Les deux formes ne sont **pas** fusionnées : ce sont deux A-labels distincts.
    assert_ne!(
        composed.host, decomposed.host,
        "aucune normalisation Unicode ne doit être appliquée en silence"
    );
    // Et aucune des deux n'est déclarée `Clean`.
    assert_eq!(composed.verdict, Verdict::Indeterminate);
    assert_eq!(decomposed.verdict, Verdict::Indeterminate);
    // La forme décomposée conserve bien son caractère combinant.
    assert!(
        decomposed
            .host_unicode
            .as_deref()
            .is_some_and(|h| h.contains('\u{0308}'))
    );
}

#[test]
fn an_invalid_punycode_label_is_indeterminate() {
    for input in ["xn--a-.com", "xn--.com", "xn--mnchen-3y!.com"] {
        let verdict = url::analyze(input);
        assert_eq!(verdict.verdict, Verdict::Indeterminate, "{input}");
        assert!(
            verdict
                .motifs
                .iter()
                .any(|m| matches!(m, Motif::InvalidPunycode { .. })),
            "{input} : {:?}",
            verdict.motifs
        );
    }
}

#[test]
fn a_mixed_script_label_is_suspicious() {
    // « х » cyrillique (U+0445) mêlé à du latin.
    let verdict = url::analyze("e\u{0445}ample.com");
    assert_eq!(verdict.verdict, Verdict::Suspicious);
    assert!(has_mixed(&verdict));
}

#[test]
fn single_script_idn_is_not_mixed() {
    for input in ["münchen.de", "пример.рф", "日本.jp"] {
        let verdict = url::analyze(input);
        assert!(!has_mixed(&verdict), "{input} : {:?}", verdict.motifs);
    }
}

#[test]
fn confusable_folding_is_exposed() {
    assert_eq!(url::fold_confusables("rnicrosoft"), "microsoft");
    assert!(url::is_confusable_with("rnicrosoft.com", "microsoft.com"));
    assert!(!url::is_confusable_with("exemple.com", "exemple.com"));
}

// ---------------------------------------------------------------------------
// Bornes, unités et entrées hostiles
// ---------------------------------------------------------------------------

#[test]
fn label_length_is_measured_in_a_label_octets() {
    let at_limit = format!("{}.com", "a".repeat(63));
    let verdict = url::analyze(&at_limit);
    assert_ne!(
        verdict.verdict,
        Verdict::NotApplicable,
        "un label de 63 octets passe"
    );
    assert!(verdict.host.is_some());

    let too_long = format!("{}.com", "a".repeat(64));
    let verdict = url::analyze(&too_long);
    assert_eq!(verdict.verdict, Verdict::NotApplicable);
    assert!(has(&verdict, &Motif::MalformedHost));
}

#[test]
fn a_unicode_label_whose_a_label_exceeds_63_is_refused() {
    // 200 caractères CJK distincts : l'A-label dépasse largement 63 octets.
    let label: String = (0x4E00_u32..0x4E00 + 200)
        .filter_map(char::from_u32)
        .collect();
    let verdict = url::analyze(&format!("{label}.com"));
    assert_eq!(verdict.verdict, Verdict::Indeterminate);
    assert!(
        verdict
            .motifs
            .iter()
            .any(|m| matches!(m, Motif::InvalidUnicodeLabel { .. })),
        "{:?}",
        verdict.motifs
    );
}

#[test]
fn hostname_length_is_measured_in_a_label_octets() {
    // 4 labels de 63 + « com » = 259 octets A-label : au-delà de 253.
    let host = format!(
        "{}.{}.{}.{}.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63)
    );
    let verdict = url::analyze(&host);
    assert_eq!(verdict.verdict, Verdict::NotApplicable);
    assert!(has(&verdict, &Motif::TooLong));
}

#[test]
fn the_input_bound_is_measured_in_raw_bytes() {
    // Exactement à la borne, en octets UTF-8 : acceptée.
    let mut at_limit = String::from("https://exemple.com/");
    while at_limit.len() < MAX_URL_LEN {
        at_limit.push('a');
    }
    assert_eq!(at_limit.len(), MAX_URL_LEN);
    assert!(!has(&url::analyze(&at_limit), &Motif::TooLong));

    // Un octet de plus : refusée, avant toute analyse.
    let oversized = "a".repeat(MAX_URL_LEN + 1);
    let verdict = url::analyze(&oversized);
    assert!(has(&verdict, &Motif::TooLong));
    assert_eq!(verdict.verdict, Verdict::NotApplicable);
}

#[test]
fn too_many_labels_are_signalled() {
    let verdict = url::analyze("a.b.c.d.e.f.exemple.com");
    assert_eq!(verdict.verdict, Verdict::Suspicious);
    assert!(has(&verdict, &Motif::ExcessiveLabels { count: 8 }));
}

#[test]
fn empty_and_malformed_inputs_are_not_applicable() {
    for input in [
        "",
        "http://",
        "http:///",
        "exemple.com/path",
        "a@b",
        "http://:80",
    ] {
        let verdict = url::analyze(input);
        assert_eq!(verdict.verdict, Verdict::NotApplicable, "{input}");
    }
}

#[test]
fn ip_addresses_have_no_registrable_domain() {
    let verdict = url::analyze("http://192.168.1.1/");
    assert_eq!(verdict.host_kind, HostKind::Ipv4);
    assert!(verdict.domain.is_none());
    assert_eq!(verdict.verdict, Verdict::NotApplicable);

    let verdict = url::analyze("http://[2001:db8::1]/");
    assert_eq!(verdict.host_kind, HostKind::Ipv6);
    assert!(verdict.domain.is_none());

    let verdict = url::analyze("http://[2001:db8::1]:8443/x");
    assert_eq!(verdict.port, Some(8443));
}

#[test]
fn ports_and_userinfo_are_parsed_without_changing_the_domain() {
    let verdict = url::analyze("https://exemple.com:8443/x");
    assert_eq!(verdict.port, Some(8443));
    assert_eq!(registrable(&verdict).as_deref(), Some("exemple.com"));

    let verdict = url::analyze("https://exemple.com@evil.com/");
    assert!(verdict.had_userinfo);
    assert_eq!(registrable(&verdict).as_deref(), Some("evil.com"));
    assert_eq!(verdict.verdict, Verdict::Suspicious);
    assert!(has(&verdict, &Motif::UserInfoPresent));
}

// ---------------------------------------------------------------------------
// Déterminisme et pureté
// ---------------------------------------------------------------------------

#[test]
fn the_verdict_is_deterministic() {
    for input in [
        "https://u@e\u{0445}ample.madeuptld:8443/p?q#f",
        "münchen.de",
        "xn--mnchen-3ya.de",
        "a.b.c.d.e.f.exemple.com",
    ] {
        assert_eq!(url::analyze(input), url::analyze(input), "{input}");
    }
}

/// L'analyse ne doit référencer **aucune** E/S ni aucun accès réseau.
///
/// Le test est **structurel** : il lit la source du module à la compilation et
/// vérifie qu'aucun de ces modules n'y est mentionné. Un `std::net` ou un
/// `std::fs` introduit plus tard ferait échouer ce test.
#[test]
fn the_module_has_no_io_and_no_network() {
    for source in [include_str!("../src/url.rs"), include_str!("../src/psl.rs")] {
        for forbidden in [
            "std::net",
            "std::fs",
            "std::io",
            "std::process",
            "std::time",
            "SystemTime",
            "reqwest",
            "tokio",
        ] {
            assert!(
                !source.contains(forbidden),
                "le module d'analyse ne doit pas référencer « {forbidden} »"
            );
        }
    }
}
