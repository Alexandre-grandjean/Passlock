//! Liste des suffixes publics (PSL) : domaine enregistrable (eTLD+1).
//!
//! # Données embarquées, aucun réseau
//!
//! Le fichier `public_suffix_list.dat` est **embarqué verbatim** (`include_str!`)
//! depuis `crates/passlock-core/data/public-suffix-list/`. Il est
//! **ré-embarqué par un commit revu** ; il n'est **jamais** récupéré au build ni à
//! l'exécution, et aucune mise à jour automatique n'existe. Provenance, licence
//! (MPL-2.0), commit amont et empreinte SHA-256 : voir `ATTRIBUTION.md` dans le
//! répertoire de données, et `tests/public_suffix_integrity.rs`.
//!
//! **Les deux sections sont utilisées** (ICANN **et** PRIVATE). Conséquence voulue :
//! `github.io` est un suffixe public, donc `a.github.io` et `b.github.io` sont deux
//! domaines enregistrables **distincts** — c'est la frontière de sécurité des
//! navigateurs, et non un détail.
//!
//! # Sémantique officielle des règles
//!
//! * **règle normale** (`com`, `co.uk`) : correspondance par suffixe de label ;
//! * **joker** (`*.ck`) : `*` remplace **exactement un** label ;
//! * **exception** (`!www.ck`) : l'hôte correspondant n'est **pas** un suffixe
//!   public ; le label de gauche est retiré du suffixe retenu ;
//! * priorité : **exception**, sinon la règle correspondante **la plus longue** ;
//! * si **aucune** règle ne correspond, la règle par défaut est `*` : le suffixe
//!   public est le **dernier label**, et le résultat est **incertain**.
//!
//! La comparaison se fait sur la forme **A-label** (minuscules), celle du fichier.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Contenu de la liste, embarqué verbatim.
const PSL_DATA: &str = include_str!("../data/public-suffix-list/public_suffix_list.dat");

/// Règles analysées, construites une seule fois.
struct PslRules {
    /// Règles normales : le domaine du suffixe tel quel.
    exact: HashSet<Box<str>>,
    /// Parents de joker : pour `*.x`, l'entrée `x`.
    wildcard_parents: HashSet<Box<str>>,
    /// Exceptions : pour `!x`, l'entrée `x`.
    exceptions: HashSet<Box<str>>,
}

static RULES: OnceLock<PslRules> = OnceLock::new();

/// Contenu embarqué **verbatim**, exposé pour le test d'intégrité.
///
/// Permet de vérifier l'empreinte SHA-256, la taille et les repères de sections sur
/// les octets **réellement compilés**, et non sur une relecture du fichier.
#[must_use]
pub fn raw_list() -> &'static str {
    PSL_DATA
}

/// Règles embarquées, analysées paresseusement.
fn rules() -> &'static PslRules {
    RULES.get_or_init(|| {
        let mut exact = HashSet::new();
        let mut wildcard_parents = HashSet::new();
        let mut exceptions = HashSet::new();

        for line in PSL_DATA.lines() {
            let rule = line.trim();
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }

            if let Some(rest) = rule.strip_prefix('!') {
                exceptions.insert(normalize_rule(rest));
            } else if let Some(rest) = rule.strip_prefix("*.") {
                wildcard_parents.insert(normalize_rule(rest));
            } else {
                exact.insert(normalize_rule(rule));
            }
        }

        PslRules {
            exact,
            wildcard_parents,
            exceptions,
        }
    })
}

/// Normalise une règle en **forme A-label** minuscule.
///
/// La liste contient **les deux formes** : la plupart des règles sont déjà en
/// A-label (`xn--…`), mais **459 lignes** sont en U-label (`aéroport.ci`,
/// `公司.cn`…). L'hôte étant analysé en A-label, les règles doivent l'être aussi —
/// sinon une règle Unicode ne correspondrait jamais.
fn normalize_rule(rule: &str) -> Box<str> {
    let labels: Vec<String> = rule.split('.').map(normalize_label).collect();
    labels.join(".").into_boxed_str()
}

/// Normalise un label : minuscules si ASCII, sinon encodé en `xn--…`.
fn normalize_label(label: &str) -> String {
    if label.is_ascii() {
        return label.to_ascii_lowercase();
    }
    // Un encodage qui échouerait laisserait la règle telle quelle : elle ne
    // correspondrait alors à aucun hôte A-label, sans panique ni règle fausse.
    match crate::encoding::punycode_encode(label) {
        Ok(payload) => format!("xn--{payload}"),
        Err(_) => label.to_ascii_lowercase(),
    }
}

/// Comment la règle a été trouvée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixCertainty {
    /// Règle normale.
    Exact,
    /// Règle joker.
    Wildcard,
    /// Règle d'exception.
    Exception,
    /// **Aucune** règle : la règle par défaut s'applique, le résultat est
    /// **incertain** (suffixe absent d'une liste vieillissante — L25).
    Default,
    /// Hôte vide : rien à analyser.
    NotApplicable,
}

impl SuffixCertainty {
    /// Vrai si le suffixe provient d'une règle effective de la liste.
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(self, Self::Exact | Self::Wildcard | Self::Exception)
    }
}

/// Résultat du calcul du domaine enregistrable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInfo {
    /// Suffixe public, en A-label minuscule.
    pub public_suffix: Option<String>,
    /// Domaine enregistrable (suffixe public + un label), en A-label minuscule.
    pub registrable: Option<String>,
    /// Comment le suffixe a été déterminé.
    pub certainty: SuffixCertainty,
}

impl DomainInfo {
    /// Résultat non applicable (hôte vide).
    const fn not_applicable() -> Self {
        Self {
            public_suffix: None,
            registrable: None,
            certainty: SuffixCertainty::NotApplicable,
        }
    }
}

/// Calcule le suffixe public et le domaine enregistrable d'un hôte.
///
/// `host` doit être **normalisé** au préalable : minuscules, A-label, **sans** point
/// final (voir `url.rs`). Un hôte vide donne [`SuffixCertainty::NotApplicable`].
#[must_use]
pub fn registrable_domain(host: &str) -> DomainInfo {
    if host.is_empty() {
        return DomainInfo::not_applicable();
    }

    let labels: Vec<&str> = host.split('.').collect();
    let count = labels.len();

    // 1. Exception prioritaire : l'hôte se termine par une exception.
    for start in 0..count {
        let candidate = join(&labels, start);
        if rules().exceptions.contains(&*candidate) {
            // Le suffixe public est l'exception **privée de son premier label**.
            let suffix = join(&labels, start + 1);
            let suffix_labels = count - start - 1;
            return finish(
                &labels,
                count,
                suffix,
                suffix_labels,
                SuffixCertainty::Exception,
            );
        }
    }

    // 2. Règle normale la plus longue (le plus petit `start` gagne).
    let exact = (0..count).find(|&start| rules().exact.contains(&join_raw(&labels, start)));
    // 3. Règle joker la plus longue : `*.x` exige un label avant `x`.
    let wildcard =
        (1..count).find(|&start| rules().wildcard_parents.contains(&join_raw(&labels, start)));

    let (suffix, suffix_labels, certainty) = match (exact, wildcard) {
        (Some(exact), Some(wild)) => {
            if exact <= wild {
                (join(&labels, exact), count - exact, SuffixCertainty::Exact)
            } else {
                (
                    join(&labels, wild - 1),
                    count - wild + 1,
                    SuffixCertainty::Wildcard,
                )
            }
        }
        (Some(exact), None) => (join(&labels, exact), count - exact, SuffixCertainty::Exact),
        (None, Some(wild)) => (
            join(&labels, wild - 1),
            count - wild + 1,
            SuffixCertainty::Wildcard,
        ),
        (None, None) => {
            // Règle par défaut `*` : le dernier label, résultat incertain.
            (labels[count - 1].to_string(), 1, SuffixCertainty::Default)
        }
    };

    finish(&labels, count, suffix, suffix_labels, certainty)
}

/// Assemble le résultat à partir du suffixe retenu.
fn finish(
    labels: &[&str],
    count: usize,
    suffix: String,
    suffix_labels: usize,
    certainty: SuffixCertainty,
) -> DomainInfo {
    // Le domaine enregistrable est le suffixe public **plus un label** à gauche.
    let registrable = if count > suffix_labels {
        Some(join(labels, count - suffix_labels - 1))
    } else {
        None
    };

    DomainInfo {
        public_suffix: if suffix.is_empty() {
            None
        } else {
            Some(suffix)
        },
        registrable,
        certainty,
    }
}

/// Joint `labels[start..]` avec des points.
fn join(labels: &[&str], start: usize) -> String {
    labels.get(start..).unwrap_or(&[]).join(".")
}

/// Joint `labels[start..]` en évitant l'allocation quand on teste une appartenance.
///
/// Le `HashSet` ne peut pas être interrogé sur une tranche : on construit la chaîne,
/// ce qui est borné par le nombre de labels (≤ 16).
fn join_raw(labels: &[&str], start: usize) -> Box<str> {
    join(labels, start).into_boxed_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(host: &str) -> (Option<String>, Option<String>, SuffixCertainty) {
        let info = registrable_domain(host);
        (info.public_suffix, info.registrable, info.certainty)
    }

    #[test]
    fn a_simple_icann_suffix_is_found() {
        let (public, registrable, certainty) = suffix("exemple.com");
        assert_eq!(public.as_deref(), Some("com"));
        assert_eq!(registrable.as_deref(), Some("exemple.com"));
        assert_eq!(certainty, SuffixCertainty::Exact);
    }

    #[test]
    fn a_multi_label_suffix_is_matched_by_the_longest_rule() {
        let (public, registrable, certainty) = suffix("login.exemple.co.uk");
        assert_eq!(public.as_deref(), Some("co.uk"));
        assert_eq!(registrable.as_deref(), Some("exemple.co.uk"));
        assert_eq!(certainty, SuffixCertainty::Exact);
    }

    #[test]
    fn the_host_equal_to_a_suffix_has_no_registrable_domain() {
        let (public, registrable, certainty) = suffix("co.uk");
        assert_eq!(public.as_deref(), Some("co.uk"));
        assert_eq!(registrable, None);
        assert_eq!(certainty, SuffixCertainty::Exact);
    }

    #[test]
    fn a_private_suffix_separates_tenants() {
        // `github.io` est un suffixe **privé** : les deux hôtes sont deux sites
        // distincts, et le domaine enregistrable inclut le locataire.
        let (public, registrable, certainty) = suffix("a.github.io");
        assert_eq!(public.as_deref(), Some("github.io"));
        assert_eq!(registrable.as_deref(), Some("a.github.io"));
        assert_eq!(certainty, SuffixCertainty::Exact);

        assert_ne!(
            registrable_domain("a.github.io").registrable,
            registrable_domain("b.github.io").registrable
        );
    }

    #[test]
    fn a_wildcard_rule_matches_exactly_one_label() {
        // `*.ck` : `a.ck` est un suffixe public (pas de domaine enregistrable),
        // `b.a.ck` a pour domaine enregistrable `b.a.ck`.
        let (public, registrable, certainty) = suffix("a.ck");
        assert_eq!(public.as_deref(), Some("a.ck"));
        assert_eq!(registrable, None);
        assert_eq!(certainty, SuffixCertainty::Wildcard);

        let (public, registrable, _) = suffix("b.a.ck");
        assert_eq!(public.as_deref(), Some("a.ck"));
        assert_eq!(registrable.as_deref(), Some("b.a.ck"));
    }

    #[test]
    fn an_exception_rule_removes_the_leftmost_label() {
        // `!www.ck` : `www.ck` n'est pas un suffixe public, il devient enregistrable.
        let (public, registrable, certainty) = suffix("www.ck");
        assert_eq!(public.as_deref(), Some("ck"));
        assert_eq!(registrable.as_deref(), Some("www.ck"));
        assert_eq!(certainty, SuffixCertainty::Exception);

        let (public, registrable, _) = suffix("a.www.ck");
        assert_eq!(public.as_deref(), Some("ck"));
        assert_eq!(registrable.as_deref(), Some("www.ck"));
    }

    #[test]
    fn an_unknown_suffix_falls_back_to_the_default_and_is_uncertain() {
        let (public, registrable, certainty) = suffix("foo.invalidtld");
        assert_eq!(public.as_deref(), Some("invalidtld"));
        assert_eq!(registrable.as_deref(), Some("foo.invalidtld"));
        assert_eq!(certainty, SuffixCertainty::Default);
        assert!(!certainty.is_known(), "un suffixe par défaut est incertain");
    }

    #[test]
    fn a_single_label_host_is_uncertain_and_has_no_registrable_domain() {
        let (_, registrable, certainty) = suffix("localhost");
        assert_eq!(registrable, None);
        assert_eq!(certainty, SuffixCertainty::Default);
    }

    #[test]
    fn an_empty_host_is_not_applicable() {
        let info = registrable_domain("");
        assert_eq!(info, DomainInfo::not_applicable());
    }

    #[test]
    fn a_unicode_rule_is_matched_through_its_a_label() {
        // La liste contient `aéroport.ci` en **U-label** ; l'hôte est normalisé en
        // A-label, donc la règle doit l'être aussi pour correspondre.
        let (public, registrable, certainty) = suffix("www.xn--aroport-bya.ci");
        assert_eq!(public.as_deref(), Some("xn--aroport-bya.ci"));
        assert_eq!(registrable.as_deref(), Some("www.xn--aroport-bya.ci"));
        assert_eq!(certainty, SuffixCertainty::Exact);
    }

    #[test]
    fn the_embedded_list_is_parsed() {
        // Sanity check : la liste contient des règles des deux sections.
        assert!(rules().exact.contains("com"));
        assert!(rules().exact.contains("co.uk"));
        assert!(
            rules().exact.contains("github.io"),
            "section PRIVATE attendue"
        );
        assert!(rules().wildcard_parents.contains("ck"));
        assert!(rules().exceptions.contains("www.ck"));
    }
}
