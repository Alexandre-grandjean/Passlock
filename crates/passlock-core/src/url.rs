//! Analyse d'URL **locale**, **pure** et **bornée**.
//!
//! # Ce que ce module fait — et ne fait pas
//!
//! Il prend une **chaîne** et rend un **verdict explicable** par une liste de
//! motifs : **aucun score numérique global**, aucune donnée sensible inutile.
//!
//! Il ne fait **aucun** accès réseau, DNS, WHOIS, certificat ou réputation : il
//! n'ouvre aucun fichier, ne lit aucune horloge et n'a **aucun** état. Il est donc
//! testable sans déverrouiller un coffre.
//!
//! # IDN : conversions, **pas** validation IDNA
//!
//! Le module sait convertir un label Unicode (U-label) en A-label `xn--…` **pour la
//! recherche PSL**, et décoder un A-label pour l'**analyse de scripts**. Mais il
//! **n'implémente pas** IDNA2008/UTS#46 : ni tables de points de code, ni NFC, ni
//! Bidi/ContextJ. Un label non-ASCII dont la validité IDNA complète n'est **pas**
//! établie ne peut donc **jamais**, à lui seul, produire un verdict `Clean` : il
//! produit [`Motif::IdnaNotFullyValidated`] et un verdict **`Indeterminate`**.
//! Le simple encodage Punycode **n'est pas** une validation IDNA.
//!
//! # Bornes
//!
//! Toutes les bornes DNS sont mesurées sur la forme **A-label** (minuscules) ; la
//! borne d'entrée, sur les **octets UTF-8 bruts**.

use crate::encoding;
use crate::psl::{self, DomainInfo, SuffixCertainty};

// ---------------------------------------------------------------------------
// Bornes
// ---------------------------------------------------------------------------

/// Longueur maximale de l'entrée, en **octets UTF-8 bruts**.
pub const MAX_URL_LEN: usize = 4096;
/// Nombre maximal de labels d'un hôte DNS.
pub const MAX_LABELS: usize = 16;
/// Longueur maximale d'un label, en **octets A-label**.
pub const MAX_LABEL_LEN: usize = 63;
/// Longueur maximale d'un hôte DNS, en **octets A-label** (sans point final).
pub const MAX_HOST_LEN: usize = 253;
/// Nombre de labels au-delà duquel on signale `ExcessiveLabels`.
pub const EXCESSIVE_LABELS: usize = 5;
/// Longueur maximale d'un schéma.
const MAX_SCHEME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Verdict global — une **catégorie**, jamais un score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Rien de signalé.
    Clean,
    /// Au moins un motif fort est présent (`MixedScriptInLabel`, `UserInfoPresent`,
    /// `ExcessiveLabels`).
    Suspicious,
    /// L'hôte est analysable mais un élément n'a pas pu être établi (suffixe hors
    /// liste, Punycode invalide, validité IDNA non établie).
    Indeterminate,
    /// Pas d'hôte analysable (entrée refusée, vide, ou adresse IP).
    NotApplicable,
}

/// Nature de l'hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// Nom de domaine (analyse PSL applicable).
    Dns,
    /// Adresse IPv4 (hors eTLD+1).
    Ipv4,
    /// Adresse IPv6 (hors eTLD+1).
    Ipv6,
}

/// Motif **explicable** d'un verdict. Aucun motif n'est un score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motif {
    /// Aucun hôte dans l'entrée.
    NoHost,
    /// L'hôte ou l'autorité est mal formé.
    MalformedHost,
    /// L'entrée dépasse [`MAX_URL_LEN`].
    TooLong,
    /// Une information d'identification précède l'hôte (`user@host`).
    UserInfoPresent,
    /// Un label `xn--…` n'est pas un A-label Punycode valide.
    InvalidPunycode {
        /// Index du label fautif.
        label: usize,
    },
    /// Un label Unicode n'a pas pu être converti proprement en A-label.
    InvalidUnicodeLabel {
        /// Index du label fautif.
        label: usize,
    },
    /// Un label contient des caractères non ASCII (informatif).
    NonAsciiLabel {
        /// Index du label.
        label: usize,
    },
    /// Un label mêle plusieurs écritures classées (latin, cyrillique, grec).
    MixedScriptInLabel {
        /// Index du label.
        label: usize,
    },
    /// La validité IDNA complète d'un label non-ASCII **n'a pas été établie**.
    IdnaNotFullyValidated,
    /// L'hôte porte plus de [`EXCESSIVE_LABELS`] labels.
    ExcessiveLabels {
        /// Nombre de labels.
        count: usize,
    },
    /// Le suffixe est absent de la liste embarquée : regroupement **incertain**.
    UnknownSuffix,
}

impl Motif {
    /// Rang d'affichage, pour un ordre **déterministe**.
    const fn rank(&self) -> u8 {
        match self {
            Self::NoHost => 0,
            Self::MalformedHost => 1,
            Self::TooLong => 2,
            Self::UserInfoPresent => 3,
            Self::InvalidPunycode { .. } => 4,
            Self::InvalidUnicodeLabel { .. } => 5,
            Self::NonAsciiLabel { .. } => 6,
            Self::MixedScriptInLabel { .. } => 7,
            Self::IdnaNotFullyValidated => 8,
            Self::ExcessiveLabels { .. } => 9,
            Self::UnknownSuffix => 10,
        }
    }

    /// Vrai si le motif rend le verdict `Indeterminate`.
    const fn is_indeterminate(&self) -> bool {
        matches!(
            self,
            Self::UnknownSuffix
                | Self::InvalidPunycode { .. }
                | Self::InvalidUnicodeLabel { .. }
                | Self::IdnaNotFullyValidated
        )
    }

    /// Vrai si le motif rend le verdict `Suspicious`.
    const fn is_suspicious(&self) -> bool {
        matches!(
            self,
            Self::UserInfoPresent | Self::MixedScriptInLabel { .. } | Self::ExcessiveLabels { .. }
        )
    }

    /// Vrai si le motif est un **refus structurel** : l'hôte n'est pas analysable.
    const fn is_refusal(&self) -> bool {
        matches!(self, Self::NoHost | Self::MalformedHost | Self::TooLong)
    }
}

/// Résultat complet d'une analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlVerdict {
    /// Verdict global.
    pub verdict: Verdict,
    /// Schéma, en minuscules, s'il était présent.
    pub scheme: Option<String>,
    /// Hôte normalisé (**A-label**, minuscules).
    pub host: Option<String>,
    /// Hôte sous forme Unicode (décodée), pour l'analyse et l'affichage.
    pub host_unicode: Option<String>,
    /// Nature de l'hôte.
    pub host_kind: HostKind,
    /// Port, s'il était présent.
    pub port: Option<u16>,
    /// Vrai si une information d'identification précédait l'hôte.
    pub had_userinfo: bool,
    /// Domaine enregistrable et suffixe public, si applicable.
    pub domain: Option<DomainInfo>,
    /// Motifs, dans un ordre déterministe.
    pub motifs: Vec<Motif>,
}

// ---------------------------------------------------------------------------
// Analyse
// ---------------------------------------------------------------------------

/// Analyse une URL ou un hôte, **sans E/S, sans réseau, sans horloge**.
#[must_use]
pub fn analyze(input: &str) -> UrlVerdict {
    match parse(input) {
        Ok(parsed) => finish(parsed),
        Err(refusal) => refusal.into_verdict(),
    }
}

/// Hôte analysé, avant décision de verdict.
struct Parsed {
    scheme: Option<String>,
    host: String,
    host_unicode: String,
    host_kind: HostKind,
    port: Option<u16>,
    had_userinfo: bool,
    domain: Option<DomainInfo>,
    motifs: Vec<Motif>,
    /// Vrai si un label DNS n'a pas pu être normalisé : l'hôte n'est pas publiable.
    dns_broken: bool,
}

/// Refus, avec ce qui a pu être observé avant.
struct Refusal {
    scheme: Option<String>,
    had_userinfo: bool,
    host_kind: HostKind,
    motifs: Vec<Motif>,
}

impl Refusal {
    fn into_verdict(mut self) -> UrlVerdict {
        sort_motifs(&mut self.motifs);
        UrlVerdict {
            verdict: verdict_for(&self.motifs, false),
            scheme: self.scheme,
            host: None,
            host_unicode: None,
            host_kind: self.host_kind,
            port: None,
            had_userinfo: self.had_userinfo,
            domain: None,
            motifs: self.motifs,
        }
    }
}

fn malformed(scheme: Option<String>, had_userinfo: bool, motif: Motif) -> Refusal {
    Refusal {
        scheme,
        had_userinfo,
        host_kind: HostKind::Dns,
        motifs: vec![motif],
    }
}

fn sort_motifs(motifs: &mut [Motif]) {
    motifs.sort_by_key(Motif::rank);
}

fn verdict_for(motifs: &[Motif], has_host: bool) -> Verdict {
    if !has_host {
        return Verdict::NotApplicable;
    }
    if motifs.iter().any(Motif::is_suspicious) {
        Verdict::Suspicious
    } else if motifs.iter().any(Motif::is_indeterminate) {
        Verdict::Indeterminate
    } else {
        Verdict::Clean
    }
}

fn finish(mut parsed: Parsed) -> UrlVerdict {
    sort_motifs(&mut parsed.motifs);

    // Une adresse IP n'a ni suffixe public ni domaine enregistrable.
    if parsed.host_kind != HostKind::Dns {
        return UrlVerdict {
            verdict: Verdict::NotApplicable,
            scheme: parsed.scheme,
            host: Some(parsed.host),
            host_unicode: Some(parsed.host_unicode),
            host_kind: parsed.host_kind,
            port: parsed.port,
            had_userinfo: parsed.had_userinfo,
            domain: None,
            motifs: parsed.motifs,
        };
    }

    // Un refus structurel rend l'hôte inanalysable ; un hôte dont un label n'a pas
    // pu être normalisé reste analysable **pour le verdict**, mais son nom n'est
    // pas publiable (`host` reste `None`).
    let structural_refusal = parsed.motifs.iter().any(Motif::is_refusal);
    let verdict = verdict_for(&parsed.motifs, !structural_refusal);
    let emit_host = !structural_refusal && !parsed.dns_broken;

    UrlVerdict {
        verdict,
        scheme: parsed.scheme,
        host: if emit_host { Some(parsed.host) } else { None },
        host_unicode: if emit_host {
            Some(parsed.host_unicode)
        } else {
            None
        },
        host_kind: parsed.host_kind,
        port: parsed.port,
        had_userinfo: parsed.had_userinfo,
        domain: parsed.domain,
        motifs: parsed.motifs,
    }
}

#[allow(clippy::too_many_lines)]
fn parse(input: &str) -> Result<Parsed, Refusal> {
    if input.len() > MAX_URL_LEN {
        return Err(malformed(None, false, Motif::TooLong));
    }
    if input.is_empty() {
        return Err(malformed(None, false, Motif::NoHost));
    }

    // --- Schéma optionnel -------------------------------------------------
    let (scheme, remainder) = match input.find("://") {
        Some(index) => {
            let candidate = &input[..index];
            if !is_valid_scheme(candidate) {
                return Err(malformed(None, false, Motif::MalformedHost));
            }
            (
                Some(candidate.to_ascii_lowercase()),
                &input[index + "://".len()..],
            )
        }
        None => (None, input),
    };

    // Un **hôte nu** n'accepte aucun composant d'URL : ni chemin, ni requête, ni
    // fragment, ni userinfo, ni port.
    if scheme.is_none() && input.contains(['/', '?', '#', '@', ':']) {
        return Err(malformed(None, false, Motif::MalformedHost));
    }

    // --- Autorité ---------------------------------------------------------
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];

    let (userinfo, hostport) = match authority.rfind('@') {
        Some(index) => (Some(&authority[..index]), &authority[index + 1..]),
        None => (None, authority),
    };
    let had_userinfo = userinfo.is_some();

    let mut motifs = Vec::new();
    if had_userinfo {
        motifs.push(Motif::UserInfoPresent);
    }

    // --- Hôte et port -----------------------------------------------------
    let (host_raw, port, is_ipv6) = if let Some(rest) = hostport.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(malformed(scheme, had_userinfo, Motif::MalformedHost));
        };
        let inner = &rest[..close];
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            None
        } else if let Some(digits) = after.strip_prefix(':') {
            Some(
                parse_port(digits)
                    .ok_or_else(|| malformed(scheme.clone(), had_userinfo, Motif::MalformedHost))?,
            )
        } else {
            return Err(malformed(scheme, had_userinfo, Motif::MalformedHost));
        };
        (inner, port, true)
    } else if let Some((raw_host, digits)) = hostport.split_once(':') {
        let port = parse_port(digits)
            .ok_or_else(|| malformed(scheme.clone(), had_userinfo, Motif::MalformedHost))?;
        (raw_host, Some(port), false)
    } else {
        (hostport, None, false)
    };

    if host_raw.is_empty() {
        return Err(malformed(scheme, had_userinfo, Motif::NoHost));
    }

    if is_ipv6 {
        if !looks_like_ipv6(host_raw) {
            return Err(malformed(scheme, had_userinfo, Motif::MalformedHost));
        }
        let host = host_raw.to_ascii_lowercase();
        return Ok(Parsed {
            scheme,
            host_unicode: host.clone(),
            host,
            host_kind: HostKind::Ipv6,
            port,
            had_userinfo,
            domain: None,
            motifs,
            dns_broken: false,
        });
    }

    // Point final : **un seul** est retiré (FQDN) ; deux sont malformés.
    let host_lowered = host_raw.to_ascii_lowercase();
    let host_lowered = match host_lowered.strip_suffix('.') {
        Some(stripped) => {
            if stripped.ends_with('.') {
                return Err(malformed(scheme, had_userinfo, Motif::MalformedHost));
            }
            stripped.to_owned()
        }
        None => host_lowered,
    };

    if host_lowered.is_empty() {
        return Err(malformed(scheme, had_userinfo, Motif::NoHost));
    }

    // IPv4 « en pointillés » : quatre octets décimaux, sans zéro de tête.
    if let Some(_address) = parse_ipv4(&host_lowered) {
        return Ok(Parsed {
            scheme,
            host_unicode: host_lowered.clone(),
            host: host_lowered,
            host_kind: HostKind::Ipv4,
            port,
            had_userinfo,
            domain: None,
            motifs,
            dns_broken: false,
        });
    }

    // --- Hôte DNS et IDN --------------------------------------------------
    let analysis = analyze_dns_host(&host_lowered, &mut motifs);
    Ok(Parsed {
        scheme,
        host: analysis.a_label,
        host_unicode: analysis.unicode,
        host_kind: HostKind::Dns,
        port,
        had_userinfo,
        domain: analysis.domain,
        motifs,
        dns_broken: analysis.broken,
    })
}

/// Résultat de l'analyse d'un hôte DNS.
struct DnsAnalysis {
    a_label: String,
    unicode: String,
    domain: Option<DomainInfo>,
    broken: bool,
}

#[allow(clippy::too_many_lines)]
fn analyze_dns_host(host: &str, motifs: &mut Vec<Motif>) -> DnsAnalysis {
    let labels: Vec<&str> = host.split('.').collect();

    if labels.len() > MAX_LABELS {
        motifs.push(Motif::TooLong);
        return DnsAnalysis {
            a_label: String::new(),
            unicode: String::new(),
            domain: None,
            broken: true,
        };
    }

    let mut a_labels: Vec<String> = Vec::with_capacity(labels.len());
    let mut unicode_labels: Vec<String> = Vec::with_capacity(labels.len());
    let mut idn_seen = false;
    let mut broken = false;

    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() {
            motifs.push(Motif::MalformedHost);
            broken = true;
            continue;
        }

        if label.is_ascii() {
            // Longueur DNS d'un label ASCII, en octets A-label.
            if label.len() > MAX_LABEL_LEN {
                motifs.push(Motif::MalformedHost);
                broken = true;
                continue;
            }
            if let Some(payload) = label.strip_prefix("xn--") {
                // Candidat A-label : on **valide** par décodage + aller-retour.
                match encoding::punycode_decode(payload) {
                    Ok(decoded)
                        if !decoded.is_empty()
                            && !decoded.is_ascii()
                            && encoding::punycode_encode(&decoded)
                                .is_ok_and(|re| re == payload) =>
                    {
                        idn_seen = true;
                        a_labels.push((*label).to_owned());
                        unicode_labels.push(decoded);
                    }
                    _ => {
                        motifs.push(Motif::InvalidPunycode { label: index });
                        broken = true;
                    }
                }
            } else if !is_ldh(label) {
                motifs.push(Motif::MalformedHost);
                broken = true;
            } else {
                a_labels.push((*label).to_owned());
                unicode_labels.push((*label).to_owned());
            }
        } else {
            // U-label : encodé en A-label **pour la PSL uniquement**.
            match encoding::punycode_encode(label) {
                Ok(payload) if payload.len() + "xn--".len() <= MAX_LABEL_LEN => {
                    idn_seen = true;
                    a_labels.push(format!("xn--{payload}"));
                    unicode_labels.push((*label).to_owned());
                }
                _ => {
                    motifs.push(Motif::InvalidUnicodeLabel { label: index });
                    broken = true;
                }
            }
        }
    }

    // Longueur DNS de l'hôte, mesurée sur la forme **A-label**.
    if !broken {
        let host_len: usize =
            a_labels.iter().map(String::len).sum::<usize>() + a_labels.len().saturating_sub(1);
        if host_len > MAX_HOST_LEN {
            motifs.push(Motif::TooLong);
            broken = true;
        }
    }

    // Analyse de scripts et confusables, sur la forme **Unicode**.
    for (index, label) in unicode_labels.iter().enumerate() {
        if !label.is_ascii() {
            motifs.push(Motif::NonAsciiLabel { label: index });
            if label_is_mixed_script(label) {
                motifs.push(Motif::MixedScriptInLabel { label: index });
            }
        }
    }

    if labels.len() > EXCESSIVE_LABELS {
        motifs.push(Motif::ExcessiveLabels {
            count: labels.len(),
        });
    }

    if idn_seen {
        // La validité IDNA complète n'a **pas** été établie : on ne peut pas
        // conclure à un verdict `Clean` sur un label non-ASCII.
        motifs.push(Motif::IdnaNotFullyValidated);
    }

    let a_label = a_labels.join(".");
    let unicode = unicode_labels.join(".");

    let domain = if broken {
        None
    } else {
        let info = psl::registrable_domain(&a_label);
        if info.certainty == SuffixCertainty::Default {
            motifs.push(Motif::UnknownSuffix);
        }
        Some(info)
    };

    DnsAnalysis {
        a_label,
        unicode,
        domain,
        broken,
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Vrai si la chaîne est un schéma valide (RFC 3986).
fn is_valid_scheme(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > MAX_SCHEME_LEN {
        return false;
    }
    let mut chars = candidate.chars();
    let first = chars.next().unwrap_or('0');
    if !first.is_ascii_alphabetic() {
        return false;
    }
    candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Vrai si un label ASCII respecte LDH (lettres, chiffres, tirets internes).
fn is_ldh(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Analyse un port décimal, `1..=65535`.
fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u32 = digits.parse().ok()?;
    if value == 0 || value > u32::from(u16::MAX) {
        return None;
    }
    u16::try_from(value).ok()
}

/// Reconnaît une IPv4 « en pointillés », strictement (pas de zéro de tête).
fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0_u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        octets[index] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

/// Vérification **syntaxique** minimale d'une IPv6 entre crochets.
///
/// Le module n'a pas besoin de valider complètement une IPv6 (il ne l'analyse pas) :
/// il vérifie qu'elle a la forme attendue, pour ne pas accepter n'importe quoi.
fn looks_like_ipv6(host: &str) -> bool {
    !host.is_empty()
        && host.contains(':')
        && host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'))
}

/// Écriture d'un caractère, parmi celles que ce module classe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
}

/// Classe un caractère dans une écriture, sur des **plages bornées** et documentées.
///
/// Tout caractère hors de ces plages n'est **pas** classé : il ne peut donc pas
/// déclencher `MixedScriptInLabel`. C'est volontaire — on ne généralise pas.
fn script_of(character: char) -> Option<Script> {
    let code = u32::from(character);
    match code {
        // Latin : ASCII, extensions A/B et latin additionnel.
        0x0041..=0x005A | 0x0061..=0x007A | 0x0100..=0x024F | 0x1E00..=0x1EFF => {
            Some(Script::Latin)
        }
        // Latin-1 : hors signes de multiplication (×) et de division (÷).
        0x00C0..=0x00FF => {
            if code == 0x00D7 || code == 0x00F7 {
                None
            } else {
                Some(Script::Latin)
            }
        }
        // Grec.
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Some(Script::Greek),
        // Cyrillique.
        0x0400..=0x052F => Some(Script::Cyrillic),
        _ => None,
    }
}

/// Vrai si un label mêle **au moins deux** écritures classées.
fn label_is_mixed_script(label: &str) -> bool {
    let mut seen = [false; 3];
    for character in label.chars() {
        match script_of(character) {
            Some(Script::Latin) => seen[0] = true,
            Some(Script::Cyrillic) => seen[1] = true,
            Some(Script::Greek) => seen[2] = true,
            None => {}
        }
    }
    seen.iter().filter(|present| **present).count() >= 2
}

/// Repli **confusable** d'une chaîne, pour **comparer** deux valeurs.
///
/// Ensemble **exact**, sans généralisation :
///
/// * `l`, `I`, `1` → `l` ;
/// * `0`, `O` → `o` ;
/// * `a` latin et `а` cyrillique (U+0430) → `a` ;
/// * la séquence `rn` → `m`.
///
/// La fonction est **sensible à la casse** : l'ensemble ci-dessus est exactement
/// celui défini, et rien de plus. Elle ne produit **aucun** motif à elle seule :
/// `login`, `corner` ou `0auth` sont légitimes. Sans **référence** (une marque),
/// une substitution confusable n'est pas une preuve.
#[must_use]
pub fn fold_confusables(input: &str) -> String {
    let mut folded = String::with_capacity(input.len());
    for character in input.chars() {
        folded.push(match character {
            'l' | 'I' | '1' => 'l',
            '0' | 'O' => 'o',
            'a' | '\u{0430}' => 'a',
            other => other,
        });
    }
    folded.replace("rn", "m")
}

/// Vrai si deux chaînes ne diffèrent que par des caractères confusables prévus.
#[must_use]
pub fn is_confusable_with(left: &str, right: &str) -> bool {
    left != right && fold_confusables(left) == fold_confusables(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn motifs_of(input: &str) -> Vec<Motif> {
        analyze(input).motifs
    }

    #[test]
    fn a_clean_ascii_url_is_clean() {
        let verdict = analyze("https://login.exemple.co.uk/path?q=1#frag");
        assert_eq!(verdict.verdict, Verdict::Clean);
        assert_eq!(verdict.host.as_deref(), Some("login.exemple.co.uk"));
        assert_eq!(verdict.scheme.as_deref(), Some("https"));
        assert!(verdict.motifs.is_empty(), "{:?}", verdict.motifs);
        let domain = verdict.domain.expect("domaine");
        assert_eq!(domain.registrable.as_deref(), Some("exemple.co.uk"));
    }

    #[test]
    fn a_bare_host_is_accepted() {
        let verdict = analyze("exemple.com");
        assert_eq!(verdict.verdict, Verdict::Clean);
        assert_eq!(verdict.scheme, None);
        assert_eq!(verdict.host.as_deref(), Some("exemple.com"));
    }

    #[test]
    fn a_bare_host_with_a_component_is_malformed() {
        for input in [
            "exemple.com/path",
            "exemple.com?q",
            "exemple.com#f",
            "a@b",
            "exemple.com:80",
        ] {
            let verdict = analyze(input);
            assert_eq!(verdict.verdict, Verdict::NotApplicable, "{input}");
            assert!(verdict.motifs.contains(&Motif::MalformedHost), "{input}");
        }
    }

    #[test]
    fn a_single_trailing_dot_is_removed_and_two_are_refused() {
        assert_eq!(analyze("exemple.com.").host.as_deref(), Some("exemple.com"));
        assert_eq!(analyze("exemple.com..").verdict, Verdict::NotApplicable);
    }

    #[test]
    fn ports_and_userinfo_are_parsed() {
        let verdict = analyze("https://exemple.com:8080/x");
        assert_eq!(verdict.port, Some(8080));
        assert_eq!(verdict.host.as_deref(), Some("exemple.com"));
        assert!(!verdict.had_userinfo);

        let verdict = analyze("https://user:pass@evil.com/");
        assert!(verdict.had_userinfo);
        assert_eq!(verdict.host.as_deref(), Some("evil.com"));
        assert!(verdict.motifs.contains(&Motif::UserInfoPresent));
        assert_eq!(verdict.verdict, Verdict::Suspicious);

        assert_eq!(
            analyze("https://exemple.com:0/x").verdict,
            Verdict::NotApplicable
        );
        assert_eq!(
            analyze("https://exemple.com:99999/x").verdict,
            Verdict::NotApplicable
        );
    }

    #[test]
    fn ip_addresses_have_no_registrable_domain() {
        let verdict = analyze("http://192.168.1.1/");
        assert_eq!(verdict.host_kind, HostKind::Ipv4);
        assert!(verdict.domain.is_none());
        assert_eq!(verdict.verdict, Verdict::NotApplicable);

        let verdict = analyze("http://[2001:db8::1]/");
        assert_eq!(verdict.host_kind, HostKind::Ipv6);
        assert!(verdict.domain.is_none());

        // IPv4 invalide (octet > 255) : traité comme un hôte DNS, pas comme une IP.
        assert_eq!(analyze("http://999.1.1.1/").host_kind, HostKind::Dns);
    }

    #[test]
    fn empty_and_malformed_inputs_never_panic() {
        for input in [
            "",
            "http://",
            "http:///",
            "://x",
            "http://:80",
            "[::1",
            "\u{0}",
        ] {
            let verdict = analyze(input);
            assert_ne!(verdict.verdict, Verdict::Suspicious, "{input}");
        }
        assert_eq!(analyze("").verdict, Verdict::NotApplicable);
        assert!(motifs_of("").contains(&Motif::NoHost));
    }

    #[test]
    fn an_oversized_input_is_refused_before_analysis() {
        let huge = "a".repeat(MAX_URL_LEN + 1);
        let verdict = analyze(&huge);
        assert!(verdict.motifs.contains(&Motif::TooLong));
        assert_eq!(verdict.verdict, Verdict::NotApplicable);
    }

    #[test]
    fn too_many_labels_are_signalled() {
        // Huit labels (a, b, c, d, e, f, exemple, com).
        let verdict = analyze("a.b.c.d.e.f.exemple.com");
        assert!(
            verdict
                .motifs
                .contains(&Motif::ExcessiveLabels { count: 8 })
        );
        assert_eq!(verdict.verdict, Verdict::Suspicious);
    }

    #[test]
    fn a_long_path_does_not_affect_the_host() {
        let path = "x".repeat(2000);
        let verdict = analyze(&format!("https://exemple.com/{path}"));
        assert_eq!(verdict.host.as_deref(), Some("exemple.com"));
        assert_eq!(verdict.verdict, Verdict::Clean);
    }

    #[test]
    fn mixed_script_labels_are_suspicious() {
        // « eхаmple » avec un « х » cyrillique (U+0445).
        let verdict = analyze("e\u{0445}ample.com");
        assert_eq!(verdict.verdict, Verdict::Suspicious);
        assert!(
            verdict
                .motifs
                .iter()
                .any(|m| matches!(m, Motif::MixedScriptInLabel { .. })),
            "{:?}",
            verdict.motifs
        );
    }

    #[test]
    fn a_single_script_idn_is_indeterminate_but_not_suspicious() {
        // « münchen.de » : latin + diacritique, une seule écriture.
        let verdict = analyze("münchen.de");
        assert_eq!(verdict.verdict, Verdict::Indeterminate);
        assert!(verdict.motifs.contains(&Motif::IdnaNotFullyValidated));
        assert!(
            !verdict
                .motifs
                .iter()
                .any(|m| matches!(m, Motif::MixedScriptInLabel { .. }))
        );
        let domain = verdict.domain.expect("domaine");
        assert_eq!(domain.registrable.as_deref(), Some("xn--mnchen-3ya.de"));
    }

    #[test]
    fn a_label_and_its_a_label_form_agree() {
        let u = analyze("münchen.de");
        let a = analyze("xn--mnchen-3ya.de");
        assert_eq!(u.host.as_deref(), a.host.as_deref());
        assert_eq!(u.verdict, a.verdict);
        assert_eq!(
            u.domain.expect("u").registrable,
            a.domain.expect("a").registrable
        );
    }

    #[test]
    fn an_invalid_punycode_label_is_indeterminate() {
        let verdict = analyze("xn--a-.com");
        assert_eq!(verdict.verdict, Verdict::Indeterminate);
        assert!(
            verdict
                .motifs
                .iter()
                .any(|m| matches!(m, Motif::InvalidPunycode { .. })),
            "{:?}",
            verdict.motifs
        );
    }

    #[test]
    fn confusable_folding_is_exact_and_case_sensitive() {
        assert_eq!(fold_confusables("rnicrosoft"), "microsoft");
        assert_eq!(fold_confusables("examp1e"), "example");
        assert_eq!(fold_confusables("g00gle"), "google");
        assert_eq!(fold_confusables("pаypal"), "paypal"); // « а » cyrillique
        assert!(is_confusable_with("rnicrosoft.com", "microsoft.com"));
        assert!(!is_confusable_with("login.com", "login.com"));
        // `O` est dans la classe de `0` : les deux se replient sur `o`.
        assert!(is_confusable_with("gOogle.com", "g00gle.com"));
        // `L` majuscule n'appartient **pas** à la classe `{l, I, 1}` : la fonction
        // est sensible à la casse, exactement selon l'ensemble défini.
        assert!(!is_confusable_with("L.com", "l.com"));
    }

    #[test]
    fn the_motif_order_is_deterministic() {
        let first = analyze("https://u@e\u{0445}ample.madeuptld/p").motifs;
        let second = analyze("https://u@e\u{0445}ample.madeuptld/p").motifs;
        assert_eq!(first, second);
        // Rangs croissants.
        let ranks: Vec<u8> = first.iter().map(Motif::rank).collect();
        assert!(ranks.windows(2).all(|pair| pair[0] <= pair[1]));
    }
}
