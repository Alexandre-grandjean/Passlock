//! Centre de sécurité : six indicateurs calculés sur un coffre déjà déchiffré.
//!
//! # Ce que ce module fait — et ne fait pas
//!
//! Il **recalcule** ce qui est déjà dans le coffre et le présente. Il n'ajoute
//! **aucun** secret, **aucune** primitive cryptographique, et il n'écrit **rien**.
//! Il ne consulte que `Archive` et, pour une seule chose (l'empreinte de
//! réutilisation), une clé du coffre.
//!
//! Six indicateurs, **et six seulement** :
//!
//! | # | Indicateur |
//! |---|---|
//! | 1 | réutilisation de secrets |
//! | 2 | ancienneté (`updated_at` → `days_since`) |
//! | 3 | estimation heuristique de robustesse |
//! | 4 | entrées faibles |
//! | 5 | absence de TOTP |
//! | 6 | expiration (`expires_at`) |
//!
//! Le module ne calcule **aucun score global** et **aucun classement**. Les
//! diagnostics déjà produits ailleurs (paramètres KDF, retour en arrière,
//! permissions, durabilité, migration) ne sont **pas** repris ici.
//!
//! # Aucune horloge
//!
//! Toutes les fonctions sont **déterministes** : l'instant de référence est
//! **fourni** par l'appelant (secondes Unix, UTC). Aucune n'appelle l'horloge.
//!
//! # Ce qui ne sort jamais
//!
//! Aucun résultat ne contient la **valeur** d'un secret ni l'**empreinte** de
//! réutilisation. Le centre manipule des identifiants d'entrée, des références de
//! champ (`ordinal`, `genre`), des dates et des compteurs.
//!
//! # L'estimation de robustesse n'est pas une entropie
//!
//! C'est le point d'honnêteté central de ce module. La phase 3 calcule une
//! entropie **exacte** pour un secret **engendré** : elle connaît la longueur,
//! l'alphabet et les contraintes. Pour un secret **choisi par un humain**, ces
//! hypothèses n'existent pas. Le module ne les invente donc pas : il produit une
//! **heuristique structurelle**, nommée comme telle, qui compte des plages de
//! caractères et la diversité des classes ASCII observées. Elle est **aveugle aux
//! dictionnaires** et ne prétend jamais connaître l'entropie réelle. Voir
//! [`StrengthEstimate`].

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::KEY_LEN;
use crate::model::{Archive, EntryId, EntryKind, Field, FieldKind};
use crate::secret::Key;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Dates civiles
// ---------------------------------------------------------------------------

/// Première année acceptée par le format d'expiration.
pub const MIN_YEAR: u16 = 1970;
/// Dernière année acceptée par le format d'expiration.
pub const MAX_YEAR: u16 = 9999;

/// Borne basse du domaine de [`CivilDate::from_days`].
///
/// Le domaine est **volontairement large mais borné** : il couvre largement
/// `1970..9999` tout en garantissant que l'arithmétique interne ne peut pas
/// déborder, quelle que soit l'entrée — `i64::MIN` comme `i64::MAX`.
const MIN_DAY_NUMBER: i64 = -1_000_000;
/// Borne haute du domaine de [`CivilDate::from_days`].
const MAX_DAY_NUMBER: i64 = 3_000_000;

/// Une date civile, sans heure ni fuseau.
///
/// La comparaison se fait par **numéro de jour** (jours depuis le 1970-01-01), en
/// entiers : aucune comparaison de chaînes, aucune arithmétique flottante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CivilDate {
    /// Année (`1970..=9999` pour une date analysée).
    pub year: u16,
    /// Mois (`1..=12`).
    pub month: u8,
    /// Jour (`1..=31`, selon le mois).
    pub day: u8,
}

/// Motif d'échec de l'analyse d'une date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateError {
    /// La forme n'est pas exactement `YYYY-MM-DD` (longueur, séparateurs, chiffres,
    /// zéro de tête manquant).
    Shape,
    /// La forme est bonne mais l'année sort de `1970..=9999`.
    Range,
    /// La forme est bonne mais la date n'existe pas (`2026-02-30`, mois 13…).
    Impossible,
}

impl CivilDate {
    /// Construit une date **sans la valider**.
    ///
    /// Réservé aux tests et aux valeurs déjà validées ; l'entrée utilisateur passe
    /// par [`CivilDate::parse`].
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Self {
        Self { year, month, day }
    }

    /// Vrai si l'année est bissextile (calendrier grégorien).
    #[must_use]
    pub const fn is_leap(year: u16) -> bool {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    }

    /// Nombre de jours d'un mois, ou `None` si le mois est invalide.
    #[must_use]
    pub const fn days_in_month(year: u16, month: u8) -> Option<u8> {
        Some(match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if Self::is_leap(year) => 29,
            2 => 28,
            _ => return None,
        })
    }

    /// Analyse une date au format canonique strict `YYYY-MM-DD`.
    ///
    /// La forme est **exactement** dix octets : quatre chiffres, `-`, deux chiffres,
    /// `-`, deux chiffres. Aucun zéro de tête omis (`2026-2-3` est refusé), aucun
    /// caractère superflu. L'année doit tenir dans `1970..=9999` et la date doit
    /// exister dans le calendrier.
    ///
    /// # Erreurs
    /// [`DateError::Shape`], [`DateError::Range`] ou [`DateError::Impossible`].
    pub fn parse(text: &str) -> std::result::Result<Self, DateError> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(DateError::Shape);
        }

        let mut year: u32 = 0;
        for &byte in &bytes[0..4] {
            if !byte.is_ascii_digit() {
                return Err(DateError::Shape);
            }
            year = year * 10 + u32::from(byte - b'0');
        }

        let mut month: u32 = 0;
        for &byte in &bytes[5..7] {
            if !byte.is_ascii_digit() {
                return Err(DateError::Shape);
            }
            month = month * 10 + u32::from(byte - b'0');
        }

        let mut day: u32 = 0;
        for &byte in &bytes[8..10] {
            if !byte.is_ascii_digit() {
                return Err(DateError::Shape);
            }
            day = day * 10 + u32::from(byte - b'0');
        }

        if !(u32::from(MIN_YEAR)..=u32::from(MAX_YEAR)).contains(&year) {
            return Err(DateError::Range);
        }

        let year16 = u16::try_from(year).map_err(|_| DateError::Range)?;
        let month8 = u8::try_from(month).map_err(|_| DateError::Impossible)?;
        let day8 = u8::try_from(day).map_err(|_| DateError::Impossible)?;

        let limit = Self::days_in_month(year16, month8).ok_or(DateError::Impossible)?;
        if day8 == 0 || day8 > limit {
            return Err(DateError::Impossible);
        }

        Ok(Self::new(year16, month8, day8))
    }

    /// Numéro de jour depuis le 1970-01-01 (algorithme de Howard Hinnant).
    #[must_use]
    pub fn to_days(self) -> i64 {
        let month_shifted = i64::from(self.month);
        let day = i64::from(self.day);
        let year = i64::from(self.year);
        let year = if month_shifted <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let day_of_year =
            (153 * (if month_shifted > 2 {
                month_shifted - 3
            } else {
                month_shifted + 9
            }) + 2)
                / 5
                + day
                - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// Date civile correspondant à un numéro de jour.
    ///
    /// La fonction est **totale** : l'entrée est d'abord bornée au domaine
    /// `MIN_DAY_NUMBER..=MAX_DAY_NUMBER`, puis le résultat est ramené dans
    /// `1970..=9999`. Aucune entrée — `i64::MIN` comprise — ne peut provoquer de
    /// débordement, et le résultat est toujours une date valide. Dans le domaine
    /// utile (instants d'un coffre réel), la conversion est **exacte**.
    #[must_use]
    pub fn from_days(days: i64) -> Self {
        // Domaine borné : au-delà, l'arithmétique ci-dessous déborderait. Les valeurs
        // extrêmes sont ramenées aux bords — cohérent pour une conversion d'instants
        // plausibles, et sans panique possible.
        let days = days.clamp(MIN_DAY_NUMBER, MAX_DAY_NUMBER);

        let shifted = days + 719_468;
        let era = if shifted >= 0 {
            shifted
        } else {
            shifted - 146_096
        } / 146_097;
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = if month_prime < 10 {
            month_prime + 3
        } else {
            month_prime - 9
        };
        let year = if month <= 2 { year + 1 } else { year };

        // Ramené dans le domaine du format : le résultat est toujours valide.
        let year =
            u16::try_from(year.clamp(i64::from(MIN_YEAR), i64::from(MAX_YEAR))).unwrap_or(MIN_YEAR);
        let month = u8::try_from(month.clamp(1, 12)).unwrap_or(1);
        let limit = Self::days_in_month(year, month).unwrap_or(31);
        let day = u8::try_from(day.clamp(1, i64::from(limit))).unwrap_or(1);

        Self::new(year, month, day)
    }

    /// Date civile **UTC** d'un instant en secondes depuis l'époque Unix.
    #[must_use]
    pub fn from_unix_seconds(seconds: u64) -> Self {
        let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
        Self::from_days(days)
    }
}

impl std::fmt::Display for CivilDate {
    /// Forme canonique `YYYY-MM-DD`, exactement celle que [`CivilDate::parse`]
    /// accepte. C'est la valeur écrite dans un champ `expires_at`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:04}-{:02}-{:02}",
            self.year, self.month, self.day
        )
    }
}

// ---------------------------------------------------------------------------
// Indicateur 6 — expiration
// ---------------------------------------------------------------------------

/// Clé du champ portant la date d'expiration.
pub const EXPIRES_AT_KEY: &str = "expires_at";

/// Fenêtre d'alerte par défaut, en jours.
///
/// Valeur **affichée** par l'appelant, jamais une constante cachée : une date
/// d'expiration dans `[aujourd'hui, aujourd'hui + 30 jours]` est « bientôt
/// expirée ».
pub const DEFAULT_EXPIRY_WINDOW_DAYS: u32 = 30;

/// État d'expiration d'une entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryState {
    /// La date est passée.
    Expired,
    /// La date tombe aujourd'hui ou dans la fenêtre d'alerte.
    Soon,
    /// La date est au-delà de la fenêtre.
    Valid,
    /// Impossible de conclure.
    Unknown(ExpiryUnknown),
}

/// Motif d'un état d'expiration indéterminé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryUnknown {
    /// Aucun champ `expires_at`.
    Absent,
    /// Le champ existe mais n'est pas de genre `Date`.
    WrongKind,
    /// La valeur n'a pas la forme `YYYY-MM-DD`.
    Malformed,
    /// La date est hors bornes ou n'existe pas.
    Impossible,
    /// Plusieurs champs `expires_at` : ambigu.
    Ambiguous,
}

/// Détail d'expiration, pour l'affichage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryReport {
    /// Entrée concernée.
    pub entry: EntryId,
    /// État.
    pub state: ExpiryState,
    /// Date lue, si elle était analysable.
    pub date: Option<CivilDate>,
    /// Jours entre la référence et la date (négatif si passée).
    pub delta_days: Option<i64>,
}

/// Classe l'expiration d'une entrée.
///
/// **Sans horloge** : la date de référence et la fenêtre sont fournies. Le jour
/// d'expiration est **inclusif** : une date égale à la référence est `Soon` (delta
/// `0`), pas `Expired`.
#[must_use]
pub fn expiry_state(fields: &[Field], reference: CivilDate, window_days: u32) -> ExpiryState {
    classify_expiry(fields, reference, window_days).0
}

fn classify_expiry(
    fields: &[Field],
    reference: CivilDate,
    window_days: u32,
) -> (ExpiryState, Option<CivilDate>, Option<i64>) {
    let mut matches = fields.iter().filter(|field| field.key == EXPIRES_AT_KEY);
    let Some(field) = matches.next() else {
        return (ExpiryState::Unknown(ExpiryUnknown::Absent), None, None);
    };
    if matches.next().is_some() {
        return (ExpiryState::Unknown(ExpiryUnknown::Ambiguous), None, None);
    }
    if field.kind != FieldKind::Date {
        return (ExpiryState::Unknown(ExpiryUnknown::WrongKind), None, None);
    }

    let date = match CivilDate::parse(&field.value) {
        Ok(date) => date,
        Err(DateError::Shape) => {
            return (ExpiryState::Unknown(ExpiryUnknown::Malformed), None, None);
        }
        Err(DateError::Range | DateError::Impossible) => {
            return (ExpiryState::Unknown(ExpiryUnknown::Impossible), None, None);
        }
    };

    let delta = date.to_days() - reference.to_days();
    let state = if delta < 0 {
        ExpiryState::Expired
    } else if delta <= i64::from(window_days) {
        ExpiryState::Soon
    } else {
        ExpiryState::Valid
    };
    (state, Some(date), Some(delta))
}

fn expiry_reports(archive: &Archive, reference: CivilDate, window_days: u32) -> Vec<ExpiryReport> {
    let mut out: Vec<ExpiryReport> = archive
        .entries
        .iter()
        .filter(|entry| !entry.is_trashed())
        .map(|entry| {
            let (state, date, delta_days) = classify_expiry(&entry.fields, reference, window_days);
            ExpiryReport {
                entry: entry.id,
                state,
                date,
                delta_days,
            }
        })
        .collect();
    out.sort_by_key(|report| report.entry);
    out
}

// ---------------------------------------------------------------------------
// Indicateur 2 — ancienneté
// ---------------------------------------------------------------------------

/// Ancienneté d'une entrée.
///
/// **Aucune bande, aucun seuil** : c'est un fait, pas un jugement. Le délai est
/// calculé à partir d'un instant de référence **fourni**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgeInfo {
    /// Entrée concernée.
    pub entry: EntryId,
    /// Dernière modification, en secondes depuis l'époque Unix.
    pub updated_at: u64,
    /// Jours entiers écoulés depuis la modification.
    pub days_since: u64,
}

/// Calcule l'ancienneté de chaque entrée vivante.
#[must_use]
pub fn detect_age(archive: &Archive, now: u64) -> Vec<AgeInfo> {
    let mut out: Vec<AgeInfo> = archive
        .entries
        .iter()
        .filter(|entry| !entry.is_trashed())
        .map(|entry| AgeInfo {
            entry: entry.id,
            updated_at: entry.updated_at,
            days_since: now.saturating_sub(entry.updated_at) / 86_400,
        })
        .collect();
    out.sort_by_key(|info| info.entry);
    out
}

// ---------------------------------------------------------------------------
// Indicateurs 3 et 4 — robustesse estimée et entrées faibles
// ---------------------------------------------------------------------------

/// Seuil d'entropie estimée en dessous duquel une entrée est signalée faible.
pub const WEAK_ENTRY_BITS: f64 = 64.0;

/// Longueur (scalaires Unicode) en dessous de laquelle une entrée est signalée faible.
pub const WEAK_ENTRY_MIN_LEN: usize = 8;

/// Bande qualitative d'une **estimation** de robustesse.
///
/// Les seuils sont les mêmes ancrages de politique que la bande d'entropie exacte,
/// mais le type est **distinct** : une estimation n'est pas une mesure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthBand {
    /// Moins de 64 bits estimés.
    VeryWeak,
    /// De 64 à 79 bits estimés.
    Weak,
    /// De 80 à 127 bits estimés.
    Moderate,
    /// 128 bits estimés ou plus.
    ///
    /// Ce nom est **volontaire** : il signifie « aucune faiblesse structurelle
    /// détectée », jamais « ce secret est robuste ». Il ne doit jamais être présenté
    /// comme `Strong`, `Secure` ou `Safe`.
    NoStructuralWeakness,
    /// Un caractère échappe aux classes connues : aucune estimation.
    Indeterminate,
}

/// Drapeaux structurels observés dans une valeur.
///
/// Chaque drapeau a une définition **formelle** ; aucun n'est deviné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrengthFlags {
    /// Au moins une plage de caractères identiques adjacents de longueur ≥ 2.
    pub repeated_run: bool,
    /// La chaîne est composée d'au moins deux répétitions exactes d'un même bloc de
    /// longueur `p`, `1 ≤ p ≤ n/2` (ex. `aB3!aB3!aB3!`).
    pub periodic: bool,
    /// Au moins un caractère n'appartient à aucune classe ASCII connue (non-ASCII,
    /// espace, contrôle).
    pub outside_known_classes: bool,
}

/// Estimation heuristique de la robustesse d'une valeur.
///
/// # Ce que c'est, et ce que ce n'est pas
///
/// Ce n'est **pas** une entropie. C'est un comptage structurel :
///
/// ```text
/// n        = nombre de scalaires Unicode
/// A        = taille de l'union des classes ASCII observées
///            (26 minuscules + 26 majuscules + 10 chiffres + 32 symboles)
/// run_count= nombre de plages maximales de caractères identiques adjacents
/// bits     = run_count × log₂(A)          si toutes les classes sont connues et n > 0
///          = indéterminé                  sinon
/// ```
///
/// **Limites, à afficher avec le chiffre.** L'estimation suppose un tirage uniforme
/// sur les classes observées. Un secret humain n'est pas uniforme : il est concentré
/// sur des mots, des dates, des substitutions. L'estimation est donc **aveugle aux
/// dictionnaires** (`Password1!` la dépasse) et **optimiste par construction**. Un
/// score **bas** est un signal ; un score **haut** ne garantit **rien**.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StrengthEstimate {
    /// Nombre de scalaires Unicode.
    pub char_count: usize,
    /// Nombre de plages maximales de caractères identiques adjacents.
    pub run_count: usize,
    /// Taille de l'union des classes ASCII observées, ou `None` si un caractère est
    /// hors classes.
    pub alphabet_observed: Option<usize>,
    /// Estimation en bits, ou `None` si indéterminée.
    pub heuristic_bits: Option<f64>,
    /// Bande associée.
    pub band: StrengthBand,
    /// Drapeaux structurels.
    pub flags: StrengthFlags,
}

impl StrengthEstimate {
    /// Vrai si un caractère est hors des classes connues.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        self.heuristic_bits.is_none()
    }
}

/// Estime la robustesse d'une valeur, **sans dépendance et sans horloge**.
#[must_use]
pub fn estimate_strength(value: &str) -> StrengthEstimate {
    let mut chars: Vec<char> = Vec::new();
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut outside = false;
    let mut run_count = 0_usize;
    let mut repeated_run = false;
    let mut previous: Option<char> = None;

    for character in value.chars() {
        chars.push(character);

        if character.is_ascii_lowercase() {
            has_lower = true;
        } else if character.is_ascii_uppercase() {
            has_upper = true;
        } else if character.is_ascii_digit() {
            has_digit = true;
        } else if crate::generator::SYMBOLS.contains(character) {
            has_symbol = true;
        } else {
            outside = true;
        }

        match previous {
            Some(previous) if previous == character => repeated_run = true,
            _ => run_count += 1,
        }
        previous = Some(character);
    }

    let char_count = chars.len();
    let periodic = is_periodic(&chars);

    let alphabet = if outside || char_count == 0 {
        None
    } else {
        let mut size = 0_usize;
        if has_lower {
            size += 26;
        }
        if has_upper {
            size += 26;
        }
        if has_digit {
            size += 10;
        }
        if has_symbol {
            size += 32;
        }
        // Une valeur non vide composée de caractères connus a toujours au moins une
        // classe : `size` ne peut pas être nul ici.
        Some(size)
    };

    let flags = StrengthFlags {
        repeated_run,
        periodic,
        outside_known_classes: outside,
    };

    // `run_count` et `size` sont bornés par la longueur d'un champ (64 Kio) : la
    // conversion en `f64` est exacte sur ce domaine.
    #[allow(
        clippy::cast_precision_loss,
        reason = "compteurs bornés par MAX_FIELD_VALUE_LEN : conversion exacte"
    )]
    let heuristic_bits = alphabet.map(|size| run_count as f64 * (size as f64).log2());

    let band = match heuristic_bits {
        None => StrengthBand::Indeterminate,
        Some(bits) => band_for(bits),
    };

    StrengthEstimate {
        char_count,
        run_count,
        alphabet_observed: alphabet,
        heuristic_bits,
        band,
        flags,
    }
}

fn band_for(bits: f64) -> StrengthBand {
    if bits < 64.0 {
        StrengthBand::VeryWeak
    } else if bits < 80.0 {
        StrengthBand::Weak
    } else if bits < 128.0 {
        StrengthBand::Moderate
    } else {
        StrengthBand::NoStructuralWeakness
    }
}

/// Test de périodicité **exact et borné en O(n)**.
///
/// `p = n − π[n−1]` (π = fonction de préfixe) est la plus petite période de la
/// chaîne. La chaîne est une répétition exacte d'un bloc dès que `p` divise `n`, et
/// elle compte **au moins deux** répétitions dès que `p ≤ n/2`.
fn is_periodic(chars: &[char]) -> bool {
    let n = chars.len();
    if n < 2 {
        return false;
    }

    let mut prefix = vec![0_usize; n];
    for index in 1..n {
        let mut k = prefix[index - 1];
        while k > 0 && chars[index] != chars[k] {
            k = prefix[k - 1];
        }
        if chars[index] == chars[k] {
            k += 1;
        }
        prefix[index] = k;
    }

    let period = n - prefix[n - 1];
    period <= n / 2 && n.is_multiple_of(period)
}

/// Estimation de robustesse rattachée à un champ.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StrengthFinding {
    /// Entrée concernée.
    pub entry: EntryId,
    /// Ordinal du champ dans l'entrée.
    pub ordinal: u16,
    /// Estimation.
    pub estimate: StrengthEstimate,
}

/// Motif de faiblesse d'un champ.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WeakReason {
    /// Estimation sous le seuil.
    LowHeuristicScore {
        /// Estimation en bits.
        bits: f64,
    },
    /// Longueur sous le seuil.
    TooShort {
        /// Longueur en scalaires Unicode.
        length: usize,
    },
}

/// Champ signalé comme faible.
#[derive(Debug, Clone, PartialEq)]
pub struct WeakSecret {
    /// Entrée concernée.
    pub entry: EntryId,
    /// Ordinal du champ.
    pub ordinal: u16,
    /// Motifs, dans l'ordre `LowHeuristicScore` puis `TooShort`.
    pub reasons: Vec<WeakReason>,
}

/// Vrai si un genre de champ est candidat aux indicateurs de secret.
fn is_secret_candidate(kind: FieldKind) -> bool {
    matches!(kind, FieldKind::Secret | FieldKind::Pin)
}

/// Estime la robustesse de chaque champ candidat.
#[must_use]
pub fn detect_strength(archive: &Archive) -> Vec<StrengthFinding> {
    let mut out = Vec::new();
    for entry in archive.entries.iter().filter(|entry| !entry.is_trashed()) {
        for field in entry
            .fields
            .iter()
            .filter(|field| is_secret_candidate(field.kind))
        {
            out.push(StrengthFinding {
                entry: entry.id,
                ordinal: field.ordinal,
                estimate: estimate_strength(&field.value),
            });
        }
    }
    out.sort_by_key(|finding| (finding.entry, finding.ordinal));
    out
}

/// Signale les champs candidats faibles.
///
/// Faible si l'estimation est `< 64` bits **ou** si la longueur est `< 8`.
/// Une estimation `Indeterminate` **n'est pas** convertie en faiblesse : seul le
/// critère de longueur peut alors déclencher le signalement.
#[must_use]
pub fn detect_weak_entries(archive: &Archive) -> Vec<WeakSecret> {
    let mut out = Vec::new();
    for entry in archive.entries.iter().filter(|entry| !entry.is_trashed()) {
        for field in entry
            .fields
            .iter()
            .filter(|field| is_secret_candidate(field.kind))
        {
            let estimate = estimate_strength(&field.value);
            let mut reasons = Vec::new();
            if estimate
                .heuristic_bits
                .is_some_and(|bits| bits < WEAK_ENTRY_BITS)
            {
                reasons.push(WeakReason::LowHeuristicScore {
                    bits: estimate.heuristic_bits.unwrap_or(0.0),
                });
            }
            if estimate.char_count < WEAK_ENTRY_MIN_LEN {
                reasons.push(WeakReason::TooShort {
                    length: estimate.char_count,
                });
            }
            if !reasons.is_empty() {
                out.push(WeakSecret {
                    entry: entry.id,
                    ordinal: field.ordinal,
                    reasons,
                });
            }
        }
    }
    out.sort_by_key(|secret| (secret.entry, secret.ordinal));
    out
}

// ---------------------------------------------------------------------------
// Indicateur 5 — absence de TOTP
// ---------------------------------------------------------------------------

/// Entrée signalée comme gagnant un second facteur et n'en portant pas.
///
/// **Règle conservatrice** : uniquement les entrées de type `Login` qui portent au
/// moins un champ `Secret` et aucun champ `Totp`. Aucune autre catégorie n'est
/// présumée bénéficier d'un TOTP.
///
/// **Faux positif documenté** : un `Login` dont le champ `Secret` n'est pas un mot
/// de passe (code de secours, par exemple) sera signalé à tort. C'est assumé : la
/// règle ne devine pas la sémantique d'une clé.
#[must_use]
pub fn detect_missing_totp(archive: &Archive) -> Vec<EntryId> {
    let mut out: Vec<EntryId> = archive
        .entries
        .iter()
        .filter(|entry| !entry.is_trashed())
        .filter(|entry| entry.kind == EntryKind::Login)
        .filter(|entry| {
            entry
                .fields
                .iter()
                .any(|field| field.kind == FieldKind::Secret)
        })
        .filter(|entry| {
            !entry
                .fields
                .iter()
                .any(|field| field.kind == FieldKind::Totp)
        })
        .map(|entry| entry.id)
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Indicateur 1 — réutilisation
// ---------------------------------------------------------------------------

/// Étiquette de séparation de domaine de l'empreinte de réutilisation.
///
/// `K_index` est une clé **HMAC-SHA256** déjà employée par la sentinelle et le MAC
/// de contenu d'une pièce jointe, chaque usage séparé par une étiquette versionnée
/// en préfixe de message (`I-KEYDOMAIN`). Ce quatrième usage suit la même règle :
/// aucune clé nouvelle, aucune étiquette HKDF nouvelle.
const REUSE_INFO: &[u8] = b"passlock/v1/reuse-fingerprint";

/// Empreinte d'une valeur : `HMAC-SHA256(K_index, "…/reuse-fingerprint" ‖ valeur)`.
///
/// La valeur est prise **verbatim** (octets UTF-8), sans normalisation, sans `trim`,
/// sans repli de casse ni d'accents : l'objectif est l'égalité **exacte**. Le
/// résultat n'est jamais persisté ni affiché.
fn reuse_fingerprint(index_key: &Key<KEY_LEN>, value: &str) -> Result<[u8; 32]> {
    let mut hmac = <HmacSha256 as KeyInit>::new_from_slice(index_key.expose()).map_err(|_| {
        Error::Internal {
            invariant: "HMAC refuse une clé de 32 octets",
        }
    })?;
    Mac::update(&mut hmac, REUSE_INFO);
    Mac::update(&mut hmac, value.as_bytes());
    Ok(hmac.finalize().into_bytes().into())
}

/// Référence d'un champ dans une entrée, **sans sa valeur**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRef {
    /// Entrée concernée.
    pub entry: EntryId,
    /// Ordinal du champ.
    pub ordinal: u16,
    /// Genre du champ.
    pub kind: FieldKind,
}

/// Groupe de champs partageant la **même valeur**, sur au moins deux entrées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReuseGroup {
    /// Identifiants des entrées concernées, triés et **distincts**.
    pub entries: Vec<EntryId>,
    /// Champs concernés, triés par `(entrée, ordinal)`.
    pub fields: Vec<FieldRef>,
}

/// Détecte les valeurs partagées par au moins deux entrées distinctes.
///
/// Candidats : `Secret` et `Pin` uniquement ; `Totp` exclu ; aucune déduction par le
/// nom de la clé ; **valeur vide exclue**. Regroupement sur la **valeur seule**,
/// indépendamment du genre.
///
/// # Erreurs
/// [`Error::Internal`] si le calcul de l'empreinte échoue, ce qui ne peut pas
/// arriver avec une clé de 32 octets.
pub fn detect_reuse(archive: &Archive, index_key: &Key<KEY_LEN>) -> Result<Vec<ReuseGroup>> {
    let mut groups: BTreeMap<[u8; 32], Vec<FieldRef>> = BTreeMap::new();

    for entry in archive.entries.iter().filter(|entry| !entry.is_trashed()) {
        for field in &entry.fields {
            if !is_secret_candidate(field.kind) || field.value.is_empty() {
                continue;
            }
            let fingerprint = reuse_fingerprint(index_key, &field.value)?;
            groups.entry(fingerprint).or_default().push(FieldRef {
                entry: entry.id,
                ordinal: field.ordinal,
                kind: field.kind,
            });
        }
    }

    let mut out = Vec::new();
    for mut fields in groups.into_values() {
        fields.sort_by_key(|reference| (reference.entry, reference.ordinal));
        let mut entries: Vec<EntryId> = fields.iter().map(|reference| reference.entry).collect();
        entries.dedup();
        if entries.len() >= 2 {
            out.push(ReuseGroup { entries, fields });
        }
    }

    // Ordre déterministe : groupes les plus larges d'abord, puis par plus petit
    // identifiant. Les ex æquo sont départagés par l'itération du `BTreeMap`, elle
    // aussi déterministe.
    out.sort_by(|left, right| {
        right
            .entries
            .len()
            .cmp(&left.entries.len())
            .then_with(|| left.entries[0].cmp(&right.entries[0]))
    });
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rapport global
// ---------------------------------------------------------------------------

/// Les six indicateurs, dans un ordre fixe.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityReport {
    /// Réutilisation de secrets.
    pub reuse: Vec<ReuseGroup>,
    /// Ancienneté.
    pub age: Vec<AgeInfo>,
    /// Estimations de robustesse (champs candidats).
    pub strengths: Vec<StrengthFinding>,
    /// Champs faibles.
    pub weak: Vec<WeakSecret>,
    /// Entrées `Login` sans TOTP.
    pub missing_totp: Vec<EntryId>,
    /// Expiration.
    pub expiry: Vec<ExpiryReport>,
}

/// Calcule les six indicateurs sur une archive déchiffrée.
///
/// `now` est l'instant de référence en secondes Unix (UTC), **fourni** : la fonction
/// n'appelle aucune horloge. `window_days` est la fenêtre d'alerte d'expiration.
///
/// # Erreurs
/// [`Error::Internal`] si une empreinte de réutilisation ne peut pas être calculée.
pub fn run_security_center(
    archive: &Archive,
    index_key: &Key<KEY_LEN>,
    now: u64,
    window_days: u32,
) -> Result<SecurityReport> {
    let reference = CivilDate::from_unix_seconds(now);
    Ok(SecurityReport {
        reuse: detect_reuse(archive, index_key)?,
        age: detect_age(archive, now),
        strengths: detect_strength(archive),
        weak: detect_weak_entries(archive),
        missing_totp: detect_missing_totp(archive),
        expiry: expiry_reports(archive, reference, window_days),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entry, Field};

    fn date(text: &str) -> CivilDate {
        CivilDate::parse(text).expect("date valide")
    }

    fn field(key: &str, kind: FieldKind, value: &str) -> Field {
        Field::new(key, kind, value, 0).expect("champ")
    }

    // -- Dates ---------------------------------------------------------------

    #[test]
    fn canonical_dates_are_parsed() {
        assert_eq!(date("1970-01-01"), CivilDate::new(1970, 1, 1));
        assert_eq!(date("2026-02-03"), CivilDate::new(2026, 2, 3));
        assert_eq!(date("9999-12-31"), CivilDate::new(9999, 12, 31));
    }

    #[test]
    fn non_canonical_dates_are_refused_as_shape_errors() {
        for text in [
            "",
            "2026-2-3",
            "2026-02-3",
            "026-02-03",
            "2026/02/03",
            "2026-02-03 ",
            "2026-02-03T",
            "abcd-ef-gh",
            "2026-02-0a",
            "+2026-02-03",
        ] {
            assert_eq!(
                CivilDate::parse(text),
                Err(DateError::Shape),
                "« {text} » devrait être une erreur de forme"
            );
        }
    }

    #[test]
    fn out_of_range_years_are_refused() {
        assert_eq!(CivilDate::parse("1969-12-31"), Err(DateError::Range));
        assert_eq!(CivilDate::parse("0000-01-01"), Err(DateError::Range));
        assert_eq!(
            CivilDate::parse("2026-02-03"),
            Ok(CivilDate::new(2026, 2, 3))
        );
    }

    #[test]
    fn impossible_dates_are_refused() {
        for text in [
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "2026-02-00",
            "2026-04-31",
        ] {
            assert_eq!(
                CivilDate::parse(text),
                Err(DateError::Impossible),
                "« {text} » n'existe pas"
            );
        }
    }

    #[test]
    fn leap_years_are_handled() {
        assert!(CivilDate::is_leap(2000));
        assert!(CivilDate::is_leap(2024));
        assert!(!CivilDate::is_leap(1900));
        assert!(!CivilDate::is_leap(2023));

        assert_eq!(date("2000-02-29"), CivilDate::new(2000, 2, 29));
        assert_eq!(date("2024-02-29"), CivilDate::new(2024, 2, 29));
        assert_eq!(CivilDate::parse("2023-02-29"), Err(DateError::Impossible));
    }

    #[test]
    fn day_numbers_round_trip() {
        for text in [
            "1970-01-01",
            "1971-01-01",
            "2000-02-29",
            "2024-12-31",
            "9999-12-31",
        ] {
            let date = date(text);
            assert_eq!(CivilDate::from_days(date.to_days()), date, "{text}");
        }
        assert_eq!(date("1970-01-01").to_days(), 0);
        assert_eq!(date("1970-01-02").to_days(), 1);
        // 1969 est hors bornes pour `parse`, mais l'arithmétique reste correcte.
        assert_eq!(CivilDate::new(1969, 12, 31).to_days(), -1);
    }

    #[test]
    fn unix_seconds_convert_to_utc_dates() {
        assert_eq!(CivilDate::from_unix_seconds(0), CivilDate::new(1970, 1, 1));
        assert_eq!(
            CivilDate::from_unix_seconds(86_400),
            CivilDate::new(1970, 1, 2)
        );
    }

    #[test]
    fn from_days_is_total_for_extreme_inputs() {
        // Le fuzzing a trouvé un débordement ici : `from_days(i64::MAX)` paniquait en
        // arithmétique débordante. La fonction est désormais bornée, donc totale.
        for days in [
            i64::MIN,
            i64::MIN + 1,
            -1_000_000_000,
            -1,
            0,
            1_000_000_000,
            i64::MAX - 1,
            i64::MAX,
        ] {
            let date = CivilDate::from_days(days);
            assert!(
                (MIN_YEAR..=MAX_YEAR).contains(&date.year),
                "{days} → {date:?}"
            );
            assert!((1..=12).contains(&date.month), "{days} → {date:?}");
            let limit = CivilDate::days_in_month(date.year, date.month).expect("mois");
            assert!((1..=limit).contains(&date.day), "{days} → {date:?}");
        }
        assert_eq!(CivilDate::from_days(0), CivilDate::new(1970, 1, 1));
    }

    // -- Expiration ----------------------------------------------------------

    #[test]
    fn expiry_boundaries_are_inclusive() {
        let reference = date("2026-06-15");
        let at = |value: &str| {
            expiry_state(
                &[field(EXPIRES_AT_KEY, FieldKind::Date, value)],
                reference,
                DEFAULT_EXPIRY_WINDOW_DAYS,
            )
        };

        assert_eq!(at("2026-06-14"), ExpiryState::Expired);
        assert_eq!(at("2026-06-15"), ExpiryState::Soon); // aujourd'hui
        assert_eq!(at("2026-07-15"), ExpiryState::Soon); // +30
        assert_eq!(at("2026-07-16"), ExpiryState::Valid); // +31
        assert_eq!(at("2027-01-01"), ExpiryState::Valid);
    }

    #[test]
    fn expiry_reports_absent_wrong_kind_and_ambiguity() {
        let reference = date("2026-06-15");
        let window = DEFAULT_EXPIRY_WINDOW_DAYS;

        assert_eq!(
            expiry_state(&[], reference, window),
            ExpiryState::Unknown(ExpiryUnknown::Absent)
        );
        assert_eq!(
            expiry_state(
                &[field(EXPIRES_AT_KEY, FieldKind::Text, "2026-06-15")],
                reference,
                window
            ),
            ExpiryState::Unknown(ExpiryUnknown::WrongKind)
        );
        assert_eq!(
            expiry_state(
                &[
                    field(EXPIRES_AT_KEY, FieldKind::Date, "2026-06-15"),
                    field(EXPIRES_AT_KEY, FieldKind::Date, "2026-07-01"),
                ],
                reference,
                window
            ),
            ExpiryState::Unknown(ExpiryUnknown::Ambiguous)
        );
    }

    #[test]
    fn expiry_reports_malformed_and_impossible() {
        let reference = date("2026-06-15");
        let window = DEFAULT_EXPIRY_WINDOW_DAYS;
        let at = |value: &str| {
            expiry_state(
                &[field(EXPIRES_AT_KEY, FieldKind::Date, value)],
                reference,
                window,
            )
        };

        assert_eq!(
            at("2026-6-15"),
            ExpiryState::Unknown(ExpiryUnknown::Malformed)
        );
        assert_eq!(
            at("2026-02-30"),
            ExpiryState::Unknown(ExpiryUnknown::Impossible)
        );
        assert_eq!(
            at("1969-01-01"),
            ExpiryState::Unknown(ExpiryUnknown::Impossible)
        );
    }

    // -- Robustesse ----------------------------------------------------------

    fn estimate(value: &str) -> StrengthEstimate {
        estimate_strength(value)
    }

    #[test]
    fn the_documented_examples_hold() {
        // 1234 : 4 plages, A=10 → 4 × log₂(10) = 13,2877…
        let e = estimate("1234");
        assert!((e.heuristic_bits.expect("bits") - 13.287_712_380).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::VeryWeak);

        // password : « ss » est une plage répétée, donc 7 plages et non 8 ;
        // A=26 → 7 × log₂(26) = 32,9030…
        let e = estimate("password");
        assert_eq!(e.run_count, 7);
        assert!(e.flags.repeated_run);
        assert!((e.heuristic_bits.expect("bits") - 32.903_078_027).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::VeryWeak);

        // aaaaaaaaaaaa : 1 plage, A=26 → log₂(26) = 4,7004…
        let e = estimate("aaaaaaaaaaaa");
        assert_eq!(e.run_count, 1);
        assert!(e.flags.repeated_run);
        assert!((e.heuristic_bits.expect("bits") - 4.700_439_718).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::VeryWeak);

        // Password1! : « ss » répété → 9 plages, A=94 → 9 × log₂(94) = 58,9913…
        // La répétition fait passer le verdict sous le seuil : l'effondrement des
        // plages sert ici, alors que l'heuristique reste aveugle au dictionnaire.
        let e = estimate("Password1!");
        assert_eq!(e.run_count, 9);
        assert!((e.heuristic_bits.expect("bits") - 58.991_299_665).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::VeryWeak);

        // Faux négatif documenté : un secret humain réellement faible qu'aucune
        // régularité structurelle ne trahit. A=94, 11 plages → 72,1004… → Weak,
        // donc **non signalé** par la règle des entrées faibles.
        let e = estimate("Tr0ub4dor&3");
        assert_eq!(e.run_count, 11);
        assert_eq!(e.band, StrengthBand::Weak);
        assert!((e.heuristic_bits.expect("bits") - 72.100_477_368).abs() < 1e-6);
        let weak = detect_weak_entries(&{
            let mut archive = Archive::new(0);
            archive.entries.push(entry_with(
                "x",
                vec![field("password", FieldKind::Secret, "Tr0ub4dor&3")],
            ));
            archive
        });
        assert!(weak.is_empty(), "faux négatif attendu : non signalé");

        // 20 minuscules distinctes : 20 × log₂(26) = 94,0088… → Moderate.
        let e = estimate("abcdefghijklmnopqrst");
        assert_eq!(e.run_count, 20);
        assert!((e.heuristic_bits.expect("bits") - 94.008_794_363).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::Moderate);

        // 20 caractères pleine alphabet ASCII : 20 × log₂(94) = 131,0918…
        let e = estimate("aB3!aB3!aB3!aB3!aB3!");
        assert!((e.heuristic_bits.expect("bits") - 131.091_777_034).abs() < 1e-6);
        assert_eq!(e.band, StrengthBand::NoStructuralWeakness);
        assert!(e.flags.periodic);

        // café! : « é » est hors classes ASCII → indéterminé.
        let e = estimate("café!");
        assert!(e.is_indeterminate());
        assert_eq!(e.alphabet_observed, None);
        assert_eq!(e.band, StrengthBand::Indeterminate);
        assert!(e.flags.outside_known_classes);
    }

    #[test]
    fn thresholds_follow_the_policy() {
        assert_eq!(band_for(63.999), StrengthBand::VeryWeak);
        assert_eq!(band_for(64.0), StrengthBand::Weak);
        assert_eq!(band_for(79.999), StrengthBand::Weak);
        assert_eq!(band_for(80.0), StrengthBand::Moderate);
        assert_eq!(band_for(127.999), StrengthBand::Moderate);
        assert_eq!(band_for(128.0), StrengthBand::NoStructuralWeakness);
    }

    #[test]
    fn periodicity_is_detected_exactly() {
        assert!(is_periodic(&"aB3!aB3!aB3!".chars().collect::<Vec<_>>()));
        assert!(is_periodic(&"abab".chars().collect::<Vec<_>>()));
        assert!(is_periodic(&"aaaa".chars().collect::<Vec<_>>()));
        assert!(!is_periodic(&"abcabcab".chars().collect::<Vec<_>>()));
        assert!(!is_periodic(&"abcde".chars().collect::<Vec<_>>()));
        assert!(!is_periodic(&"a".chars().collect::<Vec<_>>()));
    }

    #[test]
    fn a_periodic_string_is_flagged_but_not_a_single_character() {
        assert!(estimate("abababab").flags.periodic);
        assert!(!estimate("a").flags.periodic);
        assert!(!estimate("abcdefgh").flags.periodic);
    }

    #[test]
    fn spaces_and_controls_are_outside_known_classes() {
        for value in ["a b", "a\tb", "\u{7f}", "abc\u{00e9}"] {
            assert!(
                estimate(value).flags.outside_known_classes,
                "« {value} » devrait être hors classes"
            );
            assert!(estimate(value).is_indeterminate());
        }
        // Tous les symboles du générateur sont, eux, des classes connues.
        assert!(
            !estimate(crate::generator::SYMBOLS)
                .flags
                .outside_known_classes
        );
        assert_eq!(
            estimate(crate::generator::SYMBOLS).alphabet_observed,
            Some(32)
        );
    }

    #[test]
    fn a_non_ascii_estimate_is_indeterminate_but_not_weak_by_itself() {
        // Le drapeau et l'absence d'estimation sont distincts de la faiblesse : c'est
        // la règle de **longueur** qui décide, pas l'indétermination.
        let short = estimate("café!");
        assert_eq!(short.char_count, 5);
        assert!(short.is_indeterminate());

        let long = estimate("ΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩΩ");
        assert_eq!(long.char_count, 20);
        assert!(long.is_indeterminate());
    }

    #[test]
    fn an_empty_value_is_indeterminate() {
        let e = estimate("");
        assert_eq!(e.char_count, 0);
        assert_eq!(e.run_count, 0);
        assert!(e.is_indeterminate());
        assert_eq!(e.band, StrengthBand::Indeterminate);
    }

    // -- Empreinte -----------------------------------------------------------

    fn index_key() -> Key<KEY_LEN> {
        Key::from_array([0x5A; KEY_LEN])
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let key = index_key();
        let first = reuse_fingerprint(&key, "s3cr3t").expect("empreinte");
        let again = reuse_fingerprint(&key, "s3cr3t").expect("empreinte");
        let other = reuse_fingerprint(&key, "s3cr3T").expect("empreinte");
        assert_eq!(first, again);
        assert_ne!(first, other, "la comparaison doit être sensible à la casse");

        let other_key = Key::from_array([0x5B; KEY_LEN]);
        assert_ne!(
            first,
            reuse_fingerprint(&other_key, "s3cr3t").expect("empreinte")
        );
    }

    // -- Détection sur archive ----------------------------------------------

    fn entry_with(title: &str, fields: Vec<Field>) -> Entry {
        let mut entry = Entry::new(EntryKind::Login, title, 1_000).expect("entrée");
        entry.fields = fields;
        entry
    }

    #[test]
    fn reuse_requires_two_distinct_entries() {
        let mut archive = Archive::new(0);
        // Deux champs identiques dans la même entrée : pas de réutilisation.
        archive.entries.push(entry_with(
            "a",
            vec![
                Field::new("password", FieldKind::Secret, "same", 0).expect("champ"),
                Field::new("pin", FieldKind::Pin, "same", 1).expect("champ"),
            ],
        ));
        assert!(
            detect_reuse(&archive, &index_key())
                .expect("détection")
                .is_empty()
        );

        // Un doublon partagé entre deux entrées : réutilisation.
        archive.entries.push(entry_with(
            "b",
            vec![field("password", FieldKind::Secret, "same")],
        ));
        let groups = detect_reuse(&archive, &index_key()).expect("détection");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].entries.len(), 2);
    }

    #[test]
    fn reuse_groups_secret_and_pin_together_and_excludes_totp() {
        let mut archive = Archive::new(0);
        archive.entries.push(entry_with(
            "a",
            vec![field("password", FieldKind::Secret, "1234")],
        ));
        archive
            .entries
            .push(entry_with("b", vec![field("pin", FieldKind::Pin, "1234")]));
        // Un TOTP « identique » ne doit jamais compter.
        archive.entries.push(entry_with(
            "c",
            vec![field("totp", FieldKind::Totp, "1234")],
        ));

        let groups = detect_reuse(&archive, &index_key()).expect("détection");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].entries.len(), 2, "Secret et Pin se regroupent");
        assert!(
            groups[0]
                .fields
                .iter()
                .all(|reference| reference.kind != FieldKind::Totp)
        );
    }

    #[test]
    fn empty_values_are_not_reused() {
        let mut archive = Archive::new(0);
        archive.entries.push(entry_with(
            "a",
            vec![field("password", FieldKind::Secret, "")],
        ));
        archive.entries.push(entry_with(
            "b",
            vec![field("password", FieldKind::Secret, "")],
        ));
        assert!(
            detect_reuse(&archive, &index_key())
                .expect("détection")
                .is_empty()
        );
    }

    #[test]
    fn trashed_entries_are_excluded_everywhere() {
        let mut archive = Archive::new(0);
        archive.entries.push(entry_with(
            "a",
            vec![field("password", FieldKind::Secret, "same")],
        ));
        let mut trashed = entry_with("b", vec![field("password", FieldKind::Secret, "same")]);
        trashed.trashed_at = Some(1);
        archive.entries.push(trashed);

        assert!(
            detect_reuse(&archive, &index_key())
                .expect("détection")
                .is_empty()
        );
        assert_eq!(detect_age(&archive, 1_000).len(), 1);
        assert_eq!(detect_strength(&archive).len(), 1);
    }

    #[test]
    fn archived_entries_are_included() {
        let mut archive = Archive::new(0);
        let mut archived = entry_with("a", vec![field("password", FieldKind::Secret, "same")]);
        archived.archived = true;
        archive.entries.push(archived);
        archive.entries.push(entry_with(
            "b",
            vec![field("password", FieldKind::Secret, "same")],
        ));

        assert_eq!(
            detect_reuse(&archive, &index_key())
                .expect("détection")
                .len(),
            1
        );
        assert_eq!(detect_age(&archive, 1_000).len(), 2);
    }

    #[test]
    fn missing_totp_rule_is_conservative() {
        let mut archive = Archive::new(0);

        // Login + Secret, sans TOTP → signalé.
        archive.entries.push(entry_with(
            "flagged",
            vec![field("password", FieldKind::Secret, "x")],
        ));
        // Login + Secret + TOTP → non signalé.
        archive.entries.push(entry_with(
            "has-totp",
            vec![
                field("password", FieldKind::Secret, "x"),
                field("totp", FieldKind::Totp, "otpauth://totp/a?secret=AAAA"),
            ],
        ));
        // Login sans Secret → non signalé.
        archive.entries.push(entry_with("no-secret", vec![]));
        // Note sécurisée avec un Secret → non signalée (kind != Login).
        let mut note = Entry::new(EntryKind::SecureNote, "note", 1_000).expect("entrée");
        note.fields = vec![field("password", FieldKind::Secret, "x")];
        archive.entries.push(note);

        let flagged = detect_missing_totp(&archive);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0], archive.entries[0].id);
    }

    #[test]
    fn age_uses_the_provided_reference() {
        let mut archive = Archive::new(0);
        let mut entry = entry_with("a", vec![]);
        entry.updated_at = 1_000_000;
        archive.entries.push(entry);

        let info = detect_age(&archive, 1_000_000 + 86_400 * 137);
        assert_eq!(info[0].updated_at, 1_000_000);
        assert_eq!(info[0].days_since, 137);

        // Référence antérieure : saturation à zéro, jamais de sous-dépassement.
        assert_eq!(detect_age(&archive, 0)[0].days_since, 0);
    }

    // -- Rapport global ------------------------------------------------------

    #[test]
    fn the_report_has_exactly_six_indicators_and_is_deterministic() {
        let mut archive = Archive::new(0);
        archive.entries.push(entry_with(
            "a",
            vec![field("password", FieldKind::Secret, "same")],
        ));
        archive.entries.push(entry_with(
            "b",
            vec![field("password", FieldKind::Secret, "same")],
        ));

        let first = run_security_center(&archive, &index_key(), 1_000_000, 30).expect("rapport");
        let second = run_security_center(&archive, &index_key(), 1_000_000, 30).expect("rapport");
        assert_eq!(first, second);

        assert_eq!(first.reuse.len(), 1);
        assert_eq!(first.age.len(), 2);
        assert_eq!(first.strengths.len(), 2);
        assert_eq!(first.weak.len(), 2, "« same » fait 4 caractères");
        assert_eq!(first.missing_totp.len(), 2);
        assert_eq!(first.expiry.len(), 2);
    }

    #[test]
    fn the_report_never_contains_a_secret_or_a_fingerprint() {
        let mut archive = Archive::new(0);
        let marker = "MARQUEUR-SECRET-A-NE-PAS-FUITER";
        archive.entries.push(entry_with(
            "a",
            vec![field("password", FieldKind::Secret, marker)],
        ));
        archive.entries.push(entry_with(
            "b",
            vec![field("password", FieldKind::Secret, marker)],
        ));

        let report = run_security_center(&archive, &index_key(), 1_000_000, 30).expect("rapport");
        let rendered = format!("{report:?}");
        assert!(
            !rendered.contains(marker),
            "une valeur secrète apparaît dans le rapport : {rendered}"
        );

        // L'empreinte ne doit pas non plus pouvoir être extraite : on vérifie qu'elle
        // n'apparaît nulle part sous forme hexadécimale.
        let fingerprint = reuse_fingerprint(&index_key(), marker).expect("empreinte");
        let hex = crate::encoding::hex_encode(&fingerprint);
        assert!(!rendered.contains(&hex));
    }
}
