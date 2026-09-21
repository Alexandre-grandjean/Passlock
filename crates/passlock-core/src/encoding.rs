//! Encodages textuels normalisés du moteur.
//!
//! ## Pourquoi ce module existe
//!
//! Trois besoins de la phase 3 convergent ici :
//!
//! 1. **Base32 RFC 4648** — c'est le format des secrets TOTP. Il est imposé par
//!    l'écosystème : les URI `otpauth://` et tous les serveurs l'utilisent.
//! 2. **Base64url RFC 4648 §5** et **hexadécimal** — formats de sortie du
//!    générateur de secrets.
//! 3. La **défense en entrée** : `base32_decode` traite une chaîne qui vient d'un
//!    coffre, donc d'une donnée *authentifiée mais non valide par construction* —
//!    elle peut avoir été écrite par un import (phase 4) ou forgée par quiconque
//!    détient la clé.
//!
//! La preuve de conformité ne vient pas de ce code mais de la **RFC 4648 §10**,
//! dont les vecteurs sont reproduits dans les tests.
//!
//! ## Ce que le décodeur refuse, et pourquoi
//!
//! Un décodeur permissif est un **vecteur de malléabilité** : deux chaînes
//! distinctes produisant les mêmes octets. Trois cas sont donc rejetés plutôt que
//! tolérés silencieusement.
//!
//! | Cas | Décision |
//! |---|---|
//! | Bits de remplissage non nuls (`MZ` décoderait `f` avec des bits parasites) | **refus** — l'encodage canonique est le seul accepté |
//! | `=` ailleurs qu'à la fin | **refus** |
//! | Longueur impossible (un caractère isolé, ou 3/6 résidus) | **refus** — aucune suite d'octets ne produit cette longueur |
//!
//! Le remplissage **est accepté en entrée** : les secrets TOTP circulent le plus
//! souvent sans, mais la RFC 4648 en prescrit, et refuser l'un des deux usages
//! rendrait le module inutilisable pour l'autre.

use crate::error::{Error, Result};
use crate::secret::SecretVec;

/// Alphabet Base32 de la RFC 4648 §6 : `A`–`Z` puis `2`–`7`.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Alphabet Base64url de la RFC 4648 §5 : `-` et `_` remplacent `+` et `/`.
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Alphabet hexadécimal minuscule.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Longueur maximale acceptée en entrée d'un décodage.
///
/// Bornée **avant** tout calcul de taille de sortie, comme l'exige l'invariant de
/// `bytes.rs` : on ne dimensionne jamais une allocation d'après une entrée non
/// vérifiée. Un secret TOTP réel fait au plus 205 caractères ; 4096 laisse une
/// marge de vingt fois sans ouvrir d'allocation démesurée.
const MAX_ENCODED_CHARS: usize = 4096;

/// Encode en Base32 **avec** remplissage, conformément à la RFC 4648 §6.
///
/// C'est la forme que la RFC définit et que ses vecteurs de test vérifient.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = base32_encode_unpadded(bytes);
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

/// Encode en Base32 **sans** remplissage.
///
/// C'est la forme utilisée par les URI `otpauth://` : le remplissage y est
/// toléré mais jamais produit par les outils du domaine.
#[must_use]
pub fn base32_encode_unpadded(bytes: &[u8]) -> String {
    // Chaque groupe de 5 octets produit 8 caractères ; le reste produit 2, 4, 5
    // ou 7 caractères. La capacité est donc majorée par `ceil(len/5) * 8`.
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);

    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let index = (accumulator >> bits) & 0x1F;
            out.push(base32_symbol(index));
        }
    }

    // Bits résiduels : complétés par des zéros à droite pour former un dernier
    // symbole, exactement comme le prescrit la RFC 4648 §6.
    if bits > 0 {
        let index = (accumulator << (5 - bits)) & 0x1F;
        out.push(base32_symbol(index));
    }

    out
}

/// Décode une chaîne Base32, avec ou sans remplissage.
///
/// Le résultat est un [`SecretVec`] : cette fonction sert à matérialiser des
/// secrets, et un `Vec<u8>` ordinaire laisserait une copie en clair dans le tas
/// après destruction. Les octets sont écrits **directement** dans le tampon
/// verrouillé, sans `Vec` intermédiaire.
///
/// # Erreurs
/// [`Error::InvalidInput`] si l'entrée est trop longue, contient un caractère
/// hors alphabet, un remplissage mal placé, une longueur impossible, ou des bits
/// de remplissage non nuls.
pub fn base32_decode(text: &str) -> Result<SecretVec> {
    if text.len() > MAX_ENCODED_CHARS {
        return Err(Error::InvalidInput {
            reason: "chaîne Base32 au-delà de la longueur maximale admise",
        });
    }

    let body = text.trim_end_matches('=');

    // Un `=` ailleurs qu'à la fin est un encodage malformé, pas un remplissage.
    if body.contains('=') {
        return Err(Error::InvalidInput {
            reason: "remplissage Base32 à l'intérieur de la chaîne",
        });
    }

    let out_len = decoded_len(body.len())?;
    let mut out = SecretVec::zeroed(out_len);
    let buffer = out.expose_mut();

    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut written: usize = 0;

    for character in body.chars() {
        let value = base32_value(character)?;
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            let masked = (accumulator >> bits) & 0xFF;
            let byte = u8::try_from(masked).map_err(|_| Error::Internal {
                invariant: "octet Base32 hors de 0..256 après masquage",
            })?;

            let slot = buffer.get_mut(written).ok_or(Error::Internal {
                invariant: "dépassement du tampon Base32 malgré la longueur calculée",
            })?;
            *slot = byte;
            written += 1;
        }
    }

    // Bits résiduels : la RFC 4648 §6 les veut nuls. Les accepter produirait deux
    // encodages distincts pour la même suite d'octets.
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return Err(Error::InvalidInput {
            reason: "bits de remplissage Base32 non nuls : encodage non canonique",
        });
    }

    if written != out_len {
        return Err(Error::Internal {
            invariant: "nombre d'octets Base32 décodés différent de la longueur calculée",
        });
    }

    Ok(out)
}

/// Décode en Base64url **sans** remplissage.
///
/// Symétrique de [`base64url_encode`]. Sert au format de sortie `base64url` du
/// générateur et aux tests d'aller-retour.
///
/// # Erreurs
/// [`Error::InvalidInput`] si l'entrée dépasse la borne, contient un caractère
/// hors alphabet, une longueur impossible, ou des bits de remplissage non nuls.
pub fn base64url_decode(text: &str) -> Result<SecretVec> {
    if text.len() > MAX_ENCODED_CHARS {
        return Err(Error::InvalidInput {
            reason: "chaîne Base64url au-delà de la longueur maximale admise",
        });
    }

    if text.contains('=') {
        return Err(Error::InvalidInput {
            reason: "remplissage Base64url refusé : cet encodage n'en produit pas",
        });
    }

    let out_len = base64_decoded_len(text.len())?;
    let mut out = SecretVec::zeroed(out_len);
    let buffer = out.expose_mut();

    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut written: usize = 0;

    for character in text.chars() {
        let value = base64url_value(character)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            let masked = (accumulator >> bits) & 0xFF;
            let byte = u8::try_from(masked).map_err(|_| Error::Internal {
                invariant: "octet Base64url hors de 0..256 après masquage",
            })?;

            let slot = buffer.get_mut(written).ok_or(Error::Internal {
                invariant: "dépassement du tampon Base64url malgré la longueur calculée",
            })?;
            *slot = byte;
            written += 1;
        }
    }

    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return Err(Error::InvalidInput {
            reason: "bits de remplissage Base64url non nuls : encodage non canonique",
        });
    }

    if written != out_len {
        return Err(Error::Internal {
            invariant: "nombre d'octets Base64url décodés différent de la longueur calculée",
        });
    }

    Ok(out)
}

/// Encode en Base64url sans remplissage (RFC 4648 §5).
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;

        while bits >= 6 {
            bits -= 6;
            let index = (accumulator >> bits) & 0x3F;
            out.push(base64url_symbol(index));
        }
    }

    if bits > 0 {
        let index = (accumulator << (6 - bits)) & 0x3F;
        out.push(base64url_symbol(index));
    }

    out
}

/// Encode en hexadécimal minuscule.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(hex_symbol(u32::from(byte >> 4)));
        out.push(hex_symbol(u32::from(byte & 0x0F)));
    }
    out
}

/// Nombre d'octets produits par `len` caractères Base32 sans remplissage.
///
/// La RFC 4648 §6 ne laisse que cinq longueurs de reste possibles, chacune
/// correspondant à un nombre entier d'octets. Tout autre reste décrit une suite
/// d'octets **inexistante** : aucun encodage ne peut la produire.
fn decoded_len(len: usize) -> Result<usize> {
    let extra = match len % 8 {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        _ => {
            return Err(Error::InvalidInput {
                reason: "longueur Base32 impossible : aucune suite d'octets ne la produit",
            });
        }
    };
    Ok((len / 8) * 5 + extra)
}

/// Nombre d'octets produits par `len` caractères Base64url sans remplissage.
///
/// Aucun reste de 1 n'est possible : un caractère isolé ne transporte que six
/// bits, insuffisants pour un octet.
fn base64_decoded_len(len: usize) -> Result<usize> {
    let extra = match len % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => {
            return Err(Error::InvalidInput {
                reason: "longueur Base64url impossible : aucune suite d'octets ne la produit",
            });
        }
    };
    Ok((len / 4) * 3 + extra)
}

/// Valeur d'un caractère Base32, insensible à la casse.
fn base32_value(character: char) -> Result<u8> {
    let upper = character.to_ascii_uppercase();
    let byte = u8::try_from(upper).map_err(|_| Error::InvalidInput {
        reason: "caractère hors alphabet Base32",
    })?;

    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'2'..=b'7' => Ok(byte - b'2' + 26),
        _ => Err(Error::InvalidInput {
            reason: "caractère hors alphabet Base32",
        }),
    }
}

/// Valeur d'un caractère Base64url.
fn base64url_value(character: char) -> Result<u8> {
    let byte = u8::try_from(character).map_err(|_| Error::InvalidInput {
        reason: "caractère hors alphabet Base64url",
    })?;

    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Error::InvalidInput {
            reason: "caractère hors alphabet Base64url",
        }),
    }
}

// Les trois fonctions ci-dessous masquent l'index à la largeur de l'alphabet.
// L'invariant est explicite et vérifiable : `0x1F` sur un alphabet de 32 symboles,
// `0x3F` sur 64, `0x0F` sur 16. L'accès est donc dans les bornes **par
// construction**, et non « en pratique ».
//
// Un repli silencieux (`map_or('?')`) a été écarté : il ne se déclencherait jamais,
// mais s'il se déclenchait il écrirait un caractère arbitraire dans un mot de passe
// — une corruption muette, exactement le défaut que ce projet refuse.

/// Symbole Base32 d'index `index`, masqué à 5 bits.
fn base32_symbol(index: u32) -> char {
    char::from(BASE32_ALPHABET[(index & 0x1F) as usize])
}

/// Symbole Base64url d'index `index`, masqué à 6 bits.
fn base64url_symbol(index: u32) -> char {
    char::from(BASE64URL_ALPHABET[(index & 0x3F) as usize])
}

/// Symbole hexadécimal d'index `index`, masqué à 4 bits.
fn hex_symbol(index: u32) -> char {
    char::from(HEX_ALPHABET[(index & 0x0F) as usize])
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492)
//
// Punycode est une **bijection** entre une suite de points de code et une chaîne
// ASCII : il ne dit **rien** de la validité IDNA d'un label. Il est utilisé par
// l'analyse d'URL comme **mécanisme de conversion** (U-label ↔ A-label), encadré
// par les règles IDN du module `url.rs` — jamais présenté comme un validateur.
// ---------------------------------------------------------------------------

/// Base de l'algorithme Punycode.
const PUNY_BASE: u64 = 36;
/// Paramètre `tmin`.
const PUNY_TMIN: u64 = 1;
/// Paramètre `tmax`.
const PUNY_TMAX: u64 = 26;
/// Paramètre `skew`.
const PUNY_SKEW: u64 = 38;
/// Paramètre `damp`.
const PUNY_DAMP: u64 = 700;
/// Biais initial.
const PUNY_INITIAL_BIAS: u64 = 72;
/// Premier point de code non basique.
const PUNY_INITIAL_N: u64 = 0x80;
/// Plus grand point de code Unicode admis.
const PUNY_MAX_CODE_POINT: u64 = 0x10_FFFF;

/// Longueur maximale acceptée pour un label Punycode, en caractères.
///
/// Un label DNS fait au plus 63 **octets** en A-label ; cette borne, plus large,
/// vise la **fonction publique** prise isolément. Elle empêche une entrée hostile
/// de faire croître une allocation ou de faire boucler le décodage.
pub const MAX_PUNYCODE_LEN: usize = 1024;

/// Dépassement arithmétique pendant un calcul Punycode.
fn puny_overflow() -> Error {
    Error::InvalidInput {
        reason: "Punycode : dépassement arithmétique sur l'entrée",
    }
}

/// Biais adaptatif de la RFC 3492 §6.1.
fn puny_adapt(mut delta: u64, numpoints: u64, first_time: bool) -> u64 {
    delta = if first_time {
        delta / PUNY_DAMP
    } else {
        delta / 2
    };
    delta += delta / numpoints;

    let mut k = 0_u64;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    k + (((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW))
}

/// Chiffre → caractère (`a`–`z`, puis `0`–`9`).
fn puny_digit_to_char(digit: u64) -> Result<char> {
    let ascii = match digit {
        0..=25 => b'a' + u8::try_from(digit).map_err(|_| puny_overflow())?,
        26..=35 => b'0' + u8::try_from(digit - 26).map_err(|_| puny_overflow())?,
        _ => {
            return Err(Error::Internal {
                invariant: "chiffre Punycode hors de 0..36",
            });
        }
    };
    Ok(char::from(ascii))
}

/// Caractère → chiffre. **Minuscules uniquement** : les A-labels sont en
/// minuscules, et accepter les majuscules créerait deux écritures possibles.
fn puny_char_to_digit(character: char) -> Option<u64> {
    match character {
        'a'..='z' => Some(u64::from(u32::from(character) - u32::from('a'))),
        '0'..='9' => Some(u64::from(u32::from(character) - u32::from('0')) + 26),
        _ => None,
    }
}

/// Encode un label en **Punycode**, sans le préfixe `xn--`.
///
/// C'est la charge utile telle qu'elle suit `xn--` dans un A-label. Un label
/// entièrement ASCII est encodé suivi d'un **délimiteur** `-` (RFC 3492 §6.3) :
/// c'est précisément pourquoi un `xn--…` qui décode vers de l'ASCII est refusé par
/// la couche IDN.
///
/// # Erreurs
/// [`Error::InvalidInput`] si l'entrée dépasse [`MAX_PUNYCODE_LEN`] ou provoque un
/// dépassement arithmétique.
#[allow(
    clippy::many_single_char_names,
    reason = "les noms `n`, `delta`, `bias`, `k`, `q` sont ceux de la RFC 3492 §6.3 ; les renommer nuirait à la correspondance avec le texte de référence"
)]
pub fn punycode_encode(label: &str) -> Result<String> {
    if label.chars().count() > MAX_PUNYCODE_LEN {
        return Err(Error::InvalidInput {
            reason: "label Punycode au-delà de la longueur maximale admise",
        });
    }

    let code_points: Vec<u64> = label.chars().map(|c| u64::from(u32::from(c))).collect();
    let basic: Vec<u64> = code_points.iter().copied().filter(|c| *c < 0x80).collect();

    let mut output = String::new();
    for &code_point in &basic {
        let character = u32::try_from(code_point)
            .ok()
            .and_then(char::from_u32)
            .ok_or(puny_overflow())?;
        output.push(character);
    }

    let basic_count = u64::try_from(basic.len()).map_err(|_| puny_overflow())?;
    if basic_count > 0 {
        output.push('-');
    }

    let total = u64::try_from(code_points.len()).map_err(|_| puny_overflow())?;
    let mut n = PUNY_INITIAL_N;
    let mut delta: u64 = 0;
    let mut bias = PUNY_INITIAL_BIAS;
    let mut handled = basic_count;

    while handled < total {
        let m = code_points
            .iter()
            .copied()
            .filter(|code_point| *code_point >= n)
            .min()
            .ok_or(puny_overflow())?;

        delta = delta
            .checked_add((m - n).checked_mul(handled + 1).ok_or_else(puny_overflow)?)
            .ok_or_else(puny_overflow)?;
        n = m;

        for &code_point in &code_points {
            if code_point < n {
                delta = delta.checked_add(1).ok_or_else(puny_overflow)?;
            }
            if code_point == n {
                let mut q = delta;
                let mut k = PUNY_BASE;
                loop {
                    let t = k.saturating_sub(bias).clamp(PUNY_TMIN, PUNY_TMAX);
                    if q < t {
                        break;
                    }
                    output.push(puny_digit_to_char(t + (q - t) % (PUNY_BASE - t))?);
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                output.push(puny_digit_to_char(q)?);
                bias = puny_adapt(delta, handled + 1, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }

        delta = delta.checked_add(1).ok_or_else(puny_overflow)?;
        n = n.checked_add(1).ok_or_else(puny_overflow)?;
    }

    Ok(output)
}

/// Décode une charge utile Punycode (la partie qui suit `xn--`).
///
/// # Erreurs
/// [`Error::InvalidInput`] si l'entrée dépasse [`MAX_PUNYCODE_LEN`], contient un
/// chiffre invalide, est tronquée, produit un point de code hors Unicode ou
/// **basique** (impossible d'après la RFC 3492), ou provoque un dépassement.
#[allow(
    clippy::many_single_char_names,
    reason = "les noms `n`, `i`, `bias`, `k`, `t` sont ceux de la RFC 3492 §6.2 ; les renommer nuirait à la correspondance avec le texte de référence"
)]
pub fn punycode_decode(payload: &str) -> Result<String> {
    if payload.len() > MAX_PUNYCODE_LEN {
        return Err(Error::InvalidInput {
            reason: "charge utile Punycode au-delà de la longueur maximale admise",
        });
    }

    // Le **dernier** `-` est le délimiteur ; tout ce qui précède est basique.
    let (basic_part, extended) = match payload.rfind('-') {
        Some(index) => (&payload[..index], &payload[index + 1..]),
        None => ("", payload),
    };

    let mut output: Vec<char> = Vec::new();
    for character in basic_part.chars() {
        if !character.is_ascii() {
            return Err(Error::InvalidInput {
                reason: "Punycode : point de code basique non ASCII",
            });
        }
        output.push(character);
    }

    let extended: Vec<char> = extended.chars().collect();
    let mut position = 0_usize;
    let mut n = PUNY_INITIAL_N;
    let mut i: u64 = 0;
    let mut bias = PUNY_INITIAL_BIAS;

    while position < extended.len() {
        let old_i = i;
        let mut weight: u64 = 1;
        let mut k = PUNY_BASE;

        loop {
            let character = *extended.get(position).ok_or(Error::InvalidInput {
                reason: "Punycode : entrée tronquée",
            })?;
            position += 1;

            let digit = puny_char_to_digit(character).ok_or(Error::InvalidInput {
                reason: "Punycode : chiffre invalide",
            })?;

            i = i
                .checked_add(digit.checked_mul(weight).ok_or_else(puny_overflow)?)
                .ok_or_else(puny_overflow)?;

            let t = k.saturating_sub(bias).clamp(PUNY_TMIN, PUNY_TMAX);
            if digit < t {
                break;
            }
            weight = weight
                .checked_mul(PUNY_BASE - t)
                .ok_or_else(puny_overflow)?;
            k += PUNY_BASE;
        }

        let out_len = u64::try_from(output.len())
            .map_err(|_| puny_overflow())?
            .checked_add(1)
            .ok_or_else(puny_overflow)?;

        bias = puny_adapt(i - old_i, out_len, old_i == 0);
        n = n.checked_add(i / out_len).ok_or_else(puny_overflow)?;
        i %= out_len;

        if n > PUNY_MAX_CODE_POINT {
            return Err(Error::InvalidInput {
                reason: "Punycode : point de code hors d'Unicode",
            });
        }
        // RFC 3492 §6.2 : un point de code inséré ne peut pas être basique.
        if n < 0x80 {
            return Err(Error::InvalidInput {
                reason: "Punycode : point de code basique inséré",
            });
        }
        let character =
            u32::try_from(n)
                .ok()
                .and_then(char::from_u32)
                .ok_or(Error::InvalidInput {
                    reason: "Punycode : point de code invalide (demi-couple)",
                })?;

        let index = usize::try_from(i).map_err(|_| puny_overflow())?;
        if index > output.len() {
            return Err(Error::InvalidInput {
                reason: "Punycode : position d'insertion hors bornes",
            });
        }
        output.insert(index, character);
        i += 1;
    }

    Ok(output.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs de la RFC 4648 §10, reproduits **verbatim**.
    #[test]
    fn rfc4648_section_10_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "MY======"),
            (b"fo", "MZXQ===="),
            (b"foo", "MZXW6==="),
            (b"foob", "MZXW6YQ="),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI======"),
        ];

        for (plain, encoded) in vectors {
            assert_eq!(base32_encode(plain), encoded, "encodage de {plain:?}");
            assert_eq!(
                base32_encode_unpadded(plain),
                encoded.trim_end_matches('='),
                "encodage sans remplissage de {plain:?}"
            );

            let decoded = base32_decode(encoded).expect("décodage du vecteur RFC");
            assert_eq!(decoded.expose(), plain, "décodage de {encoded}");

            // Le remplissage étant facultatif en entrée, les deux formes doivent
            // donner le même résultat.
            let decoded_unpadded =
                base32_decode(encoded.trim_end_matches('=')).expect("décodage sans remplissage");
            assert_eq!(decoded_unpadded.expose(), plain);
        }
    }

    /// Toutes les longueurs de 0 à 64 octets survivent à l'aller-retour, ce qui
    /// couvre les cinq restes possibles de la RFC 4648 §6.
    #[test]
    fn every_length_round_trips() {
        for len in 0..=64 {
            let input: Vec<u8> = (0..len)
                .map(|index| u8::try_from(index).unwrap_or(0))
                .collect();

            let padded = base32_encode(&input);
            assert_eq!(
                base32_decode(&padded).expect("décodage").expose(),
                input.as_slice(),
                "aller-retour avec remplissage, longueur {len}"
            );

            let unpadded = base32_encode_unpadded(&input);
            assert_eq!(
                base32_decode(&unpadded).expect("décodage").expose(),
                input.as_slice(),
                "aller-retour sans remplissage, longueur {len}"
            );

            let b64 = base64url_encode(&input);
            assert_eq!(
                base64url_decode(&b64).expect("décodage").expose(),
                input.as_slice(),
                "aller-retour Base64url, longueur {len}"
            );
        }
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet_without_padding() {
        // 0xFB 0xFF produit '+' et '/' en Base64 standard ; en Base64url ce sont
        // '-' et '_'. C'est la seule différence, et elle doit être vérifiée.
        assert_eq!(base64url_encode(&[0xFB, 0xFF]), "-_8");
        assert!(!base64url_encode(&[0xFB, 0xFF, 0x00]).contains('='));
        assert_eq!(
            base64url_decode("-_8").expect("décodage").expose(),
            [0xFB, 0xFF]
        );
    }

    #[test]
    fn hex_is_lowercase_and_two_chars_per_byte() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0x0F, 0xFF]), "000fff");
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn base32_is_case_insensitive() {
        let upper = base32_decode("MZXW6YTBOI======").expect("majuscules");
        let lower = base32_decode("mzxw6ytboi======").expect("minuscules");
        assert_eq!(upper.expose(), lower.expose());
        assert_eq!(upper.expose(), b"foobar");
    }

    #[test]
    fn a_character_outside_the_alphabet_is_refused() {
        // 0, 1, 8 et 9 sont volontairement absents de l'alphabet Base32.
        for text in ["M0XW6YTB", "M1XW6YTB", "M8XW6YTB", "M9XW6YTB", "MZXW6YTB!"] {
            assert!(
                base32_decode(text).is_err(),
                "« {text} » devrait être refusé : caractère hors alphabet"
            );
        }
    }

    #[test]
    fn padding_in_the_middle_is_refused() {
        assert!(base32_decode("MY======").is_ok());
        assert!(
            base32_decode("MY==MZ").is_err(),
            "remplissage au milieu accepté"
        );
        assert!(base32_decode("M=Y").is_err());
    }

    #[test]
    fn impossible_lengths_are_refused() {
        // Restes 1, 3 et 6 modulo 8 : aucune suite d'octets ne les produit.
        for text in ["M", "MZX", "MZXW6Y"] {
            assert!(
                base32_decode(text).is_err(),
                "« {text} » (longueur {}) devrait être refusée",
                text.len()
            );
        }
    }

    /// Un encodage non canonique produirait deux chaînes distinctes pour les mêmes
    /// octets — un vecteur de malléabilité. Il doit être refusé.
    #[test]
    fn non_zero_padding_bits_are_refused() {
        // « MY » code « f » ; « MZ » porte les mêmes huit bits utiles mais avec les
        // deux bits résiduels à 1, ce que la RFC 4648 §6 interdit.
        assert_eq!(base32_decode("MY").expect("canonique").expose(), b"f");
        assert!(
            base32_decode("MZ").is_err(),
            "bits résiduels non nuls acceptés"
        );
    }

    #[test]
    fn an_oversized_input_is_refused_before_any_allocation() {
        let huge = "A".repeat(MAX_ENCODED_CHARS + 1);
        assert!(base32_decode(&huge).is_err());
        // Exactement à la borne : la longueur 4096 est un multiple de 8, donc
        // valide et décodable.
        let at_limit = "A".repeat(MAX_ENCODED_CHARS);
        assert!(base32_decode(&at_limit).is_ok());
    }

    #[test]
    fn an_empty_string_decodes_to_nothing() {
        assert_eq!(base32_decode("").expect("décodage").len(), 0);
        assert_eq!(base64url_decode("").expect("décodage").len(), 0);
        assert_eq!(base32_encode(&[]), "");
        assert_eq!(base64url_encode(&[]), "");
    }

    /// Toutes les troncatures d'un encodage valide : soit un refus, soit un
    /// résultat, jamais une panique.
    #[test]
    fn every_truncation_is_handled_without_panic() {
        let encoded = base32_encode(b"un secret de test");
        for cut in 0..encoded.len() {
            let _ = base32_decode(&encoded[..cut]);
        }

        let b64 = base64url_encode(b"un secret de test");
        for cut in 0..b64.len() {
            let _ = base64url_decode(&b64[..cut]);
        }
    }

    #[test]
    fn only_the_terminator_padding_is_accepted() {
        assert!(
            base32_decode("====").is_ok(),
            "quatre remplissages = zéro octet"
        );
        assert!(base32_decode("M=====").is_err(), "reste 1 impossible");
    }

    // -- Punycode ------------------------------------------------------------

    #[test]
    fn known_punycode_vectors_round_trip() {
        // Exemples canoniques (IDNA) : « bücher » et « münchen ».
        assert_eq!(punycode_encode("bücher").expect("encodage"), "bcher-kva");
        assert_eq!(punycode_decode("bcher-kva").expect("décodage"), "bücher");
        assert_eq!(punycode_encode("münchen").expect("encodage"), "mnchen-3ya");
        assert_eq!(punycode_decode("mnchen-3ya").expect("décodage"), "münchen");
    }

    #[test]
    fn punycode_is_a_bijection_on_unicode_input() {
        // Aucun vecteur mémorisé : la propriété vérifiée est l'inverse exact.
        for sample in [
            "münchen",
            "bücher",
            "日本語",
            "пример",
            "مرحبا",
            "🔐",
            "ünïcödé",
            "exemple",
            "a",
        ] {
            let encoded = punycode_encode(sample).expect("encodage");
            let decoded = punycode_decode(&encoded).expect("décodage");
            assert_eq!(
                decoded, sample,
                "aller-retour de « {sample} » via « {encoded} »"
            );
        }
    }

    #[test]
    fn an_all_ascii_label_gets_the_delimiter() {
        // C'est ce qui rend un `xn--` décodant vers de l'ASCII détectable.
        assert_eq!(punycode_encode("exemple").expect("encodage"), "exemple-");
        assert_eq!(punycode_decode("exemple-").expect("décodage"), "exemple");
    }

    #[test]
    fn invalid_punycode_payloads_are_refused() {
        // Chiffre hors alphabet.
        assert!(punycode_decode("mnchen-3y!").is_err());
        // Majuscules refusées : les A-labels sont en minuscules.
        assert!(punycode_decode("MNCHEN-3YA").is_err());
        // Entrée tronquée au milieu d'un entier.
        assert!(punycode_decode("mnchen-3").is_err());
        // Point de code basique inséré : impossible d'après la RFC.
        assert!(punycode_decode("a-1").is_err());
    }

    #[test]
    fn punycode_inputs_are_bounded() {
        let huge = "a".repeat(MAX_PUNYCODE_LEN + 1);
        assert!(punycode_decode(&huge).is_err());
        assert!(punycode_encode(&huge).is_err());
    }

    #[test]
    fn an_empty_punycode_payload_decodes_to_nothing() {
        assert_eq!(punycode_decode("").expect("décodage"), "");
        assert_eq!(punycode_encode("").expect("encodage"), "");
    }
}
