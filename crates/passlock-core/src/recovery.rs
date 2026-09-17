//! Clé de récupération : encodage Crockford Base32, total de contrôle.
//!
//! # Le problème
//!
//! Une clé de récupération est **transcrite par un être humain** : recopiée d'un
//! papier, dictée, retapée depuis une photo. Un alphabet qui confond `0` et `O`,
//! `1` et `I`, ou `l` et `1` produit des erreurs de recopie silencieuses : la clé
//! paraît juste, elle ne l'est pas, et l'utilisateur ne le découvre qu'au moment où
//! il en a besoin — c'est-à-dire trop tard.
//!
//! Crockford Base32 est conçu pour cela : son alphabet exclut `I`, `L`, `O` et `U`,
//! et la spécification **définit** la normalisation des caractères ambigus à la
//! lecture (`I` et `L` valent `1`, `O` vaut `0`).
//!
//! # Ce que ce module ajoute
//!
//! 1. un **total de contrôle** de 40 bits : une erreur de recopie est refusée avant
//!    toute tentative de déverrouillage, ce qui évite de faire croire à un mauvais
//!    chemin d'ouverture ;
//! 2. une **canonicité** stricte : les bits de remplissage doivent être nuls, donc
//!    une chaîne donnée n'a qu'une seule clé correspondante ;
//! 3. un décodage **strict** : longueur exacte, alphabet fermé, `U` refusé.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne rend pas la clé « sûre à dicter au téléphone ». Un total de contrôle
//! détecte une faute de frappe, il ne protège pas d'une écoute.

use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::rng;
use crate::secret::Key;

/// Longueur de la clé de récupération, en octets.
pub const RECOVERY_KEY_LEN: usize = 32;

/// Alphabet Crockford Base32 : `I`, `L`, `O` et `U` en sont absents.
///
/// `U` est exclu par la spécification pour éviter de former des mots malheureux par
/// accident. `I`, `L` et `O` sont exclus parce qu'ils se confondent avec `1` et `0` à
/// la lecture — et la normalisation ci-dessous rattrape le cas où l'utilisateur les
/// écrit quand même.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Nombre de caractères portant la clé : 32 octets = 256 bits.
///
/// 52 × 5 = 260 bits, soit **4 bits de remplissage**, qui doivent être nuls.
const PAYLOAD_CHARS: usize = 52;

/// Nombre de caractères du total de contrôle : 5 octets = 40 bits = 8 × 5 exactement.
const CHECK_CHARS: usize = 8;

/// Nombre d'octets de total de contrôle.
const CHECK_BYTES: usize = 5;

/// Nombre total de caractères, séparateurs exclus.
pub const TOTAL_CHARS: usize = PAYLOAD_CHARS + CHECK_CHARS;

/// Taille d'un groupe d'affichage.
const GROUP: usize = 5;

/// Séparateur d'affichage, ignoré à la lecture.
const SEPARATOR: char = '-';

/// Domaine de dérivation du total de contrôle.
///
/// Le domaine sépare ce condensé de tout autre usage de SHA-256 dans le projet : sans
/// lui, un condensé calculé ailleurs sur les mêmes octets serait valide ici.
const CHECK_DOMAIN: &[u8] = b"passlock/v1/recovery-check";

/// Une clé de récupération de 256 bits.
///
/// Le matériel est verrouillé en RAM quand le système le permet, effacé à la
/// destruction, jamais copiable implicitement et jamais affiché : `Debug` rédige.
pub struct RecoveryKey(Key<RECOVERY_KEY_LEN>);

impl RecoveryKey {
    /// Tire une clé neuve du générateur du système.
    ///
    /// # Erreurs
    /// Propage l'échec du générateur. Aucun repli n'existe.
    pub fn generate() -> Result<Self> {
        Ok(Self(rng::key::<RECOVERY_KEY_LEN>()?))
    }

    /// Reconstruit une clé à partir d'octets.
    ///
    /// # Erreurs
    /// [`Error::InvalidLength`] si `bytes` ne fait pas exactement 32 octets.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Key::<RECOVERY_KEY_LEN>::from_slice(bytes)?))
    }

    /// Accès en lecture au matériel de clé.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Vrai si le matériel a pu être verrouillé en RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// Encode la clé en Crockford Base32, avec son total de contrôle.
    ///
    /// La chaîne est effacée à la destruction : c'est un secret au même titre que la
    /// clé qu'elle transporte.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut payload = encode_bits(self.0.expose(), PAYLOAD_CHARS);
        let check = check_bytes(self.0.expose());
        payload.push_str(&encode_bits(&check, CHECK_CHARS));
        Zeroizing::new(group(&payload))
    }

    /// Décode une clé depuis sa forme textuelle.
    ///
    /// Le décodage est **strict** : longueur exacte, alphabet fermé, `U` refusé, bits
    /// de remplissage nuls et total de contrôle vérifié en temps constant.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] pour toute forme non canonique ou tout total de
    /// contrôle invalide.
    pub fn decode(text: &str) -> Result<Self> {
        let stripped: String = text.chars().filter(|c| *c != SEPARATOR).collect();
        let chars: Vec<char> = stripped.chars().collect();
        if chars.len() != TOTAL_CHARS {
            return Err(Error::InvalidInput {
                reason: "longueur de clé de récupération incorrecte",
            });
        }

        let payload = decode_bits(&chars[..PAYLOAD_CHARS], RECOVERY_KEY_LEN)?;
        let provided = decode_bits(&chars[PAYLOAD_CHARS..], CHECK_BYTES)?;

        let key = Key::<RECOVERY_KEY_LEN>::from_slice(&payload)?;
        let expected = check_bytes(key.expose());

        if !bool::from(provided.ct_eq(&expected)) {
            return Err(Error::InvalidInput {
                reason: "total de contrôle de la clé de récupération invalide",
            });
        }
        Ok(Self(key))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey([EXPURGÉ])")
    }
}

/// Total de contrôle : 40 premiers bits de `SHA-256(domaine ‖ clé)`.
///
/// # Pourquoi SHA-256 tronqué plutôt qu'un CRC
///
/// `sha2` est déjà une dépendance du cœur ; l'implémentation tient en trois lignes.
/// Un CRC exigerait de choisir et de justifier un polynôme — davantage de code à se
/// tromper, pour un gain marginal sur des chaînes de 60 caractères.
fn check_bytes(key: &[u8]) -> [u8; CHECK_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(CHECK_DOMAIN);
    hasher.update(key);
    let digest = hasher.finalize();

    let mut out = [0_u8; CHECK_BYTES];
    out.copy_from_slice(&digest[..CHECK_BYTES]);
    out
}

/// Valeur d'un caractère, après normalisation Crockford.
///
/// `I` et `L` valent `1`, `O` vaut `0`, la casse est ignorée. Tout le reste — `U`
/// compris — est refusé.
fn value_of(ch: char) -> Result<u8> {
    let normalized = match ch.to_ascii_uppercase() {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    let byte = u8::try_from(normalized).unwrap_or(0);
    ALPHABET
        .iter()
        .position(|c| *c == byte)
        .map(|index| u8::try_from(index).unwrap_or(0))
        .ok_or(Error::InvalidInput {
            reason: "caractère hors de l'alphabet Crockford Base32",
        })
}

/// Encode `bytes` sur exactement `char_count` caractères, bits de poids fort d'abord.
fn encode_bits(bytes: &[u8], char_count: usize) -> String {
    let mut out = String::with_capacity(char_count);
    let mut accumulator: usize = 0;
    let mut bits: u32 = 0;

    for byte in bytes {
        accumulator = (accumulator << 8) | usize::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = (accumulator >> bits) & 0x1F;
            out.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        // Les bits restants sont alignés en tête du dernier caractère ; les
        // positions basses, qui ne portent rien, restent à zéro — c'est ce qui rend
        // l'encodage **canonique**.
        let index = (accumulator << (5 - bits)) & 0x1F;
        out.push(char::from(ALPHABET[index]));
    }

    debug_assert_eq!(out.chars().count(), char_count);
    out
}

/// Décode `chars` et exige un résultat de `byte_count` octets, remplissage nul.
fn decode_bits(chars: &[char], byte_count: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(byte_count));
    let mut accumulator: usize = 0;
    let mut bits: u32 = 0;

    for ch in chars {
        accumulator = (accumulator << 5) | usize::from(value_of(*ch)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = (accumulator >> bits) & 0xFF;
            out.push(u8::try_from(byte).unwrap_or(0));
        }
    }

    // Les bits non consommés sont du remplissage : ils doivent être nuls. Sans cette
    // exigence, plusieurs chaînes distinctes désigneraient la même clé, et le total
    // de contrôle lui-même cesserait d'être canonique.
    if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
        return Err(Error::InvalidInput {
            reason: "bits de remplissage non nuls",
        });
    }
    if out.len() != byte_count {
        return Err(Error::InvalidInput {
            reason: "longueur décodée incorrecte",
        });
    }
    Ok(out)
}

/// Groupe les caractères par blocs de [`GROUP`] séparés par un tiret.
///
/// Le tiret ne figure pas dans l'alphabet, et la lecture l'ignore : il améliore la
/// recopie sans introduire d'ambiguïté.
fn group(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() + payload.len() / GROUP);
    for (index, ch) in payload.chars().enumerate() {
        if index > 0 && index % GROUP == 0 {
            out.push(SEPARATOR);
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn key_from(byte: u8) -> RecoveryKey {
        RecoveryKey::from_bytes(&[byte; RECOVERY_KEY_LEN]).expect("clé")
    }

    #[test]
    fn a_generated_key_round_trips() {
        for _ in 0..64 {
            let key = RecoveryKey::generate().expect("génération");
            let encoded = key.encode();
            let decoded = RecoveryKey::decode(&encoded).expect("décodage");
            assert!(
                decoded.0.constant_time_eq(&key.0),
                "la clé relue doit être identique"
            );
        }
    }

    #[test]
    fn the_encoded_form_has_the_documented_shape() {
        let encoded = key_from(0x5A).encode();
        assert_eq!(
            encoded.chars().filter(|c| *c != SEPARATOR).count(),
            TOTAL_CHARS
        );
        assert_eq!(
            encoded.chars().filter(|c| *c == SEPARATOR).count(),
            TOTAL_CHARS / GROUP - 1,
            "12 groupes de 5, donc 11 séparateurs"
        );
        assert!(
            encoded
                .chars()
                .all(|c| c == SEPARATOR || value_of(c).is_ok()),
            "tout caractère doit appartenir à l'alphabet"
        );
    }

    #[test]
    fn the_separators_are_not_significant() {
        let key = key_from(0x11);
        let encoded = key.encode();
        let without = encoded.replace(SEPARATOR, "");
        let decoded = RecoveryKey::decode(&without).expect("décodage sans séparateurs");
        assert!(decoded.0.constant_time_eq(&key.0));
    }

    #[test]
    fn decoding_is_case_insensitive() {
        let key = key_from(0x3C);
        let lower = key.encode().to_lowercase();
        let decoded = RecoveryKey::decode(&lower).expect("décodage en minuscules");
        assert!(decoded.0.constant_time_eq(&key.0));
    }

    #[test]
    fn ambiguous_characters_are_normalised() {
        // `I` et `L` valent `1`, `O` vaut `0`. On construit la forme ambiguë à partir
        // de l'encodage canonique, puis on vérifie que la lecture les rattrape.
        let key = key_from(0xFF);
        let canonical = key.encode().replace(SEPARATOR, "");
        let ambiguous: String = canonical
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                other => other,
            })
            .collect();
        assert_ne!(
            ambiguous, canonical,
            "le test doit vraiment introduire des ambiguïtés"
        );

        let decoded = RecoveryKey::decode(&ambiguous).expect("décodage ambigu");
        assert!(decoded.0.constant_time_eq(&key.0));
    }

    #[test]
    fn a_wrong_length_is_refused() {
        let encoded = key_from(7).encode();
        let without: String = encoded.chars().filter(|c| *c != SEPARATOR).collect();

        let mut too_long = without.clone();
        too_long.push('0');

        for len in [0_usize, 1, TOTAL_CHARS - 1] {
            let truncated: String = without.chars().take(len).collect();
            assert!(
                RecoveryKey::decode(&truncated).is_err(),
                "une longueur de {len} doit être refusée"
            );
        }
        assert!(
            RecoveryKey::decode(&too_long).is_err(),
            "une longueur de {} doit être refusée",
            TOTAL_CHARS + 1
        );
    }

    #[test]
    fn every_single_character_substitution_is_refused() {
        // Un total de contrôle de 40 bits doit refuser toute substitution : c'est
        // exactement le défaut qu'il existe pour attraper.
        let key = key_from(0x42);
        let canonical: Vec<char> = key.encode().chars().filter(|c| *c != SEPARATOR).collect();

        for position in 0..TOTAL_CHARS {
            for replacement in ALPHABET {
                let replacement = char::from(*replacement);
                if canonical[position] == replacement {
                    continue;
                }
                let mut candidate = canonical.clone();
                candidate[position] = replacement;
                let text: String = candidate.into_iter().collect();
                assert!(
                    RecoveryKey::decode(&text).is_err(),
                    "une substitution en position {position} a été acceptée"
                );
            }
        }
    }

    #[test]
    fn the_u_character_is_refused() {
        // `U` est absent de l'alphabet Crockford : il doit être refusé et non
        // silencieusement rangé dans une case voisine.
        assert!(value_of('U').is_err());
        assert_eq!(value_of('O').expect("O vaut 0"), 0);
        assert_eq!(value_of('I').expect("I vaut 1"), 1);
        assert_eq!(value_of('L').expect("L vaut 1"), 1);
    }

    #[test]
    fn the_final_payload_character_carries_only_one_bit() {
        // 52 × 5 = 260 bits pour 256 utiles : les **quatre bits de poids faible** du
        // dernier caractère doivent être nuls. Le bit utile occupe la position
        // haute, donc la valeur du caractère vaut 0 ou 16 — et le décodeur exige
        // exactement `valeur & 0b1111 == 0`.
        for byte in [0x00_u8, 0x01, 0x7F, 0x80, 0xFF] {
            let encoded = key_from(byte).encode();
            let payload: Vec<char> = encoded
                .chars()
                .filter(|c| *c != SEPARATOR)
                .take(PAYLOAD_CHARS)
                .collect();
            let last = value_of(payload[PAYLOAD_CHARS - 1]).expect("valeur");
            assert!(
                last & 0b1111 == 0,
                "les quatre bits de remplissage doivent être nuls, or la valeur est {last}"
            );
            assert!(
                last <= 16,
                "un seul bit utile, donc une valeur parmi {{0, 16}}, pas {last}"
            );
        }
    }

    #[test]
    fn a_non_zero_padding_bit_is_refused() {
        // On force le dernier caractère de charge utile à une valeur dont les bits
        // de remplissage ne sont pas nuls : l'encodage doit être refusé comme non
        // canonique, même si le total de contrôle était recalculé.
        let key = key_from(0x01);
        let mut chars: Vec<char> = key.encode().chars().filter(|c| *c != SEPARATOR).collect();
        chars[PAYLOAD_CHARS - 1] = 'Z';

        let text: String = chars.into_iter().collect();
        assert!(
            RecoveryKey::decode(&text).is_err(),
            "un remplissage non nul doit être refusé"
        );
    }

    #[test]
    fn debug_output_does_not_expose_the_key() {
        let rendered = format!("{:?}", key_from(0xAB));
        assert!(rendered.contains("EXPURGÉ"));
        assert!(
            !rendered.contains("AB"),
            "aucun octet de clé ne doit apparaître"
        );
    }

    #[test]
    fn the_encoded_string_is_zeroizing() {
        // `Zeroizing<String>` : le type est bien celui attendu, et il s'efface.
        fn takes_zeroizing(_: &Zeroizing<String>) {}
        let key = key_from(3);
        takes_zeroizing(&key.encode());
    }
}
