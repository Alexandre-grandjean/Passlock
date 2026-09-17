//! Identifiants du modèle.
//!
//! # Pourquoi aléatoires, et non dérivés
//!
//! Un identifiant dérivé du contenu — un condensé du titre, par exemple —
//! permettrait à quiconque connaît le titre de **confirmer la présence** d'une
//! entrée dans un coffre, sans même avoir besoin de le déchiffrer dans le cas d'un
//! identifiant stocké en clair. Un identifiant aléatoire ne dit rien.
//!
//! # Pourquoi 16 octets
//!
//! 128 bits rendent une collision négligeable même avec des millions d'entrées, et
//! la taille correspond à celle d'un UUID — ce qui rend l'export et l'interopérabilité
//! triviaux si le besoin apparaît.
//!
//! # Ne sont pas des secrets
//!
//! Ces identifiants sont aléatoires, mais ils ne sont **pas** traités comme des
//! secrets : ils ne sont jamais utilisés comme clé, et leur comparaison n'a pas
//! besoin d'être constante en temps. Ils ne vivent de toute façon que dans le corps
//! chiffré.

use std::fmt;

use super::wipe::Wipe;

/// Identifiant d'entrée.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EntryId([u8; 16]);

/// Identifiant de dossier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FolderId([u8; 16]);

/// Identifiant de tag.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TagId([u8; 16]);

/// Identifiant de pièce jointe chiffrée.
///
/// Déclaré dès la phase 2 pour que le format d'archive l'accueille sans rupture,
/// même si les pièces jointes ne sont pas encore implémentées.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlobId([u8; 16]);

/// Déclare un identifiant : accès aux octets, hexadécimal, génération aléatoire.
macro_rules! impl_identifier {
    ($type:ident, $label:literal) => {
        impl $type {
            /// Octets bruts, pour l'encodage.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Construit depuis des octets, pour le décodage.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Identifiant nul, qui signifie « aucun » pour les références
            /// optionnelles : le format encode une absence par seize zéros plutôt
            /// que par une longueur variable.
            #[must_use]
            pub const fn nil() -> Self {
                Self([0_u8; 16])
            }

            /// Vrai si l'identifiant est nul.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0 == [0_u8; 16]
            }

            /// Génère un identifiant aléatoire.
            ///
            /// # Erreurs
            /// Propage l'échec du générateur du système. Aucun repli n'existe : un
            /// identifiant prévisible serait, dans le meilleur des cas, une
            /// collision, et dans le pire une information exploitable.
            pub fn generate() -> crate::error::Result<Self> {
                Ok(Self(crate::rng::array::<16>()?))
            }

            /// Représentation hexadécimale, pour l'affichage et la saisie.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let mut out = String::with_capacity(32);
                for byte in &self.0 {
                    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
                }
                out
            }

            /// Lit un identifiant depuis sa représentation hexadécimale.
            ///
            /// # Erreurs
            /// [`crate::error::Error::Internal`] si la chaîne n'est pas exactement
            /// 32 caractères hexadécimaux. L'appelant convertit cet échec en message
            /// destiné à l'utilisateur : c'est une erreur de saisie, pas une
            /// corruption.
            pub fn from_hex(text: &str) -> crate::error::Result<Self> {
                if text.len() != 32 {
                    return Err(crate::error::Error::Internal {
                        invariant: concat!($label, " : longueur hexadécimale invalide"),
                    });
                }
                let mut bytes = [0_u8; 16];
                for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
                    let high = hex_digit(pair[0])?;
                    let low = hex_digit(pair[1])?;
                    bytes[index] = (high << 4) | low;
                }
                Ok(Self(bytes))
            }
        }

        // Un identifiant est `Copy` : il ne peut donc pas porter de `Drop`. Son
        // effacement n'est pas une exigence de sécurité — il ne s'agit pas d'un
        // secret — mais l'implémentation existe pour que les `Vec` d'identifiants
        // restent effaçables de façon uniforme, sans exception à retenir.
        impl Wipe for $type {
            fn wipe(&mut self) {
                self.0.wipe();
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "({})"), self.to_hex())
            }
        }
    };
}

/// Convertit un caractère hexadécimal en valeur.
fn hex_digit(byte: u8) -> crate::error::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(crate::error::Error::Internal {
            invariant: "caractère non hexadécimal dans un identifiant",
        }),
    }
}

impl_identifier!(EntryId, "EntryId");
impl_identifier!(FolderId, "FolderId");
impl_identifier!(TagId, "TagId");
impl_identifier!(BlobId, "BlobId");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_are_distinct() {
        let first = EntryId::generate().expect("aléa");
        let second = EntryId::generate().expect("aléa");
        assert_ne!(first, second);
        assert!(!first.is_nil());
    }

    #[test]
    fn nil_is_all_zeroes_and_detected() {
        assert!(EntryId::nil().is_nil());
        assert_eq!(EntryId::nil().as_bytes(), &[0_u8; 16]);
        assert!(!EntryId::from_bytes([1_u8; 16]).is_nil());
    }

    #[test]
    fn hex_round_trips() {
        let original = EntryId::generate().expect("aléa");
        let text = original.to_hex();
        assert_eq!(text.len(), 32);
        assert_eq!(EntryId::from_hex(&text).expect("relecture"), original);
    }

    #[test]
    fn hex_accepts_both_cases() {
        let lower = EntryId::from_hex("00112233445566778899aabbccddeeff").expect("minuscules");
        let upper = EntryId::from_hex("00112233445566778899AABBCCDDEEFF").expect("majuscules");
        assert_eq!(lower, upper);
        assert_eq!(lower.as_bytes()[0], 0x00);
        assert_eq!(lower.as_bytes()[15], 0xFF);
    }

    #[test]
    fn malformed_hex_is_refused() {
        for candidate in [
            "",
            "00",
            "00112233445566778899aabbccddeef",   // 31 caractères
            "00112233445566778899aabbccddeeff0", // 33
            "00112233445566778899aabbccddeeg",   // caractère invalide
            "00112233445566778899aabbccddee g",
        ] {
            assert!(
                EntryId::from_hex(candidate).is_err(),
                "« {candidate} » aurait dû être refusé"
            );
        }
    }

    #[test]
    fn display_and_debug_are_explicit() {
        let id = EntryId::from_bytes([0xAB_u8; 16]);
        assert_eq!(id.to_string(), "abababababababababababababababab");
        assert!(format!("{id:?}").starts_with("EntryId("));
        assert!(format!("{:?}", TagId::nil()).starts_with("TagId("));
    }
}
