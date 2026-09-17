//! Conteneur de coffre : encre de niveau 1.
//!
//! # Layout du fichier
//!
//! ```text
//!   offset  taille      contenu
//!   ------  ----------  ----------------------------------------------
//!   0       8           signature « PASSLOCK »
//!   8       2           version de format (u16, gros-boutiste)
//!   10      2           drapeaux (u16, gros-boutiste, doit valoir 0)
//!   12      4           longueur du header (u32, gros-boutiste)
//!   16      H           header (layout binaire fixe, voir header.rs)
//!   16+H    24          nonce du payload
//!   40+H    n           payload chiffré, tag d'authentification inclus
//! ```
//!
//! **Les octets `0 .. 16+H` forment l'AAD du payload.** Autrement dit, tout ce qui
//! n'est pas le contenu chiffré est authentifié : signature, version, drapeaux,
//! longueur, et l'intégralité du header — paramètres de dérivation et sels
//! compris. Il n'existe aucune donnée non authentifiée dans le fichier.
//!
//! ## Conséquence directe
//!
//! Une attaque par **abaissement des paramètres** (« downgrade ») est
//! structurellement impossible : réduire `m_cost` dans le header pour rendre le
//! cassage moins cher invalide le tag du payload. L'utilisateur légitime voit
//! « mot de passe incorrect ou coffre corrompu », l'attaquant n'apprend rien.
//!
//! ## Ce que le fichier révèle à qui le possède sans la clé
//!
//! La signature, la version, le nombre de slots, leurs paramètres de dérivation,
//! leurs sels, leurs rôles, la date de création, et la taille totale. Volontairement
//! **rien d'autre** : ni nombre d'entrées, ni titres, ni dossiers, ni index de
//! recherche. Le schéma de la base vit entièrement dans le payload chiffré, ce qui
//! permet de le faire évoluer pendant des années sans changer le conteneur.

use zeroize::Zeroizing;

use crate::aead::{self, AeadError, NONCE_LEN, TAG_LEN};
use crate::bytes as checked;
use crate::error::{Error, Result};
use crate::header::{FORMAT_VERSION, Header, MAGIC, MAX_HEADER_LEN, MAX_SUPPORTED_FORMAT_VERSION};
use crate::keys::KEY_LEN;
use crate::secret::Key;

/// Taille du préfixe fixe précédant le header.
pub const PREFIX_LEN: usize = 16;

/// Taille minimale d'un fichier de coffre valide : préfixe + header minimal
/// (un slot) + nonce + tag.
pub const MIN_VAULT_LEN: usize = PREFIX_LEN + 28 + 122 + NONCE_LEN + TAG_LEN;

/// Taille maximale acceptée pour un fichier de coffre, en octets.
///
/// Garde-fou contre un fichier démesuré, qui provoquerait une allocation massive
/// avant même l'analyse. Les pièces jointes ne sont pas dans le conteneur (elles
/// vivent dans des blobs séparés), donc cette borne est très large pour un usage
/// réel : quelques mégaoctets suffisent largement.
pub const MAX_VAULT_BYTES: usize = 512 * 1024 * 1024;

/// Vue structurelle d'un fichier de coffre, obtenue **sans** déchiffrer.
///
/// Permet de lire les métadonnées publiques (identifiant, date, slots, paramètres)
/// sans posséder la clé — utile pour un diagnostic, un rapport de santé, ou
/// simplement pour savoir quel coffre on a sous les yeux.
pub struct ParsedVault<'a> {
    /// Header décodé et validé.
    pub header: Header,
    /// Nonce du payload.
    pub payload_nonce: [u8; NONCE_LEN],
    /// Payload chiffré, tag inclus.
    pub payload_ciphertext: &'a [u8],
    /// Octets authentifiés (préfixe + header), conservés pour le déchiffrement.
    aad: Vec<u8>,
}

impl<'a> ParsedVault<'a> {
    /// Analyse la structure d'un fichier sans tenter de le déchiffrer.
    ///
    /// ## Ordre des vérifications, et pourquoi il compte
    ///
    /// 1. taille du fichier, signature, version, drapeaux ;
    /// 2. longueur du header, bornée et cohérente avec la taille du fichier ;
    /// 3. décodage du header, qui refuse les paramètres hors bornes.
    ///
    /// L'étape 3 est celle qui empêche un fichier hostile de nous faire allouer
    /// une quantité arbitraire de mémoire : le refus intervient **avant** toute
    /// dérivation. Aucune allocation n'est dimensionnée par une valeur lue dans le
    /// fichier avant d'avoir été bornée.
    ///
    /// Cette fonction ne panique sur aucune entrée, y compris un fichier vide, un
    /// fichier tronqué ou un fichier de 500 Mio de zéros. Elle est la cible
    /// principale du fuzzing.
    ///
    /// # Erreurs
    /// * [`Error::NotAVault`] si la signature est absente ;
    /// * [`Error::UnsupportedFormatVersion`] si la version dépasse nos capacités ;
    /// * [`Error::MalformedLength`] si les longueurs sont incohérentes ;
    /// * [`Error::InvalidHeader`] ou [`Error::RejectedKdfParams`] selon la
    ///   violation constatée dans le header.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_VAULT_BYTES {
            return Err(Error::MalformedLength {
                reason: "fichier de coffre au-delà de la taille maximale admise",
            });
        }
        if bytes.len() < PREFIX_LEN {
            // Un fichier trop court pour contenir ne serait-ce que le préfixe :
            // soit ce n'est pas un coffre, soit il est gravement tronqué. On ne
            // peut pas distinguer les deux, et cela n'a pas d'importance pratique.
            return Err(Error::NotAVault);
        }

        // Toutes les lectures ci-dessous passent par le module borné, qui vérifie
        // `offset + longueur` contre le débordement d'entier **avant** de découper.
        if checked::slice(bytes, 0, MAGIC.len(), "signature tronquée")? != MAGIC {
            return Err(Error::NotAVault);
        }

        let version = checked::u16_be(bytes, 8, "version de format tronquée")?;
        if version > MAX_SUPPORTED_FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion {
                found: version,
                supported: MAX_SUPPORTED_FORMAT_VERSION,
            });
        }

        let flags = checked::u16_be(bytes, 10, "drapeaux tronqués")?;
        if flags != 0 {
            // Une version future qui poserait un drapeau ne doit pas être lue par
            // cette version : ignorer un drapeau inconnu reviendrait à deviner sa
            // sémantique, ce qui est exactement la façon dont on introduit une
            // faille en rétrocompatibilité.
            return Err(Error::InvalidHeader {
                reason: "drapeaux de header non nuls et inconnus de cette version",
            });
        }

        let header_len =
            usize::try_from(checked::u32_be(bytes, 12, "longueur de header tronquée")?).map_err(
                |_| Error::MalformedLength {
                    reason: "longueur de header non représentable",
                },
            )?;

        if header_len > MAX_HEADER_LEN {
            return Err(Error::MalformedLength {
                reason: "longueur de header au-delà de la borne admise",
            });
        }

        // Le calcul est fait avec des entiers vérifiés : `checked_add` empêche
        // qu'une longueur aberrante provoque un dépassement qui contournerait la
        // vérification suivante.
        let body_start = PREFIX_LEN
            .checked_add(header_len)
            .ok_or(Error::MalformedLength {
                reason: "longueur de header provoquant un dépassement",
            })?;
        let minimum_total = body_start
            .checked_add(NONCE_LEN)
            .and_then(|value| value.checked_add(TAG_LEN))
            .ok_or(Error::MalformedLength {
                reason: "taille de fichier provoquant un dépassement",
            })?;

        if bytes.len() < minimum_total {
            return Err(Error::MalformedLength {
                reason: "fichier trop court pour la longueur de header annoncée",
            });
        }

        let aad = checked::slice(bytes, 0, body_start, "préfixe authentifié tronqué")?.to_vec();
        let header = Header::decode(checked::slice(
            bytes,
            PREFIX_LEN,
            header_len,
            "header tronqué",
        )?)?;

        let nonce_start = body_start;
        let payload_nonce = checked::array::<NONCE_LEN>(bytes, nonce_start, "nonce tronqué")?;
        let ciphertext_start =
            nonce_start
                .checked_add(NONCE_LEN)
                .ok_or(Error::MalformedLength {
                    reason: "dépassement d'entier en localisant le contenu chiffré",
                })?;
        let payload_ciphertext = checked::slice(
            bytes,
            ciphertext_start,
            bytes.len() - ciphertext_start,
            "contenu chiffré tronqué",
        )?;

        Ok(Self {
            header,
            payload_nonce,
            payload_ciphertext,
            aad,
        })
    }

    /// Déchiffre le payload et vérifie son authenticité.
    ///
    /// ## Contrat d'erreur
    ///
    /// Un échec ici devient [`Error::Corrupted`]. C'est légitime parce que cette
    /// méthode ne peut être appelée qu'avec une clé, donc après un déverrouillage
    /// réussi : si la clé est bonne et que le tag échoue, le contenu a bien été
    /// altéré. Il n'y a pas de fuite d'information, puisque l'échec du
    /// déverrouillage lui-même reste, lui, indiscernable d'un mauvais mot de passe
    /// (voir `error.rs`).
    ///
    /// ## Le contenu est renvoyé dans un buffer auto-effaçable
    ///
    /// Le résultat est le **contenu en clair du coffre entier**. Le renvoyer dans
    /// un `Zeroizing` garantit qu'il est effacé à sa destruction, y compris si
    /// l'appelant le laisse tomber sur un chemin d'erreur. Un `Vec<u8>` nu aurait
    /// reporté cette responsabilité sur chaque site d'appel.
    ///
    /// # Erreurs
    /// [`Error::Corrupted`] si le tag est invalide.
    pub fn decrypt(&self, key: &Key<KEY_LEN>) -> Result<Zeroizing<Vec<u8>>> {
        aead::open(key, &self.payload_nonce, self.payload_ciphertext, &self.aad)
            .map(Zeroizing::new)
            .map_err(|err| match err {
                AeadError::AuthenticationFailed => Error::Corrupted {
                    reason: "l'authentification du contenu a échoué : le coffre a été \
                             modifié ou tronqué depuis sa dernière écriture",
                },
                AeadError::MessageTooLong => Error::Corrupted {
                    reason: "contenu dépassant les limites du format",
                },
                _ => Error::Internal {
                    invariant: "longueur de clé ou de nonce invalide au déchiffrement",
                },
            })
    }

    /// Octets authentifiés du fichier (préfixe + header).
    #[must_use]
    pub fn authenticated_prefix(&self) -> &[u8] {
        &self.aad
    }
}

impl std::fmt::Debug for ParsedVault<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Le payload peut faire plusieurs mégaoctets : on n'affiche jamais son
        // contenu, seulement sa taille. Un `{:?}` sur cette structure est un
        // geste de diagnostic, pas une occasion de vider un fichier dans un log.
        f.debug_struct("ParsedVault")
            .field("header", &self.header)
            .field("payload_ciphertext_len", &self.payload_ciphertext.len())
            .field("authenticated_prefix_len", &self.aad.len())
            .finish()
    }
}

/// Scelle un coffre : encode le header, chiffre le payload, assemble le fichier.
///
/// Le header doit déjà contenir les slots de clé, donc les DEK enveloppées. La
/// construction complète est orchestrée par `vault.rs`.
///
/// # Erreurs
/// * [`Error::MalformedLength`] si le résultat dépasse [`MAX_VAULT_BYTES`] ;
/// * les erreurs d'encodage du header ;
/// * [`Error::Internal`] si l'AEAD échoue sur un message pourtant dimensionné.
pub fn seal(header: &Header, payload_key: &Key<KEY_LEN>, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header_bytes = header.encode()?;

    let header_len = u32::try_from(header_bytes.len()).map_err(|_| Error::MalformedLength {
        reason: "header trop long pour être décrit par le format",
    })?;

    let mut out =
        Vec::with_capacity(PREFIX_LEN + header_bytes.len() + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(&header_bytes);

    // À ce stade `out` contient exactement le préfixe et le header, c'est-à-dire
    // l'AAD. Calculer le tag sur ces octets les lie définitivement au contenu.
    let nonce = aead::generate_nonce().map_err(|_| Error::Internal {
        invariant: "générateur de nonce indisponible",
    })?;

    let ciphertext = aead::seal(payload_key, &nonce, plaintext, &out).map_err(|err| match err {
        AeadError::MessageTooLong => Error::MalformedLength {
            reason: "contenu trop volumineux pour le format de chiffrement",
        },
        _ => Error::Internal {
            invariant: "échec de chiffrement avec une clé de longueur valide",
        },
    })?;

    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    if out.len() > MAX_VAULT_BYTES {
        return Err(Error::MalformedLength {
            reason: "coffre résultant au-delà de la taille maximale admise",
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Slot, SlotLabel};
    use crate::kdf::KdfParams;
    use crate::keys::{WRAPPED_DEK_LEN, WrappedKey};

    fn test_key() -> Key<KEY_LEN> {
        Key::from_array([0x3C; KEY_LEN])
    }

    fn sample_header() -> Header {
        Header {
            vault_id: [2_u8; 16],
            created_at: 1_700_000_000,
            slots: vec![Slot {
                id: 0,
                label: SlotLabel::Master,
                params: KdfParams::low(),
                salt: [5_u8; 32],
                wrapped: WrappedKey::new([6_u8; 24], [7_u8; WRAPPED_DEK_LEN]),
            }],
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let header = sample_header();
        let key = test_key();
        let plaintext = b"contenu du coffre, non chiffre au depart";

        let file = seal(&header, &key, plaintext).expect("scellement");
        let parsed = ParsedVault::parse(&file).expect("analyse");

        assert_eq!(parsed.header.vault_id, header.vault_id);
        assert_eq!(parsed.header.created_at, header.created_at);
        assert_eq!(parsed.header.slots.len(), 1);
        assert_eq!(parsed.header.slots[0].salt, [5_u8; 32]);

        let recovered = parsed.decrypt(&key).expect("dechiffrement");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn layout_offsets_match_the_documented_format() {
        let header = sample_header();
        let key = test_key();
        let plaintext = b"AAAA";

        let file = seal(&header, &key, plaintext).expect("scellement");

        assert_eq!(&file[0..8], b"PASSLOCK");
        assert_eq!(u16::from_be_bytes([file[8], file[9]]), FORMAT_VERSION);
        assert_eq!(u16::from_be_bytes([file[10], file[11]]), 0);

        let header_len = u32::from_be_bytes([file[12], file[13], file[14], file[15]]) as usize;
        assert_eq!(header_len, header.encoded_len());
        assert_eq!(
            file.len(),
            PREFIX_LEN + header_len + NONCE_LEN + plaintext.len() + TAG_LEN
        );

        // L'AAD est exactement le préfixe suivi du header.
        let parsed = ParsedVault::parse(&file).expect("analyse");
        assert_eq!(
            parsed.authenticated_prefix(),
            &file[..PREFIX_LEN + header_len]
        );
    }

    #[test]
    fn empty_payload_roundtrips() {
        // Un coffre neuf, sans aucune entrée, doit être un cas valide.
        let file = seal(&sample_header(), &test_key(), b"").expect("scellement");
        let parsed = ParsedVault::parse(&file).expect("analyse");
        assert!(
            parsed
                .decrypt(&test_key())
                .expect("dechiffrement")
                .is_empty()
        );
    }

    #[test]
    fn wrong_key_is_reported_as_corruption() {
        // Après déverrouillage, une clé erronée ne peut pas être distinguée d'une
        // corruption : le tag ne dit pas laquelle des deux hypothèses est la
        // bonne. Le message le plus utile est donc « corrompu ».
        let file = seal(&sample_header(), &test_key(), b"contenu").expect("scellement");
        let parsed = ParsedVault::parse(&file).expect("analyse");

        let other = Key::from_array([0x3D; KEY_LEN]);
        assert!(matches!(
            parsed.decrypt(&other),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn every_payload_bit_flip_is_detected() {
        let file =
            seal(&sample_header(), &test_key(), b"contenu de reference").expect("scellement");
        let header_len = u32::from_be_bytes([file[12], file[13], file[14], file[15]]) as usize;
        let payload_start = PREFIX_LEN + header_len + NONCE_LEN;

        for index in payload_start..file.len() {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            let parsed = ParsedVault::parse(&tampered).expect("analyse");
            assert!(
                parsed.decrypt(&test_key()).is_err(),
                "un bit modifié à l'offset {index} du payload doit être détecté"
            );
        }
    }

    #[test]
    fn every_header_bit_flip_breaks_the_payload_tag() {
        // C'est LE test de l'attaque par abaissement des paramètres : modifier un
        // octet du header, c'est modifier l'AAD, donc invalider le tag.
        let file = seal(&sample_header(), &test_key(), b"contenu").expect("scellement");

        for index in 0..PREFIX_LEN + sample_header().encoded_len() {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;

            // Deux issues acceptables : le fichier est refusé à l'analyse, ou il
            // est analysé mais le déchiffrement échoue. Ce qui serait inacceptable
            // est une panique, ou un déchiffrement qui « réussit ».
            if let Ok(parsed) = ParsedVault::parse(&tampered) {
                assert!(
                    parsed.decrypt(&test_key()).is_err(),
                    "un bit modifié à l'offset {index} du header n'a pas invalidé le tag"
                );
            }
        }
    }

    #[test]
    fn lowering_the_kdf_cost_in_the_header_is_detected() {
        // Attaque concrète : un attaquant réduit m_cost dans le fichier volé pour
        // rendre le cassage hors ligne moins cher. Il ne peut pas le faire sans
        // invalider le tag.
        let file = seal(&sample_header(), &test_key(), b"contenu").expect("scellement");

        let m_cost_offset = PREFIX_LEN + 28 + 6;
        let mut tampered = file.clone();
        tampered[m_cost_offset..m_cost_offset + 4].copy_from_slice(&(8_u32 * 1024).to_be_bytes());

        // Le header reste structurellement valide (8 Mio est au-dessus du plancher),
        // donc l'analyse passe : c'est bien le tag qui doit arrêter l'attaque.
        let parsed = ParsedVault::parse(&tampered).expect("analyse");
        assert!(matches!(
            parsed.decrypt(&test_key()),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn missing_magic_is_rejected() {
        let mut file = seal(&sample_header(), &test_key(), b"x").expect("scellement");
        file[0] = b'Q';
        assert!(matches!(ParsedVault::parse(&file), Err(Error::NotAVault)));
    }

    #[test]
    fn future_version_is_reported_clearly() {
        let mut file = seal(&sample_header(), &test_key(), b"x").expect("scellement");
        file[8..10].copy_from_slice(&99_u16.to_be_bytes());
        assert!(matches!(
            ParsedVault::parse(&file),
            Err(Error::UnsupportedFormatVersion {
                found: 99,
                supported: 1
            })
        ));
    }

    #[test]
    fn unknown_flags_are_rejected() {
        let mut file = seal(&sample_header(), &test_key(), b"x").expect("scellement");
        file[10..12].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            ParsedVault::parse(&file),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn every_truncation_is_rejected_without_panic() {
        let file =
            seal(&sample_header(), &test_key(), b"contenu de reference").expect("scellement");

        for len in 0..file.len() {
            // Soit refusé à l'analyse, soit analysé mais indéchiffrable : jamais
            // une panique, jamais un déchiffrement réussi sur des données
            // incomplètes.
            if let Ok(parsed) = ParsedVault::parse(&file[..len]) {
                assert!(
                    parsed.decrypt(&test_key()).is_err(),
                    "troncature à {len} octets acceptée au déchiffrement"
                );
            }
        }
    }

    #[test]
    fn truncated_payload_is_reported_as_corruption() {
        // Cas particulier important : couper les derniers octets du payload.
        let file =
            seal(&sample_header(), &test_key(), b"contenu de reference").expect("scellement");
        let truncated = &file[..file.len() - 1];
        let parsed = ParsedVault::parse(truncated).expect("analyse");
        assert!(matches!(
            parsed.decrypt(&test_key()),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn absurd_header_lengths_are_refused_before_allocating() {
        for value in [0_u32, 1, 65_536, 1_000_000, u32::MAX] {
            let mut file = seal(&sample_header(), &test_key(), b"x").expect("scellement");
            file[12..16].copy_from_slice(&value.to_be_bytes());

            // Une longueur de header incohérente avec la taille réelle du fichier
            // doit toujours être refusée.
            assert!(
                ParsedVault::parse(&file).is_err(),
                "longueur de header {value} acceptée à tort"
            );
        }
    }

    #[test]
    fn empty_and_tiny_inputs_never_panic() {
        for candidate in [
            Vec::new(),
            vec![0_u8],
            vec![0_u8; 8],
            vec![0_u8; PREFIX_LEN - 1],
            vec![0_u8; PREFIX_LEN],
            vec![0_u8; MIN_VAULT_LEN - 1],
            vec![0xFF_u8; PREFIX_LEN],
        ] {
            assert!(ParsedVault::parse(&candidate).is_err());
        }
    }

    #[test]
    fn all_zero_file_is_not_a_vault() {
        assert!(matches!(
            ParsedVault::parse(&[0_u8; 4096]),
            Err(Error::NotAVault)
        ));
    }

    #[test]
    fn two_seals_of_the_same_content_differ() {
        // Chaque scellement doit utiliser un nonce neuf : deux fichiers de même
        // contenu ne doivent pas être identiques.
        let header = sample_header();
        let first = seal(&header, &test_key(), b"identique").expect("a");
        let second = seal(&header, &test_key(), b"identique").expect("b");
        assert_ne!(first, second);
    }

    #[test]
    fn header_is_exposed_without_the_key() {
        // Propriété voulue : on peut diagnostiquer un coffre sans le déverrouiller.
        let file = seal(&sample_header(), &test_key(), b"contenu").expect("scellement");
        let parsed = ParsedVault::parse(&file).expect("analyse");
        assert_eq!(parsed.header.vault_id, [2_u8; 16]);
        assert_eq!(parsed.header.slots[0].params, KdfParams::low());
        assert_eq!(parsed.header.slots[0].label, SlotLabel::Master);
    }
}
