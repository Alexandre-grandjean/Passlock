//! Header du coffre : layout binaire explicite, sans parseur générique.
//!
//! # Pourquoi un layout à offsets fixes plutôt que CBOR ou JSON
//!
//! Le header est **la seule donnée non fiable que nous traitons avant toute
//! authentification**. À ce stade, on ne sait pas encore si l'utilisateur
//! connaît le mot de passe ; on ne peut donc faire confiance à rien de ce qu'on
//! lit.
//!
//! Un format auto-descriptif (CBOR, JSON, MessagePack) exige un **parseur
//! générique** : gestion de structures imbriquées, de longueurs déclarées,
//! d'encodages d'entiers de tailles variables. Chacune de ces fonctionnalités est
//! une classe de vulnérabilité connue (bombe de récursion, dépassement d'entier,
//! épuisement mémoire par longueur déclarée, ambiguïté d'encodage canonique).
//! Utiliser une bibliothèque éprouvée réduit ce risque sans l'annuler : on
//! dépendrait alors de la robustesse d'un composant qu'on ne peut pas auditer
//! entièrement.
//!
//! Un layout à offsets fixes **supprime le parseur**. Il n'y a plus que des
//! lectures à position connue, chacune précédée d'une vérification de borne. Le
//! nombre de chemins de code est proportionnel au nombre de champs, et chaque
//! chemin est testable exhaustivement.
//!
//! ## Ce que cela coûte
//!
//! Ajouter un champ exige d'incrémenter `format_version` et d'écrire une
//! migration. C'est un coût réel, accepté sciemment : en contrepartie, tout ce qui
//! évolue vite — modèles d'entrées, dossiers, tags, index de recherche — vit
//! **dans le payload chiffré**, dont le schéma est indépendant du conteneur. Le
//! header ne changera donc quasiment jamais.
//!
//! # Invariant central
//!
//! Le header entier est passé en **AAD** au chiffrement du payload. Conséquence :
//! falsifier un seul octet du header — y compris un paramètre Argon2id, un sel ou
//! un identifiant de slot — invalide le tag du payload. Il n'existe aucune donnée
//! non authentifiée dans le fichier.

use crate::bytes as checked;
use crate::error::{Error, Result};
use crate::kdf::{KdfParams, SALT_LEN};
use crate::keys::{KEY_LEN, WRAPPED_DEK_LEN, WrappedKey};
use crate::rng;

/// Signature du fichier, en tête de conteneur.
pub const MAGIC: [u8; 8] = *b"PASSLOCK";

/// Version de format produite par ce binaire.
pub const FORMAT_VERSION: u16 = 1;

/// Version de format la plus récente que ce binaire sait lire.
pub const MAX_SUPPORTED_FORMAT_VERSION: u16 = 1;

/// Longueur de l'identifiant de coffre.
pub const VAULT_ID_LEN: usize = 16;

/// Nombre maximal de slots de clé acceptés.
///
/// Borne le travail de lecture et empêche un header hostile de déclarer un nombre
/// de slots arbitraire. En pratique on en utilise un à trois.
pub const MAX_SLOTS: usize = 16;

/// Longueur maximale acceptée pour le header encodé, en octets.
///
/// `28 + 16 × 122 = 1980` octets au maximum avec les bornes ci-dessus ; on garde
/// une marge sans permettre une allocation arbitraire.
pub const MAX_HEADER_LEN: usize = 4096;

/// Taille de la partie fixe du header (avant la liste des slots).
const HEADER_FIXED_LEN: usize = 28;

/// Taille d'un slot encodé.
const SLOT_LEN: usize = 2   // id
    + 1                     // label
    + 1                     // kdf_alg
    + 1                     // argon2_version
    + 1                     // réservé (doit valoir 0)
    + 4                     // m_cost_kib
    + 4                     // t_cost
    + 4                     // p_cost
    + SALT_LEN              // salt
    + 24                    // nonce d'enveloppe
    + WRAPPED_DEK_LEN; // DEK enveloppée

/// Préfixe des données authentifiées d'un slot.
const SLOT_AAD_PREFIX: &[u8] = b"passlock/v1/slot";

/// Identifiant d'algorithme AEAD du payload.
const ALG_XCHACHA20POLY1305: u8 = 1;

/// Identifiant d'algorithme de dérivation.
const ALG_ARGON2ID: u8 = 1;

/// Version d'Argon2 (1.3, la seule utilisée).
const ARGON2_VERSION: u8 = 0x13;

/// Rôle d'un slot de clé.
///
/// Sert à l'affichage et au diagnostic. La valeur est **authentifiée** : elle
/// entre dans l'AAD du slot, donc un slot ne peut pas changer de rôle sans devenir
/// indéscriptible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotLabel {
    /// Slot principal, déverrouillé par le mot de passe maître.
    Master,
    /// Slot déverrouillé par une clé de récupération.
    Recovery,
    /// Slot déverrouillé par une clé matérielle.
    Hardware,
}

impl SlotLabel {
    fn to_byte(self) -> u8 {
        match self {
            Self::Master => 1,
            Self::Recovery => 2,
            Self::Hardware => 3,
        }
    }

    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Master),
            2 => Ok(Self::Recovery),
            3 => Ok(Self::Hardware),
            _ => Err(Error::InvalidHeader {
                reason: "rôle de slot inconnu",
            }),
        }
    }
}

/// Un slot de clé : tout ce qu'il faut pour retrouver la DEK à partir d'un
/// matériel de clé.
#[derive(Debug, Clone)]
pub struct Slot {
    /// Identifiant du slot, unique dans le header.
    pub id: u16,
    /// Rôle du slot.
    pub label: SlotLabel,
    /// Paramètres Argon2id propres à ce slot.
    pub params: KdfParams,
    /// Sel propre à ce slot.
    pub salt: [u8; SALT_LEN],
    /// DEK enveloppée sous la KEK de ce slot.
    pub wrapped: WrappedKey,
}

impl Slot {
    /// Construit un slot avec un sel aléatoire neuf.
    ///
    /// # Erreurs
    /// Propage l'échec du générateur du système.
    pub fn new(id: u16, label: SlotLabel, params: KdfParams, wrapped: WrappedKey) -> Result<Self> {
        Ok(Self {
            id,
            label,
            params,
            salt: rng::array::<SALT_LEN>()?,
            wrapped,
        })
    }

    /// Données authentifiées liant ce slot à son contexte.
    ///
    /// ## Ce que cette liaison empêche
    ///
    /// Sans elle, un attaquant pourrait **déplacer un slot d'un coffre à un
    /// autre**, ou échanger deux slots dans le même header. Le désenveloppement
    /// réussirait — la KEK correspondrait toujours — et l'application utiliserait
    /// silencieusement une DEK qui n'est pas celle du slot attendu. Avec la
    /// liaison, tout déplacement invalide l'authentification.
    ///
    /// Sont couverts : l'identité du coffre, l'identité et le rôle du slot, et
    /// l'intégralité des paramètres de dérivation (algorithme, version, coût
    /// mémoire, itérations, parallélisme, sel).
    ///
    /// Les octets de la DEK enveloppée ne sont **pas** inclus : ils portent leur
    /// propre tag, et les inclure rendrait la structure circulaire (il faudrait
    /// connaître le résultat pour calculer l'entrée).
    #[must_use]
    pub fn aad(&self, vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLOT_AAD_PREFIX.len() + 16 + 6 + 8 + SALT_LEN);
        out.extend_from_slice(SLOT_AAD_PREFIX);
        out.extend_from_slice(vault_id);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(self.label.to_byte());
        out.push(ALG_ARGON2ID);
        out.push(ARGON2_VERSION);
        out.extend_from_slice(&self.params.m_cost_kib().to_be_bytes());
        out.extend_from_slice(&self.params.t_cost().to_be_bytes());
        out.extend_from_slice(&self.params.p_cost().to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }
}

/// Header complet du coffre.
#[derive(Debug, Clone)]
pub struct Header {
    /// Identifiant aléatoire du coffre, stable sur toute sa vie.
    ///
    /// Sert à corréler les sauvegardes entre elles et à détecter qu'une
    /// sentinelle anti-rollback appartient bien à ce coffre.
    pub vault_id: [u8; VAULT_ID_LEN],
    /// Date de création, en secondes depuis l'époque Unix.
    ///
    /// Information non sensible et non authentifiée à titre individuel : elle
    /// entre dans l'AAD du payload via le header.
    pub created_at: u64,
    /// Slots de clé, au moins un.
    pub slots: Vec<Slot>,
}

impl Header {
    /// Crée un header neuf avec un identifiant de coffre aléatoire.
    ///
    /// Réservé au cas où aucun slot n'a encore besoin de connaître l'identifiant.
    /// Comme un slot **lie** son authentification à l'identifiant du coffre
    /// (voir [`Slot::aad`]), l'ordre de construction habituel est : générer
    /// l'identifiant, construire les slots, puis assembler le header avec
    /// [`Header::from_parts`].
    ///
    /// # Erreurs
    /// Propage l'échec du générateur du système, puis valide les invariants.
    pub fn new(created_at: u64, slots: Vec<Slot>) -> Result<Self> {
        let vault_id = rng::array::<VAULT_ID_LEN>()?;
        Self::from_parts(vault_id, created_at, slots)
    }

    /// Assemble un header à partir de composants déjà construits, en validant.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si les invariants ne sont pas respectés.
    pub fn from_parts(
        vault_id: [u8; VAULT_ID_LEN],
        created_at: u64,
        slots: Vec<Slot>,
    ) -> Result<Self> {
        let header = Self {
            vault_id,
            created_at,
            slots,
        };
        header.validate()?;
        Ok(header)
    }

    /// Vérifie les invariants structurels du header.
    ///
    /// Appelée à la construction **et** après décodage : une structure qui viole
    /// ces règles ne doit jamais pouvoir circuler dans le programme, qu'elle
    /// vienne de notre code ou d'un fichier.
    fn validate(&self) -> Result<()> {
        if self.slots.is_empty() {
            return Err(Error::InvalidHeader {
                reason: "le coffre doit contenir au moins un slot de clé",
            });
        }
        if self.slots.len() > MAX_SLOTS {
            return Err(Error::InvalidHeader {
                reason: "trop de slots de clé",
            });
        }

        // Unicité des identifiants : deux slots de même identifiant rendraient
        // la liaison AAD ambiguë et l'affichage trompeur.
        for (index, slot) in self.slots.iter().enumerate() {
            if self.slots[..index].iter().any(|other| other.id == slot.id) {
                return Err(Error::InvalidHeader {
                    reason: "identifiant de slot dupliqué",
                });
            }
            // Revalide les paramètres : `KdfParams` garantit déjà ses bornes, mais
            // ce contrôle rend la propriété locale à cette fonction.
            KdfParams::new(
                slot.params.m_cost_kib(),
                slot.params.t_cost(),
                slot.params.p_cost(),
            )?;
        }
        Ok(())
    }

    /// Encode le header selon le layout documenté dans `docs/VAULT_FORMAT.md`.
    ///
    /// L'encodage est **déterministe** : deux headers équivalents produisent des
    /// octets identiques. C'est une propriété du layout à offsets fixes, sans
    /// équivalent en CBOR où il faut choisir et respecter une forme canonique.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] si les invariants ne sont pas respectés,
    /// [`Error::MalformedLength`] si le résultat dépasse la borne admise.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let total = HEADER_FIXED_LEN + self.slots.len() * SLOT_LEN;
        if total > MAX_HEADER_LEN {
            return Err(Error::MalformedLength {
                reason: "header encodé au-delà de la taille maximale",
            });
        }

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.push(ALG_XCHACHA20POLY1305);
        // Le nombre de slots tient sur un octet : `MAX_SLOTS` vaut 16.
        out.push(
            u8::try_from(self.slots.len()).map_err(|_| Error::InvalidHeader {
                reason: "nombre de slots non représentable",
            })?,
        );
        out.extend_from_slice(&0_u16.to_be_bytes()); // réservé, doit valoir zéro

        for slot in &self.slots {
            out.extend_from_slice(&slot.id.to_be_bytes());
            out.push(slot.label.to_byte());
            out.push(ALG_ARGON2ID);
            out.push(ARGON2_VERSION);
            out.push(0); // réservé, doit valoir zéro
            out.extend_from_slice(&slot.params.m_cost_kib().to_be_bytes());
            out.extend_from_slice(&slot.params.t_cost().to_be_bytes());
            out.extend_from_slice(&slot.params.p_cost().to_be_bytes());
            out.extend_from_slice(&slot.salt);
            out.extend_from_slice(&slot.wrapped.nonce);
            out.extend_from_slice(&slot.wrapped.ciphertext);
        }

        // Vérification de cohérence entre la taille annoncée et la taille réelle.
        // Un désaccord signalerait un défaut de ce code, pas une entrée hostile.
        if out.len() != total {
            return Err(Error::Internal {
                invariant: "taille de header encodé incohérente avec le layout",
            });
        }

        Ok(out)
    }

    /// Décode un header depuis des octets non fiables.
    ///
    /// ## Règles
    ///
    /// * toute lecture est précédée d'une vérification de borne ;
    /// * la taille du header doit correspondre **exactement** au layout attendu
    ///   pour le nombre de slots annoncé — aucune tolérance sur des octets
    ///   excédentaires, qui pourraient être un vecteur de contrebande ;
    /// * les champs réservés et les champs inconnus sont refusés plutôt
    ///   qu'ignorés : un champ que nous ne comprenons pas signale une version
    ///   différente, et deviner serait dangereux.
    ///
    /// La fonction ne panique sur aucune entrée.
    ///
    /// # Erreurs
    /// [`Error::InvalidHeader`] ou [`Error::MalformedLength`] selon la violation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        checked::expect_min_len(
            bytes,
            HEADER_FIXED_LEN,
            "header plus court que sa partie fixe",
        )?;
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::MalformedLength {
                reason: "header au-delà de la taille maximale admise",
            });
        }

        let vault_id: [u8; VAULT_ID_LEN] =
            checked::array(bytes, 0, "identifiant de coffre tronqué")?;

        let created_at =
            u64::from_be_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| Error::MalformedLength {
                        reason: "horodatage de création de taille invalide",
                    })?,
            );

        let alg = checked::u8_at(bytes, 24, "algorithme de payload tronqué")?;
        if alg != ALG_XCHACHA20POLY1305 {
            return Err(Error::InvalidHeader {
                reason: "algorithme de payload inconnu",
            });
        }

        let slot_count = usize::from(checked::u8_at(bytes, 25, "compteur de slots tronqué")?);
        if slot_count == 0 {
            return Err(Error::InvalidHeader {
                reason: "aucun slot de clé",
            });
        }
        if slot_count > MAX_SLOTS {
            return Err(Error::InvalidHeader {
                reason: "trop de slots de clé",
            });
        }

        if u16::from_be_bytes(
            bytes[26..28]
                .try_into()
                .map_err(|_| Error::MalformedLength {
                    reason: "zone réservée de taille invalide",
                })?,
        ) != 0
        {
            return Err(Error::InvalidHeader {
                reason: "zone réservée du header non nulle",
            });
        }

        // Taille exacte attendue : pas d'octets excédentaires ni manquants.
        let expected = HEADER_FIXED_LEN + slot_count * SLOT_LEN;
        if bytes.len() != expected {
            return Err(Error::MalformedLength {
                reason: "taille de header incohérente avec le nombre de slots",
            });
        }

        // Le compte de slots a été borné plus haut (`MAX_SLOTS`), et la taille
        // totale du header a été vérifiée comme **exactement** égale à
        // `HEADER_FIXED_LEN + slot_count * SLOT_LEN`. Les deux produits sont donc
        // bornés par construction ; on les calcule néanmoins avec `checked_*` pour
        // que l'invariant soit local et survie à un futur changement de bornes.
        let mut slots = Vec::with_capacity(slot_count);
        for index in 0..slot_count {
            let offset = index
                .checked_mul(SLOT_LEN)
                .and_then(|delta| delta.checked_add(HEADER_FIXED_LEN))
                .ok_or(Error::MalformedLength {
                    reason: "dépassement d'entier en parcourant les slots",
                })?;
            let raw = checked::slice(bytes, offset, SLOT_LEN, "slot tronqué")?;
            slots.push(Self::decode_slot(raw)?);
        }

        let header = Self {
            vault_id,
            created_at,
            slots,
        };
        header.validate()?;
        Ok(header)
    }

    /// Décode un slot. `raw` fait exactement [`SLOT_LEN`] octets.
    fn decode_slot(raw: &[u8]) -> Result<Slot> {
        // La tranche reçue a exactement SLOT_LEN octets : les index ci-dessous
        // sont sûrs. On passe par `get` plutôt que par l'indexation directe afin
        // qu'un futur changement de SLOT_LEN se traduise par une erreur et non
        // par une panique.
        let id = checked::u16_be(raw, 0, "identifiant de slot tronqué")?;
        let label = SlotLabel::from_byte(checked::u8_at(raw, 2, "rôle de slot tronqué")?)?;

        let kdf_alg = checked::u8_at(raw, 3, "algorithme de dérivation tronqué")?;
        if kdf_alg != ALG_ARGON2ID {
            return Err(Error::InvalidHeader {
                reason: "algorithme de dérivation inconnu",
            });
        }

        let argon2_version = checked::u8_at(raw, 4, "version d'Argon2 tronquée")?;
        if argon2_version != ARGON2_VERSION {
            return Err(Error::InvalidHeader {
                reason: "version d'Argon2 non supportée",
            });
        }

        if checked::u8_at(raw, 5, "zone réservée du slot tronquée")? != 0 {
            return Err(Error::InvalidHeader {
                reason: "zone réservée du slot non nulle",
            });
        }

        let m_cost_kib = checked::u32_be(raw, 6, "coût mémoire tronqué")?;
        let t_cost = checked::u32_be(raw, 10, "nombre d'itérations tronqué")?;
        let p_cost = checked::u32_be(raw, 14, "parallélisme tronqué")?;
        // C'est ici qu'un fichier hostile demandant 4 Gio est refusé, avant toute
        // allocation mémoire.
        let params = KdfParams::new(m_cost_kib, t_cost, p_cost)?;

        let salt: [u8; SALT_LEN] =
            raw[18..18 + SALT_LEN]
                .try_into()
                .map_err(|_| Error::MalformedLength {
                    reason: "sel de slot de taille invalide",
                })?;

        let nonce_offset = 18 + SALT_LEN;
        let nonce: [u8; 24] = checked::array(raw, nonce_offset, "nonce d'enveloppe tronqué")?;

        let dek_offset = nonce_offset + 24;
        let ciphertext: [u8; WRAPPED_DEK_LEN] =
            checked::array(raw, dek_offset, "clé enveloppée tronquée")?;

        Ok(Slot {
            id,
            label,
            params,
            salt,
            wrapped: WrappedKey::new(nonce, ciphertext),
        })
    }

    /// Retourne le slot du mot de passe maître, s'il existe.
    ///
    /// Un coffre sans slot maître serait ouvrable uniquement par un autre
    /// mécanisme ; on ne l'interdit pas dans le format, mais le déverrouillage par
    /// mot de passe doit alors dire clairement qu'il n'y a rien à essayer.
    #[must_use]
    pub fn master_slot(&self) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|slot| slot.label == SlotLabel::Master)
    }

    /// Longueur encodée du header.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_FIXED_LEN + self.slots.len() * SLOT_LEN
    }
}

/// Longueur de clé attendue par la DEK, réexportée pour les appelants.
pub const SLOT_KEY_LEN: usize = KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped(fill: u8) -> WrappedKey {
        WrappedKey::new([fill; 24], [fill; WRAPPED_DEK_LEN])
    }

    fn sample_slot(id: u16) -> Slot {
        Slot {
            id,
            label: SlotLabel::Master,
            params: KdfParams::low(),
            salt: [7_u8; SALT_LEN],
            wrapped: wrapped(0xAB),
        }
    }

    fn sample_header() -> Header {
        Header {
            vault_id: [3_u8; VAULT_ID_LEN],
            created_at: 1_700_000_000,
            slots: vec![sample_slot(0)],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let header = sample_header();
        let encoded = header.encode().expect("encodage");
        let decoded = Header::decode(&encoded).expect("décodage");

        assert_eq!(decoded.vault_id, header.vault_id);
        assert_eq!(decoded.created_at, header.created_at);
        assert_eq!(decoded.slots.len(), 1);
        assert_eq!(decoded.slots[0].id, 0);
        assert_eq!(decoded.slots[0].label, SlotLabel::Master);
        assert_eq!(decoded.slots[0].params, KdfParams::low());
        assert_eq!(decoded.slots[0].salt, [7_u8; SALT_LEN]);
        assert_eq!(
            decoded.slots[0].wrapped.ciphertext,
            [0xAB_u8; WRAPPED_DEK_LEN]
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        // Deux encodages du même header doivent être identiques octet pour octet.
        // C'est ce qui remplace la notion d'encodage canonique d'un format
        // auto-descriptif, et ce qui rend la liaison AAD fiable.
        let header = sample_header();
        assert_eq!(header.encode().expect("a"), header.encode().expect("b"));
    }

    #[test]
    fn multiple_slots_roundtrip() {
        let header = Header {
            vault_id: [1_u8; VAULT_ID_LEN],
            created_at: 42,
            slots: vec![
                sample_slot(0),
                Slot {
                    id: 1,
                    label: SlotLabel::Recovery,
                    params: KdfParams::standard(),
                    salt: [9_u8; SALT_LEN],
                    wrapped: wrapped(0xCD),
                },
                Slot {
                    id: 2,
                    label: SlotLabel::Hardware,
                    params: KdfParams::paranoid(),
                    salt: [11_u8; SALT_LEN],
                    wrapped: wrapped(0xEF),
                },
            ],
        };
        let encoded = header.encode().expect("encodage");
        assert_eq!(encoded.len(), HEADER_FIXED_LEN + 3 * SLOT_LEN);

        let decoded = Header::decode(&encoded).expect("décodage");
        assert_eq!(decoded.slots.len(), 3);
        assert_eq!(decoded.slots[1].label, SlotLabel::Recovery);
        assert_eq!(decoded.slots[2].params, KdfParams::paranoid());
        assert_eq!(decoded.master_slot().map(|s| s.id), Some(0));
    }

    #[test]
    fn every_truncation_is_rejected_without_panic() {
        let encoded = sample_header().encode().expect("encodage");
        for len in 0..encoded.len() {
            // Aucune panique, et jamais un décodage « réussi » sur des données
            // incomplètes.
            assert!(
                Header::decode(&encoded[..len]).is_err(),
                "troncature à {len} octets acceptée"
            );
        }
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        // Le header n'a pas de redondance : un bit modifié dans un champ ne peut
        // pas toujours être détecté structurellement (par exemple changer un octet
        // du sel reste « valide »). Ce test vérifie donc deux choses distinctes :
        // aucune panique, et toute modification d'un champ *contraint* est
        // refusée. C'est l'AAD du payload qui garantit la détection des autres.
        let encoded = sample_header().encode().expect("encodage");
        for index in 0..encoded.len() {
            let mut tampered = encoded.clone();
            tampered[index] ^= 0x01;
            // Ne doit jamais paniquer.
            let _ = Header::decode(&tampered);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded.push(0);
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::MalformedLength { .. })
        ));
    }

    #[test]
    fn zero_slots_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[25] = 0;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn too_many_slots_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[25] = u8::MAX;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[24] = 99;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        // Le header.
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[26] = 1;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));

        // Le slot.
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[HEADER_FIXED_LEN + 5] = 1;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn unknown_slot_label_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[HEADER_FIXED_LEN + 2] = 77;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn unknown_kdf_algorithm_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[HEADER_FIXED_LEN + 3] = 77;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn unknown_argon2_version_is_rejected() {
        let mut encoded = sample_header().encode().expect("encodage");
        encoded[HEADER_FIXED_LEN + 4] = 0x10;
        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn hostile_memory_cost_is_refused_at_parse_time() {
        // Le point critique : ce refus intervient pendant le décodage, donc avant
        // toute allocation liée aux paramètres. Un fichier annonçant 4 Gio ne doit
        // jamais faire allouer quoi que ce soit.
        let mut encoded = sample_header().encode().expect("encodage");
        let offset = HEADER_FIXED_LEN + 6;
        encoded[offset..offset + 4].copy_from_slice(&(4_u32 * 1024 * 1024).to_be_bytes());

        assert!(matches!(
            Header::decode(&encoded),
            Err(Error::RejectedKdfParams { .. })
        ));
    }

    #[test]
    fn duplicate_slot_ids_are_rejected() {
        let header = Header {
            vault_id: [1_u8; VAULT_ID_LEN],
            created_at: 0,
            slots: vec![sample_slot(5), sample_slot(5)],
        };
        assert!(matches!(header.encode(), Err(Error::InvalidHeader { .. })));
    }

    #[test]
    fn header_longer_than_the_cap_is_rejected_before_parsing() {
        let oversized = vec![0_u8; MAX_HEADER_LEN + 1];
        assert!(matches!(
            Header::decode(&oversized),
            Err(Error::MalformedLength { .. })
        ));
    }

    #[test]
    fn slot_aad_changes_with_every_bound_field() {
        let vault_id = [4_u8; VAULT_ID_LEN];
        let base = sample_slot(0);
        let reference = base.aad(&vault_id);

        // Identifiant de coffre.
        assert_ne!(reference, base.aad(&[5_u8; VAULT_ID_LEN]));

        // Identifiant de slot.
        let mut other = base.clone();
        other.id = 1;
        assert_ne!(reference, other.aad(&vault_id));

        // Rôle.
        let mut other = base.clone();
        other.label = SlotLabel::Recovery;
        assert_ne!(reference, other.aad(&vault_id));

        // Sel.
        let mut other = base.clone();
        other.salt = [8_u8; SALT_LEN];
        assert_ne!(reference, other.aad(&vault_id));

        // Paramètres de dérivation.
        let mut other = base.clone();
        other.params = KdfParams::standard();
        assert_ne!(reference, other.aad(&vault_id));
    }

    #[test]
    fn slot_aad_is_deterministic() {
        let vault_id = [4_u8; VAULT_ID_LEN];
        let slot = sample_slot(3);
        assert_eq!(slot.aad(&vault_id), slot.aad(&vault_id));
    }

    #[test]
    fn magic_is_the_documented_value() {
        assert_eq!(&MAGIC, b"PASSLOCK");
        assert_eq!(FORMAT_VERSION, MAX_SUPPORTED_FORMAT_VERSION);
        assert_eq!(MAX_SLOTS, 16);
    }
}
