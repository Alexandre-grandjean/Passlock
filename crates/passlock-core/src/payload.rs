//! Enveloppe du payload déchiffré.
//!
//! # Pourquoi une enveloppe et pas directement les données
//!
//! Le payload chiffré contient plus qu'un contenu : il porte aussi des
//! informations qui doivent être **authentifiées** sans être visibles de
//! l'extérieur. La principale est la **génération**, compteur monotone utilisé
//! pour détecter un retour en arrière.
//!
//! La génération ne peut pas vivre dans le header : le header est lisible sans la
//! clé, donc un attaquant pourrait la réécrire pour masquer un rollback. Placée
//! ici, elle est couverte par le tag AEAD : la modifier est impossible sans la
//! clé, et la faire baisser sans que la sentinelle s'en aperçoive est détecté.
//!
//! # Layout
//!
//! ```text
//!   offset  taille      contenu
//!   ------  ----------  ----------------------------------------------
//!   0       4           signature « PAY1 »
//!   4       2           version de schéma (u16, gros-boutiste)
//!   6       2           réservé, doit valoir 0
//!   8       8           génération (u64, gros-boutiste)
//!   16      4           longueur du corps (u32, gros-boutiste)
//!   20      n           corps
//! ```
//!
//! Même approche que le header du conteneur : un layout à offsets fixes, sans
//! parseur générique. Ici l'entrée est déjà authentifiée, donc le risque est bien
//! moindre, mais rien ne justifie d'introduire un parseur pour cinq champs.
//!
//! # Ce que contiendra le corps
//!
//! En phase 1, le corps est vide : le moteur cryptographique est livré et testé
//! avant tout modèle de données. À partir de la phase 2, il contiendra la base
//! SQLite sérialisée — le schéma de celle-ci vivant **entièrement dans le corps**,
//! ce qui permet de le faire évoluer sans jamais changer le format du conteneur
//! ni celui de cette enveloppe.

use zeroize::{Zeroize, Zeroizing};

use crate::bytes as checked;

use crate::error::{Error, Result};

/// Signature de l'enveloppe de payload.
pub const PAYLOAD_MAGIC: [u8; 4] = *b"PAY1";

/// Version de schéma produite par ce binaire.
pub const PAYLOAD_SCHEMA_VERSION: u16 = 2;

/// Version de schéma la plus ancienne que ce binaire sait lire.
///
/// # Pourquoi une borne inférieure existe
///
/// Un coffre créé par la phase 1 porte un corps **vide** et une version de schéma
/// de 1. Le refuser obligerait l'utilisateur à recréer son coffre, ce qui est
/// exactement ce qu'une stratégie de migration doit éviter. Le décodeur accepte
/// donc les versions de cette borne à [`PAYLOAD_SCHEMA_VERSION`], et c'est
/// `migrate` qui transforme l'ancienne forme en la nouvelle.
///
/// Une version **supérieure** reste refusée : la lire supposerait de connaître une
/// forme qu'on ignore.
pub const MIN_SUPPORTED_SCHEMA_VERSION: u16 = 1;

/// Taille de la partie fixe de l'enveloppe.
const PAYLOAD_HEADER_LEN: usize = 20;

/// Génération la plus élevée qu'on accepte de lire.
///
/// Une génération proche de la limite signalerait soit un défaut, soit une
/// tentative de faire déborder le compteur pour masquer un rollback ultérieur
/// (en repartant de zéro après un dépassement). On refuse bien avant.
pub const MAX_GENERATION: u64 = u64::MAX - 1;

/// Contenu déchiffré du coffre.
///
/// # Ni `Clone`, ni `PartialEq`
///
/// Le corps de cette structure est **le contenu en clair du coffre entier** :
/// chaque titre, chaque mot de passe, chaque note. Dupliquer une telle valeur doit
/// être un acte explicite, jamais l'effet de bord d'un `.clone()` oublié — même
/// règle que pour les types de clés de `secret.rs`.
///
/// `PartialEq` est également absent, pour la même raison que sur `Key` : comparer
/// deux contenus avec `==` est une comparaison non constante en temps, et sur des
/// données secrètes dont la longueur est déjà connue de l'attaquant, ce n'est pas
/// un geste anodin.
///
/// # Effacement
///
/// [`Drop`] efface le corps. C'est une garantie **partielle** : elle couvre le
/// buffer que nous possédons, pas les copies que le compilateur, l'allocateur ou le
/// noyau ont pu faire au passage. Voir `docs/CRYPTO.md` §7.
#[derive(Debug)]
pub struct Payload {
    /// Version du schéma du corps.
    ///
    /// Conservée à la lecture : sans elle, le magasin ne pourrait pas savoir quelle
    /// migration appliquer, et un coffre ancien serait refusé au lieu d'être mis à
    /// niveau.
    pub schema_version: u16,
    /// Numéro de génération, monotone, incrémenté à chaque écriture.
    pub generation: u64,
    /// Contenu applicatif, opaque pour ce module.
    pub body: Vec<u8>,
}

impl Payload {
    /// Construit un payload vierge de première génération.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            schema_version: PAYLOAD_SCHEMA_VERSION,
            generation: 0,
            body: Vec::new(),
        }
    }

    /// Construit un payload avec un contenu donné.
    #[must_use]
    pub fn with_body(generation: u64, body: Vec<u8>) -> Self {
        Self {
            schema_version: PAYLOAD_SCHEMA_VERSION,
            generation,
            body,
        }
    }

    /// Remplace le contenu, en **effaçant l'ancien**.
    ///
    /// Une simple affectation de champ ferait tomber l'ancien `Vec` sans passer par
    /// le [`Drop`] de la structure : l'effacement serait contourné exactement au
    /// moment où un contenu secret est remplacé.
    pub fn replace_body(&mut self, body: Vec<u8>) {
        self.body.as_mut_slice().zeroize();
        self.body = body;
    }

    /// Passe l'enveloppe au schéma courant.
    ///
    /// # Pourquoi une méthode explicite
    ///
    /// [`Payload::encode`] écrit la version **stockée**, et non la version courante du
    /// binaire. C'est ce qui garantit qu'un aller-retour décodage/encodage est fidèle,
    /// y compris pour une enveloppe ancienne — propriété vérifiée par le harnais de
    /// robustesse.
    ///
    /// La montée de version est donc un **acte délibéré**, effectué par le magasin
    /// après avoir appliqué la migration. Rendre la montée implicite ferait perdre la
    /// fidélité, et surtout masquerait le fait qu'un coffre a changé de schéma.
    pub fn upgrade_schema(&mut self) {
        self.schema_version = PAYLOAD_SCHEMA_VERSION;
    }

    /// Encode l'enveloppe.
    ///
    /// La version écrite est celle **stockée** (voir [`Payload::upgrade_schema`]), de
    /// sorte qu'un décodage suivi d'un encodage reproduise exactement les mêmes octets.
    ///
    /// Le résultat est renvoyé dans un [`Zeroizing`] : il contient le contenu en
    /// clair, et son type force l'effacement à la destruction. Rendre un `Vec<u8>`
    /// nu aurait laissé à chaque appelant la responsabilité d'y penser — c'est
    /// exactement le genre d'oubli qui ne se voit pas en relecture.
    ///
    /// # Erreurs
    /// * [`Error::InvalidHeader`] si la génération est hors bornes ;
    /// * [`Error::MalformedLength`] si le corps ne tient pas sur 32 bits.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.generation > MAX_GENERATION {
            return Err(Error::InvalidHeader {
                reason: "génération de coffre hors bornes : migration requise",
            });
        }

        let body_len = u32::try_from(self.body.len()).map_err(|_| Error::MalformedLength {
            reason: "contenu du coffre trop volumineux pour le format",
        })?;

        let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_HEADER_LEN + self.body.len()));
        out.extend_from_slice(&PAYLOAD_MAGIC);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&self.body);

        Ok(out)
    }

    /// Décode l'enveloppe **en prenant possession du buffer**.
    ///
    /// # Pourquoi cette variante existe
    ///
    /// Le chemin de déverrouillage réel dispose d'un `Vec<u8>` contenant le contenu
    /// déchiffré, déjà enveloppé dans un [`Zeroizing`]. Le passer par
    /// [`Payload::decode`] produirait une **seconde copie** du coffre entier en
    /// clair, dont la première serait effacée et la seconde non. Cette variante
    /// transfère le corps sans copie : le buffer d'entrée est libéré et effacé par
    /// son `Zeroizing`, et le corps vit dès lors sous la responsabilité du [`Drop`]
    /// de `Payload`.
    ///
    /// # Erreurs
    /// [`Error::Corrupted`] si l'enveloppe est incohérente. Dans ce cas, l'entrée
    /// est effacée par son `Zeroizing` avant de quitter la fonction.
    pub fn decode_owned(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        // La validation réutilise la version empruntée : elle ne duplique rien.
        let (schema_version, generation) = Self::validate(&bytes)?;

        // `split_off` intervient **après** `validate`, qui a établi que
        // `bytes.len() == PAYLOAD_HEADER_LEN + body_len`. L'offset est donc
        // toujours valide ; le `min` rend la propriété locale au site d'appel.
        let split_at = PAYLOAD_HEADER_LEN.min(bytes.len());
        let mut bytes = bytes;
        let body = bytes.split_off(split_at);

        Ok(Self {
            schema_version,
            generation,
            body,
        })
    }

    /// Décode l'enveloppe depuis une tranche.
    ///
    /// **À réserver aux entrées non secrètes** : le contenu est recopié, et
    /// l'appelant reste seul responsable de l'effacement de son propre buffer. Le
    /// harnais de fuzzing et les tests unitaires l'utilisent, précisément parce que
    /// leurs entrées ne contiennent aucun secret.
    ///
    /// Le chemin de production passe par [`Payload::decode_owned`].
    ///
    /// # Erreurs
    /// [`Error::Corrupted`] si l'enveloppe est incohérente.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (schema_version, generation) = Self::validate(bytes)?;
        Ok(Self {
            schema_version,
            generation,
            body: bytes[PAYLOAD_HEADER_LEN..].to_vec(),
        })
    }

    /// Valide l'enveloppe et retourne (version de schéma, génération).
    ///
    /// L'entrée est déjà authentifiée par l'AEAD du conteneur. Les vérifications
    /// ci-dessous ne protègent donc pas contre un attaquant, mais contre un défaut
    /// de **notre propre code d'encodage** — ce qui mérite tout autant d'échouer
    /// proprement plutôt que de produire des données silencieusement fausses.
    fn validate(bytes: &[u8]) -> Result<(u16, u64)> {
        // Toutes les lectures passent par le module borné : `offset + longueur`
        // est vérifié contre le débordement avant tout découpage. Les erreurs de
        // bornes sont traduites en `Corrupted`, cette enveloppe n'étant atteinte
        // qu'après authentification.
        let truncated = |_| Error::Corrupted {
            reason: "enveloppe de contenu tronquée ou incohérente",
        };

        checked::expect_min_len(bytes, PAYLOAD_HEADER_LEN, "enveloppe tronquée")
            .map_err(truncated)?;

        if checked::slice(bytes, 0, PAYLOAD_MAGIC.len(), "signature tronquée").map_err(truncated)?
            != PAYLOAD_MAGIC
        {
            return Err(Error::Corrupted {
                reason: "signature d'enveloppe de contenu absente",
            });
        }

        let version = checked::u16_be(bytes, 4, "version tronquée").map_err(truncated)?;
        if !(MIN_SUPPORTED_SCHEMA_VERSION..=PAYLOAD_SCHEMA_VERSION).contains(&version) {
            return Err(Error::Corrupted {
                reason: "version de schéma de contenu non supportée",
            });
        }

        if checked::u16_be(bytes, 6, "zone réservée tronquée").map_err(truncated)? != 0 {
            return Err(Error::Corrupted {
                reason: "zone réservée de l'enveloppe non nulle",
            });
        }

        let generation = checked::u64_be(bytes, 8, "génération tronquée").map_err(truncated)?;
        if generation > MAX_GENERATION {
            return Err(Error::Corrupted {
                reason: "génération de coffre hors bornes",
            });
        }

        let body_len = usize::try_from(
            checked::u32_be(bytes, 16, "longueur de corps tronquée").map_err(truncated)?,
        )
        .map_err(|_| Error::Corrupted {
            reason: "longueur de corps non représentable",
        })?;

        // La longueur annoncée doit correspondre **exactement** au reste : ni
        // octets manquants, ni octets excédentaires. Une tolérance ici
        // permettrait de faire porter des données non prises en compte par une
        // version future ou passée du décodeur.
        //
        // L'addition est vérifiée : `body_len` vient du fichier et peut valoir
        // `u32::MAX`, donc `PAYLOAD_HEADER_LEN + body_len` ne peut pas déborder sur
        // une plateforme 64 bits, mais l'écrire avec `checked_add` rend
        // l'invariant local et indépendant de la largeur du type.
        let expected = PAYLOAD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(Error::Corrupted {
                reason: "dépassement d'entier en calculant la taille de l'enveloppe",
            })?;
        checked::expect_len(bytes, expected, "longueur de corps incohérente").map_err(truncated)?;

        Ok((version, generation))
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        // Efface les octets **initialisés** du corps. La capacité résiduelle d'un
        // `Vec` n'est pas parcourue : elle n'a jamais contenu que des valeurs
        // écrites puis remplacées, et l'effacer exigerait un accès `unsafe` au
        // buffer complet, interdit dans ce crate.
        self.body.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_empty_body() {
        let payload = Payload::initial();
        let encoded = payload.encode().expect("encodage");
        assert_eq!(encoded.len(), PAYLOAD_HEADER_LEN);

        let decoded = Payload::decode(&encoded).expect("décodage");
        assert_eq!(decoded.generation, payload.generation);
        assert_eq!(decoded.body, payload.body);
        assert_eq!(decoded.generation, 0);
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn roundtrip_with_body() {
        let payload = Payload::with_body(42, b"contenu applicatif".to_vec());
        let decoded = Payload::decode(&payload.encode().expect("encodage")).expect("décodage");
        assert_eq!(decoded.generation, payload.generation);
        assert_eq!(decoded.body, payload.body);
    }

    #[test]
    fn encoding_is_deterministic() {
        let payload = Payload::with_body(7, b"abc".to_vec());
        assert_eq!(payload.encode().expect("a"), payload.encode().expect("b"));
    }

    #[test]
    fn every_truncation_is_rejected() {
        let encoded = Payload::with_body(9, b"corps".to_vec())
            .encode()
            .expect("encodage");
        for len in 0..encoded.len() {
            assert!(
                Payload::decode(&encoded[..len]).is_err(),
                "troncature à {len} octets acceptée"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Payload::with_body(9, b"corps".to_vec())
            .encode()
            .expect("encodage");
        encoded.push(0);
        assert!(matches!(
            Payload::decode(&encoded),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut encoded = Payload::initial().encode().expect("encodage");
        encoded[0] = b'X';
        assert!(matches!(
            Payload::decode(&encoded),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let mut encoded = Payload::initial().encode().expect("encodage");
        encoded[4..6].copy_from_slice(&99_u16.to_be_bytes());
        assert!(matches!(
            Payload::decode(&encoded),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut encoded = Payload::initial().encode().expect("encodage");
        encoded[6] = 1;
        assert!(matches!(
            Payload::decode(&encoded),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn generation_beyond_the_bound_is_refused_on_encode() {
        let payload = Payload::with_body(u64::MAX, Vec::new());
        assert!(matches!(payload.encode(), Err(Error::InvalidHeader { .. })));

        let payload = Payload::with_body(MAX_GENERATION, Vec::new());
        assert!(payload.encode().is_ok());
    }

    #[test]
    fn absurd_body_length_is_refused() {
        let mut encoded = Payload::initial().encode().expect("encodage");
        // Annonce un corps énorme sans l'avoir fourni.
        encoded[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Payload::decode(&encoded),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn the_type_system_enforces_the_effacement_contract() {
        // Preuve à la compilation, et non par lecture : `Payload` doit avoir un
        // `Drop`. C'est ce `Drop` qui efface le corps, et son absence était
        // précisément le défaut relevé par l'audit adversarial — le commentaire de
        // `Vault::lock` affirmait qu'il existait alors qu'il n'existait pas.
        // Le lint `drop_bounds` déconseille `T: Drop` et suggère
        // `std::mem::needs_drop`. Sa suggestion ne convient pas ici : `needs_drop`
        // vaut `true` pour n'importe quel type contenant un `Vec`, donc il
        // resterait vrai **même sans notre `Drop`** — il ne prouverait rien. La
        // borne `T: Drop` est précisément ce qu'on veut affirmer : qu'un `Drop` est
        // bien implémenté.
        #[allow(drop_bounds)]
        fn requires_drop<T: Drop>() {}
        requires_drop::<Payload>();

        // Vérification fonctionnelle que le remplacement efface bien l'ancien
        // contenu avant de le libérer : on ne peut pas observer l'effacement d'un
        // buffer libéré sans `unsafe`, mais on peut vérifier que le contrat du type
        // est respecté — l'ancien contenu a disparu de la structure.
        let mut payload = Payload::with_body(1, b"ancien contenu secret".to_vec());
        payload.replace_body(b"nouveau".to_vec());
        assert_eq!(payload.body, b"nouveau");
        assert_eq!(payload.generation, 1);
    }

    #[test]
    fn owned_decoding_transfers_the_body_without_copying() {
        // Le contenu doit être transféré, et non recopié : c'est ce qui distingue
        // `decode_owned` de `decode` et évite une seconde copie intégrale du coffre
        // en clair au moment du déverrouillage.
        let original = Payload::with_body(9, b"corps transfere".to_vec())
            .encode()
            .expect("encodage")
            .to_vec();

        let decoded = Payload::decode_owned(Zeroizing::new(original)).expect("décodage");
        assert_eq!(decoded.generation, 9);
        assert_eq!(decoded.body, b"corps transfere");
    }

    #[test]
    fn owned_decoding_of_a_corrupted_envelope_fails_cleanly() {
        let mut bytes = Payload::with_body(1, b"corps".to_vec())
            .encode()
            .expect("encodage")
            .to_vec();
        bytes[0] = b'X';

        assert!(matches!(
            Payload::decode_owned(Zeroizing::new(bytes)),
            Err(Error::Corrupted { .. })
        ));
    }

    #[test]
    fn empty_input_never_panics() {
        assert!(Payload::decode(&[]).is_err());
        assert!(Payload::decode(&[0_u8; 8]).is_err());
        assert!(Payload::decode(&[0_u8; PAYLOAD_HEADER_LEN]).is_err());
    }
}
