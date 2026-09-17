//! Hiérarchie de clés : mot de passe maître → MK → KEK → DEK → sous-clés.
//!
//! # Le modèle, et pourquoi il a cette forme
//!
//! ```text
//!   mot de passe maître
//!          │  Argon2id (coûteux, sel unique, paramètres stockés dans le header)
//!          ▼
//!         MK   clé maître            — jamais persistée, jamais utilisée pour chiffrer
//!          │  HKDF-SHA256, info = "passlock/v1/kek"
//!          ▼
//!        KEK   clé de chiffrement de clé
//!          │  XChaCha20-Poly1305 : désenveloppe le slot de clé du header
//!          ▼
//!        DEK   clé de données       — aléatoire sur 256 bits, créée UNE fois
//!          │  HKDF-SHA256, une étiquette par usage
//!          ├──────────────► K_records      (payload du conteneur)
//!          ├──────────────► K_index        (index aveugles, sentinelle, MAC de contenu)
//!          └──────────────► K_attachments  **racine de domaine**, jamais une clé de travail
//!                                 │
//!                                 ├──► K_blob_name   (HMAC : nom de fichier d'un blob)
//!                                 └──► K_blob_aead   (XChaCha20-Poly1305 : contenu d'un blob)
//! ```
//!
//! ## Pourquoi un second niveau sous `K_attachments`
//!
//! Les trois sous-clés de premier niveau séparent des **domaines** : chacune n'est
//! employée que par **une** primitive. `K_attachments` serait la première exception —
//! il lui faudrait servir à la fois de clé HMAC (nom de fichier) et de clé AEAD
//! (contenu). La séparation évite cette réutilisation, et elle n'est pas gratuite par
//! principe : le **nom de fichier d'un blob est publié** — il suffit de lire le
//! répertoire — donc tout processus local obtiendrait des sorties HMAC connues sous la
//! clé qui protégerait la confidentialité des mêmes pièces jointes.
//!
//! Formulation exacte : cette réutilisation **n'est pas exploitée, elle est inutile**.
//! Aucune attaque pratique n'est connue contre HMAC-SHA256 et ChaCha20 employés sous la
//! même clé. Le projet refuse simplement de reposer sur une hypothèse non prouvée quand
//! la séparation coûte un appel à [`expand`], déjà écrit.
//!
//! ## `K_index`, au contraire, n'est pas scindée
//!
//! Elle sert trois usages, tous de la **même** primitive — HMAC-SHA256 — et la
//! séparation y est déjà assurée par une **étiquette versionnée en préfixe du
//! message** : `passlock/v1/sentinel-name`, `passlock/v1/sentinel-mac`,
//! `passlock/v1/attachment-content-mac`. Scinder `K_index` par ailleurs, tout en
//! laissant la sentinelle l'employer brute, donnerait **deux mécanismes pour le même
//! problème** — moins cohérent, pas plus sûr.
//!
//! D'où la règle unique, `I-KEYDOMAIN` : *une clé n'est jamais employée par deux
//! primitives. À primitive unique et usages multiples, l'étiquette va en préfixe du
//! message. Une racine de domaine n'est jamais une clé de travail.*
//!
//! ## Pourquoi une DEK distincte plutôt que « la clé dérivée du mot de passe »
//!
//! Le raccourci naïf — chiffrer le coffre directement avec la clé issue d'Argon2 —
//! rend toute modification du mécanisme d'authentification **solidaire du
//! chiffrement de toutes les données**. Concrètement, avec ce raccourci :
//!
//! | Opération | Sans DEK | Avec DEK (ici) |
//! |---|---|---|
//! | Changer le mot de passe maître | rechiffrer tout le coffre | réécrire 72 octets |
//! | Durcir les paramètres Argon2id | rechiffrer tout le coffre | réécrire 72 octets |
//! | Ajouter une clé de récupération | impossible proprement | ajouter un slot |
//! | Révoquer une clé de récupération | impossible proprement | supprimer un slot |
//! | Ajouter une clé matérielle | impossible proprement | ajouter un slot |
//!
//! La DEK sépare donc **deux préoccupations indépendantes** : « comment on
//! déverrouille » et « comment on chiffre ». C'est aussi ce qui rend la migration
//! cryptographique sûre et bon marché : une opération sur 72 octets n'a pas de
//! fenêtre de corruption partielle sur les données.
//!
//! **Invariant vérifiable** : après un changement de mot de passe maître, la DEK
//! doit être **rigoureusement la même** et le payload déchiffré doit être
//! **octet pour octet identique**.
//!
//! *Correction d'une formulation initiale trop optimiste.* Il serait faux
//! d'exiger que le *ciphertext* du payload soit identique : le header entrant dans
//! l'AAD, toute modification d'un slot invalide le tag et impose de re-chiffrer le
//! payload. C'est un choix assumé (voir `container.rs`), et il est peu coûteux —
//! un passage d'AEAD sur quelques mégaoctets avec **la même clé**, sans nouvelle
//! dérivation.
//!
//! Le bénéfice réel de la DEK se manifeste ailleurs : les **blobs de pièces
//! jointes**, chiffrés sous une clé dérivée de la DEK, ne sont **pas** touchés par
//! un changement de mot de passe. C'est là que l'opération reste O(1) sur des
//! données qui, elles, peuvent peser des centaines de mégaoctets.
//!
//! ## Pourquoi plusieurs slots
//!
//! Chaque slot du header enveloppe **la même DEK** avec un matériel de clé
//! différent : mot de passe maître, clé de récupération, clé matérielle. Ajouter
//! ou retirer un slot ne touche pas aux données. Chaque slot possède son propre
//! sel et ses propres paramètres Argon2id, ce qui permet à une clé de récupération
//! à haute entropie d'utiliser des paramètres plus légers sans affaiblir le slot
//! du mot de passe maître.
//!
//! ## Pourquoi HKDF et des étiquettes distinctes
//!
//! Utiliser le même matériel de clé dans deux contextes cryptographiques différents
//! est une erreur classique : une faiblesse ou un oracle obtenu dans un contexte
//! peut se propager à l'autre. HKDF-SHA256 (RFC 5869) dérive des sous-clés
//! indépendantes à partir de la DEK, chacune étiquetée par une chaîne `info`
//! distincte et versionnée. Le coût est nul, la protection est structurelle.
//!
//! La DEK brute n'est **jamais** utilisée directement dans un AEAD : elle ne sert
//! qu'à dériver.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::aead::{self, AeadError, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::rng;
use crate::secret::Key;

/// Longueur du matériel de clé, en octets.
pub const KEY_LEN: usize = 32;

/// Longueur de la DEK enveloppée : DEK + tag d'authentification.
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;

// ---------------------------------------------------------------------------
// Étiquettes HKDF.
//
// Elles sont versionnées (`/v1/`) : un futur changement de format produira des
// sous-clés différentes à partir de la même DEK, ce qui permettra de faire
// cohabiter deux versions sans collision de domaine.
// ---------------------------------------------------------------------------

const INFO_KEK: &[u8] = b"passlock/v1/kek";
const INFO_RECORDS: &[u8] = b"passlock/v1/records";
const INFO_ATTACHMENTS: &[u8] = b"passlock/v1/attachments";
const INFO_INDEX: &[u8] = b"passlock/v1/index";

/// Second niveau sous [`INFO_ATTACHMENTS`] : clé **HMAC** des noms de blob.
const INFO_BLOB_NAME: &[u8] = b"passlock/v1/blob-name";

/// Second niveau sous [`INFO_ATTACHMENTS`] : clé **AEAD** du contenu des blobs.
const INFO_BLOB_AEAD: &[u8] = b"passlock/v1/blob-aead";

/// Toutes les étiquettes de dérivation, pour les vérifications globales.
///
/// Un test vérifie qu'elles sont toutes versionnées et qu'**aucune n'est préfixe d'une
/// autre** : deux étiquettes dont l'une préfixe l'autre sont une invitation à ce qu'une
/// extension future les confonde.
#[cfg(test)]
const ALL_INFO_LABELS: &[&[u8]] = &[
    INFO_KEK,
    INFO_RECORDS,
    INFO_ATTACHMENTS,
    INFO_INDEX,
    INFO_BLOB_NAME,
    INFO_BLOB_AEAD,
];

/// Clé maître dérivée du mot de passe maître.
///
/// Ne quitte jamais le processus et n'est jamais persistée. Détruite dès que la
/// KEK a été dérivée : elle n'a aucune raison de survivre au déverrouillage.
pub struct MasterKey(Key<KEY_LEN>);

impl MasterKey {
    /// Dérive la clé maître à partir du mot de passe et d'un sel.
    ///
    /// # Erreurs
    /// Propage les erreurs de [`kdf::derive`], notamment le refus de paramètres
    /// hors bornes — qui intervient **avant** toute allocation mémoire.
    pub fn derive(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Self> {
        Ok(Self(kdf::derive(password, salt, params)?))
    }

    /// Dérive la clé de chiffrement de clé (KEK) à partir de la clé maître.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si HKDF refuse la longueur de sortie, ce qui ne peut
    /// pas arriver avec une sortie de 32 octets.
    pub fn derive_kek(&self) -> Result<KeyEncryptionKey> {
        Ok(KeyEncryptionKey(expand(&self.0, INFO_KEK)?))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([EXPURGÉ])")
    }
}

/// Clé de chiffrement de clé : sert uniquement à envelopper la DEK.
pub struct KeyEncryptionKey(Key<KEY_LEN>);

impl KeyEncryptionKey {
    /// Enveloppe une DEK pour la stocker dans un slot du header.
    ///
    /// ## Rôle de `aad`
    ///
    /// `aad` doit contenir les métadonnées du slot — identifiant du coffre,
    /// identifiant du slot, étiquette, paramètres de dérivation et sel. Sans cela,
    /// un attaquant pourrait **déplacer un slot d'un coffre à un autre**, ou
    /// échanger deux slots, et le désenveloppement réussirait quand même, ce qui
    /// changerait silencieusement la DEK obtenue.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si l'AEAD échoue, ce qui ne peut pas arriver sur une
    /// sortie de longueur fixe correctement dimensionnée.
    pub fn wrap(&self, dek: &DataEncryptionKey, aad: &[u8]) -> Result<WrappedKey> {
        let nonce = aead::generate_nonce().map_err(|_| Error::Internal {
            invariant: "générateur de nonce indisponible",
        })?;

        let ciphertext =
            aead::seal(&self.0, &nonce, dek.0.expose(), aad).map_err(|err| Error::Internal {
                invariant: match err {
                    AeadError::MessageTooLong => "message trop long pour l'AEAD",
                    _ => "échec de l'enveloppe d'une clé de taille fixe",
                },
            })?;

        // La longueur est fixée par la taille de la DEK et celle du tag ; on
        // vérifie plutôt que de convertir en supposant.
        let ciphertext: [u8; WRAPPED_DEK_LEN] =
            ciphertext.try_into().map_err(|_| Error::Internal {
                invariant: "longueur inattendue après enveloppe de la DEK",
            })?;

        Ok(WrappedKey { nonce, ciphertext })
    }

    /// Désenveloppe la DEK d'un slot.
    ///
    /// ## Pourquoi l'échec devient [`Error::UnlockFailed`] ici et pas ailleurs
    ///
    /// C'est le seul endroit du programme où l'on sait que l'échec AEAD signifie
    /// « le matériel de clé fourni ne correspond pas ». Traduire à cet endroit
    /// garantit que la traduction ne peut pas être oubliée par un futur appelant,
    /// et que le message public reste indiscernable d'un mot de passe faux — la
    /// propriété anti-oracle décrite dans `error.rs`.
    ///
    /// # Erreurs
    /// [`Error::UnlockFailed`] si l'authentification échoue, [`Error::InvalidLength`]
    /// si le déchiffrement ne produit pas exactement [`KEY_LEN`] octets.
    pub fn unwrap(&self, wrapped: &WrappedKey, aad: &[u8]) -> Result<DataEncryptionKey> {
        let plaintext = aead::open(&self.0, &wrapped.nonce, &wrapped.ciphertext, aad)
            .map_err(|_| Error::UnlockFailed)?;

        Ok(DataEncryptionKey(Key::from_slice(&plaintext)?))
    }
}

impl std::fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyEncryptionKey([EXPURGÉ])")
    }
}

/// Clé de données : chiffre effectivement le contenu du coffre.
pub struct DataEncryptionKey(Key<KEY_LEN>);

impl DataEncryptionKey {
    /// Génère une DEK aléatoire.
    ///
    /// Appelée **une seule fois**, à la création du coffre. Toutes les opérations
    /// ultérieures se contentent de la ré-envelopper.
    ///
    /// # Erreurs
    /// Propage l'échec du générateur du système. Aucun repli n'existe : une DEK
    /// prévisible rendrait le chiffrement du coffre entier inutile.
    pub fn generate() -> Result<Self> {
        Ok(Self(rng::key::<KEY_LEN>()?))
    }

    /// Reconstruit une DEK à partir d'octets, pour les tests et les migrations.
    ///
    /// Exposé uniquement pour permettre la vérification de l'invariant
    /// « le ciphertext ne change pas au changement de mot de passe », qui exige de
    /// rejouer une DEK connue.
    ///
    /// # Erreurs
    /// [`Error::InvalidLength`] si la longueur ne fait pas [`KEY_LEN`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Key::from_slice(bytes)?))
    }

    /// Compare deux DEK en temps constant.
    ///
    /// Sert à vérifier qu'une opération de maintenance (changement de mot de passe,
    /// migration de paramètres, ajout d'un slot) a bien **conservé** la DEK. C'est
    /// le contrôle qui distingue une migration réussie d'un coffre rendu
    /// définitivement illisible.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.0.constant_time_eq(&other.0)
    }

    /// Dérive l'ensemble des sous-clés d'usage.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si HKDF refuse la longueur de sortie.
    pub fn subkeys(&self) -> Result<SubKeys> {
        // `K_attachments` est la **racine** du domaine des pièces jointes. Elle est
        // dérivée, employée pour produire les deux clés de travail, puis **détruite
        // immédiatement** : elle n'est pas conservée dans `SubKeys`, et ne peut donc
        // pas être employée comme clé. C'est `I-KEYDOMAIN` rendu structurel.
        let attachments: Key<KEY_LEN> = expand(&self.0, INFO_ATTACHMENTS)?;
        let blob_name = expand(&attachments, INFO_BLOB_NAME)?;
        let blob_aead = expand(&attachments, INFO_BLOB_AEAD)?;
        drop(attachments);

        Ok(SubKeys {
            records: expand(&self.0, INFO_RECORDS)?,
            blob_name,
            blob_aead,
            index: expand(&self.0, INFO_INDEX)?,
        })
    }
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataEncryptionKey([EXPURGÉ])")
    }
}

/// Sous-clés d'usage, toutes dérivées de la même DEK.
///
/// Les champs ont un nom : on ne peut pas les confondre par position, contrairement
/// à un tuple ou à un tableau.
#[derive(Debug)]
pub struct SubKeys {
    /// Chiffrement du payload du conteneur.
    pub records: Key<KEY_LEN>,
    /// Calcul des index aveugles, de la sentinelle anti-rollback **et du MAC de
    /// contenu d'une pièce jointe**.
    ///
    /// Ces trois usages relèvent de la **même** primitive, HMAC-SHA256, et sont
    /// séparés par une étiquette en préfixe de message — jamais par une clé dédiée.
    /// Voir l'en-tête du module.
    pub index: Key<KEY_LEN>,

    /// Nom de fichier d'un blob — **HMAC-SHA256 seulement**.
    ///
    /// Dérivée de `K_attachments`, qui n'est **pas conservée** : une racine de domaine
    /// n'est jamais une clé de travail (`I-KEYDOMAIN`).
    blob_name: Key<KEY_LEN>,

    /// Contenu d'un blob — **XChaCha20-Poly1305 seulement**.
    blob_aead: Key<KEY_LEN>,
}

impl SubKeys {
    /// Clé du nom de fichier d'un blob. Ne sert **qu'**à HMAC.
    #[must_use]
    pub fn blob_name(&self) -> &Key<KEY_LEN> {
        &self.blob_name
    }

    /// Clé du contenu d'un blob. Ne sert **qu'**à l'AEAD.
    #[must_use]
    pub fn blob_aead(&self) -> &Key<KEY_LEN> {
        &self.blob_aead
    }
}

/// DEK enveloppée, telle que stockée dans un slot du header.
///
/// Ne contient que du texte chiffré et un nonce : ce n'est **pas** un secret, d'où
/// la possibilité de le copier librement. Ses octets sont authentifiés par le tag
/// Polygon1305 qu'elle contient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WrappedKey {
    /// Nonce utilisé pour l'enveloppe.
    pub nonce: [u8; NONCE_LEN],
    /// DEK chiffrée suivie de son tag.
    pub ciphertext: [u8; WRAPPED_DEK_LEN],
}

impl WrappedKey {
    /// Construit une clé enveloppée à partir de composants lus dans le header.
    #[must_use]
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: [u8; WRAPPED_DEK_LEN]) -> Self {
        Self { nonce, ciphertext }
    }

    /// Construit une enveloppe factice, à remplacer avant tout usage.
    ///
    /// Existe parce que la construction d'un slot se fait en deux temps : il faut
    /// d'abord connaître l'identifiant du coffre pour calculer la valeur
    /// authentifiée, et donc assembler un slot avant de pouvoir envelopper la clé.
    /// Le contenu factice n'a aucune influence sur cette valeur, puisque
    /// [`Slot::aad`] exclut les octets de l'enveloppe.
    ///
    /// Un slot dont l'enveloppe serait restée factice ne peut pas s'ouvrir : le tag
    /// ne correspond à rien. L'erreur est donc bruyante, jamais silencieuse.
    #[must_use]
    pub fn placeholder() -> Self {
        Self {
            nonce: [0_u8; NONCE_LEN],
            ciphertext: [0_u8; WRAPPED_DEK_LEN],
        }
    }
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Le contenu est du texte chiffré, mais on reste sobre : afficher
        // l'intégralité d'un slot dans un journal n'apporte rien au diagnostic.
        f.debug_struct("WrappedKey")
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Développe une sous-clé de 32 octets via HKDF-SHA256.
///
/// Le paramètre `salt` de HKDF vaut `None` : RFC 5869 le définit comme optionnel,
/// et il n'apporte rien ici. La séparation de domaines repose entièrement sur
/// l'entrée de clé (unique par coffre, puisque la DEK est aléatoire) et sur
/// l'étiquette `info` (unique par usage). Ajouter un sel constant ne changerait
/// rien ; ajouter l'identifiant du coffre en sel n'apporterait rien non plus, la
/// DEK étant déjà unique par construction.
fn expand<const N: usize>(ikm: &Key<KEY_LEN>, info: &[u8]) -> Result<Key<N>> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm.expose());
    let mut out = Key::<N>::zeroed();
    hkdf.expand(info, out.expose_mut())
        .map_err(|_| Error::Internal {
            invariant: "HKDF refuse une longueur de sortie pourtant fixe",
        })?;
    Ok(out)
}

/// Longueur du sel d'un slot, réexportée pour les appelants qui construisent un slot.
pub const SLOT_SALT_LEN: usize = SALT_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        // Paramètres les plus légers acceptés : la validité du code ne dépend pas
        // du coût de la dérivation. Voir `test_support` pour les mesures.
        crate::test_support::cheap_params()
    }

    fn master() -> (MasterKey, [u8; SALT_LEN]) {
        let salt = kdf::generate_salt().expect("sel");
        let mk =
            MasterKey::derive(b"phrase de passe de test", &salt, params()).expect("dérivation");
        (mk, salt)
    }

    #[test]
    fn same_password_and_salt_give_same_kek() {
        let salt = [3_u8; SALT_LEN];
        let first = MasterKey::derive(b"motdepasse", &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");
        let second = MasterKey::derive(b"motdepasse", &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");
        assert!(first.0.constant_time_eq(&second.0));
    }

    #[test]
    fn different_password_gives_different_kek() {
        let salt = [3_u8; SALT_LEN];
        let first = MasterKey::derive(b"motdepasse", &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");
        let other = MasterKey::derive(b"motdepassX", &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");
        assert!(!first.0.constant_time_eq(&other.0));
    }

    #[test]
    fn unicode_passwords_are_accepted_and_distinct() {
        // Un gestionnaire de mots de passe doit accepter l'Unicode complet
        // (cf. recommandation OWASP : ne pas réduire l'entropie de l'entrée).
        // On vérifie aussi que deux compositions différentes du même glyphe
        // produisent bien deux clés différentes : c'est le comportement correct
        // (l'entrée est traitée comme une suite d'octets, pas normalisée par nos
        // soins), mais il doit être connu et non découvert par l'utilisateur au
        // moment où il ne peut plus ouvrir son coffre.
        let salt = [5_u8; SALT_LEN];
        let composed = MasterKey::derive("clé".as_bytes(), &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");
        let decomposed = MasterKey::derive("cle\u{0301}".as_bytes(), &salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");

        assert!(
            !composed.0.constant_time_eq(&decomposed.0),
            "les deux formes Unicode doivent produire des clés distinctes"
        );
    }

    #[test]
    fn wrap_unwrap_roundtrips() {
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");
        let aad = b"liaison-de-slot";

        let wrapped = kek.wrap(&dek, aad).expect("enveloppe");
        let recovered = kek.unwrap(&wrapped, aad).expect("désenveloppe");

        assert!(dek.0.constant_time_eq(&recovered.0));
    }

    #[test]
    fn unwrap_fails_with_a_different_aad() {
        // C'est la protection contre le déplacement d'un slot d'un coffre à un
        // autre : le slot ne s'ouvre que dans son contexte d'origine.
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");

        let wrapped = kek.wrap(&dek, b"coffre-A/slot-0").expect("enveloppe");
        assert!(matches!(
            kek.unwrap(&wrapped, b"coffre-B/slot-0"),
            Err(Error::UnlockFailed)
        ));
        assert!(matches!(
            kek.unwrap(&wrapped, b"coffre-A/slot-1"),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn unwrap_fails_with_the_wrong_kek() {
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");
        let wrapped = kek.wrap(&dek, b"aad").expect("enveloppe");

        let other_salt = [9_u8; SALT_LEN];
        let other_kek = MasterKey::derive(b"autre mot de passe", &other_salt, params())
            .expect("dérivation")
            .derive_kek()
            .expect("kek");

        assert!(matches!(
            other_kek.unwrap(&wrapped, b"aad"),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");
        let wrapped = kek.wrap(&dek, b"aad").expect("enveloppe");

        for index in 0..WRAPPED_DEK_LEN {
            let mut bytes = wrapped.ciphertext;
            bytes[index] ^= 0x01;
            let tampered = WrappedKey::new(wrapped.nonce, bytes);
            assert!(
                matches!(kek.unwrap(&tampered, b"aad"), Err(Error::UnlockFailed)),
                "un octet modifié à l'offset {index} doit être détecté"
            );
        }

        // Le nonce aussi est authentifié de fait : le changer change la clé de
        // flux, donc le déchiffrement produit autre chose et le tag échoue.
        let mut nonce = wrapped.nonce;
        nonce[0] ^= 0xFF;
        assert!(matches!(
            kek.unwrap(&WrappedKey::new(nonce, wrapped.ciphertext), b"aad"),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn subkeys_are_distinct_from_each_other() {
        // Si deux étiquettes produisaient la même sous-clé, la séparation de
        // domaines serait fictive.
        let dek = DataEncryptionKey::generate().expect("dek");
        let sub = dek.subkeys().expect("sous-clés");
        let root = expand(&dek.0, INFO_ATTACHMENTS).expect("racine");

        assert!(!sub.records.constant_time_eq(&sub.index));
        assert!(!sub.records.constant_time_eq(&root));
        assert!(!sub.index.constant_time_eq(&root));
    }

    #[test]
    fn the_blob_keys_are_distinct_from_every_other_key() {
        // `I-KEYDOMAIN` : `K_blob_name` sert à HMAC, `K_blob_aead` à l'AEAD, et
        // **aucune** des deux n'est la racine ni une autre sous-clé.
        let dek = DataEncryptionKey::generate().expect("dek");
        let sub = dek.subkeys().expect("sous-clés");
        let root = expand(&dek.0, INFO_ATTACHMENTS).expect("racine");

        let others = [
            ("records", &sub.records),
            ("index", &sub.index),
            ("attachments", &root),
        ];
        for (name, other) in others {
            assert!(
                !sub.blob_name().constant_time_eq(other),
                "K_blob_name ne doit pas être {name}"
            );
            assert!(
                !sub.blob_aead().constant_time_eq(other),
                "K_blob_aead ne doit pas être {name}"
            );
        }
        assert!(
            !sub.blob_name().constant_time_eq(sub.blob_aead()),
            "les deux clés dérivées doivent différer : l'une HMAC, l'autre AEAD"
        );
    }

    #[test]
    fn the_attachments_root_is_not_stored() {
        // La racine n'est dérivée que le temps de produire les deux clés de travail :
        // elle n'est **pas** conservée, donc elle ne peut pas être employée comme clé.
        // Le test fige la propriété observable : `SubKeys` n'expose que deux clés de
        // domaine « pièces jointes », et toutes deux diffèrent de la racine.
        let dek = DataEncryptionKey::generate().expect("dek");
        let sub = dek.subkeys().expect("sous-clés");
        let root = expand(&dek.0, INFO_ATTACHMENTS).expect("racine");

        assert!(!sub.blob_name().constant_time_eq(&root));
        assert!(!sub.blob_aead().constant_time_eq(&root));
    }

    #[test]
    fn the_blob_keys_are_deterministic_for_a_given_dek() {
        let dek = DataEncryptionKey::from_bytes(&[0x22; KEY_LEN]).expect("dek");
        let first = dek.subkeys().expect("sous-clés");
        let second = dek.subkeys().expect("sous-clés");

        assert!(first.blob_name().constant_time_eq(second.blob_name()));
        assert!(first.blob_aead().constant_time_eq(second.blob_aead()));
    }

    #[test]
    fn every_key_label_is_versioned_and_no_label_is_a_prefix_of_another() {
        for label in ALL_INFO_LABELS {
            let text = std::str::from_utf8(label).expect("étiquette UTF-8");
            assert!(
                text.starts_with("passlock/v1/"),
                "l'étiquette « {text} » n'est pas versionnée"
            );
        }

        // Aucune étiquette ne doit être le préfixe d'une autre : deux étiquettes
        // emboîtées sont une invitation à ce qu'une extension future les confonde.
        for (index, label) in ALL_INFO_LABELS.iter().enumerate() {
            for (other_index, other) in ALL_INFO_LABELS.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                assert!(
                    !other.starts_with(label),
                    "« {} » est un préfixe de « {} »",
                    std::str::from_utf8(label).unwrap_or("?"),
                    std::str::from_utf8(other).unwrap_or("?")
                );
            }
        }
    }

    #[test]
    fn subkeys_are_deterministic_for_a_given_dek() {
        let dek = DataEncryptionKey::from_bytes(&[0x11; KEY_LEN]).expect("dek");
        let first = dek.subkeys().expect("sous-clés");
        let second = dek.subkeys().expect("sous-clés");
        assert!(first.records.constant_time_eq(&second.records));
        assert!(first.index.constant_time_eq(&second.index));
    }

    #[test]
    fn two_vaults_never_share_subkeys() {
        let first = DataEncryptionKey::generate()
            .expect("dek")
            .subkeys()
            .expect("sous-clés");
        let second = DataEncryptionKey::generate()
            .expect("dek")
            .subkeys()
            .expect("sous-clés");
        assert!(!first.records.constant_time_eq(&second.records));
    }

    // Note : une « valeur de contrôle de clé » (KCV = HKDF(DEK, "…/keycheck")
    // tronquée) avait été prévue dans la conception initiale puis a été **retirée**.
    //
    // Raison : aucun de ses usages envisagés ne survit à l'examen. Vérifier qu'une
    // clé de récupération correspond au coffre est déjà fait par le succès du
    // désenveloppement ; vérifier qu'une sauvegarde vient du même coffre est déjà
    // fait par `vault_id`, qui est public ; vérifier qu'un changement de mot de
    // passe a conservé la DEK se fait en comparant directement la DEK en mémoire.
    //
    // La conserver aurait publié une valeur dérivée de la DEK permettant de tester
    // une DEK candidate. Cet oracle est inexploitable en pratique (la DEK est
    // aléatoire sur 256 bits), mais un oracle inutile reste un oracle inutile :
    // la surface n'a aucune raison de le contenir.

    #[test]
    fn debug_output_never_exposes_key_material() {
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");

        for rendered in [format!("{mk:?}"), format!("{kek:?}"), format!("{dek:?}")] {
            assert!(rendered.contains("EXPURGÉ"), "{rendered}");
        }
        assert!(format!("{mk:?}").contains("MasterKey"));
        assert!(format!("{kek:?}").contains("KeyEncryptionKey"));
        assert!(format!("{dek:?}").contains("DataEncryptionKey"));
    }

    #[test]
    fn wrapped_key_debug_does_not_print_ciphertext() {
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");
        let wrapped = kek.wrap(&dek, b"aad").expect("enveloppe");
        let rendered = format!("{wrapped:?}");
        assert!(rendered.contains("ciphertext_len"), "{rendered}");
        assert!(!rendered.contains("222"), "{rendered}");
    }

    #[test]
    fn wrapping_the_same_dek_twice_produces_different_ciphertexts() {
        // Chaque enveloppe doit utiliser un nonce neuf.
        let (mk, _) = master();
        let kek = mk.derive_kek().expect("kek");
        let dek = DataEncryptionKey::generate().expect("dek");

        let first = kek.wrap(&dek, b"aad").expect("enveloppe");
        let second = kek.wrap(&dek, b"aad").expect("enveloppe");

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        // ... et les deux doivent rester désenveloppables.
        assert!(
            dek.0
                .constant_time_eq(&kek.unwrap(&first, b"aad").expect("ouverture").0)
        );
        assert!(
            dek.0
                .constant_time_eq(&kek.unwrap(&second, b"aad").expect("ouverture").0)
        );
    }

    #[test]
    fn dek_from_bytes_enforces_length() {
        assert!(DataEncryptionKey::from_bytes(&[0u8; KEY_LEN - 1]).is_err());
        assert!(DataEncryptionKey::from_bytes(&[0u8; KEY_LEN + 1]).is_err());
        assert!(DataEncryptionKey::from_bytes(&[0u8; KEY_LEN]).is_ok());
    }
}
