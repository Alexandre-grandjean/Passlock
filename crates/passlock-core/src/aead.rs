//! Chiffrement authentifié (AEAD) — XChaCha20-Poly1305.
//!
//! ## Pourquoi XChaCha20-Poly1305 et non AES-256-GCM
//!
//! **Le critère décisif est la taille du nonce.** AES-GCM utilise un nonce de
//! 96 bits. Avec des nonces tirés au hasard, la probabilité de collision devient
//! non négligeable bien avant ce qu'on imagine : le paradoxe des anniversaires
//! donne une collision probable dès ~2^32 messages sous la même clé, et une
//! collision de nonce sous AES-GCM casse **à la fois** la confidentialité
//! (récupération du XOR des deux messages) et l'intégrité (falsification possible
//! du tag). C'est une défaillance silencieuse : rien ne la signale à l'exécution.
//!
//! XChaCha20 utilise un nonce de **192 bits**. La même analyse donne une
//! probabilité de collision de l'ordre de 2^-96 après 2^48 messages sous la même
//! clé. La classe entière de bugs disparaît, au prix d'une performance inférieure
//! là où AES-NI est disponible — écart réel mais sans conséquence pour quelques
//! sauvegardes par minute.
//!
//! Secondairement, ChaCha20 est une construction ARX (addition, rotation, XOR)
//! naturellement constante en temps, alors que les implémentations logicielles
//! d'AES dépendent de tables de substitution sensibles au cache.
//!
//! ## Contrat d'erreur
//!
//! Ce module ne renvoie pas [`crate::error::Error`] mais [`AeadError`]. C'est
//! délibéré : un échec d'authentification doit être **traduit par l'appelant**,
//! car le message correct dépend du contexte.
//!
//! * un échec à l'ouverture du *slot de clé* doit devenir « mot de passe incorrect
//!   ou coffre corrompu » et rester indiscernable d'un mot de passe faux ;
//! * un échec sur le *payload*, atteint seulement après un déverrouillage réussi,
//!   peut légitimement dire « coffre corrompu ».
//!
//! En l'absence de `From<AeadError> for Error`, le compilateur oblige chaque site
//! d'appel à faire ce choix explicitement. Une conversion automatique laisserait
//! passer par défaut l'erreur générique, ce qui rouvrirait la fuite d'information
//! que `error.rs` cherche justement à fermer.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::rng;
use crate::secret::Key;

/// Longueur d'un nonce XChaCha20, en octets.
pub const NONCE_LEN: usize = 24;

/// Longueur du tag d'authentification Poly1305, en octets.
pub const TAG_LEN: usize = 16;

/// Longueur de clé attendue par XChaCha20-Poly1305.
pub const KEY_LEN: usize = 32;

/// Échec d'une opération AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// L'authentification a échoué.
    ///
    /// Les causes possibles — clé différente, nonce différent, AAD différent,
    /// ciphertext ou tag altéré — sont **indiscernables par construction** : le tag
    /// Poly1305 ne dit pas laquelle est en cause. C'est une propriété recherchée,
    /// pas une imprécision.
    AuthenticationFailed,

    /// La clé fournie n'a pas la longueur attendue.
    ///
    /// Ne peut survenir qu'en cas de défaut de programmation, puisque la longueur
    /// est fixée par le type `Key<32>`.
    InvalidKeyLength,

    /// Le nonce fourni n'a pas la longueur attendue.
    InvalidNonceLength,

    /// La bibliothèque a refusé le message, typiquement parce qu'il est trop long
    /// pour le format (limite de XChaCha20-Poly1305 : 2^32 octets par message).
    MessageTooLong,
}

/// Génère un nonce aléatoire.
///
/// ## Pourquoi un nonce aléatoire convient ici
///
/// En XChaCha20 l'espace de nonces fait 192 bits. Tirer un nonce au hasard à
/// chaque chiffrement est donc sûr : après 2^48 chiffrements sous la même clé, la
/// probabilité qu'un nonce ait été réutilisé reste de l'ordre de 2^-96.
///
/// Ce choix évite un compteur persistant, qui serait un état supplémentaire à
/// maintenir correctement — donc une source de bugs silencieusement dangereux.
///
/// # Erreurs
/// La fonction panique-t-elle ? Non : elle propage l'échec du générateur du
/// système. Il n'existe **aucun** repli, car un nonce prévisible ruinerait la
/// confidentialité du message.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], AeadError> {
    rng::array::<NONCE_LEN>().map_err(|_| AeadError::InvalidNonceLength)
}

/// Chiffre `plaintext` et authentifie `aad` avec, sous `key` et `nonce`.
///
/// Le tag d'authentification est **ajouté à la fin** du résultat (tag postfixe),
/// ce qui donne une longueur de sortie égale à `plaintext.len() + TAG_LEN`.
///
/// ## Rôle de `aad`
///
/// `aad` n'est pas chiffré mais **est authentifié**. Toute modification ultérieure
/// de `aad` rendra le déchiffrement impossible. C'est ce mécanisme qui protège les
/// métadonnées du coffre (version, paramètres de dérivation, identifiant) : elles
/// restent lisibles sans la clé, mais falsifiables par personne.
///
/// # Erreurs
/// [`AeadError::InvalidKeyLength`] ou [`AeadError::InvalidNonceLength`] en cas de
/// longueur incorrecte, [`AeadError::MessageTooLong`] si le message dépasse la
/// limite du format.
pub fn seal(
    key: &Key<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = cipher_for(key)?;
    let nonce_ref = nonce_ref(nonce)?;
    cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError::MessageTooLong)
}

/// Déchiffre `ciphertext` en vérifiant le tag et l'authenticité de `aad`.
///
/// # Erreurs
/// [`AeadError::AuthenticationFailed`] si le tag est invalide. Conformément au
/// contrat du module, c'est à l'appelant de décider quel message public produire.
pub fn open(
    key: &Key<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // Un ciphertext plus court que le tag est nécessairement invalide. On le refuse
    // explicitement plutôt que de laisser la bibliothèque le faire : cela évite de
    // dépendre de son comportement exact sur une entrée dégénérée.
    if ciphertext.len() < TAG_LEN {
        return Err(AeadError::AuthenticationFailed);
    }

    let cipher = cipher_for(key)?;
    let nonce_ref = nonce_ref(nonce)?;
    cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::AuthenticationFailed)
}

/// Construit le chiffreur à partir d'un matériel de clé.
fn cipher_for(key: &Key<KEY_LEN>) -> Result<XChaCha20Poly1305, AeadError> {
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| AeadError::InvalidKeyLength)
}

/// Convertit un tableau de nonce en référence de type attendu par la bibliothèque.
///
/// La conversion échoue uniquement si la longueur ne correspond pas, ce qui est
/// garanti impossible par le type `[u8; NONCE_LEN]`. On évite ainsi `from_slice`,
/// qui panique en cas de désaccord de longueur.
fn nonce_ref(nonce: &[u8; NONCE_LEN]) -> Result<&XNonce, AeadError> {
    nonce
        .as_slice()
        .try_into()
        .map_err(|_| AeadError::InvalidNonceLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key<KEY_LEN> {
        Key::from_array([0x5A; KEY_LEN])
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let message = b"contenu du coffre";
        let aad = b"metadonnees";

        let sealed = seal(&key, &nonce, message, aad).expect("chiffrement");
        assert_eq!(sealed.len(), message.len() + TAG_LEN);

        let opened = open(&key, &nonce, &sealed, aad).expect("dechiffrement");
        assert_eq!(opened.as_slice(), message);
    }

    #[test]
    fn empty_plaintext_is_supported() {
        // Cas limite réel : un coffre sans entrée reste un message valide.
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let sealed = seal(&key, &nonce, b"", b"").expect("chiffrement");
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(
            open(&key, &nonce, &sealed, b"")
                .expect("dechiffrement")
                .is_empty()
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let mut sealed = seal(&key, &nonce, b"message", b"").expect("chiffrement");

        for index in 0..sealed.len() {
            let original = sealed[index];
            sealed[index] = original ^ 0x01;
            assert_eq!(
                open(&key, &nonce, &sealed, b""),
                Err(AeadError::AuthenticationFailed),
                "un bit modifié à l'offset {index} doit être détecté"
            );
            sealed[index] = original;
        }
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let mut sealed = seal(&key, &nonce, b"message", b"").expect("chiffrement");

        // Le tag est en fin de message ; on altère chacun de ses octets.
        let tag_start = sealed.len() - TAG_LEN;
        for index in tag_start..sealed.len() {
            sealed[index] ^= 0x80;
            assert_eq!(
                open(&key, &nonce, &sealed, b""),
                Err(AeadError::AuthenticationFailed)
            );
            sealed[index] ^= 0x80;
        }
    }

    #[test]
    fn modified_aad_is_rejected() {
        // C'est la propriété qui protège le header du conteneur : le tag couvre
        // les métadonnées, pas seulement le contenu.
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let sealed = seal(&key, &nonce, b"message", b"en-tete-v1").expect("chiffrement");

        assert_eq!(
            open(&key, &nonce, &sealed, b"en-tete-v2"),
            Err(AeadError::AuthenticationFailed)
        );
        assert_eq!(
            open(&key, &nonce, &sealed, b""),
            Err(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let nonce = generate_nonce().expect("nonce");
        let sealed = seal(&test_key(), &nonce, b"message", b"").expect("chiffrement");

        let other = Key::from_array([0x5B; KEY_LEN]);
        assert_eq!(
            open(&other, &nonce, &sealed, b""),
            Err(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let key = test_key();
        let sealed =
            seal(&key, &generate_nonce().expect("nonce"), b"message", b"").expect("chiffrement");
        let mut other_nonce = generate_nonce().expect("nonce");
        // On force un nonce différent de façon déterministe.
        other_nonce[0] ^= 0xFF;

        assert_eq!(
            open(&key, &other_nonce, &sealed, b""),
            Err(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn truncated_ciphertext_is_rejected_without_panic() {
        let key = test_key();
        let nonce = generate_nonce().expect("nonce");
        let sealed = seal(&key, &nonce, b"message", b"").expect("chiffrement");

        for len in 0..sealed.len() {
            assert_eq!(
                open(&key, &nonce, &sealed[..len], b""),
                Err(AeadError::AuthenticationFailed),
                "troncature à {len} octets non détectée"
            );
        }
    }

    #[test]
    fn generated_nonces_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1024 {
            let nonce = generate_nonce().expect("nonce");
            assert!(
                seen.insert(nonce),
                "collision de nonce détectée : l'hypothèse de tirage aléatoire est fausse"
            );
        }
    }

    #[test]
    fn distinct_nonces_produce_distinct_ciphertexts() {
        // Vérifie qu'aucun état n'est réutilisé entre deux chiffrements : même
        // clé, même message, nonce différent ⇒ ciphertext différent.
        let key = test_key();
        let first =
            seal(&key, &generate_nonce().expect("nonce"), b"identique", b"").expect("chiffrement");
        let second =
            seal(&key, &generate_nonce().expect("nonce"), b"identique", b"").expect("chiffrement");
        assert_ne!(first, second);
    }
}
