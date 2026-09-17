//! Pièces jointes : blobs chiffrés **séparés du conteneur**.
//!
//! # Pourquoi hors du conteneur
//!
//! Le conteneur est chiffré en **un seul bloc AEAD** (ADR-002). Y loger une pièce
//! jointe de 500 Mo imposerait de réécrire ces 500 Mo à chaque modification d'un
//! titre — ce que l'architecture entière est construite pour éviter. Un blob vit donc
//! dans son propre fichier, chiffré sous une clé dédiée, et le conteneur ne porte que
//! ses métadonnées.
//!
//! # Ce que ce module garantit, et ce qu'il ne garantit pas
//!
//! **Garanti.** Chaque morceau est authentifié sous l'identité du coffre, du blob,
//! l'intégralité du header de blob **et sa position** (`I-BLOB-AAD`) : aucun morceau ne
//! peut être réordonné, dupliqué à une autre position, ni déplacé d'un blob ou d'un
//! coffre à un autre sans qu'un tag devienne invalide. Et l'ensemble est cohérent avec
//! les métadonnées de l'archive : nombre de morceaux, taille en clair, et
//! `content_mac` recalculé.
//!
//! **Non garanti, et il faut le dire.**
//!
//! * **La longueur du fichier n'est pas protégée par l'AEAD.** Une troncature propre —
//!   des morceaux de queue retirés — se déchiffre morceau par morceau sans qu'aucun tag
//!   n'échoue. Ce qui la détecte est la confrontation au `chunk_count` **de
//!   l'archive**, donnée authentifiée par le coffre, et à la longueur exacte attendue.
//!   L'AEAD seul ne suffit donc pas : la validation croise **trois** sources — le tag
//!   par morceau, le header de blob, et les métadonnées de l'archive.
//! * **Le rejeu d'une version antérieure du même blob** (mêmes identifiants et index,
//!   contenu différent) n'est pas écarté par l'AEAD : c'est `content_mac` qui l'écarte.
//! * **L'indisponibilité** : supprimer le fichier ne casse aucun tag. C'est
//!   [`sweep_blobs`] qui constate l'absence — jamais un silence.
//!
//! # Quand le clair est-il considéré comme valide ?
//!
//! Un morceau est *authentifié pour sa position* dès que son tag vérifie ; la pièce
//! jointe n'est *valide* qu'après les contrôles de fin de flux. [`AttachmentReader`] est
//! construit **avec** le [`AttachmentMeta`] attendu et rend [`Error::Corrupted`] à tout
//! échec. **Un morceau intermédiaire est authentique, pas validé** : les appelants qui
//! écrivent le clair quelque part doivent attendre la fin du flux avant de le
//! considérer comme complet — c'est ce que fait `attach get`, qui écrit dans un
//! temporaire et ne le renomme qu'après.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::encoding::hex_encode;
use crate::error::{Error, Result};
use crate::keys::{KEY_LEN, SubKeys};
use crate::model::{Archive, AttachmentMeta, BlobId};
use crate::secret::Key;

use passlock_platform::fs;

type HmacSha256 = Hmac<Sha256>;

/// Signature d'un fichier de blob.
pub const BLOB_MAGIC: [u8; 4] = *b"ATB1";

/// Version du format de blob. Un décodeur refuse toute autre valeur.
pub const BLOB_VERSION: u16 = 1;

/// Taille du header de blob, en octets.
const BLOB_HEADER_LEN: usize = 40;

/// Taille d'un morceau en clair : **1 Mio**.
///
/// Ce n'est pas un réglage de confort : c'est ce qui borne le pic mémoire d'une pièce
/// jointe de 500 Mio à quelques mégaoctets. Un morceau tient en mémoire **une fois**.
pub const ATTACHMENT_CHUNK_SIZE: u32 = 1024 * 1024;

/// Taille maximale d'une pièce jointe en clair.
pub const MAX_ATTACHMENT_BYTES: u64 = 512 * 1024 * 1024;

/// Taille maximale acceptée pour `chunk_size` **au décodage**.
///
/// Le producteur écrit toujours [`ATTACHMENT_CHUNK_SIZE`]. Le décodeur accepte une
/// autre valeur dans cette borne, pour ne pas rendre illisible un fichier écrit par une
/// version future ou par une autre implémentation du format — mais il ne l'accepte pas
/// sans borne, puisqu'elle dimensionne une allocation.
const MAX_DECODED_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

/// Étiquette du MAC de contenu, **en préfixe du message**.
///
/// `K_index` n'est pas scindée : elle sert une seule primitive, HMAC-SHA256, et la
/// séparation de ses trois usages se fait par étiquette. Voir `keys.rs`.
const CONTENT_MAC_LABEL: &[u8] = b"passlock/v1/attachment-content-mac";

/// Longueur d'un nom de fichier de blob, en caractères hexadécimaux.
const BLOB_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Emplacement et nommage
// ---------------------------------------------------------------------------

/// Répertoire des blobs d'un coffre.
///
/// La règle est **unique** et partagée par le coffre vivant, la sauvegarde et la
/// vérification : `<répertoire>/<nom du coffre>.attachments/`. Elle est calculée à
/// partir du chemin du coffre, jamais devinée.
#[must_use]
pub fn blob_dir_for(vault_path: &Path) -> PathBuf {
    let mut name = vault_path
        .file_name()
        .map_or_else(std::ffi::OsString::new, std::ffi::OsStr::to_os_string);
    name.push(".attachments");
    vault_path.with_file_name(name)
}

/// Vrai si `name` a exactement la forme d'un nom de fichier de blob.
///
/// Sert au ramasse-miettes : un fichier qui ne ressemble pas à un blob **n'est jamais
/// supprimé**, même s'il traîne dans le répertoire. Une suppression hasardeuse serait
/// irréversible ; un fichier étranger laissé en place ne l'est pas.
#[must_use]
pub fn is_blob_name(name: &str) -> bool {
    name.len() == BLOB_NAME_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Nom de fichier d'un blob : `hex(HMAC(K_blob_name, vault_id ‖ blob_id))`.
///
/// Tronqué à 128 bits. L'étiquette de domaine vit dans le **HKDF** qui produit
/// `K_blob_name` ; la répéter ici donnerait deux mécanismes pour le même problème
/// (`I-KEYDOMAIN`).
///
/// # Erreurs
/// [`Error::Internal`] si HMAC refuse une clé de 32 octets.
pub fn blob_file_name(subkeys: &SubKeys, vault_id: &[u8; 16], blob_id: BlobId) -> Result<String> {
    let mut hmac = new_hmac(subkeys.blob_name())?;
    Mac::update(&mut hmac, vault_id);
    Mac::update(&mut hmac, blob_id.as_bytes());
    let digest = hmac.finalize().into_bytes();
    Ok(hex_encode(&digest[..BLOB_NAME_LEN / 2]))
}

// ---------------------------------------------------------------------------
// Header de blob
// ---------------------------------------------------------------------------

/// Header d'un fichier de blob — 40 octets à offsets fixes.
///
/// Il n'y a **pas de parseur** : mêmes raisons qu'au conteneur (ADR-004). Toutes les
/// valeurs sont confrontées à des bornes avant d'être utilisées, et notamment avant
/// toute allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobHeader {
    /// Identifiant aléatoire du blob, celui de l'archive.
    pub blob_id: BlobId,
    /// Taille du contenu en clair.
    pub plaintext_size: u64,
    /// Taille d'un morceau en clair.
    pub chunk_size: u32,
    /// Nombre de morceaux.
    pub chunk_count: u32,
}

impl BlobHeader {
    /// Construit le header d'un blob de `plaintext_size` octets.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si la taille dépasse [`MAX_ATTACHMENT_BYTES`].
    pub fn new(blob_id: BlobId, plaintext_size: u64) -> Result<Self> {
        if plaintext_size > MAX_ATTACHMENT_BYTES {
            return Err(Error::InvalidInput {
                reason: "pièce jointe au-delà de la taille maximale",
            });
        }
        Ok(Self {
            blob_id,
            plaintext_size,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count: chunk_count_for(plaintext_size, ATTACHMENT_CHUNK_SIZE),
        })
    }

    /// Encode le header en 40 octets, à offsets fixes.
    #[must_use]
    pub fn encode(&self) -> [u8; BLOB_HEADER_LEN] {
        let mut out = [0_u8; BLOB_HEADER_LEN];
        out[0..4].copy_from_slice(&BLOB_MAGIC);
        out[4..6].copy_from_slice(&BLOB_VERSION.to_be_bytes());
        // 6..8 : réservé, laissé à zéro.
        out[8..24].copy_from_slice(self.blob_id.as_bytes());
        out[24..32].copy_from_slice(&self.plaintext_size.to_be_bytes());
        out[32..36].copy_from_slice(&self.chunk_size.to_be_bytes());
        out[36..40].copy_from_slice(&self.chunk_count.to_be_bytes());
        out
    }

    /// Décode un header de 40 octets, en vérifiant **tout** ce qui peut l'être.
    ///
    /// # Erreurs
    /// [`Error::Corrupted`] pour toute incohérence : magic, version, champ réservé non
    /// nul, `chunk_size` hors bornes, `chunk_count` incohérent avec la taille annoncée.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BLOB_HEADER_LEN {
            return Err(Error::Corrupted {
                reason: "header de pièce jointe de taille incorrecte",
            });
        }
        if bytes[0..4] != BLOB_MAGIC {
            return Err(Error::Corrupted {
                reason: "signature de pièce jointe inconnue",
            });
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != BLOB_VERSION {
            return Err(Error::Corrupted {
                reason: "version de format de pièce jointe non prise en charge",
            });
        }
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(Error::Corrupted {
                reason: "champ réservé non nul dans un header de pièce jointe",
            });
        }

        let mut id = [0_u8; 16];
        id.copy_from_slice(&bytes[8..24]);

        let mut size = [0_u8; 8];
        size.copy_from_slice(&bytes[24..32]);
        let plaintext_size = u64::from_be_bytes(size);
        if plaintext_size > MAX_ATTACHMENT_BYTES {
            return Err(Error::Corrupted {
                reason: "taille de pièce jointe au-delà de la borne",
            });
        }

        let mut chunk = [0_u8; 4];
        chunk.copy_from_slice(&bytes[32..36]);
        let chunk_size = u32::from_be_bytes(chunk);
        if chunk_size == 0 || chunk_size > MAX_DECODED_CHUNK_SIZE {
            return Err(Error::Corrupted {
                reason: "taille de morceau hors bornes",
            });
        }

        let mut count = [0_u8; 4];
        count.copy_from_slice(&bytes[36..40]);
        let chunk_count = u32::from_be_bytes(count);
        if chunk_count != chunk_count_for(plaintext_size, chunk_size) {
            return Err(Error::Corrupted {
                reason: "nombre de morceaux incohérent avec la taille annoncée",
            });
        }

        Ok(Self {
            blob_id: BlobId::from_bytes(id),
            plaintext_size,
            chunk_size,
            chunk_count,
        })
    }

    /// Longueur en clair du morceau `index`.
    ///
    /// Seul le **dernier** morceau peut être plus court que `chunk_size`.
    fn chunk_len(&self, index: u32) -> u64 {
        let offset = u64::from(index) * u64::from(self.chunk_size);
        if offset >= self.plaintext_size {
            0
        } else {
            (self.plaintext_size - offset).min(u64::from(self.chunk_size))
        }
    }

    /// Longueur totale attendue du fichier, **avant** toute allocation.
    fn encoded_len(&self) -> u64 {
        let overhead =
            u64::from(self.chunk_count) * u64::try_from(NONCE_LEN + TAG_LEN).unwrap_or(0);
        u64::try_from(BLOB_HEADER_LEN).unwrap_or(0) + overhead + self.plaintext_size
    }
}

/// Nombre de morceaux pour `size` octets découpés en morceaux de `chunk`.
///
/// Un contenu **vide** occupe **un** morceau de zéro octet : l'archive refuse
/// `chunk_count == 0`, et un blob sans morceau n'aurait aucune preuve d'intégrité.
#[must_use]
pub fn chunk_count_for(size: u64, chunk: u32) -> u32 {
    let chunk = u64::from(chunk).max(1);
    if size == 0 {
        return 1;
    }
    let count = size.div_ceil(chunk);
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Données authentifiées d'un morceau : header exact, coffre, **et position**.
///
/// Le header est repris **octet pour octet**, et non reconstruit depuis les champs :
/// c'est la raison d'`ADR-005`, appliquée ici. L'index est ce qui empêche qu'un
/// morceau change de place — sans lui, le nonce voyageant avec son chiffré, permuter
/// deux morceaux de même taille produirait un clair réordonné et des tags valides.
fn chunk_aad(header_bytes: &[u8; BLOB_HEADER_LEN], vault_id: &[u8; 16], index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLOB_HEADER_LEN + 16 + 4);
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&index.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// MAC de contenu
// ---------------------------------------------------------------------------

/// HMAC de contenu, alimenté au fil de l'eau.
///
/// Le contenu en clair est MACé **pendant** qu'il est chiffré, jamais en le relisant :
/// relire supposerait de le conserver, ou de le déchiffrer deux fois.
struct ContentMac(HmacSha256);

impl ContentMac {
    /// `HMAC(K_index, "…/attachment-content-mac" ‖ vault_id ‖ blob_id ‖ taille ‖ clair)`.
    ///
    /// La liaison au coffre, au blob et à la taille rend le MAC non rejouable d'un blob
    /// à un autre. Ce n'est **pas** la correction d'une faille démontrée — l'AAD des
    /// morceaux lie déjà ces valeurs — mais une défense en profondeur qui rend la valeur
    /// auto-descriptive, là où le modèle ne documentait qu'« un HMAC du contenu ».
    fn new(
        index_key: &Key<KEY_LEN>,
        vault_id: &[u8; 16],
        blob_id: BlobId,
        size: u64,
    ) -> Result<Self> {
        let mut hmac = new_hmac(index_key)?;
        Mac::update(&mut hmac, CONTENT_MAC_LABEL);
        Mac::update(&mut hmac, vault_id);
        Mac::update(&mut hmac, blob_id.as_bytes());
        Mac::update(&mut hmac, &size.to_be_bytes());
        Ok(Self(hmac))
    }

    fn update(&mut self, bytes: &[u8]) {
        Mac::update(&mut self.0, bytes);
    }

    fn finish(self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out.copy_from_slice(&self.0.finalize().into_bytes());
        out
    }
}

/// Instancie un HMAC-SHA256 avec la clé fournie.
fn new_hmac(key: &Key<KEY_LEN>) -> Result<HmacSha256> {
    <HmacSha256 as KeyInit>::new_from_slice(key.expose()).map_err(|_| Error::Internal {
        invariant: "HMAC refuse une clé de 32 octets",
    })
}

// ---------------------------------------------------------------------------
// Écriture
// ---------------------------------------------------------------------------

/// Ce qu'un scellement produit, indépendamment de l'entrée à laquelle il se rattache.
#[derive(Debug, Clone, Copy)]
pub struct SealedBlob {
    /// Header effectivement écrit.
    pub header: BlobHeader,
    /// MAC du contenu en clair, à ranger dans les métadonnées de l'archive.
    pub content_mac: [u8; 32],
}

/// Chiffre `source` vers `out`, par morceaux de [`ATTACHMENT_CHUNK_SIZE`].
///
/// La taille en clair est **connue à l'avance** et fournie par l'appelant. Ce n'est pas
/// une contrainte de confort : le header entre dans l'AAD de chaque morceau, donc
/// l'écrire puis le corriger invaliderait tous les tags déjà produits. Il faudrait
/// alors tout réécrire, ce qui est exactement ce que ce format évite.
///
/// # Erreurs
/// * [`Error::InvalidInput`] si `source` ne contient pas exactement `plaintext_size`
///   octets — un fichier qui change de taille pendant l'opération est refusé plutôt que
///   tronqué en silence ;
/// * [`Error::Io`] pour toute erreur de lecture ou d'écriture.
pub fn seal_blob<R: Read, W: Write>(
    blob_id: BlobId,
    vault_id: &[u8; 16],
    subkeys: &SubKeys,
    plaintext_size: u64,
    source: &mut R,
    out: &mut W,
) -> Result<SealedBlob> {
    let header = BlobHeader::new(blob_id, plaintext_size)?;
    let header_bytes = header.encode();
    out.write_all(&header_bytes)?;

    let mut mac = ContentMac::new(&subkeys.index, vault_id, blob_id, plaintext_size)?;

    // Un seul tampon, réutilisé : sa taille est notre constante, jamais une valeur lue.
    let mut buffer = vec![0_u8; ATTACHMENT_CHUNK_SIZE as usize];

    for index in 0..header.chunk_count {
        let len = usize::try_from(header.chunk_len(index)).unwrap_or(0);
        read_exactly(source, &mut buffer[..len])?;
        mac.update(&buffer[..len]);

        let nonce = aead::generate_nonce().map_err(|_| Error::Internal {
            invariant: "le générateur du système a refusé un nonce",
        })?;
        let aad = chunk_aad(&header_bytes, vault_id, index);
        let ciphertext = aead::seal(subkeys.blob_aead(), &nonce, &buffer[..len], &aad).map_err(
            |err| match err {
                // Un morceau fait au plus `ATTACHMENT_CHUNK_SIZE` : la limite du format
                // AEAD (2⁶⁴ octets) ne peut pas être atteinte par un morceau.
                aead::AeadError::MessageTooLong => Error::Internal {
                    invariant: "morceau de pièce jointe au-delà de la limite de l'AEAD",
                },
                _ => Error::Internal {
                    invariant: "échec du scellement d'un morceau de taille bornée",
                },
            },
        )?;

        out.write_all(&nonce)?;
        out.write_all(&ciphertext)?;
    }

    // La source doit être épuisée. Un octet de plus signifie que le fichier a changé
    // entre la mesure de sa taille et sa lecture : on refuse, plutôt que d'écrire une
    // pièce jointe dont la taille annoncée ne serait pas la taille réelle.
    let mut probe = [0_u8; 1];
    if source.read(&mut probe)? != 0 {
        return Err(Error::InvalidInput {
            reason: "le fichier source a changé de taille pendant la lecture",
        });
    }

    Ok(SealedBlob {
        header,
        content_mac: mac.finish(),
    })
}

/// Lit exactement `buffer.len()` octets, ou refuse.
fn read_exactly<R: Read>(source: &mut R, buffer: &mut [u8]) -> Result<()> {
    source.read_exact(buffer).map_err(|_| Error::InvalidInput {
        reason: "le fichier source a changé de taille pendant la lecture",
    })
}

// ---------------------------------------------------------------------------
// Lecture
// ---------------------------------------------------------------------------

/// Lecteur d'un blob, qui ne rend un verdict qu'en fin de flux.
///
/// Voir l'en-tête du module : **un morceau intermédiaire est authentique, pas validé**.
pub struct AttachmentReader<'a> {
    file: std::fs::File,
    /// Header **lu** dans le fichier, après confrontation aux métadonnées.
    header: BlobHeader,
    header_bytes: [u8; BLOB_HEADER_LEN],
    subkeys: &'a SubKeys,
    vault_id: [u8; 16],
    /// HMAC de contenu en cours. `None` après une lecture menée à son terme : une
    /// seconde lecture est un défaut de programmation, pas une opération à rejouer.
    mac: Option<ContentMac>,
    /// `content_mac` attendu, tel que les métadonnées de l'archive le portent.
    expected_mac: [u8; 32],
}

impl<'a> AttachmentReader<'a> {
    /// Ouvre un blob et l'accorde à ses métadonnées **avant** toute allocation.
    ///
    /// # Erreurs
    /// * [`Error::Corrupted`] si le fichier n'est pas un blob, si sa taille ne correspond
    ///   pas à ce que son header annonce, ou si le header contredit les métadonnées de
    ///   l'archive ;
    /// * [`Error::Io`] si le fichier est absent ou illisible.
    pub fn open(
        path: &Path,
        meta: &AttachmentMeta,
        subkeys: &'a SubKeys,
        vault_id: &[u8; 16],
    ) -> Result<Self> {
        let mut file = fs::open_read(path)?;

        let mut header_bytes = [0_u8; BLOB_HEADER_LEN];
        file.read_exact(&mut header_bytes)
            .map_err(|_| Error::Corrupted {
                reason: "fichier de pièce jointe trop court pour contenir un header",
            })?;
        let header = BlobHeader::decode(&header_bytes)?;

        // Les métadonnées de l'archive sont **l'autorité** : le fichier ne peut pas
        // déclarer une autre identité, une autre taille ni un autre découpage.
        if header.blob_id.as_bytes() != meta.id.as_bytes() {
            return Err(Error::Corrupted {
                reason: "l'identifiant du fichier de pièce jointe ne correspond pas aux métadonnées",
            });
        }
        if header.plaintext_size != meta.size
            || header.chunk_size != meta.chunk_size
            || header.chunk_count != meta.chunk_count
        {
            return Err(Error::Corrupted {
                reason: "le découpage du fichier de pièce jointe ne correspond pas aux métadonnées",
            });
        }

        // Longueur exacte, **avant** toute allocation. C'est ce contrôle qui détecte la
        // troncature propre, que l'AEAD seul laisserait passer.
        let actual = file.metadata()?.len();
        if actual != header.encoded_len() {
            return Err(Error::Corrupted {
                reason: "la longueur du fichier de pièce jointe ne correspond pas à son header",
            });
        }

        let mac = ContentMac::new(
            &subkeys.index,
            vault_id,
            header.blob_id,
            header.plaintext_size,
        )?;

        Ok(Self {
            file,
            header,
            header_bytes,
            subkeys,
            vault_id: *vault_id,
            mac: Some(mac),
            expected_mac: meta.content_mac,
        })
    }

    /// Lit le blob entier vers `out`, et **rend le verdict en fin de flux**.
    ///
    /// # Erreurs
    /// * [`Error::Corrupted`] si un tag échoue, si le fichier est plus court ou plus
    ///   long que ce que son header annonce, ou si `content_mac` ne correspond pas ;
    /// * [`Error::Internal`] si la même instance est relue — ce serait un défaut de
    ///   programmation, et le HMAC ne peut pas être rejoué ;
    /// * [`Error::Io`] pour toute erreur de lecture ou d'écriture.
    pub fn read_all<W: Write>(&mut self, out: &mut W) -> Result<()> {
        let Some(mut mac) = self.mac.take() else {
            return Err(Error::Internal {
                invariant: "un lecteur de pièce jointe ne peut pas être relu",
            });
        };

        for index in 0..self.header.chunk_count {
            let len = usize::try_from(self.header.chunk_len(index)).unwrap_or(0);

            let mut nonce = [0_u8; NONCE_LEN];
            self.file
                .read_exact(&mut nonce)
                .map_err(|_| Error::Corrupted {
                    reason: "fichier de pièce jointe tronqué au milieu d'un morceau",
                })?;

            // Une allocation par morceau, bornée par la constante du format : quelques
            // mégaoctets au plus, jamais la taille totale de la pièce jointe.
            let mut ciphertext = vec![0_u8; len + TAG_LEN];
            self.file
                .read_exact(&mut ciphertext)
                .map_err(|_| Error::Corrupted {
                    reason: "fichier de pièce jointe tronqué au milieu d'un morceau",
                })?;

            let aad = chunk_aad(&self.header_bytes, &self.vault_id, index);
            let plaintext = aead::open(self.subkeys.blob_aead(), &nonce, &ciphertext, &aad)
                .map_err(|_| Error::Corrupted {
                    reason: "un morceau de pièce jointe n'a pas pu être authentifié",
                })?;

            mac.update(&plaintext);
            out.write_all(&plaintext)?;
        }

        // Aucun octet ne doit subsister après le dernier morceau : c'est ce qui
        // distingue un fichier complet d'un fichier auquel on a ajouté quelque chose.
        let mut probe = [0_u8; 1];
        if self.file.read(&mut probe)? != 0 {
            return Err(Error::Corrupted {
                reason: "fichier de pièce jointe plus long que ce que son header annonce",
            });
        }

        // Comparaison en temps constant : un MAC se compare comme un secret, même quand
        // son enjeu est l'intégrité et non la confidentialité.
        let computed = mac.finish();
        if !bool::from(computed.ct_eq(&self.expected_mac)) {
            return Err(Error::Corrupted {
                reason: "le contenu de la pièce jointe ne correspond pas à son empreinte",
            });
        }
        Ok(())
    }
}

/// Vérifie un blob **sans écrire le clair nulle part**.
///
/// # Erreurs
/// Voir [`AttachmentReader::read_all`].
pub fn verify_blob(
    path: &Path,
    meta: &AttachmentMeta,
    subkeys: &SubKeys,
    vault_id: &[u8; 16],
) -> Result<()> {
    let mut reader = AttachmentReader::open(path, meta, subkeys, vault_id)?;
    let mut sink = std::io::sink();
    reader.read_all(&mut sink)
}

// Le `Debug` est écrit à la main : `SubKeys` est un emprunt vers du matériel de clé, et
// le dériver exposerait sa structure. Le lint signale l'omission ; ici, l'omission est
// l'objectif.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for AttachmentReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentReader")
            .field("blob_id", &self.header.blob_id)
            .field("plaintext_size", &self.header.plaintext_size)
            .field("chunk_count", &self.header.chunk_count)
            .field("verdict_rendu", &self.mac.is_none())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Ramasse-miettes
// ---------------------------------------------------------------------------

/// Ce qu'un balayage du répertoire des blobs constate.
///
/// Les trois catégories sont **séparées** parce qu'elles n'appellent pas la même
/// décision : un orphelin peut être supprimé, un fichier étranger **non**, et une
/// absence est une incohérence à signaler — jamais un élément à supprimer.
///
/// Le balayage rend des **noms**, pas des chemins : l'appelant ne peut donc agir que
/// sur une entrée du répertoire des blobs, jamais sur un chemin arbitraire.
#[derive(Debug, Default)]
pub struct BlobSweep {
    /// Noms bien formés qu'aucune métadonnée ne référence : **supprimables**.
    pub orphans: Vec<std::ffi::OsString>,
    /// Entrées dont le nom **ne peut pas** être un nom de blob.
    ///
    /// **Jamais supprimées.** Le répertoire est à nous, mais rien ne prouve qu'une
    /// entrée étrangère n'y a pas été déposée, et une suppression est irréversible.
    pub unexpected: Vec<std::ffi::OsString>,
    /// Métadonnées sans fichier correspondant — une **promesse non tenue**.
    ///
    /// Une absence n'est **pas** un candidat à la suppression : il n'y a rien à
    /// supprimer, et c'est une incohérence à signaler telle quelle.
    pub missing: Vec<BlobId>,
}

impl BlobSweep {
    /// Vrai si le répertoire et les métadonnées sont exactement d'accord.
    ///
    /// Un fichier étranger ne rend pas l'ensemble incohérent : il n'appartient
    /// simplement pas à Passlock.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.orphans.is_empty() && self.missing.is_empty()
    }
}

/// Confronte le répertoire des blobs aux métadonnées de l'archive.
///
/// # Ce que cette fonction ne fait pas
///
/// Elle **ne vérifie aucun contenu** et **ne supprime rien**. Un blob référencé mais
/// corrompu ou invérifiable n'est ni orphelin, ni absent : il est **présent**, donc
/// jamais candidat à la suppression. C'est la propriété qui empêche qu'une corruption
/// se transforme en perte de données par l'effet d'un ramasse-miettes.
///
/// La politique de suppression appartient à la ligne de commande, qui demande
/// confirmation : c'est la seule opération du produit qui retire des fichiers.
///
/// # Erreurs
/// * [`Error::Io`] si le répertoire ne peut pas être listé ;
/// * [`Error::Internal`] si la dérivation d'un nom échoue.
pub fn sweep_blobs(
    dir: &Path,
    archive: &Archive,
    subkeys: &SubKeys,
    vault_id: &[u8; 16],
) -> Result<BlobSweep> {
    let referenced: Vec<(BlobId, std::ffi::OsString)> = archive
        .attachments
        .iter()
        .map(|meta| {
            let name = blob_file_name(subkeys, vault_id, meta.id)?;
            Ok((meta.id, std::ffi::OsString::from(name)))
        })
        .collect::<Result<_>>()?;

    let mut sweep = BlobSweep::default();

    // Métadonnées sans fichier.
    for (id, name) in &referenced {
        if !fs::path_exists(&dir.join(name)) {
            sweep.missing.push(*id);
        }
    }

    // Fichiers sans métadonnée.
    if fs::path_exists(dir) {
        for entry in fs::list_dir(dir)? {
            if !entry.to_str().is_some_and(is_blob_name) {
                sweep.unexpected.push(entry);
                continue;
            }
            if !referenced.iter().any(|(_, name)| *name == entry) {
                sweep.orphans.push(entry);
            }
        }
        sweep.orphans.sort();
        sweep.unexpected.sort();
    }

    Ok(sweep)
}
