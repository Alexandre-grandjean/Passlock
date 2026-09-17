//! Sentinelle anti-rollback.
//!
//! # Le problème
//!
//! Un attaquant qui peut écrire sur le disque peut **remplacer le coffre par une
//! version antérieure**. Les conséquences concrètes :
//!
//! * restaurer un coffre d'avant un changement de mot de passe, pour revenir à un
//!   secret que l'utilisateur croyait révoqué ;
//! * restaurer un coffre d'avant un durcissement des paramètres Argon2id, pour
//!   bénéficier d'un cassage hors ligne moins coûteux ;
//! * ressusciter une entrée supprimée, y compris une clé d'API révoquée.
//!
//! Le tag AEAD ne détecte rien : un ancien fichier est parfaitement authentique.
//! Il faut donc un état **extérieur** au coffre.
//!
//! # La solution, et sa limite
//!
//! Un compteur monotone conservé dans le répertoire de configuration de
//! l'utilisateur, et non à côté du coffre — sinon un attaquant capable d'écrire le
//! coffre écrirait la sentinelle du même geste.
//!
//! ## Les limites, énoncées sans détour
//!
//! ### 1. Le HMAC empêche de *forger*, pas de *restaurer*
//!
//! C'est la distinction la plus facile à confondre, et la plus importante à écrire.
//! Le tag HMAC garantit qu'un attaquant **ne peut pas inventer** une sentinelle
//! arbitraire : il lui faudrait `K_index`, donc la DEK. Il n'empêche **pas** de
//! remettre en place une sentinelle authentique d'une époque antérieure, ni de
//! recopier la sentinelle courante telle quelle. Rejouer une valeur valide ne
//! demande aucune connaissance cryptographique.
//!
//! ### 2. Effacer la sentinelle désactive la détection — et c'est le chemin le plus accessible
//!
//! Un attaquant qui peut écrire dans le répertoire de configuration peut
//! **supprimer** ces 64 octets. L'ouverture suivante rapporte `NoSentinel` et
//! l'implémentation **rétablit la référence** à la génération du coffre présenté,
//! donc à celle de l'attaquant. Un avertissement est affiché, mais rien ne le
//! distingue d'une première ouverture sur une machine neuve — situation banale.
//!
//! Conséquence : la suppression de la sentinelle est un contournement plus simple
//! que la réécriture coordonnée des deux emplacements.
//!
//! ### 3. Aucune correction possible localement
//!
//! La protection réelle exigerait un état que l'attaquant ne peut pas réécrire : un
//! compteur monotone matériel (compteur NV d'un TPM), un support en ajout seul, ou
//! un journal distant. Les trois sortent du périmètre fixé (aucun serveur, aucune
//! dépendance à un cloud).
//!
//! Cette sentinelle est donc une **détection partielle**, et elle doit être
//! présentée comme telle : écrire « détection de rollback » sans nuance donnerait
//! une confiance injustifiée. La matrice complète des capacités de l'attaquant
//! figure dans `docs/AUDIT_PHASE1.md` §5.
//!
//! # Pourquoi le nom du fichier de sentinelle ne contient pas celui du coffre
//!
//! Le nom est `HMAC(K_index, "…/name" || vault_id)`. Il n'est donc pas dérivable
//! sans la clé, et un attaquant qui lirait le répertoire de configuration
//! n'apprendrait pas quels coffres l'utilisateur possède ni où ils se trouvent.
//! Corollaire assumé : la sentinelle n'est lisible qu'après déverrouillage, donc
//! la détection a lieu **après** l'ouverture, pas avant.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::KEY_LEN;
use crate::secret::Key;

type HmacSha256 = Hmac<Sha256>;

/// Longueur du fichier de sentinelle.
const SENTINEL_LEN: usize = 16 + 8 + 8 + 32;

/// Domaine de dérivation du nom de fichier.
const NAME_INFO: &[u8] = b"passlock/v1/sentinel-name";

/// Domaine d'authentification de la sentinelle.
const MAC_INFO: &[u8] = b"passlock/v1/sentinel-mac";

/// État anti-rollback d'un coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sentinel {
    /// Identifiant du coffre auquel cette sentinelle se rapporte.
    pub vault_id: [u8; 16],
    /// Dernière génération connue.
    pub generation: u64,
    /// Date du dernier enregistrement, en secondes depuis l'époque Unix.
    pub updated_at: u64,
}

/// Résultat de la comparaison entre un coffre et sa sentinelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackCheck {
    /// Aucune sentinelle n'existe pour ce coffre : la détection est **inactive**.
    ///
    /// Ce n'est pas une erreur — c'est l'état normal d'un premier enregistrement,
    /// ou d'un coffre créé sur une autre machine. L'appelant doit le signaler à
    /// l'utilisateur au lieu de laisser croire à une protection active.
    NoSentinel,

    /// Le coffre est au moins aussi récent que la sentinelle.
    Consistent,

    /// Le coffre est plus ancien que le dernier état connu.
    Rollback {
        /// Génération enregistrée dans la sentinelle.
        known: u64,
        /// Génération lue dans le coffre.
        found: u64,
    },
}

/// Emplacement et nom de la sentinelle d'un coffre.
#[derive(Debug, Clone)]
pub struct SentinelStore {
    path: PathBuf,
}

impl SentinelStore {
    /// Calcule l'emplacement de la sentinelle d'un coffre.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si la dérivation du nom échoue, ce qui ne peut pas
    /// arriver avec une clé de longueur valide.
    pub fn new(state_dir: &Path, index_key: &Key<KEY_LEN>, vault_id: &[u8; 16]) -> Result<Self> {
        let mut input = Vec::with_capacity(NAME_INFO.len() + vault_id.len());
        input.extend_from_slice(NAME_INFO);
        input.extend_from_slice(vault_id);
        let digest = mac(index_key, &input)?;

        let mut name = String::with_capacity(32 + 5);
        // 16 octets du condensé suffisent : l'espace de noms est local à un compte
        // utilisateur, et un nom plus long n'apporterait rien.
        for byte in &digest[..16] {
            // `write!` dans une `String` ne peut pas échouer, et évite
            // l'allocation d'une chaîne intermédiaire par octet.
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(".sent");

        Ok(Self {
            path: state_dir.join(name),
        })
    }

    /// Chemin du fichier de sentinelle.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lit la sentinelle, si elle existe et si elle est intègre.
    ///
    /// ## Choix sur les sentinelles illisibles
    ///
    /// Une sentinelle tronquée, dont le tag ne correspond pas, ou qui porte un
    /// autre identifiant de coffre est traitée comme **absente** — avec un
    /// avertissement émis par l'appelant. Refuser d'ouvrir le coffre dans ce cas
    /// serait disproportionné : la sentinelle est un auxiliaire, pas l'autorité.
    /// Mais il faut le dire, car une sentinelle corrompue peut aussi bien résulter
    /// d'un effacement par un attaquant, ce qui est précisément le scénario qu'on
    /// cherche à détecter.
    ///
    /// # Erreurs
    /// [`Error::Io`] si le fichier existe mais ne peut pas être lu.
    pub fn load(&self, index_key: &Key<KEY_LEN>, vault_id: &[u8; 16]) -> Result<SentinelLoad> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SentinelLoad::Absent);
            }
            Err(err) => return Err(Error::Io(err)),
        };

        if bytes.len() != SENTINEL_LEN {
            return Ok(SentinelLoad::Corrupted {
                reason: "taille de sentinelle invalide",
            });
        }

        if !verify_mac(index_key, &bytes[..32], &bytes[32..64])? {
            return Ok(SentinelLoad::Corrupted {
                reason: "authentification de la sentinelle invalide",
            });
        }

        let mut id = [0_u8; 16];
        id.copy_from_slice(&bytes[0..16]);
        if &id != vault_id {
            // Le nom du fichier dérive de l'identifiant du coffre, donc ce cas ne
            // devrait pas se produire. On le traite comme une corruption plutôt
            // que de comparer des générations qui ne concernent pas ce coffre.
            return Ok(SentinelLoad::Corrupted {
                reason: "sentinelle associée à un autre coffre",
            });
        }

        let generation = read_u64(&bytes[16..24]);
        let updated_at = read_u64(&bytes[24..32]);

        Ok(SentinelLoad::Found(Sentinel {
            vault_id: id,
            generation,
            updated_at,
        }))
    }

    /// Écrit la sentinelle de façon atomique.
    ///
    /// # Erreurs
    /// [`Error::Io`] si le répertoire ne peut pas être créé ou si l'écriture échoue.
    pub fn store(&self, index_key: &Key<KEY_LEN>, sentinel: &Sentinel) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut bytes = Vec::with_capacity(SENTINEL_LEN);
        bytes.extend_from_slice(&sentinel.vault_id);
        bytes.extend_from_slice(&sentinel.generation.to_be_bytes());
        bytes.extend_from_slice(&sentinel.updated_at.to_be_bytes());
        let tag = mac(index_key, &bytes)?;
        bytes.extend_from_slice(&tag);

        let suffix = crate::rng::u64()
            .map_err(|_| Error::Internal {
                invariant: "générateur d'aléa indisponible pour le nom temporaire",
            })?
            .to_string();

        passlock_platform::fs::write_atomic(&self.path, &suffix, &bytes).map_err(Error::Io)
    }

    /// Compare la génération d'un coffre à celle de la sentinelle.
    ///
    /// # Erreurs
    /// Propage les erreurs de lecture.
    pub fn check(
        &self,
        index_key: &Key<KEY_LEN>,
        vault_id: &[u8; 16],
        generation: u64,
    ) -> Result<RollbackCheck> {
        match self.load(index_key, vault_id)? {
            SentinelLoad::Absent | SentinelLoad::Corrupted { .. } => Ok(RollbackCheck::NoSentinel),
            SentinelLoad::Found(sentinel) => {
                if generation < sentinel.generation {
                    Ok(RollbackCheck::Rollback {
                        known: sentinel.generation,
                        found: generation,
                    })
                } else {
                    Ok(RollbackCheck::Consistent)
                }
            }
        }
    }
}

/// Résultat de la lecture d'une sentinelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentinelLoad {
    /// Aucun fichier de sentinelle.
    Absent,
    /// Sentinelle lisible et authentique.
    Found(Sentinel),
    /// Fichier présent mais inutilisable.
    Corrupted {
        /// Description statique de l'incohérence.
        reason: &'static str,
    },
}

/// Calcule la date courante en secondes depuis l'époque Unix.
///
/// Une horloge antérieure à 1970 ou une erreur de lecture donne `0`. Ce n'est pas
/// une donnée de sécurité : elle sert à l'affichage et est de toute façon couverte
/// par l'authentification de la sentinelle.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Calcule un HMAC-SHA256 sur une sentinelle.
///
/// ## Pourquoi HMAC et non SHA-256 direct
///
/// La sentinelle n'est pas un simple condensé d'intégrité : c'est un condensé
/// **clé**. Sans clé, un attaquant pourrait recalculer un SHA-256 après avoir
/// modifié la génération, et la falsification serait indétectable. HMAC-SHA256
/// avec la sous-clé `K_index` exige la DEK, donc le déverrouillage.
///
/// ## Séparation de domaine
///
/// `K_index` sert aussi à dériver le **nom** du fichier de sentinelle. Le préfixe
/// [`MAC_INFO`] garantit que les deux usages ne peuvent pas se confondre : sans
/// lui, une valeur calculée pour l'un pourrait accidentellement être valide pour
/// l'autre. Les longueurs d'entrée diffèrent aujourd'hui, mais s'appuyer sur une
/// différence de longueur est fragile — un préfixe explicite ne l'est pas.
fn mac(key: &Key<KEY_LEN>, payload: &[u8]) -> Result<[u8; 32]> {
    let mut hmac = new_hmac(key)?;
    Mac::update(&mut hmac, MAC_INFO);
    Mac::update(&mut hmac, payload);
    Ok(hmac.finalize().into_bytes().into())
}

/// Vérifie un tag HMAC en temps constant.
///
/// Délègue à `verify_slice` de la bibliothèque plutôt que de comparer les octets
/// nous-mêmes : la comparaison fournie par RustCrypto est constante en temps par
/// construction, ce qui évite d'avoir à la réécrire correctement — une comparaison
/// non constante est exactement le genre de défaut qui ne se voit pas en relecture.
///
/// La sentinelle n'est pas un secret, mais un attaquant capable de mesurer le temps
/// de comparaison pourrait retrouver un préfixe de tag correct, puis forger une
/// sentinelle. Le coût de la précaution est nul.
fn verify_mac(key: &Key<KEY_LEN>, payload: &[u8], tag: &[u8]) -> Result<bool> {
    let mut hmac = new_hmac(key)?;
    Mac::update(&mut hmac, MAC_INFO);
    Mac::update(&mut hmac, payload);
    Ok(hmac.verify_slice(tag).is_ok())
}

/// Instancie un HMAC-SHA256 avec la clé fournie.
fn new_hmac(key: &Key<KEY_LEN>) -> Result<HmacSha256> {
    <HmacSha256 as KeyInit>::new_from_slice(key.expose()).map_err(|_| Error::Internal {
        invariant: "HMAC refuse une clé de 32 octets",
    })
}

/// Lit un `u64` en gros-boutiste. La tranche doit faire 8 octets.
fn read_u64(bytes: &[u8]) -> u64 {
    let mut out = [0_u8; 8];
    out.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key<KEY_LEN> {
        Key::from_array([0x21; KEY_LEN])
    }

    fn store(dir: &Path, key: &Key<KEY_LEN>, vault_id: &[u8; 16]) -> SentinelStore {
        SentinelStore::new(dir, key, vault_id).expect("sentinelle")
    }

    fn sentinel(vault_id: [u8; 16], generation: u64) -> Sentinel {
        Sentinel {
            vault_id,
            generation,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn absent_sentinel_is_reported_as_absent() {
        let dir = tempfile::tempdir().expect("répertoire");
        let store = store(dir.path(), &key(), &[1_u8; 16]);
        assert_eq!(
            store.load(&key(), &[1_u8; 16]).expect("lecture"),
            SentinelLoad::Absent
        );
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [7_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        let written = sentinel(vault_id, 1234);

        store.store(&key(), &written).expect("écriture");
        let loaded = store.load(&key(), &vault_id).expect("lecture");

        assert_eq!(loaded, SentinelLoad::Found(written));
    }

    #[test]
    fn sentinel_file_name_does_not_reveal_the_vault() {
        // Un attaquant lisant le répertoire de configuration ne doit rien apprendre :
        // ni le chemin du coffre, ni son identifiant.
        //
        // Note de rédaction : une première version de ce test assertait que le nom
        // ne contenait pas la sous-chaîne « ab », tirée de l'identifiant `[0xAB; 16]`.
        // C'était une assertion fausse : le nom est un condensé **hexadécimal**, donc
        // il contient n'importe quelle paire de caractères hexadécimaux avec une
        // probabilité non nulle, et « ab » est apparu par hasard. Le test échouait
        // alors que le comportement était correct.
        //
        // La propriété réelle à vérifier n'est pas une histoire de sous-chaîne, mais
        // que le nom soit **dérivé** de l'identifiant et non une simple
        // transformation réversible de celui-ci.
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [0xAB_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        let name = store
            .path()
            .file_name()
            .expect("nom")
            .to_string_lossy()
            .to_string();

        // Le nom ne doit pas être l'identifiant sous forme hexadécimale.
        let hex_of_id: String = vault_id.iter().fold(String::new(), |mut acc, byte| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!("{byte:02x}"));
            acc
        });
        assert!(
            !name.contains(&hex_of_id),
            "le nom de la sentinelle contient l'identifiant du coffre en clair : {name}"
        );

        // Le nom ne doit rien contenir du chemin du coffre.
        assert!(!name.contains("coffre"), "{name}");
        assert!(!name.contains('/'), "{name}");
        assert_eq!(
            Path::new(&name)
                .extension()
                .and_then(std::ffi::OsStr::to_str),
            Some("sent"),
            "extension inattendue : {name}"
        );

        // Et il doit être de la forme attendue : un condensé hexadécimal.
        let stem = name.trim_end_matches(".sent");
        assert_eq!(stem.len(), 32, "longueur de condensé inattendue : {name}");
        assert!(
            stem.chars().all(|c| c.is_ascii_hexdigit()),
            "le nom n'est pas un condensé hexadécimal : {name}"
        );
    }

    #[test]
    fn sentinel_name_is_stable_for_a_given_vault_and_key() {
        let dir = tempfile::tempdir().expect("répertoire");
        let first = store(dir.path(), &key(), &[3_u8; 16]);
        let second = store(dir.path(), &key(), &[3_u8; 16]);
        assert_eq!(first.path(), second.path());
    }

    #[test]
    fn sentinel_name_differs_between_vaults() {
        let dir = tempfile::tempdir().expect("répertoire");
        let first = store(dir.path(), &key(), &[3_u8; 16]);
        let second = store(dir.path(), &key(), &[4_u8; 16]);
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn sentinel_name_differs_for_a_different_key() {
        // Deux coffres distincts ne peuvent pas se marcher dessus, même si leurs
        // identifiants se ressemblent.
        let dir = tempfile::tempdir().expect("répertoire");
        let first = store(dir.path(), &key(), &[3_u8; 16]);
        let other_key = Key::from_array([0x22; KEY_LEN]);
        let second = store(dir.path(), &other_key, &[3_u8; 16]);
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn storing_downgrades_are_detected() {
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [5_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);

        store
            .store(&key(), &sentinel(vault_id, 100))
            .expect("écriture");

        assert_eq!(
            store.check(&key(), &vault_id, 101).expect("contrôle"),
            RollbackCheck::Consistent
        );
        assert_eq!(
            store.check(&key(), &vault_id, 100).expect("contrôle"),
            RollbackCheck::Consistent
        );
        assert_eq!(
            store.check(&key(), &vault_id, 99).expect("contrôle"),
            RollbackCheck::Rollback {
                known: 100,
                found: 99
            }
        );
    }

    #[test]
    fn missing_sentinel_makes_detection_inactive() {
        let dir = tempfile::tempdir().expect("répertoire");
        let store = store(dir.path(), &key(), &[5_u8; 16]);
        assert_eq!(
            store.check(&key(), &[5_u8; 16], 10).expect("contrôle"),
            RollbackCheck::NoSentinel
        );
    }

    #[test]
    fn tampered_generation_is_detected() {
        // L'attaque à contrer : un attaquant réécrit la génération pour masquer un
        // rollback. Sans la clé, il ne peut pas recalculer le tag.
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [6_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        store
            .store(&key(), &sentinel(vault_id, 500))
            .expect("écriture");

        let mut bytes = std::fs::read(store.path()).expect("lecture");
        bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
        std::fs::write(store.path(), &bytes).expect("écriture");

        assert!(matches!(
            store.load(&key(), &vault_id).expect("lecture"),
            SentinelLoad::Corrupted { .. }
        ));
        // Et un coffre reculé ne doit pas être déclaré cohérent.
        assert_eq!(
            store.check(&key(), &vault_id, 1).expect("contrôle"),
            RollbackCheck::NoSentinel
        );
    }

    #[test]
    fn every_byte_flip_in_the_sentinel_is_detected() {
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [6_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        store
            .store(&key(), &sentinel(vault_id, 500))
            .expect("écriture");
        let original = std::fs::read(store.path()).expect("lecture");

        for index in 0..original.len() {
            let mut bytes = original.clone();
            bytes[index] ^= 0x01;
            std::fs::write(store.path(), &bytes).expect("écriture");

            assert!(
                matches!(
                    store.load(&key(), &vault_id).expect("lecture"),
                    SentinelLoad::Corrupted { .. }
                ),
                "un octet modifié à l'offset {index} n'a pas invalidé la sentinelle"
            );
        }
    }

    #[test]
    fn truncated_sentinel_is_reported_as_corrupted() {
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [6_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        store
            .store(&key(), &sentinel(vault_id, 500))
            .expect("écriture");

        let bytes = std::fs::read(store.path()).expect("lecture");
        for len in 0..bytes.len() {
            std::fs::write(store.path(), &bytes[..len]).expect("écriture");
            assert!(matches!(
                store.load(&key(), &vault_id).expect("lecture"),
                SentinelLoad::Corrupted { .. }
            ));
        }
    }

    #[test]
    fn sentinel_from_another_key_is_rejected() {
        let dir = tempfile::tempdir().expect("répertoire");
        let vault_id = [8_u8; 16];
        let store = store(dir.path(), &key(), &vault_id);
        store
            .store(&key(), &sentinel(vault_id, 10))
            .expect("écriture");

        // Même emplacement, clé différente : le tag ne correspond plus.
        let other_key = Key::from_array([0x23; KEY_LEN]);
        assert!(matches!(
            store.load(&other_key, &vault_id).expect("lecture"),
            SentinelLoad::Corrupted { .. }
        ));
    }

    #[test]
    fn now_unix_is_plausible() {
        // 2020-01-01, borne basse large : le but est de détecter une horloge
        // manifestement cassée, pas de valider la date.
        assert!(now_unix() > 1_577_836_800);
    }
}
