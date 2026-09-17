//! Orchestration du coffre : création, ouverture, verrouillage, enregistrement.
//!
//! # Enchaînement d'une ouverture
//!
//! ```text
//!   1. lire le fichier
//!   2. analyser la structure (sans clé)          → header, paramètres, slots
//!   3. sélectionner le slot du mot de passe maître
//!   4. Argon2id(mot de passe, sel du slot, params du slot) → MK
//!   5. HKDF(MK) → KEK
//!   6. désenvelopper le slot → DEK                (échec ⇒ « mot de passe
//!                                                  incorrect ou coffre corrompu »)
//!   7. HKDF(DEK) → sous-clés
//!   8. déchiffrer le payload avec K_records       (échec ⇒ « coffre corrompu »)
//!   9. décoder l'enveloppe → génération + corps
//!  10. comparer la génération à la sentinelle     → alerte de rollback éventuelle
//! ```
//!
//! ## Ce que laisser vivre ce coffre en mémoire implique
//!
//! Tant que l'objet `Vault` existe, la DEK et les sous-clés sont en mémoire, et le
//! corps du coffre est déchiffré. C'est inévitable pour toute architecture où l'on
//! affiche une entrée — il faut bien la déchiffrer. La seule vraie réduction serait
//! de ne déchiffrer qu'une entrée à la fois, au prix d'une clé par entrée et d'une
//! comptabilité de nonces nettement plus délicate, et sans changer le fond : le
//! coffre reste utilisable par un attaquant qui contrôle le processus.
//!
//! La durée de vie est donc le levier réel : [`Vault::lock`] détruit les clés, et
//! un coffre rouvert coûte une dérivation Argon2id complète.
//!
//! # Verrouillage de fichier
//!
//! Une ouverture en lecture-écriture prend un verrou exclusif. Deux instances qui
//! écriraient le même coffre feraient perdre le travail de l'une des deux, sans
//! qu'aucune ne s'en aperçoive : c'est exactement le genre de perte de données
//! silencieuse qu'un gestionnaire de secrets ne peut pas se permettre.
//!
//! Une ouverture en lecture seule ne prend **pas** de verrou : l'écriture étant
//! atomique, un lecteur voit toujours un fichier complet, soit l'ancien, soit le
//! nouveau. Autoriser la lecture pendant une écriture est donc sûr et utile.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::container::{self, MAX_VAULT_BYTES, ParsedVault};
use crate::error::{Error, Result};
use crate::header::{Header, Slot, SlotLabel, VAULT_ID_LEN};
use crate::kdf::{self, KdfParams};
use crate::keys::{DataEncryptionKey, KEY_LEN, KeyEncryptionKey, MasterKey, SubKeys, WrappedKey};
use crate::payload::Payload;
use crate::recovery::RecoveryKey;
use crate::rollback::{RollbackCheck, Sentinel, SentinelLoad, SentinelStore, now_unix};

use passlock_platform::fs::{FileLock, app_state_dir, verify_private, write_atomic};

/// Paramètres d'ouverture ou de création.
///
/// Le `Default` dérive de [`KdfParams::default`], qui retourne le profil **durci**
/// et non le plus léger : un défaut doit être le choix sûr, jamais
/// l'affaiblissement maximal obtenu par distraction.
#[derive(Debug, Clone, Default)]
pub struct VaultConfig {
    /// Paramètres de dérivation à utiliser **à la création**.
    ///
    /// À l'ouverture, ce champ est ignoré : les paramètres sont lus dans le fichier,
    /// et jamais pris dans une constante du code. C'est ce qui permet de durcir les
    /// valeurs par défaut sans rendre illisibles les coffres existants.
    pub params: KdfParams,
    /// Ouvrir sans permettre aucune écriture.
    pub read_only: bool,
    /// Répertoire d'état pour la sentinelle.
    ///
    /// `None` demande le répertoire de configuration de l'utilisateur. Un
    /// emplacement explicite est utile aux tests et aux usages avancés (coffre sur
    /// support amovible, sentinelle volontairement placée sur un autre volume).
    pub state_dir: Option<PathBuf>,
}

/// Observations faites à l'ouverture, à communiquer à l'utilisateur.
///
/// Quatre booléens indépendants : ce sont quatre conditions observables
/// distinctes, dont une seule, plusieurs ou aucune peuvent être vraies
/// simultanément. Les remplacer par une énumération obligerait à énumérer les
/// seize combinaisons pour n'en exploiter aucune.
#[allow(clippy::struct_excessive_bools)]
///
/// Ce type existe pour que l'appelant ne puisse pas **oublier** une dégradation :
/// les champs sont là, nommés, et l'interface a la matière pour avertir.
#[derive(Debug, Clone)]
pub struct Diagnostics {
    /// Les permissions étaient trop ouvertes et ont été corrigées.
    pub permissions_corrected: bool,
    /// Les paramètres de dérivation sont plus faibles que le profil par défaut.
    pub params_below_recommendation: bool,
    /// Résultat de la comparaison avec la sentinelle anti-rollback.
    pub rollback: RollbackCheck,
    /// Une sentinelle existait mais était inutilisable.
    pub sentinel_corrupted: bool,
    /// La sentinelle n'a pas pu être enregistrée lors de la dernière écriture.
    pub sentinel_write_failed: bool,
    /// Version de schéma d'origine, si une migration a eu lieu à l'ouverture.
    ///
    /// Renseigné pour qu'une migration ne soit **jamais silencieuse** : elle
    /// modifie la forme des données de l'utilisateur, et cela doit être dit.
    pub migrated_from: Option<u16>,
}

impl Diagnostics {
    /// Vrai si au moins un point mérite d'être porté à la connaissance de
    /// l'utilisateur.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.permissions_corrected
            || self.params_below_recommendation
            || self.sentinel_corrupted
            || self.sentinel_write_failed
            || self.migrated_from.is_some()
            || matches!(
                self.rollback,
                RollbackCheck::Rollback { .. } | RollbackCheck::NoSentinel
            )
    }
}

/// Composants obtenus après déverrouillage.
///
/// Regroupe ce qui est nécessaire pour exploiter un coffre une fois la clé
/// obtenue, avant toute considération de verrou de fichier ou de permissions.
#[derive(Debug)]
pub struct Unlocked {
    /// Header du coffre, tel que lu dans le fichier.
    pub header: Header,
    /// Clé de données, conservée pour permettre les opérations de maintenance.
    pub dek: DataEncryptionKey,
    /// Sous-clés d'usage dérivées de la DEK.
    pub subkeys: SubKeys,
    /// Contenu déchiffré et décodé.
    pub payload: Payload,
}

/// Matériel d'ouverture présenté à un coffre, et le rôle qu'il vise.
///
/// # Pourquoi un type, et pas trois fonctions
///
/// Les trois mécanismes d'ouverture — mot de passe maître, clé de récupération,
/// fichier-clé — produisent une KEK **par le même chemin** : Argon2id sur le secret
/// du slot, puis HKDF. Seuls le rôle visé et le matériel changent. Les nommer par un
/// type rend explicite qu'il n'existe qu'**un seul chemin de code**, et que le rôle
/// détermine quel slot est désenveloppé.
///
/// # Emprunts, et non copies
///
/// Les variantes empruntent le matériel : présenter une clé ne doit pas en produire
/// une seconde copie en mémoire.
pub enum Credentials<'a> {
    /// Mot de passe maître — slot [`SlotLabel::Master`].
    Password(&'a [u8]),
    /// Clé de récupération transcrite — slot [`SlotLabel::Recovery`].
    RecoveryKey(&'a RecoveryKey),
    /// Contenu d'un fichier-clé — slot [`SlotLabel::Hardware`].
    KeyFile(&'a [u8]),
}

impl Credentials<'_> {
    /// Rôle de slot visé.
    #[must_use]
    pub const fn label(&self) -> SlotLabel {
        match self {
            Self::Password(_) => SlotLabel::Master,
            Self::RecoveryKey(_) => SlotLabel::Recovery,
            Self::KeyFile(_) => SlotLabel::Hardware,
        }
    }

    /// Secret présenté à la dérivation.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        match self {
            Self::Password(bytes) | Self::KeyFile(bytes) => bytes,
            Self::RecoveryKey(key) => key.expose(),
        }
    }
}

// `Debug` est écrit à la main, et non dérivé : `&[u8]` afficherait **le mot de passe
// en clair**. Les types de secret du projet rédigent leur propre `Debug` ; en dériver
// un ici l'aurait contourné par la bande.
impl std::fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Password(_) => "Password",
            Self::RecoveryKey(_) => "RecoveryKey",
            Self::KeyFile(_) => "KeyFile",
        };
        write!(f, "Credentials::{name}([EXPURGÉ])")
    }
}

/// Rend le slot du rôle demandé.
///
/// # Erreurs
/// [`Error::InvalidHeader`] si le coffre ne porte aucun slot de ce rôle.
fn slot_with_label(header: &Header, label: SlotLabel) -> Result<&Slot> {
    header
        .slots
        .iter()
        .find(|slot| slot.label == label)
        .ok_or(Error::InvalidHeader {
            reason: missing_slot_reason(label),
        })
}

/// Motif d'absence, propre au rôle.
const fn missing_slot_reason(label: SlotLabel) -> &'static str {
    match label {
        SlotLabel::Master => "ce coffre ne contient aucun slot de mot de passe maître",
        SlotLabel::Recovery => "ce coffre ne contient aucun slot de clé de récupération",
        SlotLabel::Hardware => "ce coffre ne contient aucun slot de clé matérielle",
    }
}

/// Dérive la clé de chiffrement de clé du slot d'un rôle donné.
///
/// ## Un seul chemin de dérivation, quel que soit le rôle
///
/// Les trois rôles passent par **Argon2id puis HKDF**, sans branche : c'est délibéré.
///
/// * Le champ `params` d'un slot est **authentifié** (il entre dans l'AAD du slot),
///   affiché par `passlock info` **sans déverrouillage**, et sert à calculer
///   l'avertissement « paramètres sous la recommandation ». Un slot qui déclarerait
///   Argon2id 256 Mio sans qu'il soit appliqué porterait donc un octet authentifié
///   décrivant une dérivation qui n'a pas eu lieu.
/// * Le rôle ne doit pas décider du chemin : une clé de 256 bits n'a pas besoin
///   d'étirement, mais **rien ne garantit** qu'un matériel de clé futur ait cette
///   entropie (fichier tronqué, comblé, clé fournie par l'utilisateur). Argon2id y
///   est un filet, pas un rituel.
/// * Le coût — une fois par déverrouillage, sur une action humaine rare — reste sous
///   le limiteur de concurrence en processus.
///
/// Ce qui n'est **pas** affirmé : qu'Argon2id renforce une clé de 256 bits contre la
/// force brute. Il ne l'renforce pas, et cette fonction ne le prétend pas.
///
/// # Erreurs
/// * [`Error::InvalidHeader`] si le coffre ne porte aucun slot de ce rôle ;
/// * les erreurs de dérivation (paramètres refusés, mémoire insuffisante).
pub fn derive_slot_kek(
    header: &Header,
    label: SlotLabel,
    secret: &[u8],
) -> Result<KeyEncryptionKey> {
    let slot = slot_with_label(header, label)?;
    let master_key = MasterKey::derive(secret, &slot.salt, slot.params)?;
    master_key.derive_kek()
}

/// Déverrouille un coffre à partir de son contenu et d'une KEK déjà obtenue.
///
/// ## Où se situe la seule comparaison qui décide de l'ouverture
///
/// [`KeyEncryptionKey::unwrap`] est le seul endroit où le matériel fourni est
/// confronté au coffre. Son échec devient « mot de passe incorrect ou coffre
/// corrompu », sans distinction : voir `error.rs` sur l'absence d'oracle.
///
/// ## Nuance sur les erreurs en aval
///
/// Une fois le slot ouvert, l'échec du déchiffrement du payload devient
/// [`Error::Corrupted`] et non `UnlockFailed`. C'est légitime : pour atteindre ce
/// point il faut déjà avoir présenté la bonne clé, donc l'information ne donne
/// rien à un attaquant. En revanche, cela signifie qu'un octet altéré dans la
/// **charge utile** est rapporté différemment d'un octet altéré dans le **slot** —
/// distinction volontaire et testée.
///
/// # Erreurs
/// [`Error::UnlockFailed`] si le slot ne s'ouvre pas, [`Error::Corrupted`] si le
/// contenu est altéré, ainsi que les erreurs de format en amont.
pub fn unlock_with_kek(bytes: &[u8], kek: &KeyEncryptionKey, label: SlotLabel) -> Result<Unlocked> {
    let parsed = ParsedVault::parse(bytes)?;

    let slot = slot_with_label(&parsed.header, label)?;

    let dek = kek.unwrap(&slot.wrapped, &slot.aad(&parsed.header.vault_id))?;

    let subkeys = dek.subkeys()?;
    // Le buffer déchiffré est **pris** et non emprunté : `decode_owned` transfère le
    // corps sans le recopier. Une version antérieure faisait
    // `Payload::decode(&plaintext)`, ce qui produisait une seconde copie intégrale du
    // coffre en clair — et seule la première était effacée.
    let payload = Payload::decode_owned(parsed.decrypt(&subkeys.records)?)?;

    Ok(Unlocked {
        header: parsed.header,
        dek,
        subkeys,
        payload,
    })
}

/// Dérive la KEK du rôle visé **et** ouvre le coffre avec elle.
///
/// Raccourci de composition, pour les appelants qui n'ont pas besoin de séparer les
/// deux étapes : dérivation puis désenveloppement, exactement comme
/// [`Vault::open_with`].
///
/// L'analyse du fichier est faite **deux fois**, comme dans `Vault::open_with` : elle
/// est bon marché (aucun calcul cryptographique) et évite de faire circuler une vue
/// empruntée à travers toute la fonction.
///
/// # Erreurs
/// Voir [`derive_slot_kek`] et [`unlock_with_kek`].
pub fn unlock_with_slot_label(bytes: &[u8], label: SlotLabel, secret: &[u8]) -> Result<Unlocked> {
    let kek = {
        let header = ParsedVault::parse(bytes)?.header;
        derive_slot_kek(&header, label, secret)?
    };
    unlock_with_kek(bytes, &kek, label)
}

/// Lit un fichier de coffre en bornant la quantité lue.
///
/// # Pourquoi ce n'est pas un simple `std::fs::read`
///
/// `ParsedVault::parse` refuse un fichier dépassant [`MAX_VAULT_BYTES`], mais ce
/// contrôle intervient **après** la lecture : un fichier de plusieurs gigaoctets
/// était donc entièrement chargé en mémoire avant d'être rejeté. Un attaquant
/// pouvant déposer un fichier volumineux à l'emplacement du coffre disposait ainsi
/// d'un déni de service par épuisement mémoire.
///
/// La lecture est ici bornée par `Take`, ce qui plafonne l'allocation réelle. Le
/// contrôle dans `parse` est conservé : il protège les appelants qui l'utilisent
/// directement, sans passer par cette fonction.
///
/// # Erreurs
/// [`Error::MalformedLength`] si le fichier dépasse [`MAX_VAULT_BYTES`].
fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)?;

    // La capacité initiale est bornée par la taille annoncée : réserver
    // `MAX_VAULT_BYTES` d'emblée pour un fichier de quelques kilo-octets serait un
    // gaspillage, et ne pas borner du tout exposerait à une taille annoncée
    // mensongèrement grande.
    let announced = file.metadata().map_or(0, |meta| meta.len());
    let hint = usize::try_from(announced)
        .unwrap_or(MAX_VAULT_BYTES)
        .min(MAX_VAULT_BYTES);

    let mut bytes = Vec::with_capacity(hint);
    file.take(u64::try_from(MAX_VAULT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;

    if bytes.len() > MAX_VAULT_BYTES {
        return Err(Error::MalformedLength {
            reason: "fichier de coffre au-delà de la taille maximale admise",
        });
    }

    Ok(bytes)
}

/// Un coffre ouvert.
pub struct Vault {
    path: PathBuf,
    header: Header,
    /// DEK conservée pour permettre un changement de mot de passe ou l'ajout d'un
    /// slot sans nouvelle dérivation. Elle est détruite par [`Vault::lock`].
    dek: DataEncryptionKey,
    subkeys: SubKeys,
    payload: Payload,
    state_dir: Option<PathBuf>,
    read_only: bool,
    lock: Option<FileLock>,
    diagnostics: Diagnostics,
}

impl Vault {
    /// Crée un coffre neuf sur le disque.
    ///
    /// Le fichier doit ne pas exister : écraser un coffre existant détruirait des
    /// données sans que l'utilisateur l'ait demandé. Une restauration de sauvegarde
    /// passe par une suppression explicite.
    ///
    /// # Erreurs
    /// [`Error::Io`] avec `AlreadyExists` si la cible existe déjà.
    pub fn create(path: &Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
        // ORDRE CRITIQUE : le verrou est pris **avant** le contrôle d'existence.
        //
        // NOTE DE CORRECTION. Une version antérieure testait `path.exists()` puis
        // acquérait le verrou. Deux exécutions concurrentes pouvaient alors franchir
        // le contrôle toutes les deux, se sérialiser sur le verrou, et la seconde
        // écrasait silencieusement le coffre que la première venait de créer. C'est
        // exactement le TOCTOU que le verrou était censé fermer : il était pris trop
        // tard pour servir à quoi que ce soit.
        let try_lock = FileLock::acquire(path).map_err(Error::Io)?;

        if path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "un fichier existe déjà à l'emplacement {} : la création est refusée \
                     pour ne pas écraser un coffre existant",
                    path.display()
                ),
            )));
        }

        let dek = DataEncryptionKey::generate()?;
        let vault_id = crate::rng::array::<VAULT_ID_LEN>()?;
        let salt = kdf::generate_salt()?;

        let master_key = MasterKey::derive(password, &salt, config.params)?;
        let kek = master_key.derive_kek()?;

        // Le slot est construit en deux temps car son authentification couvre ses
        // propres métadonnées, mais pas la clé enveloppée, qui porte son propre tag.
        let mut slot = Slot {
            id: 0,
            label: SlotLabel::Master,
            params: config.params,
            salt,
            wrapped: WrappedKey::placeholder(),
        };
        let slot_aad = slot.aad(&vault_id);
        slot.wrapped = kek.wrap(&dek, &slot_aad)?;

        let header = Header::from_parts(vault_id, now_unix(), vec![slot])?;
        let subkeys = dek.subkeys()?;

        // La clé maître et la KEK ne servent plus : elles sont détruites ici, et
        // seul ce qui a été explicitement construit ci-dessus subsiste.
        drop(kek);
        drop(master_key);

        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            dek,
            subkeys,
            payload: Payload::initial(),
            state_dir: config.state_dir.clone(),
            read_only: config.read_only,
            lock: Some(try_lock),
            diagnostics: Diagnostics {
                permissions_corrected: false,
                params_below_recommendation: false,
                rollback: RollbackCheck::NoSentinel,
                sentinel_corrupted: false,
                sentinel_write_failed: false,
                migrated_from: None,
            },
        };

        vault.write_to_disk()?;

        // La sentinelle vient d'être écrite : la référence existe désormais. Sans
        // cette mise à jour, le diagnostic afficherait « aucune sentinelle » sur un
        // coffre qui en possède une depuis quelques microsecondes — une information
        // fausse, alors que ce champ n'existe que pour être exact.
        if !vault.diagnostics.sentinel_write_failed {
            vault.diagnostics.rollback = RollbackCheck::Consistent;
        }

        Ok(vault)
    }

    /// Ouvre un coffre existant avec son mot de passe maître.
    ///
    /// Raccourci du cas le plus courant : délègue à [`Vault::open_with`] avec
    /// [`Credentials::Password`]. Les clés de récupération et les fichiers-clés
    /// passent par `open_with` directement.
    ///
    /// # Erreurs
    /// Voir [`Vault::open_with`].
    pub fn open(path: &Path, password: &[u8], config: &VaultConfig) -> Result<Self> {
        Self::open_with(path, &Credentials::Password(password), config)
    }

    /// Ouvre un coffre existant avec un matériel d'ouverture quelconque.
    ///
    /// # Rôle du matériel
    ///
    /// `credentials` détermine **quel slot** est désenveloppé et **quel secret** est
    /// présenté à la dérivation. Le reste du chemin d'ouverture est identique pour
    /// les trois mécanismes : c'est la propriété qui garantit qu'aucun d'eux ne peut
    /// être plus faible qu'un autre par inadvertance.
    ///
    /// # Conséquence sur l'alerte de retour en arrière
    ///
    /// Un coffre ouvert par une clé de récupération produit exactement les mêmes
    /// diagnostics qu'un coffre ouvert par mot de passe : la comparaison à la
    /// sentinelle porte sur la **génération**, pas sur le mode d'ouverture.
    ///
    /// # Erreurs
    /// * [`Error::UnlockFailed`] si le secret est incorrect ou le slot altéré ;
    /// * [`Error::NotAVault`] si le fichier n'est pas un coffre ;
    /// * [`Error::Corrupted`] si la structure est authentique mais le contenu altéré ;
    /// * [`Error::AlreadyLocked`] si un autre processus détient le verrou d'écriture ;
    /// * [`Error::InvalidHeader`] si le coffre ne porte aucun slot du rôle demandé.
    pub fn open_with(
        path: &Path,
        credentials: &Credentials<'_>,
        config: &VaultConfig,
    ) -> Result<Self> {
        let file_lock = if config.read_only {
            None
        } else {
            Some(FileLock::acquire(path).map_err(|err| {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    Error::AlreadyLocked
                } else {
                    Error::Io(err)
                }
            })?)
        };

        let bytes = read_vault_file(path)?;

        let label = credentials.label();

        // Le header est lu une première fois pour connaître le sel et les
        // paramètres du slot visé : ils sont stockés dans le fichier, jamais pris
        // dans une constante du code. L'analyse est bon marché (aucun calcul
        // cryptographique) et sera refaite par `unlock_with_kek`, ce qui évite de
        // faire circuler une vue empruntée à travers toute la fonction.
        let kek = {
            let parsed = ParsedVault::parse(&bytes)?;
            derive_slot_kek(&parsed.header, label, credentials.secret())?
        };

        let unlocked = unlock_with_kek(&bytes, &kek, label)?;

        // Le fichier n'est plus utile : le contenu est déchiffré.
        drop(bytes);
        drop(kek);

        let Unlocked {
            header,
            dek,
            subkeys,
            payload,
        } = unlocked;

        let mut diagnostics = Diagnostics {
            permissions_corrected: false,
            params_below_recommendation: header
                .master_slot()
                .is_some_and(|slot| slot.params.is_below_recommendation()),
            rollback: RollbackCheck::NoSentinel,
            sentinel_corrupted: false,
            sentinel_write_failed: false,
            migrated_from: None,
        };

        // Les permissions ne sont corrigées que si l'on a le droit d'écrire, pour ne
        // pas échouer sur un support monté en lecture seule.
        if !config.read_only {
            diagnostics.permissions_corrected = verify_private(path)?;
        }

        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            dek,
            subkeys,
            payload,
            state_dir: config.state_dir.clone(),
            read_only: config.read_only,
            lock: file_lock,
            diagnostics,
        };

        vault.refresh_rollback_state()?;
        Ok(vault)
    }

    /// Enregistre l'état courant sur le disque.
    ///
    /// La génération est incrémentée **avant** l'écriture : une écriture qui
    /// échoue ne doit pas laisser croire à un enregistrement. Comme l'écriture est
    /// atomique, soit l'ancien fichier reste en place avec son ancienne génération,
    /// soit le nouveau est complet avec la nouvelle.
    ///
    /// # Erreurs
    /// [`Error::ReadOnly`] si le coffre a été ouvert en lecture seule.
    pub fn save(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.write_to_disk()
    }

    /// Change le mot de passe maître, en conservant la DEK.
    ///
    /// ## Effet sur les autres slots
    ///
    /// Les slots de récupération et matériels sont **conservés tels quels**. Ils
    /// enveloppent la même DEK : leur validité ne dépend pas du mot de passe maître.
    /// C'est la propriété qui rend l'opération sûre — aucun autre accès au coffre
    /// n'est perdu.
    ///
    /// ## Vérification avant écriture
    ///
    /// Le mot de passe actuel est exigé et vérifié, puis la DEK récupérée est
    /// comparée à celle de la session. Si les deux diffèrent, l'opération est
    /// abandonnée sans rien écrire : mieux vaut un échec bruyant qu'un coffre
    /// ré-enveloppé autour d'une clé différente, qui serait définitivement
    /// illisible.
    ///
    /// # Erreurs
    /// [`Error::UnlockFailed`] si le mot de passe actuel est incorrect,
    /// [`Error::ReadOnly`], ou toute erreur d'écriture.
    pub fn change_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
        new_params: KdfParams,
    ) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }

        let master_index = self
            .header
            .slots
            .iter()
            .position(|slot| slot.label == SlotLabel::Master)
            .ok_or(Error::InvalidHeader {
                reason: "ce coffre ne contient aucun slot de mot de passe maître",
            })?;

        // 1. Vérifier le mot de passe actuel en retrouvant la DEK.
        let current_slot = &self.header.slots[master_index];
        let master_key =
            MasterKey::derive(current_password, &current_slot.salt, current_slot.params)?;
        let kek = master_key.derive_kek()?;
        let recovered = kek.unwrap(
            &current_slot.wrapped,
            &current_slot.aad(&self.header.vault_id),
        )?;

        // 2. Confirmer que la DEK retrouvée est bien celle de la session.
        if !recovered.constant_time_eq(&self.dek) {
            return Err(Error::Internal {
                invariant: "la clé récupérée par le slot maître ne correspond pas à la \
                            clé de session",
            });
        }

        // 3. Ré-envelopper la DEK sous le nouveau mot de passe, avec un sel neuf.
        let salt = kdf::generate_salt()?;
        let new_master_key = MasterKey::derive(new_password, &salt, new_params)?;
        let new_kek: KeyEncryptionKey = new_master_key.derive_kek()?;

        let mut new_slot = Slot {
            id: current_slot.id,
            label: SlotLabel::Master,
            params: new_params,
            salt,
            wrapped: WrappedKey::placeholder(),
        };
        // L'identifiant du coffre est inchangé : la sentinelle anti-rollback reste
        // valide après l'opération.
        let slot_aad = new_slot.aad(&self.header.vault_id);
        new_slot.wrapped = new_kek.wrap(&self.dek, &slot_aad)?;

        self.header.slots[master_index] = new_slot;
        self.diagnostics.params_below_recommendation = new_params.is_below_recommendation();

        drop(new_kek);
        drop(new_master_key);
        drop(kek);
        drop(master_key);

        self.write_to_disk()
    }

    // -----------------------------------------------------------------------
    // Slots supplémentaires : clé de récupération, clé matérielle
    // -----------------------------------------------------------------------

    /// Rôles des slots présents, dans l'ordre du header.
    #[must_use]
    pub fn slot_labels(&self) -> Vec<SlotLabel> {
        self.header.slots.iter().map(|slot| slot.label).collect()
    }

    /// Installe un slot supplémentaire, en enveloppant la DEK courante.
    ///
    /// ## Le coût réel, dit sans l'embellir
    ///
    /// Ajouter un slot **n'est pas O(1)** sur le fichier de coffre. Le header entier
    /// entre dans l'AAD du payload (`container::seal`) : le prochain enregistrement
    /// **ré-écrit tout le payload**, parce que son tag doit couvrir le nouveau header.
    /// C'est le prix assumé d'`ADR-005`, proportionnel à la taille du payload — pas à
    /// celle des pièces jointes, qui vivent hors du conteneur et ne sont pas touchées.
    ///
    /// Ce que l'opération a bien d'instantané : aucun rechiffrement du contenu sous une
    /// nouvelle clé, aucune nouvelle dérivation de la DEK, et les autres slots restent
    /// valides tels quels.
    ///
    /// ## Aucune écriture ici
    ///
    /// Cette méthode modifie l'état en mémoire. L'appelant doit faire suivre d'un
    /// [`Vault::save`] ; une mutation non enregistrée est perdue, c'est le contrat du
    /// magasin.
    ///
    /// # Refus
    /// * [`Error::ReadOnly`] sur un coffre ouvert en lecture seule ;
    /// * [`Error::InvalidInput`] pour le rôle maître — il s'installe par
    ///   [`Vault::change_password`], qui exige le mot de passe actuel. Autoriser
    ///   `install_slot(Master, …)` contournerait cette ré-authentification ;
    /// * [`Error::InvalidInput`] si un slot de ce rôle existe déjà : remplacer est un
    ///   acte distinct, et se tromper de méthode ne doit pas écraser silencieusement une
    ///   clé de récupération déjà rangée.
    pub fn install_slot(
        &mut self,
        label: SlotLabel,
        secret: &[u8],
        params: KdfParams,
    ) -> Result<()> {
        self.refuse_non_master_role(label)?;

        if self.header.slots.iter().any(|slot| slot.label == label) {
            return Err(Error::InvalidInput {
                reason: "un slot de ce rôle est déjà installé ; utilisez `replace_slot`",
            });
        }

        let id = self.allocate_slot_id()?;
        let slot = self.build_slot(label, secret, params, id)?;

        let mut candidate = self.header.slots.clone();
        candidate.push(slot);
        self.apply_candidate_slots(candidate)
    }

    /// Remplace le slot d'un rôle, en conservant son identifiant.
    ///
    /// L'identifiant est conservé parce qu'il entre dans l'AAD du slot : le réutiliser
    /// n'affaiblit rien (le sel et la clé enveloppée changent) et évite de faire
    /// diverger la numérotation des slots à chaque rotation.
    ///
    /// Le coût et le contrat d'écriture sont ceux d'[`Vault::install_slot`].
    ///
    /// # Refus
    /// Les mêmes, plus [`Error::InvalidHeader`] si aucun slot de ce rôle n'existe.
    pub fn replace_slot(
        &mut self,
        label: SlotLabel,
        secret: &[u8],
        params: KdfParams,
    ) -> Result<()> {
        self.refuse_non_master_role(label)?;

        let index = self
            .header
            .slots
            .iter()
            .position(|slot| slot.label == label)
            .ok_or(Error::InvalidHeader {
                reason: missing_slot_reason(label),
            })?;
        let id = self.header.slots[index].id;
        let slot = self.build_slot(label, secret, params, id)?;

        let mut candidate = self.header.slots.clone();
        candidate[index] = slot;
        self.apply_candidate_slots(candidate)
    }

    /// Révoque le slot d'un rôle.
    ///
    /// ## Ce que la révocation ne fait pas
    ///
    /// Elle ne rend pas inutilisable une clé déjà recopiée ailleurs : si la clé de
    /// récupération a été photographiée, la révocation retire le slot du coffre mais ne
    /// reprend pas la copie. Il faut **considérer la clé comme compromise**.
    ///
    /// Elle ne ré-écrit pas non plus les sauvegardes antérieures, qui contiennent
    /// toujours le slot.
    ///
    /// Le coût et le contrat d'écriture sont ceux d'[`Vault::install_slot`].
    ///
    /// # Refus
    /// * [`Error::ReadOnly`], [`Error::InvalidHeader`] si le rôle est absent ;
    /// * [`Error::InvalidInput`] s'il s'agit du **dernier** slot, ou du dernier slot
    ///   maître : dans les deux cas le coffre deviendrait inouvrable par le chemin
    ///   restant.
    pub fn revoke_slot(&mut self, label: SlotLabel) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }

        let index = self
            .header
            .slots
            .iter()
            .position(|slot| slot.label == label)
            .ok_or(Error::InvalidHeader {
                reason: missing_slot_reason(label),
            })?;

        if self.header.slots.len() == 1 {
            return Err(Error::InvalidInput {
                reason: "impossible de révoquer le dernier slot : le coffre deviendrait \
                         définitivement inouvrable",
            });
        }
        if label == SlotLabel::Master
            && self
                .header
                .slots
                .iter()
                .filter(|slot| slot.label == SlotLabel::Master)
                .count()
                == 1
        {
            return Err(Error::InvalidInput {
                reason: "impossible de révoquer le dernier slot maître : le coffre ne serait \
                         plus ouvrable par mot de passe",
            });
        }

        let mut candidate = self.header.slots.clone();
        candidate.remove(index);
        self.apply_candidate_slots(candidate)
    }

    /// Refuse en lecture seule et pour le rôle maître.
    ///
    /// Un seul point de refus, pour que les deux méthodes d'installation ne puissent
    /// pas diverger sur cette règle.
    fn refuse_non_master_role(&self, label: SlotLabel) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        if label == SlotLabel::Master {
            return Err(Error::InvalidInput {
                reason: "le rôle maître s'installe et se remplace par `change_password`, qui \
                         exige le mot de passe actuel",
            });
        }
        Ok(())
    }

    /// Construit un slot neuf, avec un sel neuf, en enveloppant la DEK courante.
    fn build_slot(
        &self,
        label: SlotLabel,
        secret: &[u8],
        params: KdfParams,
        id: u16,
    ) -> Result<Slot> {
        let salt = kdf::generate_salt()?;
        let master_key = MasterKey::derive(secret, &salt, params)?;
        let kek: KeyEncryptionKey = master_key.derive_kek()?;

        let mut slot = Slot {
            id,
            label,
            params,
            salt,
            wrapped: WrappedKey::placeholder(),
        };
        // Les métadonnées du slot entrent dans sa propre AAD : le rôle, le sel et les
        // paramètres sont donc authentifiés, et un slot déplacé vers un autre rôle ne
        // s'ouvre pas.
        let aad = slot.aad(&self.header.vault_id);
        slot.wrapped = kek.wrap(&self.dek, &aad)?;

        drop(kek);
        drop(master_key);
        Ok(slot)
    }

    /// Rend un identifiant de slot libre.
    fn allocate_slot_id(&self) -> Result<u16> {
        (0..=u16::MAX)
            .find(|candidate| !self.header.slots.iter().any(|slot| slot.id == *candidate))
            .ok_or(Error::InvalidInput {
                reason: "aucun identifiant de slot disponible",
            })
    }

    /// Valide une liste de slots **avant** de l'appliquer.
    ///
    /// C'est le motif « valider puis appliquer » de la phase 2 : le header candidat est
    /// construit par `Header::from_parts`, qui rejette une liste vide, un dépassement de
    /// `MAX_SLOTS` et des identifiants dupliqués. En cas d'échec, `self.header` est
    /// **inchangé**.
    fn apply_candidate_slots(&mut self, candidate: Vec<Slot>) -> Result<()> {
        let header = Header::from_parts(self.header.vault_id, self.header.created_at, candidate)?;
        self.header = header;
        Ok(())
    }

    /// Détruit les clés et le contenu déchiffré.
    ///
    /// ## Ce que cette méthode garantit, et ce qu'elle ne garantit pas
    ///
    /// Elle détruit les valeurs Rust qui détiennent le matériel de clé, et
    /// `zeroize` efface leurs buffers avant libération. Elle **ne garantit pas**
    /// que plus aucune copie n'existe en mémoire : le compilateur peut avoir
    /// conservé des valeurs dans des registres, l'allocateur peut avoir recopié des
    /// blocs, et le corps déchiffré transite par plusieurs `Vec` intermédiaires
    /// dont l'effacement n'est pas maîtrisé bout en bout.
    ///
    /// Verrouiller réduit fortement la fenêtre d'exposition ; cela ne la ferme pas.
    pub fn lock(self) {
        // Il n'y a rien à faire ici : la destruction des champs suffit, et c'est
        // précisément ce qui rend cette méthode lisible.
        //
        // * `DataEncryptionKey` et `Key` ont un `Drop` qui appelle `zeroize` ;
        // * `SubKeys` détient des `Key`, donc bénéficie du même effacement ;
        // * `Payload` a un `Drop` qui efface le corps.
        //
        // NOTE DE CORRECTION. Une version antérieure de cette méthode portait le
        // commentaire « Drop sur DataEncryptionKey, SubKeys et Payload libère et
        // efface ce qui peut l'être » — alors que `Payload` n'avait **aucun** `Drop`.
        // L'affirmation était fausse, et `self.payload.body.clear()` ne faisait que
        // rendre la mémoire au tas sans l'effacer. Un audit adversarial de la phase 1
        // a relevé cet écart entre le commentaire et le comportement ; le `Drop` de
        // `Payload` a été ajouté et ce commentaire corrigé.
    }

    /// Header courant, y compris les modifications non encore enregistrées.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Sous-clés d'usage, dont `K_records` et `K_index`.
    ///
    /// # Pourquoi cet accès est large, et pourquoi il est assumé
    ///
    /// La couche des pièces jointes a besoin de deux clés du domaine
    /// `K_attachments` — cf. [`crate::attachment`] — et de `K_index` pour le MAC de
    /// contenu. Les exposer une par une multiplierait les accesseurs pour un gain
    /// nominal : `SubKeys` **est** la surface prévue pour la manipulation des
    /// sous-clés, et elle ne quitte pas ce crate, dont l'objet est précisément la
    /// gestion du matériel de clé.
    ///
    /// Ce qui **n'est pas** exposé : la DEK elle-même, qui exigerait
    /// [`DataEncryptionKey::from_bytes`] et ne serait donc jamais obtenue par
    /// distraction. Et la racine du domaine `K_attachments` **n'existe plus** après
    /// `subkeys()` : elle est dérivée, employée, puis détruite (`I-KEYDOMAIN`).
    #[must_use]
    pub fn subkeys(&self) -> &SubKeys {
        &self.subkeys
    }

    /// Génération courante.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.payload.generation
    }

    /// Contenu applicatif déchiffré.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.payload.body
    }

    /// Déplace le contenu applicatif hors du coffre, avec sa version de schéma.
    ///
    /// # Pourquoi un déplacement plutôt qu'une copie
    ///
    /// Le corps contient le coffre entier en clair. Le décoder produirait une
    /// **seconde copie intégrale** si on le lui passait par référence. Ici, le
    /// buffer est déplacé : le coffre n'en conserve plus aucune trace, et le
    /// [`Zeroizing`] rendu efface le contenu à sa destruction.
    ///
    /// C'est la même correction que celle appliquée en phase 1 à
    /// `Payload::decode_owned`, étendue à la frontière du magasin.
    ///
    /// Après cet appel, `body()` renvoie une tranche vide jusqu'au prochain
    /// [`Vault::set_body`].
    pub fn take_body(&mut self) -> (u16, Zeroizing<Vec<u8>>) {
        let version = self.payload.schema_version;
        (
            version,
            Zeroizing::new(std::mem::take(&mut self.payload.body)),
        )
    }

    /// Signale qu'une migration a eu lieu à l'ouverture.
    ///
    /// Appelé par le magasin, qui est le seul à connaître la version d'origine. Le
    /// coffre ne fait que la porter jusqu'aux diagnostics, pour qu'une migration ne
    /// soit **jamais silencieuse**.
    pub fn set_migrated_from(&mut self, from: Option<u16>) {
        self.diagnostics.migrated_from = from;
    }

    /// Version de schéma du contenu actuellement chargé.
    #[must_use]
    pub fn schema_version(&self) -> u16 {
        self.payload.schema_version
    }

    /// Remplace le contenu applicatif.
    ///
    /// N'écrit rien : l'appelant décide quand enregistrer, ce qui permet de
    /// regrouper plusieurs modifications en une seule écriture atomique.
    pub fn set_body(&mut self, body: Vec<u8>) {
        // Le corps fourni est toujours produit par ce binaire, donc au schéma courant :
        // l'enveloppe est mise à niveau au même moment. C'est ici que la migration
        // devient persistante, et non à l'ouverture — une consultation ne doit rien
        // écrire.
        self.payload.upgrade_schema();
        self.payload.replace_body(body);
    }

    /// Observations faites à l'ouverture.
    #[must_use]
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }

    /// Chemin du fichier de coffre.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Vrai si le coffre est ouvert en lecture seule.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Chemin du fichier de verrou, si un verrou d'écriture est détenu.
    ///
    /// Exposé pour le diagnostic : quand une ouverture échoue parce qu'une autre
    /// instance détient le verrou, l'utilisateur doit pouvoir savoir lequel.
    #[must_use]
    pub fn lock_path(&self) -> Option<&Path> {
        self.lock.as_ref().map(FileLock::path)
    }

    // -----------------------------------------------------------------------
    // Détails d'implémentation
    // -----------------------------------------------------------------------

    /// Scelle l'état courant et l'écrit de façon atomique, puis met à jour la
    /// sentinelle.
    fn write_to_disk(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }

        self.payload.generation += 1;
        // `encode` renvoie un `Zeroizing` : le contenu en clair est effacé à la
        // sortie de cette fonction, y compris si le scellement échoue.
        let encoded = self.payload.encode()?;

        let bytes = container::seal(&self.header, &self.subkeys.records, &encoded)?;

        // Le suffixe aléatoire empêche la pré-création d'un lien symbolique à un
        // emplacement devinable (voir `passlock_platform::fs`).
        let suffix = crate::rng::u64()
            .map_err(|_| Error::Internal {
                invariant: "générateur d'aléa indisponible pour le nom temporaire",
            })?
            .to_string();

        write_atomic(&self.path, &suffix, &bytes).map_err(|err| {
            // La génération a été incrémentée mais rien n'a été écrit : on la
            // rétablit pour que l'état en mémoire reste cohérent avec le disque.
            self.payload.generation -= 1;
            Error::Io(err)
        })?;

        self.update_sentinel();
        Ok(())
    }

    /// Met à jour la sentinelle, sans faire échouer l'enregistrement du coffre.
    ///
    /// ## Pourquoi l'échec est toléré
    ///
    /// Le coffre a déjà été écrit avec succès quand cette méthode s'exécute. Faire
    /// échouer `save` à cause de la sentinelle donnerait à l'utilisateur
    /// l'impression que son travail est perdu, alors qu'il est enregistré. On
    /// signale la dégradation dans les diagnostics, et c'est tout.
    fn update_sentinel(&mut self) {
        let Some(store) = self.sentinel_store() else {
            self.diagnostics.sentinel_write_failed = true;
            return;
        };

        let sentinel = Sentinel {
            vault_id: self.header.vault_id,
            generation: self.payload.generation,
            updated_at: now_unix(),
        };

        if store.store(&self.subkeys.index, &sentinel).is_err() {
            self.diagnostics.sentinel_write_failed = true;
        }
    }

    /// Construit le magasin de sentinelles, si un répertoire d'état est disponible.
    fn sentinel_store(&self) -> Option<SentinelStore> {
        let dir = match &self.state_dir {
            Some(dir) => dir.clone(),
            None => app_state_dir().ok()?,
        };
        SentinelStore::new(&dir, &self.subkeys.index, &self.header.vault_id).ok()
    }

    /// Compare la génération du coffre à celle de la sentinelle et met à jour les
    /// diagnostics.
    fn refresh_rollback_state(&mut self) -> Result<()> {
        let Some(store) = self.sentinel_store() else {
            // Sans répertoire d'état, la détection est structurellement impossible.
            self.diagnostics.rollback = RollbackCheck::NoSentinel;
            return Ok(());
        };

        let loaded = store.load(&self.subkeys.index, &self.header.vault_id)?;

        match loaded {
            SentinelLoad::Found(sentinel) => {
                if self.payload.generation < sentinel.generation {
                    self.diagnostics.rollback = RollbackCheck::Rollback {
                        known: sentinel.generation,
                        found: self.payload.generation,
                    };
                } else {
                    self.diagnostics.rollback = RollbackCheck::Consistent;
                }
            }
            SentinelLoad::Corrupted { .. } => {
                self.diagnostics.sentinel_corrupted = true;
                self.diagnostics.rollback = RollbackCheck::NoSentinel;
            }
            SentinelLoad::Absent => {
                self.diagnostics.rollback = RollbackCheck::NoSentinel;
            }
        }

        // Établir la référence si elle manque. En cas de rollback détecté, on
        // s'abstient : écraser la sentinelle effacerait la seule preuve dont on
        // dispose. Le prochain enregistrement la fera avancer naturellement.
        if self.diagnostics.rollback == RollbackCheck::NoSentinel && !self.read_only {
            self.update_sentinel();
        }

        Ok(())
    }
}

// Le `Debug` de `Vault` omet délibérément `dek`, `subkeys`, `state_dir` et `lock` :
/// l'implémentation manuelle existe précisément pour **ne pas** tout afficher. Le
/// lint signale une omission involontaire ; ici, l'omission est l'objectif.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("header", &self.header)
            .field("generation", &self.payload.generation)
            .field("body_len", &self.payload.body.len())
            .field("read_only", &self.read_only)
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

/// Longueur de clé réexportée pour l'API publique.
pub const VAULT_KEY_LEN: usize = KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    /// Paramètres de dérivation les plus légers **acceptés par la validation**.
    ///
    /// Les valeurs livrées par défaut restent [`KdfParams::standard`] (256 Mio,
    /// t=3, p=4), utilisé par `VaultConfig::default()`. Ce profil minimal n'existe
    /// que dans les tests : voir [`crate::test_support::cheap_params`] pour les
    /// mesures qui motivent ce choix (685 s de suite avant ce changement) et pour
    /// l'argument de non-régression de couverture.
    ///
    /// Les tests qui portent **spécifiquement** sur la valeur des paramètres
    /// (avertissement de recommandation, migration) construisent explicitement
    /// leurs propres valeurs.
    fn test_params() -> KdfParams {
        crate::test_support::cheap_params()
    }

    fn config(dir: &Path) -> VaultConfig {
        VaultConfig {
            params: test_params(),
            read_only: false,
            state_dir: Some(dir.to_path_buf()),
        }
    }

    fn locked_config(dir: &Path) -> VaultConfig {
        VaultConfig {
            read_only: true,
            ..config(dir)
        }
    }

    const PASSWORD: &[u8] = b"phrase de passe de test";

    /// Longueur du préfixe de conteneur, avant le header.
    const FILE_PREFIX: usize = 16;

    /// Décalage du premier slot dans le fichier : préfixe + partie fixe du header.
    const FIRST_SLOT: usize = FILE_PREFIX + 28;

    /// Décalage, dans un slot, de la clé de données enveloppée.
    ///
    /// Un slot se compose de : identifiant (2), rôle (1), algorithme (1),
    /// version Argon2 (1), réservé (1), coût mémoire (4), itérations (4),
    /// parallélisme (4), sel (32), nonce d'enveloppe (24), puis la clé enveloppée.
    const SLOT_WRAPPED_OFFSET: usize = 2 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 32 + 24;

    #[test]
    fn create_then_open_recovers_state() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let created = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        let generation_after_create = created.generation();
        drop(created);

        let opened = Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture");
        assert_eq!(opened.generation(), generation_after_create);
        assert!(opened.body().is_empty());
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_vault() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let first = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        drop(first);

        let second = Vault::create(&path, PASSWORD, &config(dir.path()));
        assert!(second.is_err(), "la création a écrasé un coffre existant");
    }

    #[test]
    fn wrong_password_is_indistinguishable_from_corruption() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        let wrong = Vault::open(&path, b"mauvais mot de passe", &config(dir.path()));
        assert!(matches!(wrong, Err(Error::UnlockFailed)));
    }

    #[test]
    fn tampering_with_the_slot_yields_the_same_error_as_a_wrong_password() {
        // Propriété anti-oracle : un attaquant qui altère le slot ne doit pas
        // pouvoir distinguer cet échec d'un mot de passe faux.
        //
        // Le test vise la **clé enveloppée** du slot, et non le dernier octet du
        // fichier : ce dernier appartient au payload chiffré, où l'altération
        // produit légitimement `Corrupted` (voir le test complémentaire ci-dessous).
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        let original = std::fs::read(&path).expect("lecture");
        let wrapped_start = FIRST_SLOT + SLOT_WRAPPED_OFFSET;
        // Borne **exclusive** : la clé enveloppée occupe 48 octets, et au-delà on
        // entre dans le payload chiffré où une altération produit légitimement
        // `Corrupted`. Boucler jusqu'à la fin du fichier aurait mélangé les deux
        // régions et fait échouer le test pour une mauvaise raison.
        let wrapped_end = wrapped_start + crate::keys::WRAPPED_DEK_LEN;
        assert!(
            wrapped_end < original.len(),
            "le fichier de test devrait contenir un payload après le slot"
        );

        // La dérivation est sortie de la boucle. Argon2id est une fonction pure de
        // (mot de passe, sel, paramètres) : la recalculer à chaque itération ne
        // teste rien de plus sur l'octet muté, et coûterait ~3,3 s par octet en
        // profil `dev`. Une seule dérivation suffit, puis on rejoue exactement la
        // même fonction de déverrouillage que `Vault::open` utilise.
        let kek = {
            let parsed = ParsedVault::parse(&original).expect("analyse");
            derive_slot_kek(&parsed.header, SlotLabel::Master, PASSWORD).expect("dérivation")
        };

        for index in wrapped_start..wrapped_end {
            let mut bytes = original.clone();
            bytes[index] ^= 0x01;

            let outcome = unlock_with_kek(&bytes, &kek, SlotLabel::Master);
            assert!(
                matches!(outcome, Err(Error::UnlockFailed)),
                "un octet altéré à l'offset {index} de la clé enveloppée doit produire \
                 UnlockFailed, indiscernable d'un mot de passe faux"
            );
        }

        // Et la même propriété, une fois, à travers l'API publique complète.
        let mut bytes = original.clone();
        bytes[wrapped_start] ^= 0x01;
        std::fs::write(&path, &bytes).expect("écriture");
        assert!(matches!(
            Vault::open(&path, PASSWORD, &config(dir.path())),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn tampering_with_the_payload_is_reported_as_corruption_not_as_a_bad_password() {
        // Contrepartie assumée et volontaire de la propriété précédente.
        //
        // Une fois le slot ouvert — donc le mot de passe connu —, l'échec du tag du
        // payload peut légitimement être annoncé comme une corruption. Pour
        // atteindre ce message il faut déjà la clé, donc l'information ne donne rien
        // à un attaquant, et elle évite à l'utilisateur légitime de croire à une
        // erreur de saisie.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"contenu".to_vec());
        vault.save().expect("enregistrement");
        drop(vault);

        let mut bytes = std::fs::read(&path).expect("lecture");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).expect("écriture");

        let outcome = Vault::open(&path, PASSWORD, &config(dir.path()));
        assert!(
            matches!(outcome, Err(Error::Corrupted { .. })),
            "une altération du payload doit être annoncée comme une corruption"
        );
    }

    #[test]
    fn save_persists_the_body_and_advances_the_generation() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        let before = vault.generation();
        vault.set_body(b"contenu applicatif".to_vec());
        vault.save().expect("enregistrement");
        assert_eq!(vault.generation(), before + 1);
        drop(vault);

        let reopened = Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture");
        assert_eq!(reopened.body(), b"contenu applicatif");
        assert_eq!(reopened.generation(), before + 1);
    }

    #[test]
    fn read_only_vault_refuses_to_write() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        let mut vault =
            Vault::open(&path, PASSWORD, &locked_config(dir.path())).expect("ouverture");
        assert!(vault.is_read_only());
        assert!(matches!(vault.save(), Err(Error::ReadOnly)));
    }

    #[test]
    fn second_writer_is_refused_while_the_first_holds_the_lock() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        let first = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        let second = Vault::open(&path, PASSWORD, &config(dir.path()));
        assert!(
            matches!(second, Err(Error::AlreadyLocked)),
            "une seconde ouverture en écriture doit être refusée"
        );

        drop(first);

        Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture après libération");
    }

    #[test]
    fn read_only_open_is_allowed_while_another_instance_writes() {
        // La lecture pendant une écriture est sûre : l'écriture est atomique, donc
        // on lit toujours un fichier complet.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        let writer = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        Vault::open(&path, PASSWORD, &locked_config(dir.path()))
            .expect("la lecture seule doit rester possible");
        drop(writer);
    }

    #[test]
    fn change_password_preserves_the_data_key_and_the_body() {
        // C'est l'invariant central de l'architecture : changer le mot de passe
        // ré-enveloppe la DEK, sans toucher au contenu.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"contenu a preserver".to_vec());
        vault.save().expect("enregistrement");

        vault
            .change_password(PASSWORD, b"nouvelle phrase de passe", test_params())
            .expect("changement de mot de passe");
        drop(vault);

        let reopened = Vault::open(&path, b"nouvelle phrase de passe", &config(dir.path()))
            .expect("ouverture avec le nouveau mot de passe");
        assert_eq!(
            reopened.body(),
            b"contenu a preserver",
            "le contenu a été altéré par le changement de mot de passe"
        );

        // L'ancien mot de passe ne doit plus fonctionner.
        drop(reopened);
        let old = Vault::open(&path, PASSWORD, &config(dir.path()));
        assert!(matches!(old, Err(Error::UnlockFailed)));
    }

    #[test]
    fn change_password_requires_the_correct_current_password() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        let outcome = vault.change_password(b"mauvais mot de passe", b"nouveau", test_params());
        assert!(matches!(outcome, Err(Error::UnlockFailed)));

        // Et le coffre doit rester ouvrable avec le mot de passe d'origine : un
        // échec ne doit rien avoir écrit.
        drop(vault);
        Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture inchangée");
    }

    #[test]
    fn change_password_can_also_upgrade_kdf_parameters() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        // Paramètres volontairement plus coûteux que le plancher utilisé par les
        // autres tests : ce cas vérifie précisément qu'une **augmentation** des
        // paramètres est bien enregistrée puis relue depuis le fichier.
        let stronger = KdfParams::new(16 * 1024, 2, 1).expect("paramètres valides");
        vault
            .change_password(PASSWORD, PASSWORD, stronger)
            .expect("migration de paramètres");

        assert_eq!(vault.header().master_slot().expect("slot").params, stronger);
        drop(vault);

        let reopened = Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture");
        assert_eq!(
            reopened.header().master_slot().expect("slot").params,
            stronger,
            "les paramètres durcis doivent être relus depuis le fichier"
        );
    }

    #[test]
    fn weak_parameters_raise_a_warning_without_blocking() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");
        Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");

        let opened = Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture");
        assert!(
            opened.diagnostics().params_below_recommendation,
            "un coffre en profil réduit doit être signalé"
        );
        assert!(opened.diagnostics().has_warnings());
    }

    #[test]
    fn vault_id_is_stable_across_reopenings_and_password_changes() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        let original = vault.header().vault_id;

        vault
            .change_password(PASSWORD, b"autre phrase", test_params())
            .expect("changement");
        assert_eq!(vault.header().vault_id, original);
        drop(vault);

        let reopened = Vault::open(&path, b"autre phrase", &config(dir.path())).expect("ouverture");
        assert_eq!(reopened.header().vault_id, original);
    }

    #[test]
    fn rollback_of_the_vault_file_is_detected() {
        // Scénario complet : on enregistre, on copie le fichier, on avance encore,
        // puis on restaure la copie. La génération a reculé et la sentinelle,
        // restée en avant, doit le révéler.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"version ancienne".to_vec());
        vault.save().expect("enregistrement");
        let backup = std::fs::read(&path).expect("lecture");

        vault.set_body(b"version recente".to_vec());
        vault.save().expect("enregistrement");
        drop(vault);

        // Restauration de la sauvegarde : le fichier recule en génération.
        std::fs::write(&path, &backup).expect("restauration");

        let reopened = Vault::open(&path, PASSWORD, &config(dir.path())).expect("ouverture");
        assert!(
            matches!(
                reopened.diagnostics().rollback,
                RollbackCheck::Rollback { .. }
            ),
            "un retour en arrière n'a pas été détecté : {:?}",
            reopened.diagnostics().rollback
        );
        assert!(reopened.diagnostics().has_warnings());
    }

    #[test]
    fn a_legitimate_backup_restore_remains_openable() {
        // Contrepartie indispensable : la détection alerte mais ne bloque jamais.
        // Une restauration après sinistre doit rester possible.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"contenu sauvegarde".to_vec());
        vault.save().expect("enregistrement");
        let backup = std::fs::read(&path).expect("lecture");
        drop(vault);

        std::fs::write(&path, &backup).expect("restauration");

        let reopened = Vault::open(&path, PASSWORD, &config(dir.path()))
            .expect("une restauration légitime doit rester possible");
        assert_eq!(reopened.body(), b"contenu sauvegarde");
    }

    #[test]
    fn absent_sentinel_is_reported_as_inactive_detection() {
        let dir = tempfile::tempdir().expect("répertoire");
        let state = dir.path().join("etat");
        let path = dir.path().join("coffre.plk");

        Vault::create(&path, PASSWORD, &config(&state)).expect("création");

        // Une nouvelle machine n'a pas de sentinelle : la détection est inactive et
        // cela doit être dit, pas passé sous silence.
        let fresh_state = dir.path().join("etat-vierge");
        let opened = Vault::open(
            &path,
            PASSWORD,
            &VaultConfig {
                state_dir: Some(fresh_state),
                ..config(&state)
            },
        )
        .expect("ouverture");

        assert_eq!(opened.diagnostics().rollback, RollbackCheck::NoSentinel);
        assert!(opened.diagnostics().has_warnings());
    }

    #[test]
    fn every_single_byte_flip_in_the_file_is_rejected_cleanly() {
        // Parcours exhaustif du fichier : aucune modification d'un octet ne doit
        // produire autre chose qu'un échec propre, et jamais un contenu accepté qui
        // ne serait pas le contenu d'origine.
        //
        // ## Pourquoi la dérivation est hors de la boucle
        //
        // Ce test a été à l'origine écrit en appelant `Vault::open` à chaque
        // itération, soit ~234 dérivations Argon2id complètes. Mesuré : **685 s**
        // pour la suite, dont l'essentiel imputable à ce test et au suivant.
        //
        // La dérivation est une fonction pure de (mot de passe, sel, paramètres) :
        // la recalculer ne teste rien de plus sur l'octet muté. On la calcule donc
        // **une fois**, et on rejoue la même fonction de déverrouillage que
        // `Vault::open` emploie, avec exactement la même couverture et un coût
        // négligeable.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"contenu".to_vec());
        vault.save().expect("enregistrement");
        drop(vault);

        let original = std::fs::read(&path).expect("lecture");
        let kek = {
            let parsed = ParsedVault::parse(&original).expect("analyse");
            derive_slot_kek(&parsed.header, SlotLabel::Master, PASSWORD).expect("dérivation")
        };

        for index in 0..original.len() {
            let mut bytes = original.clone();
            bytes[index] ^= 0x01;

            match unlock_with_kek(&bytes, &kek, SlotLabel::Master) {
                Ok(unlocked) => {
                    // Cas légitime : l'octet modifié n'est pas authentifié. On
                    // s'assure alors qu'aucun contenu incohérent n'est produit.
                    assert_eq!(
                        unlocked.payload.body, b"contenu",
                        "un octet modifié à l'offset {index} a produit un contenu altéré"
                    );
                }
                Err(err) => assert!(
                    matches!(
                        err,
                        Error::UnlockFailed
                            | Error::Corrupted { .. }
                            | Error::InvalidHeader { .. }
                            | Error::NotAVault
                            | Error::MalformedLength { .. }
                            | Error::RejectedKdfParams { .. }
                            | Error::UnsupportedFormatVersion { .. }
                            | Error::Io(_)
                            | Error::Internal { .. }
                    ),
                    "erreur inattendue à l'offset {index} : {err}"
                ),
            }
        }

        // Un passage à travers l'API publique complète, pour vérifier que le chemin
        // réel — verrou, permissions, diagnostics, sentinelle — se comporte bien.
        let mut bytes = original.clone();
        bytes[0] ^= 0x01;
        std::fs::write(&path, &bytes).expect("écriture");
        assert!(Vault::open(&path, PASSWORD, &config(dir.path())).is_err());
    }

    #[test]
    fn truncations_are_rejected_cleanly() {
        // Même raisonnement que ci-dessus : la dérivation est une fonction pure, on
        // la sort de la boucle de troncature.
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"contenu".to_vec());
        vault.save().expect("enregistrement");
        drop(vault);

        let original = std::fs::read(&path).expect("lecture");
        let kek = {
            let parsed = ParsedVault::parse(&original).expect("analyse");
            derive_slot_kek(&parsed.header, SlotLabel::Master, PASSWORD).expect("dérivation")
        };

        for len in 0..original.len() {
            assert!(
                unlock_with_kek(&original[..len], &kek, SlotLabel::Master).is_err(),
                "troncature à {len} octets acceptée"
            );
        }

        // Et un passage par l'API publique.
        std::fs::write(&path, &original[..original.len() - 1]).expect("écriture");
        assert!(Vault::open(&path, PASSWORD, &config(dir.path())).is_err());
    }

    #[test]
    fn debug_output_does_not_expose_content_or_keys() {
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("coffre.plk");

        let mut vault = Vault::create(&path, PASSWORD, &config(dir.path())).expect("création");
        vault.set_body(b"SECRET-EN-CLAIR-MARQUEUR".to_vec());

        let rendered = format!("{vault:?}");
        assert!(
            !rendered.contains("SECRET-EN-CLAIR-MARQUEUR"),
            "le contenu du coffre apparaît dans le Debug : {rendered}"
        );
        assert!(!rendered.contains("phrase de passe"), "{rendered}");
    }
}
