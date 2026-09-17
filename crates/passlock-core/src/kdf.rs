//! Dérivation de la clé maître à partir du mot de passe maître (Argon2id).
//!
//! ## Rôle exact dans l'architecture
//!
//! Ce module transforme un mot de passe (entropie inconnue, souvent faible) en
//! une clé de 32 octets d'entropie pleine (la clé maître `MK`). Il ne chiffre
//! rien et n'authentifie rien : c'est uniquement une fonction de durcissement.
//!
//! ## Pourquoi Argon2id et pas autre chose
//!
//! * Vainqueur du Password Hashing Competition (2015), normalisé dans la RFC 9106.
//! * `id` est la variante hybride : la première passe se comporte comme `i`
//!   (résistante aux attaques par canal auxiliaire, utile puisque le même mot de
//!   passe est dérivé sur la même machine à chaque déverrouillage) et les suivantes
//!   comme `d` (résistante au calcul parallèle sur GPU/ASIC).
//! * Coût **mémoire** configurable : c'est le levier décisif face à un attaquant
//!   qui loue des GPU, car chaque cœur d'attaque doit disposer de la totalité de
//!   `m`, ce qui plafonne son parallélisme.
//!
//! ## Pourquoi un SHA rapide serait une faute
//!
//! Un SHA-256 seul se calcule des milliards de fois par seconde sur un GPU. Le
//! mot de passe maître d'un coffre volé serait retrouvé en quelques heures pour
//! tout mot de passe humain réaliste. Argon2id ne rend pas l'attaque impossible :
//! il la rend coûteuse en mémoire et en temps.
//!
//! ## Choix des paramètres
//!
//! Les valeurs par défaut sont **au-dessus** des minima OWASP *délibérément*, et
//! non par excès de prudence :
//!
//! * Les minima OWASP (« m=19 MiB, t=2, p=1 ») visent une **authentification
//!   serveur**, où le coût est payé à chaque connexion pour des millions
//!   d'utilisateurs et où le hachage protège un mot de passe parmi des milliards
//!   de hashes. Ici le coût est payé **une fois par session de déverrouillage**,
//!   sur un seul coffre, pour un seul utilisateur.
//! * Le budget de latence disponible est donc bien plus large : une seconde de
//!   déverrouillage est acceptable, alors qu'une seconde par requête HTTP ne
//!   l'est pas.
//! * RFC 9106 recommande par ailleurs `t=3, m=64 MiB` pour les environnements
//!   contraints, et `t=1, m=2 GiB` comme premier choix.
//!
//! Voir `docs/CRYPTO.md` pour la justification paramètre par paramètre et les
//! mesures de latence **réellement observées** sur une machine donnée.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::rng;
use crate::secret::Key;

/// Nombre maximal de dérivations simultanées par défaut.
///
/// # Pourquoi une limite existe
///
/// Argon2id alloue sa zone de travail — [`KdfParams::standard`] demande 256 Mio —
/// pour **toute la durée** de la dérivation, pas seulement à l'instant du hachage.
/// La campagne de mesure `scripts/measure-memory-pressure.sh` donne, sur une machine
/// à 7,7 Gio, un pic **strictement linéaire** :
///
/// | Dérivations simultanées | Pic agrégé | Durée unitaire | Part de la RAM |
/// |---|---|---|---|
/// | 1 | 258 Mio | 682 ms | 3 % |
/// | 4 | 1 034 Mio | 1 264 ms | 13 % |
/// | 16 | 4 135 Mio | 5 220 ms | 53 % |
///
/// Le mode de défaillance est le point important : **un dépassement de la mémoire
/// disponible ne produit pas d'erreur franche sur Linux**. Le noyau échange, ce qui
/// fait passer la durée de 0,7 s à plusieurs dizaines de secondes et dégrade la
/// machine entière — y compris les autres applications de l'utilisateur. Une erreur
/// serait préférable à une dégradation silencieuse ; à défaut, on l'empêche.
///
/// # Pourquoi 1 par défaut
///
/// Un déverrouillage est une action humaine : personne n'ouvre seize coffres dans
/// la même seconde. Sérialiser ne coûte donc rien en pratique — au pire une seconde
/// d'attente au démarrage d'une interface qui ouvre deux coffres — et plafonne le
/// pic à 256 Mio au lieu de le laisser croître sans borne.
///
/// Une application qui sait ce qu'elle fait peut relever cette limite avec
/// [`set_max_concurrent_derivations`], en connaissance des chiffres ci-dessus.
const DEFAULT_MAX_CONCURRENT_DERIVATIONS: usize = 1;

/// Limiteur de concurrence des dérivations.
///
/// Sémaphore à comptage, sans dépendance externe. Le maximum est relu à chaque
/// acquisition, ce qui permet de le modifier après la première dérivation sans
/// réinitialiser l'état.
#[derive(Debug)]
struct DerivationLimiter {
    /// Nombre de dérivations en cours.
    in_flight: Mutex<usize>,
    /// Réveillé lorsqu'une place se libère.
    released: Condvar,
    /// Plafond courant.
    maximum: AtomicUsize,
}

impl DerivationLimiter {
    const fn new(maximum: usize) -> Self {
        Self {
            in_flight: Mutex::new(0),
            released: Condvar::new(),
            maximum: AtomicUsize::new(maximum),
        }
    }

    /// Attend qu'une place soit disponible et la réserve.
    ///
    /// Un empoisonnement du verrou signifie qu'un thread a paniqué alors qu'il
    /// détenait une place. Le compteur reste cohérent dans ce cas — il est mis à
    /// jour sous le verrou, et la panique a eu lieu après — donc on poursuit plutôt
    /// que de propager la panique à tous les appelants.
    fn acquire(&self) -> DerivationPermit<'_> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        while *in_flight >= self.maximum.load(Ordering::Acquire) {
            in_flight = self
                .released
                .wait(in_flight)
                .unwrap_or_else(PoisonError::into_inner);
        }

        *in_flight += 1;
        DerivationPermit { limiter: self }
    }

    fn release(&self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *in_flight = in_flight.saturating_sub(1);
        drop(in_flight);
        // Un seul réveil suffit : une seule place vient d'être libérée.
        self.released.notify_one();
    }

    fn maximum(&self) -> usize {
        self.maximum.load(Ordering::Acquire).max(1)
    }

    fn set_maximum(&self, maximum: usize) {
        self.maximum.store(maximum.max(1), Ordering::Release);
        // Le plafond a pu être relevé : on réveille tous les threads en attente,
        // car plusieurs places ont pu apparaître d'un coup.
        self.released.notify_all();
    }
}

/// Place réservée dans le limiteur, libérée à la destruction.
#[derive(Debug)]
struct DerivationPermit<'a> {
    limiter: &'a DerivationLimiter,
}

impl Drop for DerivationPermit<'_> {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

/// Limiteur global du processus.
static DERIVATION_LIMITER: OnceLock<DerivationLimiter> = OnceLock::new();

/// Limiteur global, initialisé à la première utilisation.
fn derivation_limiter() -> &'static DerivationLimiter {
    DERIVATION_LIMITER.get_or_init(|| DerivationLimiter::new(DEFAULT_MAX_CONCURRENT_DERIVATIONS))
}

/// Fixe le nombre maximal de dérivations Argon2id simultanées.
///
/// # Portée
///
/// Le réglage est **global au processus** et affecte toutes les dérivations
/// suivantes, y compris celles d'autres coffres. Il ne touche à aucun paramètre
/// cryptographique : seule la concurrence change, jamais la difficulté.
///
/// # Quand le relever
///
/// Un appelant qui sait que sa machine dispose de beaucoup de mémoire, ou qui
/// ouvre délibérément plusieurs coffres en parallèle, peut relever cette limite. Les
/// chiffres de la documentation de [`DEFAULT_MAX_CONCURRENT_DERIVATIONS`] donnent la
/// consommation à attendre : chaque place supplémentaire coûte `m_cost` octets
/// pendant la durée d'une dérivation.
///
/// Une valeur de `0` est ramenée à `1` : accepter zéro bloquerait indéfiniment.
pub fn set_max_concurrent_derivations(maximum: usize) {
    derivation_limiter().set_maximum(maximum.max(1));
}

/// Retourne le nombre maximal de dérivations simultanées actuellement autorisé.
#[must_use]
pub fn max_concurrent_derivations() -> usize {
    derivation_limiter().maximum()
}

/// Nombre de dérivations actuellement en cours, dans ce processus.
///
/// Exposé **uniquement pour les tests**. Il sert à vérifier que la limite est bien
/// appliquée par le chemin réel et non seulement par le sémaphore pris isolément —
/// une distinction qui compte, puisque c'est le câblage qui peut être oublié.
/// Cette fonction n'existe pas dans un binaire compilé sans `cfg(test)`.
#[cfg(test)]
pub(crate) fn derivations_in_flight() -> usize {
    *derivation_limiter()
        .in_flight
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Longueur du sel, en octets.
///
/// 32 octets : au-delà de ce que la sécurité exige, mais un sel court n'apporte
/// rien en échange, et une taille fixe d'une puissance de deux simplifie la
/// sérialisation du header.
pub const SALT_LEN: usize = 32;

/// Longueur de la clé maître dérivée, en octets.
pub const KEY_LEN: usize = 32;

/// Longueur maximale acceptée pour un mot de passe maître.
///
/// Argon2 hache d'abord son entrée avec Blake2b, donc une entrée très longue n'est
/// pas un problème de coût CPU. Ce plafond sert à refuser une entrée aberrante
/// (collage accidentel d'un fichier entier) plutôt qu'à protéger le calcul.
///
/// 1024 octets laissent une marge très large au-dessus de toute phrase de passe
/// réaliste, y compris en notation Unicode composée.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Plancher absolu du coût mémoire, en Kio.
///
/// En dessous, le header est considéré comme mal formé plutôt que comme le
/// résultat d'un choix volontaire : aucun profil de ce logiciel ne descend là.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;

/// Plafond absolu du coût mémoire, en Kio.
///
/// **C'est une protection contre le déni de service**, et non un choix de
/// sécurité. Le header est lu *avant* toute authentification : un fichier hostile
/// peut y annoncer `m = 4 GiB` et nous faire allouer cette mémoire avant même de
/// savoir si le mot de passe est correct. On refuse donc au-delà de cette borne.
pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;

/// Plafond du nombre d'itérations.
pub const MAX_T_COST: u32 = 16;

/// Plafond du degré de parallélisme.
pub const MAX_P_COST: u32 = 16;

/// Ensemble des paramètres Argon2id d'un slot de clé.
///
/// Le type est volontairement **opaque** : on ne peut pas le construire sans
/// passer par [`KdfParams::new`], qui valide. Aucun `pub` sur les champs, donc
/// aucun moyen de fabriquer des paramètres hors bornes depuis l'extérieur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    /// Profil par défaut : [`KdfParams::standard`].
    ///
    /// Définir `Default` sur le profil durci plutôt que sur le plus léger évite
    /// qu'un appelant distrait obtienne silencieusement l'affaiblissement maximal.
    /// Un défaut doit être le choix sûr.
    fn default() -> Self {
        Self::standard()
    }
}

impl KdfParams {
    /// Construit des paramètres validés.
    ///
    /// # Erreurs
    /// [`Error::RejectedKdfParams`] si une des bornes est dépassée. La borne est
    /// vérifiée **ici**, donc avant toute allocation mémoire d'Argon2.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        if m_cost_kib < MIN_M_COST_KIB {
            return Err(Error::RejectedKdfParams {
                reason: "coût mémoire inférieur au minimum admis",
            });
        }
        if m_cost_kib > MAX_M_COST_KIB {
            return Err(Error::RejectedKdfParams {
                reason: "coût mémoire supérieur au plafond de sécurité",
            });
        }
        if t_cost == 0 || t_cost > MAX_T_COST {
            return Err(Error::RejectedKdfParams {
                reason: "nombre d'itérations hors bornes",
            });
        }
        if p_cost == 0 || p_cost > MAX_P_COST {
            return Err(Error::RejectedKdfParams {
                reason: "parallélisme hors bornes",
            });
        }
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
        })
    }

    /// Profil réduit — machines à mémoire limitée ou environnements virtualisés.
    ///
    /// **Affaiblissement assumé.** Ce profil doit être présenté comme tel à
    /// l'utilisateur, en dernier recours, et non comme une option de confort.
    #[must_use]
    pub fn low() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 2,
        }
    }

    /// Profil par défaut.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }

    /// Profil maximal, pour utilisateurs avertis et machines disposant de RAM.
    #[must_use]
    pub fn paranoid() -> Self {
        Self {
            m_cost_kib: 1024 * 1024,
            t_cost: 4,
            p_cost: 4,
        }
    }

    /// Liste des profils, du moins coûteux au plus coûteux.
    #[must_use]
    pub fn profiles() -> [Self; 3] {
        [Self::low(), Self::standard(), Self::paranoid()]
    }

    #[must_use]
    pub fn m_cost_kib(&self) -> u32 {
        self.m_cost_kib
    }

    #[must_use]
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    #[must_use]
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// Vrai si ces paramètres sont plus faibles que le profil par défaut actuel.
    ///
    /// La référence est [`KdfParams::standard`] et non une constante externe :
    /// ainsi, durcir le profil par défaut fait automatiquement apparaître
    /// l'avertissement sur les coffres plus anciens, sans qu'il faille penser à
    /// mettre à jour un second nombre.
    ///
    /// Sert à déclencher un avertissement et une proposition de migration, sans
    /// **jamais** empêcher l'ouverture : refuser d'ouvrir un coffre parce que ses
    /// paramètres sont anciens transformerait une migration en perte de données.
    #[must_use]
    pub fn is_below_recommendation(&self) -> bool {
        let reference = Self::standard();
        self.m_cost_kib < reference.m_cost_kib || self.t_cost < reference.t_cost
    }
}

/// Dérive la clé maître et l'écrit dans `out`.
///
/// `out` doit faire exactement [`KEY_LEN`] octets.
///
/// ## Pourquoi nous allouons nous-mêmes la mémoire de travail
///
/// Argon2 0.6 expose `hash_password_into_with_memory`, qui laisse l'appelant
/// fournir les blocs de travail. Nous nous en servons pour **effacer
/// explicitement** les `m` Kio d'état intermédiaire après la dérivation.
///
/// Cet état est un dérivé direct du mot de passe maître : le laisser traîner dans
/// le tas après l'opération reviendrait à conserver une version « à mi-parcours »
/// du secret. L'effacement n'est pas une garantie absolue (voir `secret.rs`), mais
/// il retire une copie que nous contrôlons pour un coût nul.
///
/// Nous ne verrouillons **pas** cette zone avec `mlock` : elle fait jusqu'à
/// 256 Mio, ce qui dépasserait systématiquement `RLIMIT_MEMLOCK` et ferait échouer
/// la protection pour toutes les autres clés. Le compromis est explicite : on
/// efface sans verrouiller.
///
/// ## Pourquoi `try_reserve` et non `vec![]`
///
/// Une allocation qui échoue en Rust déclenche un `abort`, donc un arrêt brutal
/// et non un message d'erreur. Avec des paramètres venus d'un fichier — donc non
/// fiables — on préfère un échec propre : `try_reserve_exact` transforme
/// l'épuisement mémoire en erreur exploitable, ce qui permet notamment de
/// proposer le profil réduit à l'utilisateur au lieu de tuer le processus.
///
/// # Erreurs
/// * [`Error::InvalidLength`] si `out` ou `salt` n'ont pas la bonne taille ;
/// * [`Error::RejectedKdfParams`] si `params` est hors bornes ou si la mémoire
///   ne peut pas être allouée ;
/// * [`Error::Internal`] si Argon2 refuse des paramètres que nous avons validés.
pub fn derive_into(password: &[u8], salt: &[u8], params: KdfParams, out: &mut [u8]) -> Result<()> {
    if salt.len() != SALT_LEN {
        return Err(Error::InvalidLength {
            field: "salt",
            expected: SALT_LEN,
            actual: salt.len(),
        });
    }
    if out.len() != KEY_LEN {
        return Err(Error::InvalidLength {
            field: "master key",
            expected: KEY_LEN,
            actual: out.len(),
        });
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(Error::RejectedKdfParams {
            reason: "mot de passe au-delà de la longueur maximale acceptée",
        });
    }

    // Revalidation : `KdfParams` ne peut pas être construit hors bornes depuis
    // l'extérieur, mais la refaire ici rend la propriété locale à la fonction et
    // donc indépendante d'un futur changement d'encapsulation.
    let params = KdfParams::new(params.m_cost_kib, params.t_cost, params.p_cost)?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Internal {
        invariant: "paramètres Argon2id refusés par la bibliothèque après validation locale",
    })?;

    let block_count = argon_params.block_count();

    let mut memory: Vec<Block> = Vec::new();
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| Error::RejectedKdfParams {
            reason: "mémoire insuffisante pour les paramètres de dérivation demandés",
        })?;
    memory.resize(block_count, Block::new());

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // La place est réservée **avant** la dérivation et libérée après : c'est la
    // durée pendant laquelle la zone de travail de `m` octets est vivante qui doit
    // être plafonnée, pas l'instant du calcul.
    let _permit = derivation_limiter().acquire();
    let outcome = argon.hash_password_into_with_memory(password, salt, out, &mut memory);

    // Effacement inconditionnel : il doit avoir lieu même si la dérivation a
    // échoué, car les blocs peuvent avoir été partiellement remplis avant l'échec.
    memory.zeroize();

    outcome.map_err(|_| Error::Internal {
        invariant: "échec de hachage Argon2id sur des paramètres validés",
    })
}

/// Dérive la clé maître et la retourne.
///
/// # Erreurs
/// Propage les erreurs de [`derive_into`]. Le buffer de sortie est verrouillé en
/// RAM si possible et effacé à sa destruction.
pub fn derive(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key<KEY_LEN>> {
    let mut key = Key::<KEY_LEN>::zeroed();
    derive_into(password, salt, params, key.expose_mut())?;
    Ok(key)
}

/// Génère un sel aléatoire.
///
/// # Erreurs
/// Propage l'échec du générateur du système.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    rng::array::<SALT_LEN>()
}

/// Résultat d'une mesure de calibration.
#[derive(Debug, Clone, Copy)]
pub struct CalibrationMeasurement {
    /// Profil mesuré.
    pub params: KdfParams,
    /// Durée effectivement observée pour une dérivation complète.
    pub observed: Duration,
}

/// Rapport complet de calibration.
///
/// Contient **toutes** les mesures effectuées, et pas seulement le profil retenu.
/// C'est délibéré : l'intérêt d'une calibration est de produire un chiffre
/// vérifiable et publiable, pas seulement de choisir un paramètre. Un rapport qui
/// ne garderait que la sélection rendrait la mesure invérifiable par un tiers.
#[derive(Debug, Clone)]
pub struct CalibrationReport {
    /// Mesures effectuées, dans l'ordre croissant de coût.
    pub measurements: Vec<CalibrationMeasurement>,
    /// Profil retenu au regard du budget.
    pub selected: CalibrationMeasurement,
    /// Vrai si même le profil le plus léger dépasse le budget demandé.
    pub budget_exceeded: bool,
}

/// Mesure le coût réel de chaque profil sur cette machine, du moins au plus cher,
/// et retient le plus coûteux qui tienne dans le budget.
///
/// ## Pourquoi mesurer plutôt que de fixer une constante
///
/// Le bon paramètre dépend du CPU, de la mémoire disponible et surtout de la
/// pression mémoire réelle de la machine : sur un système au bord du swap, une
/// dérivation de 1 Gio peut être des dizaines de fois plus lente que sur la même
/// machine au repos. Une valeur « trouvée sur Internet » ne peut donc pas être
/// universelle — c'est précisément ce que la calibration remplace.
///
/// ## Ce que cette mesure ne garantit pas
///
/// Elle donne le confort de l'utilisateur **sur sa machine**, à cet instant. Elle
/// ne borne en rien le coût pour un attaquant disposant de matériel dédié : c'est
/// la propriété recherchée, mais elle signifie aussi que « calibré » ne veut pas
/// dire « suffisant ».
///
/// # Erreurs
/// Propage l'échec de la dérivation.
pub fn calibrate(password: &[u8], budget: Duration) -> Result<CalibrationReport> {
    let mut measurements = Vec::with_capacity(KdfParams::profiles().len());
    let mut selected: Option<CalibrationMeasurement> = None;
    let mut budget_exceeded = false;

    for params in KdfParams::profiles() {
        let salt = generate_salt()?;
        let start = Instant::now();
        let _key = derive(password, &salt, params)?;
        let observed = start.elapsed();

        let measurement = CalibrationMeasurement { params, observed };
        measurements.push(measurement);

        if observed <= budget {
            // On ne remplace la sélection que si l'on fait mieux : la liste est
            // parcourue dans l'ordre croissant, donc la dernière qui tient est la
            // plus coûteuse qui tienne.
            selected = Some(measurement);
        } else {
            // Les profils sont ordonnés par coût, et l'écart entre deux voisins est
            // d'un facteur proche de 4. Continuer ne ferait qu'allouer de la mémoire
            // pour confirmer un dépassement déjà acquis.
            budget_exceeded = true;
            break;
        }
    }

    // Si même le profil le plus léger dépasse le budget, on le retient quand même :
    // l'utilisateur doit pouvoir déverrouiller son coffre. Le champ
    // `budget_exceeded` permet à l'appelant de le dire honnêtement.
    let selected = if let Some(measurement) = selected {
        measurement
    } else {
        let params = KdfParams::low();
        let salt = generate_salt()?;
        let start = Instant::now();
        let _key = derive(password, &salt, params)?;
        let measurement = CalibrationMeasurement {
            params,
            observed: start.elapsed(),
        };
        if measurements.is_empty() {
            measurements.push(measurement);
        }
        measurement
    };

    Ok(CalibrationReport {
        measurements,
        selected,
        budget_exceeded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sérialise les tests qui touchent au **limiteur global**.
    ///
    /// Le limiteur est un état partagé par tout le processus : un test qui le
    /// modifie pendant qu'un autre le lit produit une assertion instable, et une
    /// instabilité ne se distingue pas d'une régression. Ce verrou rend les deux
    /// tests concernés déterministes sans renoncer à les exécuter.
    static GLOBAL_LIMITER_LOCK: Mutex<()> = Mutex::new(());

    /// Paramètres les plus légers acceptés par la validation.
    ///
    /// La correction du code ne dépend pas du coût, et un test unitaire n'a pas à
    /// allouer 64 Mio ni à dériver pendant plusieurs secondes par cas. Voir
    /// `test_support` pour les mesures qui motivent ce choix.
    fn fast() -> KdfParams {
        crate::test_support::cheap_params()
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7_u8; SALT_LEN];
        let first = derive(b"mot de passe de test", &salt, fast()).expect("dérivation");
        let second = derive(b"mot de passe de test", &salt, fast()).expect("dérivation");
        assert!(first.constant_time_eq(&second));
    }

    #[test]
    fn different_password_gives_different_key() {
        let salt = [7_u8; SALT_LEN];
        let first = derive(b"mot de passe de test", &salt, fast()).expect("dérivation");
        let other = derive(b"mot de passe de tesu", &salt, fast()).expect("dérivation");
        assert!(!first.constant_time_eq(&other));
    }

    #[test]
    fn different_salt_gives_different_key() {
        let first = derive(b"mot de passe de test", &[1_u8; SALT_LEN], fast()).expect("dérivation");
        let other = derive(b"mot de passe de test", &[2_u8; SALT_LEN], fast()).expect("dérivation");
        assert!(
            !first.constant_time_eq(&other),
            "le sel doit modifier la clé dérivée, sinon le salage ne sert à rien"
        );
    }

    #[test]
    fn different_params_give_different_key() {
        let salt = [7_u8; SALT_LEN];
        let low = derive(b"mot de passe de test", &salt, fast()).expect("dérivation");
        let stronger = derive(
            b"mot de passe de test",
            &salt,
            // Choisi juste au-dessus du plancher : le but est de vérifier que les
            // paramètres entrent bien dans la dérivation, pas de mesurer un coût.
            KdfParams::new(16 * 1024, 2, 1).expect("paramètres valides"),
        )
        .expect("dérivation");
        assert!(!low.constant_time_eq(&stronger));
    }

    #[test]
    fn generated_salts_are_distinct() {
        let first = generate_salt().expect("sel");
        let second = generate_salt().expect("sel");
        assert_ne!(first, second, "deux sels successifs identiques");
    }

    #[test]
    fn rejects_weak_and_excessive_parameters() {
        assert!(KdfParams::new(MIN_M_COST_KIB - 1, 3, 1).is_err());
        assert!(KdfParams::new(MAX_M_COST_KIB + 1, 3, 1).is_err());
        assert!(KdfParams::new(64 * 1024, 0, 1).is_err());
        assert!(KdfParams::new(64 * 1024, MAX_T_COST + 1, 1).is_err());
        assert!(KdfParams::new(64 * 1024, 3, 0).is_err());
        assert!(KdfParams::new(64 * 1024, 3, MAX_P_COST + 1).is_err());

        assert!(KdfParams::new(MIN_M_COST_KIB, 1, 1).is_ok());
        assert!(KdfParams::new(MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST).is_ok());
    }

    #[test]
    fn hostile_memory_request_is_refused_before_any_allocation() {
        // Le point important : le refus intervient sur la valeur du header, sans
        // que 4 Gio ne soient jamais alloués. Un test qui « réussirait » ici en
        // allouant serait un test dangereux à exécuter ; il ne doit pas atteindre
        // la phase d'allocation.
        let hostile = KdfParams::new(4 * 1024 * 1024, 3, 4);
        assert!(matches!(hostile, Err(Error::RejectedKdfParams { .. })));
    }

    #[test]
    fn wrong_salt_length_is_rejected() {
        let mut out = [0_u8; KEY_LEN];
        assert!(matches!(
            derive_into(b"x", &[0_u8; SALT_LEN - 1], fast(), &mut out),
            Err(Error::InvalidLength {
                field: "salt",
                expected: SALT_LEN,
                ..
            })
        ));
    }

    #[test]
    fn wrong_output_length_is_rejected() {
        let mut out = [0_u8; KEY_LEN - 1];
        assert!(matches!(
            derive_into(b"x", &[0_u8; SALT_LEN], fast(), &mut out),
            Err(Error::InvalidLength {
                field: "master key",
                ..
            })
        ));
    }

    #[test]
    fn oversized_password_is_rejected() {
        let huge = vec![0x41_u8; MAX_PASSWORD_LEN + 1];
        let mut out = [0_u8; KEY_LEN];
        assert!(matches!(
            derive_into(&huge, &[0_u8; SALT_LEN], fast(), &mut out),
            Err(Error::RejectedKdfParams { .. })
        ));
    }

    #[test]
    fn the_semaphore_serialises_with_a_single_permit() {
        use std::sync::atomic::AtomicUsize;

        let limiter = DerivationLimiter::new(1);
        let concurrent = AtomicUsize::new(0);
        let observed_max = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let _permit = limiter.acquire();
                    let now = concurrent.fetch_add(1, Ordering::AcqRel) + 1;
                    observed_max.fetch_max(now, Ordering::AcqRel);
                    std::thread::sleep(Duration::from_millis(5));
                    concurrent.fetch_sub(1, Ordering::AcqRel);
                });
            }
        });

        assert_eq!(
            observed_max.load(Ordering::Acquire),
            1,
            "avec une seule place, deux dérivations ne doivent jamais se chevaucher"
        );
    }

    #[test]
    fn raising_the_ceiling_actually_allows_concurrency() {
        use std::sync::atomic::AtomicUsize;

        let limiter = DerivationLimiter::new(4);
        let concurrent = AtomicUsize::new(0);
        let observed_max = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let _permit = limiter.acquire();
                    let now = concurrent.fetch_add(1, Ordering::AcqRel) + 1;
                    observed_max.fetch_max(now, Ordering::AcqRel);
                    std::thread::sleep(Duration::from_millis(20));
                    concurrent.fetch_sub(1, Ordering::AcqRel);
                });
            }
        });

        assert_eq!(
            observed_max.load(Ordering::Acquire),
            4,
            "le relèvement du plafond doit permettre quatre dérivations simultanées"
        );
    }

    #[test]
    fn a_panicking_holder_does_not_block_the_others() {
        // Un empoisonnement du verrou signifie qu'un thread a paniqué en détenant
        // une place. Le compteur reste cohérent, et le `Drop` de la place a bien
        // été exécuté pendant le déroulement de la pile : les suivants doivent
        // pouvoir continuer.
        let limiter = DerivationLimiter::new(1);

        // `thread::spawn` et non `thread::scope` : `scope` repropage la panique de
        // l'enfant, ce qui ferait échouer le test avant même d'examiner le limiteur.
        // `Arc` plutôt qu'un pointeur brut : `unsafe` est interdit dans ce crate, et
        // le limiteur est `Send + Sync` de toute façon.
        let limiter = std::sync::Arc::new(limiter);
        let handle = std::thread::spawn({
            let limiter = std::sync::Arc::clone(&limiter);
            move || {
                let _permit = limiter.acquire();
                panic!("panique volontaire pendant la détention d'une place");
            }
        });
        assert!(
            handle.join().is_err(),
            "le thread de test est censé avoir paniqué"
        );

        // Si le limiteur restait bloqué, cette acquisition ne retournerait jamais.
        let _permit = limiter.acquire();
        assert!(limiter.maximum() >= 1);
    }

    #[test]
    fn a_zero_ceiling_is_raised_to_one() {
        // Accepter zéro bloquerait indéfiniment toute dérivation : le programme ne
        // pourrait plus jamais ouvrir un coffre, sans message d'erreur.
        let limiter = DerivationLimiter::new(0);
        assert_eq!(limiter.maximum(), 1);

        limiter.set_maximum(0);
        assert_eq!(limiter.maximum(), 1);
    }

    #[test]
    fn concurrent_derivations_never_exceed_the_ceiling() {
        // Vérifie le **câblage** : le sémaphore peut être correct et n'être jamais
        // utilisé par `derive`. C'est exactement le genre d'oubli qu'un test du
        // sémaphore pris isolément ne détecterait pas.
        //
        // La propriété vérifiée est « ne jamais dépasser », et non « redescendre à
        // zéro après coup » : le limiteur est **global au processus**, et la suite de
        // tests exécute d'autres dérivations en parallèle. Une assertion sur un état
        // instantané serait instable sans rien prouver de plus.
        const CEILING: usize = 2;
        let _serialised = GLOBAL_LIMITER_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        set_max_concurrent_derivations(CEILING);

        let observed = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                // Échantillonne pendant que les dérivations s'exécutent.
                for _ in 0..2_000 {
                    observed.fetch_max(derivations_in_flight(), Ordering::AcqRel);
                    std::thread::yield_now();
                }
            });

            for _ in 0..4 {
                scope.spawn(|| {
                    let _ = derive(b"mesure de concurrence", &[0_u8; SALT_LEN], fast());
                });
            }
        });

        let peak = observed.load(Ordering::Acquire);
        assert!(
            peak <= CEILING,
            "le plafond de {CEILING} dérivations simultanées a été dépassé : {peak} observées"
        );

        // Rétablit la valeur par défaut, que d'autres tests partagent.
        set_max_concurrent_derivations(DEFAULT_MAX_CONCURRENT_DERIVATIONS);
    }

    #[test]
    fn a_derivation_cannot_finish_while_the_only_slot_is_taken() {
        // Test **déterministe** du câblage, et non un échantillonnage.
        //
        // Le raisonnement ne dépend pas de la charge : en détenant la seule place,
        // une dérivation correctement câblée ne PEUT pas se terminer. Une dérivation
        // non câblée, elle, s'achève en quelques dizaines de millisecondes au pire
        // (le plancher de validation), donc bien avant la fenêtre d'observation.
        let _serialised = GLOBAL_LIMITER_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        set_max_concurrent_derivations(1);
        let held = derivation_limiter().acquire();

        let handle = std::thread::spawn(|| derive(b"bloquee", &[0_u8; SALT_LEN], fast()));

        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !handle.is_finished(),
            "la dérivation s'est terminée alors que la seule place était détenue : \
             le limiteur n'est pas appliqué par le chemin réel"
        );

        drop(held);

        handle
            .join()
            .expect("le thread de dérivation ne doit pas paniquer")
            .expect("la dérivation doit aboutir une fois la place libérée");

        set_max_concurrent_derivations(DEFAULT_MAX_CONCURRENT_DERIVATIONS);
    }

    #[test]
    fn the_default_ceiling_is_a_single_derivation() {
        // La constante est vérifiée directement, sans passer par le limiteur
        // global : celui-ci est partagé avec les autres tests, qui s'exécutent en
        // parallèle et peuvent le modifier. Une assertion sur son état instantané
        // serait instable — et ne prouverait rien de plus que la constante.
        assert_eq!(
            DEFAULT_MAX_CONCURRENT_DERIVATIONS, 1,
            "le pic mémoire doit être plafonné à une seule dérivation par défaut"
        );
    }

    #[test]
    fn the_ceiling_is_configurable_on_a_limiter() {
        let limiter = DerivationLimiter::new(DEFAULT_MAX_CONCURRENT_DERIVATIONS);
        assert_eq!(limiter.maximum(), 1);

        limiter.set_maximum(3);
        assert_eq!(limiter.maximum(), 3);

        limiter.set_maximum(0);
        assert_eq!(
            limiter.maximum(),
            1,
            "un plafond nul bloquerait toute dérivation"
        );
    }

    #[test]
    fn the_global_setter_is_effective() {
        // Le verrou sérialise ce test avec le seul autre qui touche au limiteur
        // global : sans lui, la valeur pourrait être modifiée entre l'écriture et la
        // lecture, et l'échec serait indistinguable d'une régression.
        let _serialised = GLOBAL_LIMITER_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        set_max_concurrent_derivations(7);
        assert_eq!(max_concurrent_derivations(), 7);
        set_max_concurrent_derivations(DEFAULT_MAX_CONCURRENT_DERIVATIONS);
    }

    #[test]
    fn recommendation_flag_tracks_parameters() {
        assert!(KdfParams::low().is_below_recommendation());
        assert!(!KdfParams::standard().is_below_recommendation());
        assert!(!KdfParams::paranoid().is_below_recommendation());
    }
}
