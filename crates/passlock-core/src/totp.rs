//! HOTP (RFC 4226) et TOTP (RFC 6238).
//!
//! ## Passlock est le prouveur, pas le validateur
//!
//! La RFC 6238 définit deux rôles : le **prouveur**, qui produit un code à partir
//! d'un secret partagé et de l'heure, et le **validateur**, qui le vérifie. Ce
//! module implémente le prouveur, et **uniquement** le prouveur. Il n'y a ni
//! fenêtre de tolérance, ni resynchronisation, ni comparaison de codes reçus :
//! toute la section 6 de la RFC (« Resynchronization ») décrit le comportement du
//! **validateur** et n'a pas d'objet ici.
//!
//! Cette distinction a une conséquence directe, développée dans `docs/TOTP.md` :
//! **Passlock ne peut ni détecter ni corriger une horloge fausse.** Le serveur est
//! la seule référence temporelle du protocole.
//!
//! ## Pourquoi SHA-1 est supporté
//!
//! La RFC 6238 autorise HMAC-SHA-256 et HMAC-SHA-512 « à la place de HMAC-SHA-1 »,
//! et son implémentation de référence utilise HMAC-SHA-1. La justification précise
//! se trouve dans la RFC 4226, appendice B.2, texte exact :
//!
//! > The new attacks on SHA-1 have no impact on the security of HMAC-SHA-1. […]
//! > HMAC is not a hash function. It is a message authentication code (MAC) that
//! > uses a hash function internally. […] What one needs to worry about with a MAC
//! > is forgery, not collisions.
//!
//! Et B.3 :
//!
//! > The security proof of HOTP requires that HMAC-SHA-1 behave like a
//! > pseudorandom function. The quality of HMAC-SHA-1 as a pseudorandom function
//! > is not impacted by the new attacks on SHA-1.
//!
//! La règle de la phase 1 — « pas de SHA-1 » — vise SHA-1 comme **fonction de
//! hachage** et comme **fonction de dérivation de mot de passe**, où les
//! collisions et la vitesse comptent. Dans HMAC, l'attaque pertinente est la
//! falsification, et les collisions ne s'y transposent pas. Par ailleurs SHA-1 est
//! ce que les serveurs déploient : le refuser rendrait la fonction inutilisable.
//!
//! ## Preuve de conformité
//!
//! Les tests ne vérifient pas que ce code fait ce que son auteur attend, mais
//! qu'il fait ce que **la norme prescrit** : les 10 vecteurs de la RFC 4226
//! appendice D et les 18 vecteurs de la RFC 6238 appendice B sont reproduits
//! verbatim dans `tests/rfc_vectors.rs`.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::encoding;
use crate::error::{Error, Result};
use crate::secret::SecretVec;

/// Période par défaut, en secondes.
///
/// RFC 6238 §5.2 : « We RECOMMEND a default time-step size of 30 seconds. »
pub const DEFAULT_PERIOD: u32 = 30;

/// Période minimale acceptée.
pub const MIN_PERIOD: u32 = 1;

/// Période maximale acceptée.
///
/// La RFC ne fixe pas de borne. 600 secondes couvre largement les déploiements
/// réels (30, 60, 90) sans laisser entrer une valeur qui rendrait la fenêtre de
/// validité absurde.
pub const MAX_PERIOD: u32 = 600;

/// Longueur minimale d'un secret, en octets.
///
/// RFC 4226 §4, exigence R6 : « The length of the shared secret MUST be at least
/// 128 bits. » Un secret plus court est **refusé**, jamais corrigé ni complété :
/// « réparer » un secret produirait des codes que le serveur ne reconnaîtrait pas,
/// en donnant l'illusion que tout va bien.
pub const MIN_SECRET_LEN: usize = 16;

/// Longueur de secret recommandée, en octets.
///
/// RFC 4226 §4, R6 : « This document RECOMMENDs a shared secret length of 160
/// bits. » C'est la longueur engendrée par [`Totp::generate`].
pub const RECOMMENDED_SECRET_LEN: usize = 20;

/// Longueur maximale d'un secret, en octets.
pub const MAX_SECRET_LEN: usize = 128;

/// Longueur maximale d'une URI `otpauth://` acceptée.
///
/// Bien en deçà des 64 Kio qu'un champ peut porter : une URI TOTP réelle fait
/// quelques dizaines d'octets, et cette borne est vérifiée **avant** tout travail.
pub const MAX_URI_LEN: usize = 2048;

/// Longueur maximale d'un libellé ou d'un émetteur.
pub const MAX_TEXT_LEN: usize = 256;

/// Algorithme de hachage sous-jacent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1. Défaut de la RFC 4226 et de tous les déploiements réels.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// Nom canonique utilisé dans les URI `otpauth://`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Analyse un nom d'algorithme, insensible à la casse.
    ///
    /// Accepte les deux graphies rencontrées dans la nature : `SHA1` (celle du
    /// format `otpauth`) et `SHA-1` (celle de la RFC).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized: String = text
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .flat_map(char::to_uppercase)
            .collect();

        match normalized.as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Nombre de chiffres du code.
///
/// RFC 4226 §5.3 autorise 6, 7 ou 8 chiffres. La valeur 7 est délibérément exclue :
/// aucun déploiement réel ne l'utilise, et offrir une valeur jamais rencontrée
/// élargirait la surface de test sans bénéfice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Digits {
    /// Code à six chiffres.
    #[default]
    Six,
    /// Code à huit chiffres.
    Eight,
}

impl Digits {
    /// Nombre de chiffres sous forme entière.
    #[must_use]
    pub const fn count(self) -> u32 {
        match self {
            Self::Six => 6,
            Self::Eight => 8,
        }
    }

    /// Analyse une valeur numérique de chiffres.
    #[must_use]
    pub const fn parse(value: u32) -> Option<Self> {
        match value {
            6 => Some(Self::Six),
            8 => Some(Self::Eight),
            _ => None,
        }
    }
}

/// Paramètres TOTP complets, secret compris.
///
/// Ce type porte un secret. Il n'implémente donc **ni `Clone`, ni `PartialEq`** :
/// une copie implicite serait une copie non suivie, qui survivrait à l'effacement
/// de l'originale, et une comparaison serait un oracle de synchronisation. Son
/// `Debug` est rédigé à la main et n'affiche jamais le secret.
pub struct Totp {
    secret: SecretVec,
    algorithm: Algorithm,
    digits: Digits,
    period: u32,
    label: String,
    issuer: Option<String>,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("secret_len", &self.secret.len())
            .field("secret", &"[EXPURGÉ]")
            .field("label_len", &self.label.len())
            .field("issuer_len", &self.issuer.as_ref().map_or(0, String::len))
            .finish()
    }
}

impl Totp {
    /// Construit un TOTP à partir de ses éléments, en validant chacun.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] si le secret est hors bornes, si la période est hors
    /// bornes, ou si le libellé ou l'émetteur contient un caractère de contrôle ou
    /// dépasse sa longueur maximale.
    pub fn new(
        secret: &[u8],
        algorithm: Algorithm,
        digits: Digits,
        period: u32,
        label: impl Into<String>,
        issuer: Option<impl Into<String>>,
    ) -> Result<Self> {
        validate_secret_len(secret.len())?;
        validate_period(period)?;

        let label = label.into();
        validate_text(&label, "libellé")?;

        let issuer = match issuer {
            Some(value) => {
                let value = value.into();
                validate_text(&value, "émetteur")?;
                Some(value)
            }
            None => None,
        };

        Ok(Self {
            secret: SecretVec::from_slice(secret),
            algorithm,
            digits,
            period,
            label,
            issuer,
        })
    }

    /// Engendre un TOTP doté d'un secret neuf.
    ///
    /// Le secret est tiré du générateur du système (via [`crate::rng`]) et fait
    /// [`RECOMMENDED_SECRET_LEN`] octets, soit 160 bits — la longueur recommandée
    /// par la RFC 4226 §4 R6.
    ///
    /// # Erreurs
    /// Propage l'échec du générateur, et les mêmes refus que [`Totp::new`].
    pub fn generate(
        algorithm: Algorithm,
        digits: Digits,
        period: u32,
        label: impl Into<String>,
        issuer: Option<impl Into<String>>,
    ) -> Result<Self> {
        let mut secret = SecretVec::zeroed(RECOMMENDED_SECRET_LEN);
        crate::rng::fill(secret.expose_mut())?;

        Self::new(secret.expose(), algorithm, digits, period, label, issuer)
    }

    /// Algorithme retenu.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Nombre de chiffres retenu.
    #[must_use]
    pub const fn digits(&self) -> Digits {
        self.digits
    }

    /// Période retenue, en secondes.
    #[must_use]
    pub const fn period(&self) -> u32 {
        self.period
    }

    /// Libellé associé.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Longueur du secret, en octets.
    ///
    /// Le secret lui-même n'est jamais exposé : seuls les codes le sont. Cette
    /// accesseur sert à **vérifier** une longueur — à l'affichage d'un diagnostic,
    /// ou lors d'un aller-retour d'URI — sans donner prise sur la valeur.
    #[must_use]
    pub fn secret_len(&self) -> usize {
        self.secret.len()
    }

    /// Émetteur associé, s'il est connu.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Numéro de pas de temps correspondant à un instant Unix.
    ///
    /// `T = (instant − T0) / X` avec `T0 = 0` et `X` la période (RFC 6238 §4.2).
    #[must_use]
    pub const fn counter_at(&self, unix_time: u64) -> u64 {
        unix_time / self.period as u64
    }

    /// Secondes restantes avant le changement de pas.
    ///
    /// Toujours comprise entre `1` et la période : la valeur n'est jamais nulle,
    /// car un compte à rebours affichant « 0 s » inviterait à recopier un code
    /// déjà mort.
    #[must_use]
    pub const fn remaining(&self, unix_time: u64) -> u32 {
        let period = self.period as u64;
        // Le reste est strictement inférieur à la période, elle-même bornée par
        // `MAX_PERIOD` (600) : la valeur tient donc toujours sur 32 bits.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "reste strictement inférieur à MAX_PERIOD, donc à 600"
        )]
        let elapsed = (unix_time % period) as u32;
        self.period - elapsed
    }

    /// Code TOTP pour un instant donné.
    ///
    /// **L'instant est un paramètre, le module ne lit jamais l'horloge.** C'est ce
    /// qui rend ce code rejouable sur les vecteurs de la RFC, donc vérifiable, et
    /// ce qui interdit d'y glisser une lecture d'horloge non maîtrisée.
    ///
    /// Le résultat est effacé à sa destruction : un code est un secret de courte
    /// durée, mais c'en est un.
    ///
    /// # Erreurs
    /// [`Error::Internal`] si la troncature dynamique sort des bornes de
    /// l'empreinte — situation impossible, mais écrite plutôt que supposée.
    pub fn code(&self, unix_time: u64) -> Result<Zeroizing<String>> {
        hotp(
            self.secret.expose(),
            self.counter_at(unix_time),
            self.algorithm,
            self.digits,
        )
    }
}

/// Calcule un code HOTP (RFC 4226).
///
/// # Erreurs
/// [`Error::InvalidLength`] si la clé est vide, [`Error::Internal`] si la
/// troncature sort des bornes de l'empreinte.
pub fn hotp(
    secret: &[u8],
    counter: u64,
    algorithm: Algorithm,
    digits: Digits,
) -> Result<Zeroizing<String>> {
    if secret.is_empty() {
        return Err(Error::InvalidLength {
            field: "secret HOTP",
            expected: MIN_SECRET_LEN,
            actual: 0,
        });
    }

    // Le compteur est encodé sur **huit** octets, jamais quatre : la RFC 6238 §4.2
    // exige le support d'un instant au-delà de 2038, ce que le vecteur
    // `20000000000` (an 2603) vérifie.
    let message = counter.to_be_bytes();

    // Tampon de pile effacé à la destruction : l'empreinte HMAC est dérivée du
    // secret. Elle n'est pas le secret lui-même, mais elle n'a aucune raison de
    // survivre à la fonction.
    let mut digest = Zeroizing::new([0_u8; 64]);
    let digest_len = compute_mac(secret, &message, algorithm, digest.as_mut())?;

    // --- Troncature dynamique (RFC 4226 §5.3) ---
    //
    // L'offset vient des **quatre derniers bits du dernier octet** de l'empreinte.
    // L'invariant qui compte : `offset ≤ 15`, et l'empreinte fait au moins 20
    // octets, donc `offset + 4 ≤ 19 < 20 ≤ digest_len`. La lecture est dans les
    // bornes par construction ; le `get` le vérifie plutôt que de le supposer.
    let last = digest
        .get(digest_len - 1)
        .ok_or(Error::Internal {
            invariant: "empreinte HMAC vide",
        })?
        .to_owned();
    let offset = usize::from(last & 0x0F);

    let window = digest.get(offset..offset + 4).ok_or(Error::Internal {
        invariant: "troncature HOTP hors des bornes de l'empreinte",
    })?;

    let mut value = u32::from_be_bytes([window[0], window[1], window[2], window[3]]);
    // Dernier bit de poids fort masqué : la valeur reste sur 31 bits, donc
    // strictement positive.
    value &= 0x7FFF_FFFF;

    let modulus = 10_u32.pow(digits.count());
    let code = value % modulus;

    Ok(Zeroizing::new(format!(
        "{code:0width$}",
        width = digits.count() as usize
    )))
}

/// Calcule l'empreinte HMAC dans `out` et retourne sa longueur.
///
/// Les trois algorithmes ne diffèrent que par le type de hachage : la macro évite
/// de recopier trois fois la même séquence d'appels, où une divergence entre les
/// branches passerait inaperçue.
macro_rules! compute_mac_arm {
    ($hash:ty, $secret:expr, $message:expr, $out:expr) => {{
        let mut mac =
            <Hmac<$hash> as KeyInit>::new_from_slice($secret).map_err(|_| Error::Internal {
                invariant: "HMAC refuse une clé de longueur arbitraire",
            })?;
        Mac::update(&mut mac, $message);
        let bytes = mac.finalize().into_bytes();
        let len = bytes.len();
        let slot = $out.get_mut(..len).ok_or(Error::Internal {
            invariant: "empreinte HMAC plus longue que le tampon de travail",
        })?;
        slot.copy_from_slice(&bytes);
        len
    }};
}

/// Applique la macro au type de hachage choisi.
fn compute_mac(
    secret: &[u8],
    message: &[u8],
    algorithm: Algorithm,
    out: &mut [u8],
) -> Result<usize> {
    match algorithm {
        Algorithm::Sha1 => Ok(compute_mac_arm!(Sha1, secret, message, out)),
        Algorithm::Sha256 => Ok(compute_mac_arm!(Sha256, secret, message, out)),
        Algorithm::Sha512 => Ok(compute_mac_arm!(Sha512, secret, message, out)),
    }
}

/// Vérifie la longueur d'un secret.
fn validate_secret_len(len: usize) -> Result<()> {
    if len < MIN_SECRET_LEN {
        return Err(Error::InvalidInput {
            reason: "secret TOTP trop court : la RFC 4226 §4 R6 en exige au moins \
                     128 bits (16 octets)",
        });
    }
    if len > MAX_SECRET_LEN {
        return Err(Error::InvalidInput {
            reason: "secret TOTP au-delà de la longueur maximale admise",
        });
    }
    Ok(())
}

/// Vérifie la période.
fn validate_period(period: u32) -> Result<()> {
    if !(MIN_PERIOD..=MAX_PERIOD).contains(&period) {
        return Err(Error::InvalidInput {
            reason: "période TOTP hors des bornes admises (1 à 600 secondes)",
        });
    }
    Ok(())
}

/// Vérifie un texte destiné à l'affichage.
///
/// ## Pourquoi les caractères de contrôle sont refusés ici
///
/// Un libellé ou un émetteur peut contenir une séquence d'échappement ANSI. Sur un
/// terminal, une telle séquence **réécrit le tampon de l'écran** : elle peut
/// effacer le code affiché et le remplacer par un autre. Un attaquant qui contrôle
/// le libellé d'une entrée importée contrôlerait donc ce que l'utilisateur croit
/// lire.
///
/// Le refus a lieu **à l'entrée**, pas à l'affichage. Échapper au moment de
/// l'affichage serait une défense au point d'usage, qu'un futur site d'affichage
/// oublierait ; refuser à l'analyse protège tous les usages présents et à venir.
/// C'est la même logique que la phase 2 : *le lieu d'une vérification est
/// lui-même une propriété de sécurité*.
fn validate_text(text: &str, what: &'static str) -> Result<()> {
    if text.len() > MAX_TEXT_LEN {
        return Err(Error::InvalidInput { reason: what });
    }
    if text.chars().any(char::is_control) {
        return Err(Error::InvalidInput { reason: what });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Format d'échange otpauth://
// ---------------------------------------------------------------------------

/// Préfixe de schéma attendu.
const SCHEME: &[u8] = b"otpauth://";

impl Totp {
    /// Analyse une URI `otpauth://totp/…`.
    ///
    /// ## Le texte analysé n'est pas fiable
    ///
    /// Cette chaîne vient d'un champ du coffre : elle est **authentifiée** par
    /// l'AEAD, mais **pas valide par construction**. Elle peut avoir été écrite par
    /// une version antérieure, importée (phase 4), ou forgée par quiconque détient
    /// la clé. Elle est donc traitée comme une entrée non fiable : bornes fermées,
    /// échec fermé, et **jamais** de réparation silencieuse.
    ///
    /// ## Ce qui est refusé
    ///
    /// - longueur supérieure à [`MAX_URI_LEN`], vérifiée avant tout travail ;
    /// - schéma autre que `otpauth`, type autre que `totp` — **`hotp` est refusé**
    ///   explicitement : compteur non temporel, sémantique différente, et
    ///   l'accepter « au cas où » créerait un chemin non testé ;
    /// - `secret` absent, vide, hors alphabet Base32, ou donnant un secret de
    ///   moins de 128 bits ;
    /// - `digits` hors de {6, 8}, `period` hors de 1 à 600, `algorithm` inconnu ;
    /// - séquence d'échappement pourcent malformée ;
    /// - caractère de contrôle dans le libellé ou l'émetteur.
    ///
    /// ## Ce qui est toléré
    ///
    /// Les paramètres **inconnus sont ignorés**, pas rejetés : les URI réelles en
    /// portent (`image=`, `lock=true`…) et les refuser rendrait l'analyse
    /// inutilisable. Ignorer un paramètre inconnu n'est pas échouer ouvert : les
    /// paramètres connus, eux, sont validés strictement.
    ///
    /// # Erreurs
    /// [`Error::InvalidInput`] dans tous les cas de refus ci-dessus.
    pub fn parse_uri(uri: &str) -> Result<Self> {
        if uri.len() > MAX_URI_LEN {
            return Err(Error::InvalidInput {
                reason: "URI otpauth au-delà de la longueur maximale admise",
            });
        }

        let bytes = uri.as_bytes();
        if bytes.len() < SCHEME.len() || !bytes[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
            return Err(Error::InvalidInput {
                reason: "URI otpauth : schéma absent ou inconnu",
            });
        }

        // Après avoir constaté que les octets du préfixe sont ceux du schéma ASCII,
        // la position est nécessairement une frontière de caractère. La vérifier
        // transforme une panique potentielle en erreur — le coût est nul.
        if !uri.is_char_boundary(SCHEME.len()) {
            return Err(Error::InvalidInput {
                reason: "URI otpauth : frontière de caractère invalide",
            });
        }
        let rest = &uri[SCHEME.len()..];

        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, raw_label) = path.split_once('/').unwrap_or((path, ""));

        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidInput {
                reason: "URI otpauth : seul le type « totp » est supporté (HOTP est \
                         refusé, son compteur n'est pas temporel)",
            });
        }

        let label = percent_decode(raw_label)?;

        let mut secret: Option<SecretVec> = None;
        let mut issuer: Option<String> = None;
        let mut algorithm = Algorithm::default();
        let mut digits = Digits::default();
        let mut period = DEFAULT_PERIOD;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));

            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    if secret.is_some() {
                        return Err(Error::InvalidInput {
                            reason: "URI otpauth : paramètre « secret » répété",
                        });
                    }
                    let decoded = encoding::base32_decode(value)?;
                    validate_secret_len(decoded.len())?;
                    secret = Some(decoded);
                }
                "issuer" => {
                    issuer = Some(percent_decode(value)?);
                }
                "algorithm" => {
                    algorithm = Algorithm::parse(value).ok_or(Error::InvalidInput {
                        reason: "URI otpauth : algorithme inconnu",
                    })?;
                }
                "digits" => {
                    let count = parse_decimal(value, 2)?;
                    digits = Digits::parse(count).ok_or(Error::InvalidInput {
                        reason: "URI otpauth : nombre de chiffres hors de {6, 8}",
                    })?;
                }
                "period" => {
                    let seconds = parse_decimal(value, 6)?;
                    validate_period(seconds)?;
                    period = seconds;
                }
                // Paramètres inconnus : ignorés délibérément. Voir la documentation.
                _ => {}
            }
        }

        let secret = secret.ok_or(Error::InvalidInput {
            reason: "URI otpauth : paramètre « secret » absent",
        })?;

        validate_text(&label, "libellé d'URI otpauth")?;
        if let Some(ref value) = issuer {
            validate_text(value, "émetteur d'URI otpauth")?;
        }

        // Le libellé d'une URI porte souvent « Émetteur:compte ». Si aucun
        // `issuer=` n'est fourni, la partie gauche fait office d'émetteur — c'est
        // la convention des exportateurs du domaine.
        let (derived_issuer, account) = match label.split_once(':') {
            Some((left, right)) => (Some(left.trim().to_owned()), right.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };
        let issuer = issuer.or(derived_issuer);

        // Le libellé retenu est le compte seul, plus lisible que le libellé complet
        // de l'URI ; l'émetteur est conservé à part.
        Self::new(secret.expose(), algorithm, digits, period, account, issuer)
    }

    /// Produit l'URI `otpauth://` correspondante.
    ///
    /// Le remplissage Base32 est omis, comme le font les outils du domaine.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut label = String::new();
        if let Some(issuer) = &self.issuer {
            label.push_str(&percent_encode(issuer));
            label.push(':');
        }
        label.push_str(&percent_encode(&self.label));

        let mut uri = format!(
            "otpauth://totp/{label}?secret={}&algorithm={}&digits={}&period={}",
            encoding::base32_encode_unpadded(self.secret.expose()),
            self.algorithm.label(),
            self.digits.count(),
            self.period,
        );

        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        uri
    }
}

/// Analyse un entier décimal borné en nombre de chiffres.
fn parse_decimal(value: &str, max_digits: usize) -> Result<u32> {
    if value.is_empty() || value.len() > max_digits || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidInput {
            reason: "URI otpauth : paramètre numérique invalide",
        });
    }
    value.parse::<u32>().map_err(|_| Error::InvalidInput {
        reason: "URI otpauth : paramètre numérique hors bornes",
    })
}

/// Décode les séquences `%XX` d'une composante d'URI.
///
/// Strict par construction : un `%` non suivi de deux chiffres hexadécimaux est
/// une erreur, jamais un caractère littéral. La sortie est validée en UTF-8.
fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).copied().and_then(hex_digit);
            let low = bytes.get(index + 2).copied().and_then(hex_digit);

            match (high, low) {
                (Some(high), Some(low)) => {
                    // `high` et `low` sont dans 0..=15 : le produit tient sur 8 bits.
                    out.push((high << 4) | low);
                    index += 3;
                }
                _ => {
                    return Err(Error::InvalidInput {
                        reason: "URI otpauth : séquence d'échappement pourcent malformée",
                    });
                }
            }
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(out).map_err(|_| Error::InvalidInput {
        reason: "URI otpauth : texte non conforme à UTF-8 après décodage",
    })
}

/// Encode les caractères non réservés d'une composante d'URI.
///
/// N'échappe que ce que la RFC 3986 impose : les caractères non réservés
/// (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~`) passent tels quels.
#[must_use]
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_symbol(byte >> 4));
            out.push(hex_symbol(byte & 0x0F));
        }
    }
    out
}

/// Symbole hexadécimal majuscule d'un quartet.
fn hex_symbol(nibble: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(nibble & 0x0F)])
}

/// Valeur d'un chiffre hexadécimal.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Secret de test : 20 octets, la longueur recommandée.
    const SECRET: &[u8] = b"12345678901234567890";

    fn totp() -> Totp {
        Totp::new(
            SECRET,
            Algorithm::Sha1,
            Digits::Six,
            DEFAULT_PERIOD,
            "alice@exemple.fr",
            Some("Exemple"),
        )
        .expect("construction")
    }

    #[test]
    fn the_counter_follows_the_rfc_definition() {
        // RFC 6238 §4.2 : « T = 1 if the current Unix time is 59 seconds, and
        // T = 2 if the current Unix time is 60 seconds. »
        let totp = totp();
        assert_eq!(totp.counter_at(0), 0);
        assert_eq!(totp.counter_at(29), 0);
        assert_eq!(totp.counter_at(30), 1);
        assert_eq!(totp.counter_at(59), 1);
        assert_eq!(totp.counter_at(60), 2);
    }

    #[test]
    fn the_remaining_time_is_never_zero() {
        let totp = totp();
        for instant in [0_u64, 1, 29, 30, 59, 60, 1_700_000_000] {
            let remaining = totp.remaining(instant);
            assert!(
                (1..=DEFAULT_PERIOD).contains(&remaining),
                "instant {instant} : reste {remaining}"
            );
        }
        assert_eq!(totp.remaining(0), 30);
        assert_eq!(totp.remaining(29), 1);
        assert_eq!(totp.remaining(30), 30);
    }

    #[test]
    fn the_code_has_exactly_the_requested_number_of_digits() {
        for digits in [Digits::Six, Digits::Eight] {
            let totp = Totp::new(
                SECRET,
                Algorithm::Sha1,
                digits,
                DEFAULT_PERIOD,
                "test",
                None::<String>,
            )
            .expect("construction");

            for instant in [0_u64, 59, 1_700_000_000, 2_000_000_000] {
                let code = totp.code(instant).expect("code");
                assert_eq!(
                    code.len(),
                    digits.count() as usize,
                    "code « {} » pour {digits:?}",
                    *code
                );
                assert!(code.chars().all(|c| c.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn a_secret_shorter_than_128_bits_is_refused() {
        // 15 octets : sous le plancher de la RFC 4226 §4 R6.
        let outcome = Totp::new(
            &[0x21; 15],
            Algorithm::Sha1,
            Digits::Six,
            DEFAULT_PERIOD,
            "test",
            None::<String>,
        );
        assert!(
            matches!(outcome, Err(Error::InvalidInput { .. })),
            "un secret de 120 bits doit être refusé, pas complété"
        );

        // 16 octets : exactement au plancher, accepté.
        assert!(
            Totp::new(
                &[0x21; 16],
                Algorithm::Sha1,
                Digits::Six,
                DEFAULT_PERIOD,
                "test",
                None::<String>,
            )
            .is_ok()
        );

        // 129 octets : au-delà du plafond.
        assert!(
            Totp::new(
                &[0x21; 129],
                Algorithm::Sha1,
                Digits::Six,
                DEFAULT_PERIOD,
                "test",
                None::<String>,
            )
            .is_err()
        );
    }

    #[test]
    fn periods_outside_the_bounds_are_refused() {
        assert!(validate_period(0).is_err());
        assert!(validate_period(1).is_ok());
        assert!(validate_period(30).is_ok());
        assert!(validate_period(600).is_ok());
        assert!(validate_period(601).is_err());
        assert!(validate_period(u32::MAX).is_err());
    }

    /// Le libellé ne doit pas pouvoir porter de séquence d'échappement.
    #[test]
    fn control_characters_in_a_label_are_refused() {
        // Une séquence ANSI qui effacerait la ligne et réafficherait autre chose.
        let attack = "Exemple\x1b[2K\x1b[G  Code : 00000000";
        assert!(
            Totp::new(
                SECRET,
                Algorithm::Sha1,
                Digits::Six,
                DEFAULT_PERIOD,
                attack,
                None::<String>,
            )
            .is_err(),
            "un libellé portant une séquence ANSI doit être refusé"
        );

        // Le titre de fenêtre, autre vecteur classique.
        assert!(
            Totp::new(
                SECRET,
                Algorithm::Sha1,
                Digits::Six,
                DEFAULT_PERIOD,
                "x\x1b]0;pwned\x07",
                None::<String>,
            )
            .is_err()
        );

        // Un simple saut de ligne suffit à fausser un affichage.
        assert!(
            Totp::new(
                SECRET,
                Algorithm::Sha1,
                Digits::Six,
                DEFAULT_PERIOD,
                "deux\nlignes",
                None::<String>,
            )
            .is_err()
        );
    }

    #[test]
    fn the_secret_is_never_printed_by_debug() {
        let totp = totp();
        let rendered = format!("{totp:?}");
        // Le secret est `12345678901234567890` ; aucun de ses fragments ne doit
        // apparaître, ni sa longueur en clair sous forme de contenu.
        for fragment in ["1234567890", "12345678901234567890", "31323334"] {
            assert!(
                !rendered.contains(fragment),
                "« {fragment} » trouvé dans le Debug : {rendered}"
            );
        }
        assert!(rendered.contains("[EXPURGÉ]"));
        assert!(rendered.contains("secret_len"));
    }

    #[test]
    fn a_generated_secret_has_the_recommended_length() {
        let totp = Totp::generate(
            Algorithm::Sha1,
            Digits::Six,
            DEFAULT_PERIOD,
            "test",
            None::<String>,
        )
        .expect("génération");

        assert_eq!(totp.secret.len(), RECOMMENDED_SECRET_LEN);
        // 160 bits, la longueur recommandée par la RFC 4226 §4 R6.
        assert_eq!(totp.secret.len() * 8, 160);
        assert!(totp.code(1_700_000_000).is_ok());
    }

    #[test]
    fn two_generated_secrets_differ() {
        let first = Totp::generate(
            Algorithm::Sha1,
            Digits::Six,
            DEFAULT_PERIOD,
            "a",
            None::<String>,
        )
        .expect("génération");
        let second = Totp::generate(
            Algorithm::Sha1,
            Digits::Six,
            DEFAULT_PERIOD,
            "b",
            None::<String>,
        )
        .expect("génération");
        assert_ne!(first.secret.expose(), second.secret.expose());
    }

    // -- Analyse d'URI ------------------------------------------------------

    #[test]
    fn a_well_formed_uri_is_parsed() {
        let uri = "otpauth://totp/Exemple:alice@exemple.fr?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &issuer=Exemple&algorithm=SHA256&digits=8&period=60";
        let totp = Totp::parse_uri(uri).expect("analyse");

        assert_eq!(totp.algorithm(), Algorithm::Sha256);
        assert_eq!(totp.digits(), Digits::Eight);
        assert_eq!(totp.period(), 60);
        assert_eq!(totp.issuer(), Some("Exemple"));
        assert_eq!(totp.label(), "alice@exemple.fr");
        assert_eq!(totp.secret.len(), 20);
    }

    #[test]
    fn defaults_apply_when_parameters_are_absent() {
        let totp = Totp::parse_uri("otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
            .expect("analyse");
        assert_eq!(totp.algorithm(), Algorithm::Sha1);
        assert_eq!(totp.digits(), Digits::Six);
        assert_eq!(totp.period(), DEFAULT_PERIOD);
        assert_eq!(totp.issuer(), None);
    }

    /// L'issuer dérivé du libellé, convention des exportateurs du domaine.
    #[test]
    fn the_issuer_is_derived_from_the_label_when_absent() {
        let totp =
            Totp::parse_uri("otpauth://totp/Banque:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
                .expect("analyse");
        assert_eq!(totp.issuer(), Some("Banque"));
        assert_eq!(totp.label(), "alice");
    }

    #[test]
    fn unknown_parameters_are_ignored_not_rejected() {
        let uri = "otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &image=https%3A%2F%2Fexemple.fr%2Flogo.png&lock=true";
        assert!(Totp::parse_uri(uri).is_ok());
    }

    #[test]
    fn hotp_uris_are_refused_explicitly() {
        let outcome = Totp::parse_uri(
            "otpauth://hotp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&counter=0",
        );
        assert!(
            matches!(outcome, Err(Error::InvalidInput { .. })),
            "le type hotp doit être refusé, son compteur n'est pas temporel"
        );
    }

    #[test]
    fn a_missing_or_empty_secret_is_refused() {
        assert!(Totp::parse_uri("otpauth://totp/Compte").is_err());
        assert!(Totp::parse_uri("otpauth://totp/Compte?secret=").is_err());
        assert!(Totp::parse_uri("otpauth://totp/Compte?issuer=X").is_err());
    }

    #[test]
    fn a_short_decoded_secret_is_refused() {
        // « MZXW6 » décode « foo », soit 3 octets : très en dessous du plancher.
        let outcome = Totp::parse_uri("otpauth://totp/Compte?secret=MZXW6");
        assert!(matches!(outcome, Err(Error::InvalidInput { .. })));
    }

    #[test]
    fn invalid_base32_in_a_secret_is_refused() {
        // 0, 1, 8 et 9 sont hors de l'alphabet Base32.
        for secret in ["0189JBSWY3DPEHPK3PXP", "JBSWY3DP!HPK3PXPJBSW"] {
            let uri = format!("otpauth://totp/Compte?secret={secret}");
            assert!(
                Totp::parse_uri(&uri).is_err(),
                "« {secret} » devrait être refusé"
            );
        }
    }

    #[test]
    fn out_of_range_numeric_parameters_are_refused() {
        let base = "otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        for suffix in [
            "&digits=7",
            "&digits=0",
            "&digits=99",
            "&digits=abc",
            "&digits=",
            "&period=0",
            "&period=601",
            "&period=",
            "&period=99999999",
            "&algorithm=MD5",
            "&algorithm=",
        ] {
            let uri = format!("{base}{suffix}");
            assert!(
                Totp::parse_uri(&uri).is_err(),
                "« {suffix} » devrait être refusé"
            );
        }
    }

    #[test]
    fn a_repeated_secret_parameter_is_refused() {
        let uri = "otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        assert!(
            Totp::parse_uri(uri).is_err(),
            "un paramètre secret répété doit être refusé : ambiguïté exploitable"
        );
    }

    #[test]
    fn the_scheme_is_case_insensitive_but_must_be_otpauth() {
        assert!(
            Totp::parse_uri("OTPAUTH://TOTP/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
                .is_ok()
        );
        assert!(
            Totp::parse_uri("otpauth://TOTP/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
                .is_ok()
        );

        for bad in [
            "https://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth:/totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauthx://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        ] {
            assert!(
                Totp::parse_uri(bad).is_err(),
                "« {bad} » devrait être refusé"
            );
        }
    }

    #[test]
    fn a_malformed_percent_sequence_is_refused() {
        for bad in [
            "otpauth://totp/Compte%?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/Compte%A?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/Compte%ZZ?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/Compte%2?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        ] {
            assert!(
                Totp::parse_uri(bad).is_err(),
                "« {bad} » devrait être refusé"
            );
        }
    }

    #[test]
    fn percent_encoding_round_trips_through_the_uri() {
        let totp = Totp::new(
            SECRET,
            Algorithm::Sha256,
            Digits::Eight,
            60,
            "alice@exemple.fr",
            Some("Banque Générale & Cie"),
        )
        .expect("construction");

        let uri = totp.to_uri();
        let parsed = Totp::parse_uri(&uri).expect("analyse de notre propre URI");

        assert_eq!(parsed.algorithm(), Algorithm::Sha256);
        assert_eq!(parsed.digits(), Digits::Eight);
        assert_eq!(parsed.period(), 60);
        assert_eq!(parsed.label(), "alice@exemple.fr");
        assert_eq!(parsed.issuer(), Some("Banque Générale & Cie"));
        assert_eq!(parsed.secret.expose(), SECRET);
    }

    #[test]
    fn an_oversized_uri_is_refused_before_any_work() {
        let uri = format!("otpauth://totp/Compte?secret={}", "A".repeat(MAX_URI_LEN));
        assert!(matches!(
            Totp::parse_uri(&uri),
            Err(Error::InvalidInput { .. })
        ));
    }

    #[test]
    fn the_algorithm_name_accepts_both_written_forms() {
        for (text, expected) in [
            ("SHA1", Algorithm::Sha1),
            ("sha1", Algorithm::Sha1),
            ("SHA-1", Algorithm::Sha1),
            ("Sha-256", Algorithm::Sha256),
            ("SHA_512", Algorithm::Sha512),
        ] {
            assert_eq!(Algorithm::parse(text), Some(expected), "« {text} »");
        }
        for text in ["", "MD5", "SHA3", "SHA", "SHA1024"] {
            assert_eq!(
                Algorithm::parse(text),
                None,
                "« {text} » devrait être refusé"
            );
        }
    }
}
