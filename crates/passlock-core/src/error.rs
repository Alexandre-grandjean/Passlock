//! Type d'erreur du moteur.
//!
//! ## Deux contraintes de sécurité pèsent sur ce module
//!
//! ### 1. Aucune erreur ne contient de secret
//!
//! Aucune variante ne porte de `String` construite à partir de données du coffre,
//! ni du mot de passe maître, ni d'un matériel de clé. Toutes les charges utiles
//! sont des `&'static str` choisies dans le code. Un message d'erreur peut donc
//! être journalisé sans précaution, ce qui évite d'avoir à faire confiance à la
//! discipline de chaque site d'appel.
//!
//! ### 2. Pas d'oracle distinguant « mauvais mot de passe » de « coffre altéré »
//!
//! Un attaquant qui ne connaît pas le mot de passe maître ne doit pas pouvoir
//! apprendre si sa tentative a échoué parce que le mot de passe était faux ou
//! parce que le conteneur avait été modifié. Ces deux causes produisent donc
//! [`Error::UnlockFailed`], avec un message strictement identique.
//!
//! **La règle exacte**, établie lors de l'audit adversarial de la phase 1. Une
//! version antérieure de cette documentation affirmait que « toute altération de
//! slot produit `UnlockFailed` », ce qui était faux :
//!
//! | Nature de l'altération | Erreur produite | Dépend du mot de passe ? |
//! |---|---|---|
//! | viole un invariant structurel (rôle inconnu, plus de slot maître, champ réservé non nul, algorithme inconnu) | erreur de format explicite | **non** |
//! | préserve la structure (octets de la clé enveloppée, sel, paramètres de dérivation, identifiant de coffre, rôle restant valide) | [`Error::UnlockFailed`] | **non** |
//! | le slot s'ouvre mais le payload est altéré | [`Error::Corrupted`] | oui — il faut la clé |
//!
//! **La propriété qui compte est la troisième colonne.** Aucun message d'erreur ne
//! dépend de la valeur du mot de passe : un attaquant ne peut donc pas s'en servir
//! comme oracle pour deviner le secret. Savoir qu'un fichier *qu'il a lui-même
//! modifié* est devenu structurellement invalide ne lui apprend rien.
//!
//! La distinction `UnlockFailed` / `Corrupted` est, elle, volontairement utile :
//! pour atteindre `Corrupted` il faut déjà avoir présenté la bonne clé, donc
//! l'information ne donne rien à un attaquant, et elle évite à l'utilisateur
//! légitime de croire à une erreur de saisie.

use std::fmt;

/// Erreur du moteur Passlock.
#[derive(Debug)]
pub enum Error {
    /// Le fichier ne commence pas par la signature attendue.
    NotAVault,

    /// La version de format du conteneur n'est pas gérée par ce binaire.
    ///
    /// Ce cas est détecté **avant** toute allocation ou travail cryptographique,
    /// pour qu'un fichier hostile ne puisse pas nous faire travailler.
    UnsupportedFormatVersion {
        /// Version lue dans le fichier.
        found: u16,
        /// Version maximale gérée par ce binaire.
        supported: u16,
    },

    /// Le déverrouillage a échoué : mot de passe incorrect **ou** conteneur altéré.
    ///
    /// Les deux causes sont volontairement indiscernables. Voir la documentation
    /// du module.
    UnlockFailed,

    /// Le conteneur est cohérent structurellement mais son contenu a été altéré.
    ///
    /// Cette variante n'est atteignable qu'après un déverrouillage réussi.
    Corrupted {
        /// Description statique de l'incohérence constatée.
        reason: &'static str,
    },

    /// Les paramètres de dérivation lus dans le fichier sont refusés.
    ///
    /// Sert de garde-fou contre un fichier qui demanderait une allocation
    /// déraisonnable avant même de vérifier le mot de passe.
    RejectedKdfParams {
        /// Description statique du dépassement constaté.
        reason: &'static str,
    },

    /// Le fichier est tronqué ou annonce une longueur incohérente.
    MalformedLength {
        /// Description statique de l'incohérence.
        reason: &'static str,
    },

    /// Le header est un CBOR valide mais ne respecte pas le schéma attendu.
    InvalidHeader {
        /// Description statique de la violation de schéma.
        reason: &'static str,
    },

    /// Le fichier contient une donnée d'une taille attendue fixe qui ne l'est pas.
    InvalidLength {
        /// Nom du champ concerné.
        field: &'static str,
        /// Taille attendue.
        expected: usize,
        /// Taille réellement lue.
        actual: usize,
    },

    /// Un coffre est déjà ouvert en écriture par un autre processus.
    AlreadyLocked,

    /// Le coffre a été chargé en lecture seule ; l'écriture est refusée.
    ReadOnly,

    /// L'état d'écriture a échoué avant de toucher au coffre.
    AtomicWriteFailed {
        /// Étape qui a échoué.
        step: &'static str,
    },

    /// Un verrou de fichier n'a pas pu être posé ou retiré.
    FileLockFailed {
        /// Opération concernée.
        operation: &'static str,
    },

    /// Le coffre recule par rapport à la dernière génération connue.
    ///
    /// Signalée comme une **alerte**, jamais comme un échec d'ouverture : une
    /// restauration de sauvegarde légitime doit rester possible.
    RollbackDetected {
        /// Dernière génération connue de la sentinelle.
        known: u64,
        /// Génération lue dans le coffre.
        found: u64,
    },

    /// Erreur d'entrée/sortie sous-jacente.
    Io(std::io::Error),

    /// Un paramètre fourni par l'appelant est hors bornes, ou une combinaison de
    /// paramètres est incohérente.
    ///
    /// Cette variante ne décrit **jamais** un fichier : elle désigne une demande
    /// que le programme refuse, comme une longueur de mot de passe hors bornes,
    /// des contraintes insatisfaisables, ou une liste de mots invalide. Le motif
    /// est une constante du code, jamais une donnée lue — un paramètre refusé peut
    /// contenir un secret (une liste de mots n'en contient pas, une valeur saisie
    /// pourrait), et le type `Error` ne doit jamais en porter.
    InvalidInput {
        /// Description statique de la contrainte violée.
        reason: &'static str,
    },

    /// Un invariant interne a été violé. Indique un défaut du programme, pas une
    /// condition d'exploitation.
    Internal {
        /// Description statique de l'invariant violé.
        invariant: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAVault => write!(
                f,
                "ce fichier n'est pas un coffre Passlock (signature absente)"
            ),
            Self::UnsupportedFormatVersion { found, supported } => write!(
                f,
                "coffre au format v{found}, ce binaire gère jusqu'à la v{supported} : \
                 mettez l'application à jour pour l'ouvrir"
            ),
            Self::UnlockFailed => write!(
                f,
                "déverrouillage impossible : mot de passe incorrect ou coffre corrompu"
            ),
            Self::Corrupted { reason } => {
                write!(f, "coffre corrompu : {reason}")
            }
            Self::RejectedKdfParams { reason } => write!(
                f,
                "ce coffre demande des paramètres de dérivation refusés ({reason}) : \
                 l'ouverture est abandonnée pour éviter une consommation de ressources \
                 incontrôlée"
            ),
            Self::MalformedLength { reason } => {
                write!(f, "fichier de coffre mal formé : {reason}")
            }
            Self::InvalidHeader { reason } => {
                write!(f, "entête de coffre invalide : {reason}")
            }
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "champ « {field} » de taille invalide : {actual} octets lus, {expected} attendus"
            ),
            Self::AlreadyLocked => write!(
                f,
                "ce coffre est déjà ouvert en écriture par un autre processus"
            ),
            Self::ReadOnly => write!(
                f,
                "coffre ouvert en lecture seule : toute modification est refusée"
            ),
            Self::AtomicWriteFailed { step } => write!(
                f,
                "écriture du coffre abandonnée à l'étape « {step} » : \
                 le coffre existant n'a pas été modifié"
            ),
            Self::FileLockFailed { operation } => {
                write!(
                    f,
                    "verrou de fichier : échec de l'opération « {operation} »"
                )
            }
            Self::RollbackDetected { known, found } => write!(
                f,
                "le coffre présenté est plus ancien que le dernier état connu \
                 (génération {found} contre {known} attendue) : restauration de \
                 sauvegarde ou tentative de retour en arrière"
            ),
            Self::Io(err) => write!(f, "erreur d'entrée/sortie : {err}"),
            Self::InvalidInput { reason } => {
                write!(f, "demande refusée : {reason}")
            }
            Self::Internal { invariant } => write!(
                f,
                "défaut interne du programme (invariant « {invariant} » violé) ; \
                 merci de signaler ce cas"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Alias de résultat du moteur.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Toutes les variantes doivent être formatables sans panique, et aucune ne
    /// doit contenir de marqueur de secret.
    #[test]
    fn every_variant_formats_without_secret_material() {
        let variants = [
            Error::NotAVault,
            Error::UnsupportedFormatVersion {
                found: 9,
                supported: 1,
            },
            Error::UnlockFailed,
            Error::Corrupted {
                reason: "test de motivation",
            },
            Error::RejectedKdfParams {
                reason: "mémoire demandée trop élevée",
            },
            Error::MalformedLength {
                reason: "longueur d'entête incohérente",
            },
            Error::InvalidHeader {
                reason: "champ inconnu",
            },
            Error::InvalidLength {
                field: "salt",
                expected: 32,
                actual: 3,
            },
            Error::AlreadyLocked,
            Error::ReadOnly,
            Error::AtomicWriteFailed { step: "fsync" },
            Error::FileLockFailed {
                operation: "acquisition",
            },
            Error::RollbackDetected {
                known: 10,
                found: 3,
            },
            Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "absent")),
            Error::InvalidInput {
                reason: "longueur hors bornes",
            },
            Error::Internal {
                invariant: "taille de clé",
            },
        ];

        for variant in &variants {
            let plain = format!("{variant}");
            let debug = format!("{variant:?}");
            assert!(!plain.is_empty(), "message vide pour {debug}");
            assert!(!debug.is_empty());
        }
    }

    /// Le message d'échec de déverrouillage ne doit pas varier selon la cause :
    /// c'est la propriété anti-oracle du module.
    #[test]
    fn unlock_failure_message_is_cause_agnostic() {
        let rendered = format!("{}", Error::UnlockFailed);
        for forbidden in [
            "slot",
            "enveloppe",
            "tag",
            "poly1305",
            "header",
            "payload",
            "argon",
        ] {
            assert!(
                !rendered.to_lowercase().contains(forbidden),
                "le message d'échec de déverrouillage ne doit pas désigner la cause \
                 interne (« {forbidden} » trouvé dans « {rendered} »)"
            );
        }
    }
}
