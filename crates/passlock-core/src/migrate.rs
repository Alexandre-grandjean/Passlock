//! Migration du schéma du corps du coffre.
//!
//! # Le problème que ce module résout
//!
//! Le format du **conteneur** (phase 1) et le schéma du **corps** (phase 2) sont
//! indépendants, et c'est délibéré : ajouter un type d'entrée ou un champ ne doit
//! jamais imposer de changer le conteneur. Corollaire : le schéma du corps évolue,
//! et un coffre écrit par une version antérieure doit rester lisible.
//!
//! # Où vit la version
//!
//! Dans l'enveloppe du payload, donc **à l'intérieur du chiffré**. Conséquence
//! assumée : un binaire ancien ne peut pas *savoir* qu'un coffre est trop récent
//! avant de l'avoir déchiffré — mais il refuse alors explicitement, ce qui est le
//! comportement voulu.
//!
//! # Règles
//!
//! 1. Les migrations s'appliquent **de proche en proche**, jamais par saut de
//!    version : chaque étape reçoit la version `n` et produit la version `n+1`.
//!    C'est ce qui rend chaque étape testable isolément.
//! 2. Une migration s'exécute **en mémoire**. Si elle échoue, **rien n'est écrit** :
//!    le fichier reste octet pour octet identique. C'est la propriété la plus
//!    importante de ce module, et elle est testée.
//! 3. Une migration ne devine **jamais**. Si une étape ne sait pas interpréter une
//!    donnée, elle échoue plutôt que de produire une archive plausible mais fausse.
//!
//! # Ajouter une migration
//!
//! 1. incrémenter [`CURRENT_SCHEMA`] ;
//! 2. ajouter un bras dans [`migrate_step`] pour la version précédente ;
//! 3. écrire un test qui part d'un corps de cette version.
//!
//! Aucune autre modification n'est nécessaire : la chaîne d'appel s'adapte.

use crate::archive;
use crate::error::{Error, Result};
use crate::model::Archive;
use crate::payload::{MAX_GENERATION, PAYLOAD_SCHEMA_VERSION};

/// Version de schéma produite par ce binaire.
///
/// Tenue en cohérence avec [`PAYLOAD_SCHEMA_VERSION`] par un test : deux constantes
/// qui divergeraient produiraient des coffres que nous refuserions nous-mêmes.
pub const CURRENT_SCHEMA: u16 = PAYLOAD_SCHEMA_VERSION;

/// Rétention par défaut de l'historique, en jours.
///
/// Choisie pour permettre de rattraper une modification accidentelle récente sans
/// conserver indéfiniment des secrets que l'utilisateur croit supprimés — c'est
/// précisément le piège que le cahier des charges demandait d'éviter.
pub const HISTORY_RETENTION_DAYS: u64 = 90;

/// Résultat d'une migration.
///
/// Le `Debug` est rédacteur : il n'affiche que la version d'origine, jamais le
/// contenu de l'archive.
pub struct Migrated {
    /// Archive obtenue, à la version courante.
    pub archive: Archive,
    /// Version d'origine, si une migration a eu lieu.
    pub from: Option<u16>,
}

impl std::fmt::Debug for Migrated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Migrated")
            .field("from", &self.from)
            .field("archive", &self.archive)
            .finish_non_exhaustive()
    }
}

/// Décode un corps quelle que soit sa version, en appliquant les migrations.
///
/// `created_at` provient du header du conteneur : une archive ancienne n'portait pas
/// de date de création propre, et la reprendre du conteneur est plus fidèle que
/// d'inventer une date.
///
/// # Erreurs
/// * [`Error::InvalidHeader`] si la version est hors de l'intervalle supporté ;
/// * [`Error::Corrupted`] si le corps ne correspond pas à sa version déclarée.
pub fn decode_any(version: u16, body: &[u8], created_at: u64) -> Result<Migrated> {
    // ORDRE CRITIQUE : la version est validée **avant** tout raccourci.
    //
    // NOTE DE CORRECTION : un premier correctif plaçait le cas « corps vide » en tête
    // de fonction. Les versions 0 et futures étaient alors acceptées dès que le corps
    // était vide — c'est-à-dire que le raccourci contournait exactement le contrôle
    // que les tests de version vérifient. Ce sont ces tests qui l'ont attrapé. Une
    // validation de format précède toute interprétation, jamais l'inverse.
    if version == 0 || version > CURRENT_SCHEMA {
        return Err(Error::InvalidHeader {
            reason: "version de schéma du contenu non supportée par ce binaire",
        });
    }

    // Un corps **vide** est une archive vide, y compris à la version courante.
    //
    // Ce cas est nécessaire parce que `Vault::create` écrit l'enveloppe courante avec
    // un corps vide : le moteur cryptographique ne connaît pas le modèle de données,
    // et un coffre se déclarait donc « schéma 2 » sans contenir d'archive — ce qui le
    // rendait inouvrable. Un corps vide ne peut être une archive valide pour aucune
    // version : le lire comme une archive vide est la seule lecture possible, et elle
    // ne dispense jamais de valider la version au préalable.
    if body.is_empty() {
        return Ok(Migrated {
            archive: Archive::new(created_at),
            from: (version != CURRENT_SCHEMA).then_some(version),
        });
    }

    if version == CURRENT_SCHEMA {
        return Ok(Migrated {
            archive: archive::decode(body)?,
            from: None,
        });
    }

    Ok(Migrated {
        archive: migrate_step(version, body, created_at)?,
        from: Some(version),
    })
}

/// Applique la migration depuis `from` vers la version courante.
///
/// Chaque bras traite **une** montée de version. Pour en ajouter une, décaler le
/// bras existant et ajouter le nouveau.
fn migrate_step(from: u16, body: &[u8], created_at: u64) -> Result<Archive> {
    match from {
        1 => v1_to_v2(body, created_at),
        _ => Err(Error::Internal {
            invariant: "migration absente pour une version pourtant déclarée supportée",
        }),
    }
}

/// Migration de la version 1 vers la version 2.
///
/// # Ce que contenait la version 1
///
/// Le corps de la phase 1 était **toujours vide** : le moteur cryptographique était
/// livré et testé avant tout modèle de données. La migration consiste donc à
/// produire une archive vide.
///
/// # Pourquoi une migration aussi triviale est implémentée
///
/// Ce n'est pas la transformation qu'on teste, c'est le **mécanisme** : chaîne
/// d'appel, application en mémoire, atomicité en cas d'échec, copie de sécurité. Les
/// migrations des phases suivantes ne seront pas triviales, et elles réutiliseront
/// exactement ce chemin.
///
/// # Vérification
///
/// Un corps v1 non vide est **refusé** plutôt que d'être ignoré : la version 1
/// n'écrivait jamais de corps, donc en trouver un signale soit une corruption, soit
/// un binaire qui mentait sur sa version. Deviner serait le pire des choix.
fn v1_to_v2(body: &[u8], created_at: u64) -> Result<Archive> {
    if !body.is_empty() {
        return Err(Error::Corrupted {
            reason: "un coffre de schéma 1 ne doit pas contenir de corps",
        });
    }
    Ok(Archive::new(created_at))
}

/// Tronque l'historique d'une entrée selon la politique de rétention.
///
/// Deux bornes, appliquées ensemble : un **nombre** maximal de révisions et une
/// **durée** maximale. La plus contraignante l'emporte, ce qui évite qu'un usage
/// intensif ne conserve cinquante versions en une journée comme qu'une entrée
/// modifiée une fois par an ne garde indéfiniment une version obsolète.
///
/// Retourne le nombre de révisions supprimées.
pub fn truncate_history(entry: &mut crate::model::Entry, now: u64) -> usize {
    use crate::model::MAX_HISTORY_PER_ENTRY;

    let before = entry.history.len();
    let oldest_allowed = now.saturating_sub(HISTORY_RETENTION_DAYS * 86_400);

    entry
        .history
        .retain(|revision| revision.at >= oldest_allowed);

    if entry.history.len() > MAX_HISTORY_PER_ENTRY {
        // Les révisions sont ajoutées en fin de vecteur : les plus anciennes sont au
        // début. On retire donc par l'avant.
        let excess = entry.history.len() - MAX_HISTORY_PER_ENTRY;
        entry.history.drain(..excess);
    }

    before - entry.history.len()
}

/// Vrai si la génération est utilisable.
///
/// Placé ici plutôt que dispersé, pour que la borne soit vérifiée au même endroit
/// que les autres contraintes de version.
///
/// # Erreurs
/// [`Error::InvalidHeader`] si la génération est hors bornes.
pub fn check_generation(generation: u64) -> Result<()> {
    if generation > MAX_GENERATION {
        return Err(Error::InvalidHeader {
            reason: "génération de coffre hors bornes : migration requise",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entry, EntryKind, Revision};

    #[test]
    fn the_current_schema_matches_the_payload_version() {
        // Deux constantes qui divergeraient produiraient des coffres que nous
        // refuserions nous-mêmes à la réouverture.
        assert_eq!(CURRENT_SCHEMA, PAYLOAD_SCHEMA_VERSION);
    }

    #[test]
    fn a_current_version_body_is_decoded_without_migration() {
        let archive = Archive::new(7);
        let encoded = archive::encode(&archive).expect("encodage");

        let migrated = decode_any(CURRENT_SCHEMA, &encoded, 7).expect("décodage");
        assert!(
            migrated.from.is_none(),
            "aucune migration ne devait avoir lieu"
        );
        assert_eq!(migrated.archive.created_at, 7);
    }

    #[test]
    fn a_version_one_body_becomes_an_empty_archive() {
        // Le corps de la phase 1 était toujours vide.
        let migrated = decode_any(1, &[], 1_700_000_000).expect("migration");

        assert_eq!(migrated.from, Some(1));
        assert_eq!(migrated.archive.created_at, 1_700_000_000);
        assert!(migrated.archive.entries.is_empty());
        assert!(migrated.archive.folders.is_empty());
    }

    #[test]
    fn a_version_one_body_that_is_not_empty_is_refused() {
        // La version 1 n'écrivait jamais de corps : en trouver un signale une
        // incohérence, et deviner serait le pire des choix.
        let outcome = decode_any(1, b"donnees inattendues", 0);
        assert!(matches!(outcome, Err(Error::Corrupted { .. })));
    }

    #[test]
    fn a_future_version_is_refused_explicitly() {
        let outcome = decode_any(CURRENT_SCHEMA + 1, &[], 0);
        assert!(matches!(outcome, Err(Error::InvalidHeader { .. })));
    }

    #[test]
    fn version_zero_is_refused() {
        assert!(decode_any(0, &[], 0).is_err());
    }

    #[test]
    fn a_migrated_archive_encodes_to_the_current_version() {
        // La migration produit une archive à la version courante, et son encodage
        // doit donc être relisible sans nouvelle migration.
        let migrated = decode_any(1, &[], 42).expect("migration");
        let encoded = archive::encode(&migrated.archive).expect("encodage");

        let again = decode_any(CURRENT_SCHEMA, &encoded, 42).expect("relecture");
        assert!(again.from.is_none());
    }

    #[test]
    fn history_is_capped_by_count() {
        let mut entry = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
        let now = 1_700_000_000;

        for index in 0..(crate::model::MAX_HISTORY_PER_ENTRY + 20) {
            entry.history.push(Revision {
                at: now - u64::try_from(index).unwrap_or(0),
                snapshot: Entry::new(EntryKind::Login, "x", 0).expect("entrée"),
            });
        }

        let removed = truncate_history(&mut entry, now);
        assert_eq!(entry.history.len(), crate::model::MAX_HISTORY_PER_ENTRY);
        assert_eq!(removed, 20);
    }

    #[test]
    fn history_is_capped_by_age() {
        let mut entry = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
        let now = 1_000_000_000;

        // Une révision récente, une plus ancienne que la rétention.
        entry.history.push(Revision {
            at: now - 86_400,
            snapshot: Entry::new(EntryKind::Login, "récente", 0).expect("entrée"),
        });
        entry.history.push(Revision {
            at: now - (HISTORY_RETENTION_DAYS + 1) * 86_400,
            snapshot: Entry::new(EntryKind::Login, "ancienne", 0).expect("entrée"),
        });

        let removed = truncate_history(&mut entry, now);
        assert_eq!(removed, 1);
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].snapshot.title, "récente");
    }

    #[test]
    fn truncating_an_empty_history_is_harmless() {
        let mut entry = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
        assert_eq!(truncate_history(&mut entry, 0), 0);
    }
}
