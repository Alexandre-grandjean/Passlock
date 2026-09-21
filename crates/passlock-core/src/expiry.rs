//! Définition de la date d'expiration d'une entrée.
//!
//! C'est la **seule écriture** de la phase 5. Elle passe par le chemin métier
//! existant — [`VaultStore::update_entry`](crate::store::VaultStore::update_entry) —
//! et n'ajoute **ni schéma, ni champ, ni mécanisme d'historique** : `expires_at` est
//! un `Field` clé-valeur ordinaire, et une écriture réussie crée une **révision
//! d'historique** comme n'importe quelle modification.
//!
//! # Validation avant mutation
//!
//! La date est analysée **avant** d'ouvrir la transaction. Une date invalide est donc
//! refusée sans qu'aucune mutation n'ait lieu.
//!
//! # Unicité
//!
//! Après une écriture réussie, l'entrée porte **exactement un** champ `expires_at`.
//! Plusieurs champs préexistants ne sont **jamais** départagés arbitrairement :
//! l'ambiguïté est **signalée**, et l'écriture est refusée — rien n'est supprimé en
//! silence.

use crate::error::{Error, Result};
use crate::model::{Entry, EntryId, Field, FieldKind};
use crate::security::{CivilDate, DateError, EXPIRES_AT_KEY};
use crate::store::VaultStore;

/// Ce que l'écriture a fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryWrite {
    /// Aucun champ n'existait : il a été ajouté.
    Added,
    /// Un champ existait : son contenu a été remplacé.
    Replaced,
}

/// Définit la date d'expiration d'une entrée.
///
/// `date` doit être au format canonique `YYYY-MM-DD` (année `1970..=9999`), celui de
/// [`CivilDate::parse`].
///
/// # Erreurs
/// * [`Error::InvalidInput`] si la date est mal formée, hors bornes ou impossible ;
/// * [`Error::InvalidInput`] si l'entrée porte **plusieurs** champs `expires_at` ;
/// * [`Error::InvalidHeader`] si l'entrée est introuvable ;
/// * [`Error::ReadOnly`] si le magasin est ouvert en lecture seule.
pub fn set_expires_at(store: &mut VaultStore, entry: &EntryId, date: &str) -> Result<ExpiryWrite> {
    // **Avant toute mutation** : une date refusée ne laisse rien derrière elle.
    let parsed = CivilDate::parse(date).map_err(date_error)?;
    let value = parsed.to_string();

    let mut outcome = ExpiryWrite::Added;
    store.update_entry(entry, |entry| {
        outcome = write_field(entry, &value)?;
        Ok(())
    })?;
    Ok(outcome)
}

/// Traduit l'échec d'analyse d'une date en erreur du moteur.
///
/// Le motif reste une constante du code : aucune donnée de l'utilisateur n'entre dans
/// le message.
fn date_error(error: DateError) -> Error {
    Error::InvalidInput {
        reason: match error {
            DateError::Shape => "date d'expiration mal formée : format attendu AAAA-MM-JJ",
            DateError::Range => "date d'expiration hors bornes : année attendue entre 1970 et 9999",
            DateError::Impossible => "date d'expiration impossible : ce jour n'existe pas",
        },
    }
}

/// Ajoute ou remplace le champ `expires_at`, et signale l'ambiguïté.
fn write_field(entry: &mut Entry, value: &str) -> Result<ExpiryWrite> {
    let mut indices = entry
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.key == EXPIRES_AT_KEY)
        .map(|(index, _)| index);

    let first = indices.next();
    if indices.next().is_some() {
        // On ne **choisit pas** : on refuse, et rien n'est supprimé.
        return Err(Error::InvalidInput {
            reason: "l'entrée porte plusieurs champs « expires_at » : levez l'ambiguïté \
                     avant de définir une expiration",
        });
    }

    match first {
        None => {
            let ordinal = next_ordinal(entry);
            let field = Field::new(EXPIRES_AT_KEY, FieldKind::Date, value, ordinal)?;
            entry.fields.push(field);
            Ok(ExpiryWrite::Added)
        }
        Some(index) => {
            // L'ordinal d'origine est conservé : l'ordre d'affichage ne bouge pas.
            let ordinal = entry.fields[index].ordinal;
            entry.fields[index] = Field::new(EXPIRES_AT_KEY, FieldKind::Date, value, ordinal)?;
            Ok(ExpiryWrite::Replaced)
        }
    }
}

/// Ordinal libre suivant : le plus grand ordinal plus un, ou `0`.
fn next_ordinal(entry: &Entry) -> u16 {
    entry
        .fields
        .iter()
        .map(|field| field.ordinal)
        .max()
        .map_or(0, |ordinal| ordinal.saturating_add(1))
}
