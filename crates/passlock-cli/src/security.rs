//! Commande `security` : **présentation** du centre de sécurité.
//!
//! # Une couche de présentation, rien de plus
//!
//! Toute la logique vit dans `passlock_core::security`. Cette commande **ne calcule
//! rien**, ne décide rien, et **ne modifie rien** : elle ouvre le coffre en **lecture
//! seule** et affiche les six indicateurs déjà calculés.
//!
//! # Ce qu'elle n'affiche jamais
//!
//! Aucune valeur de champ, aucun secret, aucune **empreinte** de réutilisation. Une
//! entrée est désignée par son **identifiant** et son **titre**, comme partout dans
//! l'interface. Le contenu sensible ne franchit pas cette couche.
//!
//! # Aucun verdict de sécurité
//!
//! Il n'y a **aucun score global**, aucun pourcentage, aucun classement. Chaque
//! indicateur est une **liste de faits explicables**. L'estimation de robustesse est
//! présentée comme une **heuristique structurelle**, jamais comme une entropie
//! mesurée, et son meilleur verdict n'est pas « fort » mais « aucune faiblesse
//! structurelle détectée ».

use clap::Command;

use passlock_core::model::EntryId;
use passlock_core::security::{
    self, ExpiryState, ExpiryUnknown, SecurityReport, StrengthBand, StrengthFlags, WeakReason,
};
use passlock_core::store::VaultStore;
use passlock_core::vault::VaultConfig;

use crate::{CliResult, GlobalOptions, open_store, vault_argument, vault_path};

/// Sous-commande `security`.
pub(crate) fn command() -> Command {
    Command::new("security")
        .about("Présente l'état de sécurité des entrées (lecture seule)")
        .long_about(
            "Calcule et affiche six indicateurs sur le coffre déverrouillé : \
             réutilisation de secrets, ancienneté, estimation de robustesse, entrées \
             faibles, absence de TOTP, expiration.

             **Strictement en lecture seule** : rien n'est modifié, rien n'est \
             enregistré. Aucune valeur de secret et aucune empreinte ne sont affichées.

             Aucun score global n'est produit : chaque indicateur est une liste de faits \
             explicables. L'estimation de robustesse est une **heuristique structurelle**, \
             pas une entropie mesurée ; un résultat élevé ne garantit rien.",
        )
        .arg(vault_argument())
}

/// Présente le centre de sécurité.
pub(crate) fn cmd_security(
    matches: &clap::ArgMatches,
    options: &GlobalOptions,
    config: &VaultConfig,
) -> CliResult {
    let path = vault_path(matches)?;

    // **Lecture seule imposée** : aucune écriture, aucun verrou, aucune sentinelle.
    let read_only = VaultConfig {
        read_only: true,
        ..config.clone()
    };
    let store = open_store(&path, options, &read_only)?;

    // L'instant de référence est lu **ici**, à la frontière : le module de sécurité,
    // lui, le reçoit en argument et n'appelle aucune horloge.
    let now = crate::now_seconds();
    let report = security::run_security_center(
        store.archive(),
        &store.vault().subkeys().index,
        now,
        security::DEFAULT_EXPIRY_WINDOW_DAYS,
    )?;

    print_report(&store, &report, now);
    Ok(())
}

/// Titre d'une entrée, ou chaîne vide si elle a disparu entre-temps.
fn title<'a>(store: &'a VaultStore, entry: &EntryId) -> &'a str {
    store
        .archive()
        .entry(entry)
        .map_or("", |found| found.title.as_str())
}

/// Clé du champ portant cet ordinal, si elle est retrouvable.
fn field_key(store: &VaultStore, entry: &EntryId, ordinal: u16) -> Option<String> {
    store.archive().entry(entry).and_then(|found| {
        found
            .fields
            .iter()
            .find(|field| field.ordinal == ordinal)
            .map(|field| field.key.clone())
    })
}

/// Désigne un champ par sa clé si elle existe, sinon par son ordinal.
fn field_label(store: &VaultStore, entry: &EntryId, ordinal: u16) -> String {
    match field_key(store, entry, ordinal) {
        Some(key) => format!("champ « {key} » (ordinal {ordinal})"),
        None => format!("champ (ordinal {ordinal})"),
    }
}

fn print_report(store: &VaultStore, report: &SecurityReport, now: u64) {
    let reference = security::CivilDate::from_unix_seconds(now);

    println!(
        "Centre de sécurité — {} entrée(s) analysée(s), corbeille exclue.",
        report.age.len()
    );
    println!(
        "Fenêtre d'expiration : {} jour(s). Référence : {reference} (UTC).",
        security::DEFAULT_EXPIRY_WINDOW_DAYS
    );

    print_reuse(store, report);
    print_age(store, report);
    print_strength(store, report);
    print_weak(store, report);
    print_missing_totp(store, report);
    print_expiry(store, report);

    println!();
    println!(
        "Ces indications sont des **faits**, pas des garanties : l'absence de signal \
         n'est pas une preuve de sécurité."
    );
}

fn print_reuse(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Réutilisation");
    if report.reuse.is_empty() {
        println!("  Aucune valeur partagée par plusieurs entrées.");
        return;
    }

    println!(
        "  {} groupe(s) de valeurs partagées (la valeur n'est jamais affichée) :",
        report.reuse.len()
    );
    for group in &report.reuse {
        let fields: Vec<String> = group
            .fields
            .iter()
            .map(|reference| field_label(store, &reference.entry, reference.ordinal))
            .collect();
        println!("    • {} entrées :", group.entries.len());
        for entry in &group.entries {
            println!("        {entry}  {}", title(store, entry));
        }
        println!("      champs concernés : {}", fields.join(", "));
    }
}

fn print_age(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Ancienneté");
    if report.age.is_empty() {
        println!("  Aucune entrée.");
        return;
    }
    for info in &report.age {
        println!(
            "  {}  {} — {} jour(s)",
            info.entry,
            title(store, &info.entry),
            info.days_since
        );
    }
}

fn print_strength(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Robustesse estimée (heuristique structurelle — PAS une entropie mesurée)");
    if report.strengths.is_empty() {
        println!("  Aucun champ « secret » ou « code » à estimer.");
        return;
    }
    for finding in &report.strengths {
        let estimate = &finding.estimate;
        let measurement = match estimate.heuristic_bits {
            Some(bits) => format!("{bits:.1} bits — {}", band_label(estimate.band)),
            // Aucune estimation chiffrée : on le dit, plutôt que d'afficher un chiffre.
            None => "indéterminée (aucune estimation chiffrée)".to_string(),
        };
        println!(
            "  {}  {} — {} : {measurement}{}",
            finding.entry,
            title(store, &finding.entry),
            field_label(store, &finding.entry, finding.ordinal),
            flags_suffix(estimate.flags)
        );
    }
    println!(
        "  Note : cette estimation compte des plages et des classes de caractères ; elle \
         est aveugle aux mots de dictionnaire. Un résultat élevé ne garantit rien."
    );
}

fn print_weak(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Entrées faibles");
    if report.weak.is_empty() {
        println!("  Aucun champ sous les seuils (estimation < 64 bits ou moins de 8 caractères).");
        return;
    }
    for secret in &report.weak {
        let reasons: Vec<String> = secret
            .reasons
            .iter()
            .map(|reason| match reason {
                WeakReason::LowHeuristicScore { bits } => format!("estimation {bits:.1} bits"),
                WeakReason::TooShort { length } => format!("longueur {length}"),
            })
            .collect();
        println!(
            "  {}  {} — {} : {}",
            secret.entry,
            title(store, &secret.entry),
            field_label(store, &secret.entry, secret.ordinal),
            reasons.join(" ; ")
        );
    }
}

fn print_missing_totp(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Absence de TOTP");
    if report.missing_totp.is_empty() {
        println!("  Aucune entrée « identifiant » avec mot de passe sans second facteur.");
        return;
    }
    for entry in &report.missing_totp {
        println!("  {entry}  {} — aucun TOTP détecté", title(store, entry));
    }
}

fn print_expiry(store: &VaultStore, report: &SecurityReport) {
    println!();
    println!("Expiration");
    if report.expiry.is_empty() {
        println!("  Aucune entrée.");
        return;
    }
    for item in &report.expiry {
        let label = expiry_label(item.state, item.delta_days);
        match item.date {
            Some(date) => println!(
                "  {}  {} — {date} — {label}",
                item.entry,
                title(store, &item.entry)
            ),
            None => println!("  {}  {} — {label}", item.entry, title(store, &item.entry)),
        }
    }
}

/// Libellé d'un état d'expiration, avec l'écart en jours quand il est connu.
fn expiry_label(state: ExpiryState, delta_days: Option<i64>) -> String {
    let gap = match delta_days {
        Some(delta) if delta < 0 => format!(" (il y a {} jour(s))", -delta),
        Some(delta) => format!(" (dans {delta} jour(s))"),
        None => String::new(),
    };
    match state {
        ExpiryState::Expired => format!("expirée{gap}"),
        ExpiryState::Soon => format!("bientôt expirée{gap}"),
        ExpiryState::Valid => format!("valide{gap}"),
        // Un état indéterminé est affiché **comme tel**, jamais comme « valide ».
        ExpiryState::Unknown(reason) => format!("indéterminée ({})", unknown_label(reason)),
    }
}

const fn unknown_label(reason: ExpiryUnknown) -> &'static str {
    match reason {
        ExpiryUnknown::Absent => "aucune date",
        ExpiryUnknown::WrongKind => "type de champ inattendu",
        ExpiryUnknown::Malformed => "date mal formée",
        ExpiryUnknown::Impossible => "date impossible",
        ExpiryUnknown::Ambiguous => "plusieurs champs « expires_at »",
    }
}

/// Libellé d'une bande d'estimation.
///
/// Le verdict haut n'est **jamais** « fort » ni « sûr » : il décrit l'absence de
/// faiblesse **structurelle** détectée, rien de plus.
const fn band_label(band: StrengthBand) -> &'static str {
    match band {
        StrengthBand::VeryWeak => "très faible",
        StrengthBand::Weak => "faible",
        StrengthBand::Moderate => "modéré",
        StrengthBand::NoStructuralWeakness => "aucune faiblesse structurelle détectée",
        StrengthBand::Indeterminate => "indéterminée",
    }
}

/// Suffixe décrivant les régularités structurelles observées.
fn flags_suffix(flags: StrengthFlags) -> String {
    let mut parts = Vec::new();
    if flags.repeated_run {
        parts.push("plages répétées");
    }
    if flags.periodic {
        parts.push("motif périodique");
    }
    if flags.outside_known_classes {
        parts.push("caractères hors des classes connues");
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(", "))
    }
}
