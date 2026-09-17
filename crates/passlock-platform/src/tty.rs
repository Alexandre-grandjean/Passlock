//! Contrôle du mode du terminal, façade portable.
//!
//! Ce module ne lit **jamais** de secret : il ne fait que basculer l'écho du
//! terminal. La lecture reste à la charge de l'appelant, qui sait quel type de
//! secret il manipule et donc comment l'effacer ensuite. Mélanger les deux
//! responsabilités obligerait ce crate à connaître les types secrets de
//! `passlock-core`, ce qui inverserait la dépendance entre les deux.

use std::io;

/// Désactive l'écho du terminal tant que la valeur existe.
///
/// ## Pourquoi ce n'est pas du confort
///
/// Saisir un mot de passe maître avec l'écho actif l'inscrit dans le tampon
/// défilant du terminal, dans l'historique de session s'il est capturé, et
/// éventuellement dans un enregistrement de session. C'est une fuite par un canal
/// que l'application ne contrôle pas du tout, et qu'aucune mesure cryptographique
/// ne rattrape.
///
/// ## Portée
///
/// L'écho est rétabli à la destruction de la valeur, y compris si l'appelant sort
/// par une erreur. Si le processus est tué brutalement entre les deux, le terminal
/// peut rester sans écho : c'est un désagrément d'ergonomie, jamais une fuite, et
/// la commande `stty echo` le corrige.
///
/// # Erreurs
/// Propage l'erreur du système si le descripteur d'entrée n'est pas un terminal —
/// cas normal quand l'entrée est redirigée depuis un fichier ou un tube.
pub use crate::backend::EchoGuard;

/// Vrai si l'entrée standard est un terminal.
///
/// Permet à l'appelant de choisir entre une saisie interactive et une lecture sur
/// une entrée redirigée, et surtout de **ne pas** tenter d'afficher une invite
/// dans un tube.
#[must_use]
pub fn stdin_is_terminal() -> bool {
    crate::backend::stdin_is_terminal()
}

/// Écrit une invite sur la sortie d'erreur, sans saut de ligne final.
///
/// L'invite va sur la sortie d'erreur et non sur la sortie standard : ainsi, la
/// sortie standard d'une commande reste exploitable dans un tube, sans texte
/// parasite mêlé aux données.
///
/// # Erreurs
/// Propage les erreurs d'écriture.
pub fn prompt(text: &str) -> io::Result<()> {
    use std::io::Write;
    let mut err = io::stderr();
    err.write_all(text.as_bytes())?;
    err.flush()
}
