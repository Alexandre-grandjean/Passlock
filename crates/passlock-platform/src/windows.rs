//! Backend Windows pour le verrouillage mémoire.
//!
//! # Statut de vérification — À LIRE
//!
//! Ce fichier **n'a pas pu être compilé ni testé** dans l'environnement de
//! développement actuel (WSL2, cible `x86_64-unknown-linux-gnu` uniquement, aucune
//! cible Windows installée). Il est écrit d'après la documentation Microsoft et
//! doit être considéré comme **non vérifié** jusqu'à ce qu'un job de CI sur
//! `x86_64-pc-windows-msvc` le compile et l'exécute.
//!
//! Les API sont référencées par leur chemin complet afin qu'une erreur se
//! manifeste à la **compilation** et non par un comportement silencieusement
//! dégradé à l'exécution.

use std::io;

use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

/// `VirtualLock` — maintient ces pages dans la mémoire physique.
///
/// # Erreurs
/// Échoue si le processus dépasse son quota de pages verrouillées. Comme pour
/// `mlock` sur Linux, l'échec est un cas normal à signaler sans interrompre le
/// programme.
pub fn lock_region(addr: *const u8, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: `addr` provient d'un slice vivant chez l'appelant et `len` en est la
    // longueur, donc [addr, addr+len) est alloué et valide pour la durée de
    // l'appel. `VirtualLock` ne lit ni n'écrit la mémoire.
    let rc = unsafe { VirtualLock(addr.cast::<core::ffi::c_void>().cast_mut(), len) };
    if rc != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `VirtualUnlock` — annule [`lock_region`].
pub fn unlock_region(addr: *const u8, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: mêmes garanties que dans `lock_region`.
    let rc = unsafe { VirtualUnlock(addr.cast::<core::ffi::c_void>().cast_mut(), len) };
    if rc != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Non supporté sur Windows.
///
/// Windows n'a pas d'équivalent direct de `madvise(MADV_DONTDUMP)` : l'exclusion
/// d'une zone des vidages se décide au niveau du mécanisme de rapport d'erreurs
/// (WER), pas de la zone mémoire. Nous refusons de configurer WER, ce qui
/// exigerait d'écrire dans le registre et sortirait du principe de moindre
/// privilège.
///
/// Conséquence assumée : sur Windows, une zone verrouillée reste susceptible
/// d'apparaître dans un vidage mémoire. Ce point figure dans `SECURITY.md`.
pub fn exclude_from_dump(addr: *const u8, len: usize) -> io::Result<()> {
    let _ = (addr, len);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "MADV_DONTDUMP n'a pas d'équivalent Windows utilisable sans privilèges",
    ))
}

/// Désactive les vidages mémoire du processus — Windows.
///
/// # Pourquoi le résultat est `Failed` et non `Applied`
///
/// La configuration des vidages mémoire passe par Windows Error Reporting, qui se
/// règle dans le registre ou via `WerAddExcludedApplication`. Les deux exigent des
/// privilèges d'administration que ce projet refuse de demander (principe de
/// moindre privilège, §26).
///
/// Un filtre d'exception non géré (`SetUnhandledExceptionFilter`) permettrait
/// d'empêcher WER d'intervenir sans privilèges, mais il détourne la gestion des
/// fautes fatales et introduit un risque de comportement indéfini au moment
/// précis où le processus est déjà dans un état inconnu. Nous ne le faisons pas.
///
/// Le résultat est donc rapporté honnêtement comme `Failed`, et l'utilisateur en
/// est informé.
pub(crate) fn disable_core_dumps() -> crate::process::HardeningOutcome {
    crate::process::HardeningOutcome::Failed
}

/// Non supporté sur Windows.
///
/// `prctl(PR_SET_DUMPABLE)` n'a pas d'équivalent : l'accès en lecture à la mémoire
/// d'un autre processus est régi par la DACL du processus, et un processus du même
/// utilisateur dispose par défaut du droit `PROCESS_VM_READ`. Restreindre cela
/// demanderait de réécrire les descripteurs de sécurité, ce que nous ne faisons pas.
pub(crate) fn restrict_ptrace() -> crate::process::HardeningOutcome {
    crate::process::HardeningOutcome::Unsupported
}

// ---------------------------------------------------------------------------
// Écriture atomique, verrouillage et permissions.
//
// ATTENTION : la surface FFI ci-dessous est volontairement réduite à deux appels
// (`MoveFileExW` et `LockFileEx`) précisément parce qu'elle ne peut pas être
// compilée dans l'environnement de développement actuel. Moins de code non
// vérifié signifie moins de risque d'y introduire une erreur silencieuse.
// ---------------------------------------------------------------------------

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Décompose un chemin cible en (répertoire, nom de fichier).
fn split_target(target: &Path) -> io::Result<(PathBuf, std::ffi::OsString)> {
    let name = target.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "le chemin cible ne désigne pas un fichier",
        )
    })?;
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((dir, name.to_os_string()))
}

/// Transforme un chemin en chaîne UTF-16 terminée par un nul.
///
/// Windows n'accepte pas l'octet nul dans un chemin : on refuse explicitement
/// plutôt que de laisser le noyau tronquer la chaîne à notre insu.
fn to_wide(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "le chemin contient un caractère nul, ce qui tronquerait la chaîne côté noyau",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Écrit `data` dans `target` de façon atomique.
///
/// ## Différences assumées par rapport à l'implémentation unix
///
/// * `CREATE_NEW` joue le rôle de `O_CREAT|O_EXCL` : le nom temporaire doit être
///   neuf, ce qui empêche la pré-création d'un fichier à un emplacement devinable.
/// * Windows ne dispose pas de `O_NOFOLLOW` : la protection contre les liens
///   symboliques repose sur le refus par `CREATE_NEW` d'écraser une entrée
///   existante, y compris un lien. Un lien symbolique créé **entre** la
///   vérification et l'ouverture reste théoriquement possible ; la séquence est
///   réduite au minimum mais non éliminée.
/// * `MOVEFILE_WRITE_THROUGH` remplace le `fsync` du répertoire, qui n'existe pas
///   sous cette forme sur Windows.
///
/// Le mode 0600 n'a pas d'équivalent : la confidentialité repose sur les ACL
/// héritées du profil utilisateur. Voir [`verify_private`].
pub fn write_atomic(target: &Path, temp_suffix: &str, data: &[u8]) -> io::Result<()> {
    let (dir, file_name) = split_target(target)?;

    // Windows n'a pas d'équivalent de la famille `*at` : on ne peut pas tenir un
    // descripteur de répertoire et opérer relativement à lui. La vérification est
    // donc faite **avant** l'opération, ce qui laisse une fenêtre de course entre
    // les deux. Elle est documentée plutôt que passée sous silence :
    // `crates/passlock-platform/src/windows.rs`, section « écriture atomique ».
    //
    // Ce n'est pas équivalent à la marche avec descripteurs utilisée sur Unix, et
    // ne doit pas être présenté comme tel.
    crate::fs::ensure_no_symlink_components(&dir)?;

    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(&file_name);
    temp_name.push(".tmp-");
    temp_name.push(temp_suffix);
    let temp_path = dir.join(temp_name);

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
    {
        Ok(file) => file,
        Err(err) => {
            // Un résidu d'une exécution précédente ne doit pas bloquer l'écriture
            // indéfiniment tout en restant présent : on le signale plutôt que de
            // le supprimer aveuglément, ce qui pourrait détruire une écriture
            // concurrente légitime.
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "impossible de créer le fichier temporaire {} : {err}",
                    temp_path.display()
                ),
            ));
        }
    };

    if let Err(err) = file.write_all(data).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(file);

    let temp_wide = to_wide(&temp_path)?;
    let target_wide = to_wide(target)?;

    // SAFETY: les deux chaînes UTF-16 sont terminées par un nul et vivantes pour
    // la durée de l'appel. `MoveFileExW` ne lit que ces deux buffers.
    let rc = unsafe {
        MoveFileExW(
            temp_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if rc == 0 {
        let err = io::Error::last_os_error();
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }

    Ok(())
}

/// Verrou exclusif sur un coffre.
#[derive(Debug)]
pub struct FileLock {
    file: File,
    path: PathBuf,
}

impl FileLock {
    /// Acquiert un verrou exclusif non bloquant associé à `target`.
    ///
    /// # Erreurs
    /// [`io::ErrorKind::WouldBlock`] si un autre processus détient le verrou.
    pub fn acquire(target: &Path) -> io::Result<Self> {
        let mut lock_name = target
            .file_name()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "le chemin du coffre ne désigne pas un fichier",
                )
            })?
            .to_os_string();
        lock_name.push(".lock");
        let lock_path = target.with_file_name(lock_name);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "l'emplacement du verrou n'est pas un fichier ordinaire",
            ));
        }

        // `OVERLAPPED` doit être remis à zéro : il décrit la région verrouillée et
        // un contenu non initialisé provoquerait un comportement indéfini.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

        // SAFETY: `overlapped` est initialisé sur toute sa taille et reste vivant
        // pendant l'appel. Le descripteur appartient à `file`, vivant lui aussi.
        // Le verrou couvre tout le fichier en partant de l'offset zéro.
        let rc = unsafe {
            LockFileEx(
                file.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &raw mut overlapped,
            )
        };

        if rc == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            file,
            path: lock_path,
        })
    }

    /// Chemin du fichier de verrou.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: mêmes garanties que dans `acquire`.
        unsafe {
            UnlockFileEx(
                self.file.as_raw_handle().cast(),
                0,
                u32::MAX,
                u32::MAX,
                &raw mut overlapped,
            );
        }
        // La fermeture du descripteur, par la destruction de `file`, libère de
        // toute façon le verrou.
    }
}

/// **Non implémenté sur Windows : vérification ACL absente.**
///
/// Windows ne représente pas les permissions par un mode numérique : la
/// confidentialité d'un fichier vient de sa liste de contrôle d'accès. Vérifier
/// qu'un coffre n'est lisible que par son propriétaire exigerait d'appeler
/// `GetNamedSecurityInfoW`, de parcourir la DACL et d'évaluer les ACE héritées —
/// plusieurs centaines de lignes d'FFI qui, dans cet environnement, ne pourraient
/// pas être compilées ni testées.
///
/// Cette fonction retourne donc `Ok(false)`, ce qui signifie « rien à corriger »
/// et **non** « permissions vérifiées ». La distinction est importante et figure
/// dans `SECURITY.md` : sur Windows, la confidentialité du fichier repose
/// entièrement sur les ACL héritées du profil utilisateur, et l'application ne
/// les contrôle pas. Créer ou déplacer un coffre hors du profil utilisateur
/// (dossier partagé, racine d'un disque) le rendrait accessible à d'autres
/// comptes sans qu'aucun avertissement ne soit émis.
///
/// Piste de correction identifiée : implémenter la vérification via
/// `GetNamedSecurityInfoW` + `EqualSid` sur le propriétaire, et refuser un coffre
/// dont la DACL accorde un droit à un principal autre que l'utilisateur
/// propriétaire, `SYSTEM` ou `Administrators`.
pub fn verify_private(path: &Path) -> io::Result<bool> {
    // On vérifie au moins que le chemin désigne un fichier ordinaire, ce qui ne
    // dépend pas des ACL.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "le coffre n'est pas un fichier ordinaire",
        ));
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Contrôle du terminal.
//
// NON VÉRIFIÉ : comme le reste de ce fichier, ce code n'a pas pu être compilé
// dans l'environnement de développement (pas de cible Windows installée).
// ---------------------------------------------------------------------------

use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

/// Vrai si l'entrée standard est une console.
pub(crate) fn stdin_is_terminal() -> bool {
    // En l'absence de console (entrée redirigée), `GetStdHandle` peut renvoyer un
    // descripteur nul ou invalide ; `GetConsoleMode` échouerait alors, ce qui est
    // exactement le comportement souhaité.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode: u32 = 0;
    // SAFETY: `handle` provient de `GetStdHandle` et `mode` est vivant.
    unsafe { GetConsoleMode(handle, &raw mut mode) != 0 }
}

/// Désactive l'écho de la console tant que la valeur existe.
pub struct EchoGuard {
    handle: *mut core::ffi::c_void,
    original: u32,
}

impl EchoGuard {
    /// Désactive l'écho sur l'entrée standard.
    ///
    /// # Erreurs
    /// `io::ErrorKind::NotConnected` si l'entrée standard n'est pas une console.
    pub fn disable() -> io::Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };

        let mut mode: u32 = 0;
        // SAFETY: `handle` provient de `GetStdHandle` et `mode` est vivant.
        if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("impossible de lire le mode de la console : {err}"),
            ));
        }

        let original = mode;
        let without_echo = mode & !ENABLE_ECHO_INPUT;

        // SAFETY: mêmes garanties ; le descripteur et le mode sont valides.
        if unsafe { SetConsoleMode(handle, without_echo) } == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { handle, original })
    }
}

impl std::fmt::Debug for EchoGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EchoGuard { echo: désactivé }")
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: `handle` a été obtenu par `GetStdHandle` et `original` par un
        // `GetConsoleMode` réussi sur ce même descripteur.
        unsafe {
            SetConsoleMode(self.handle, self.original);
        }
    }
}
