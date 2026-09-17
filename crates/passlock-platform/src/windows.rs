//! Backend Windows pour le verrouillage mémoire et les fichiers.
//!
//! # Statut de vérification — À LIRE
//!
//! **NOTE DE CORRECTION.** Ce commentaire affirmait que le fichier « n'a pas pu
//! être compilé ». **C'était faux depuis l'installation de la cible
//! `x86_64-pc-windows-msvc`** : `cargo check --target x86_64-pc-windows-msvc
//! --workspace --all-targets` passe, et cette compilation a d'ailleurs révélé deux
//! erreurs réelles en leur temps (un import `io` dupliqué, une implémentation de
//! `Debug` référençant un champ renommé).
//!
//! La distinction exacte, et c'est elle qui compte :
//!
//! * **compilation VÉRIFIÉE** — les signatures FFI et les types sont validés par le
//!   compilateur, y compris pour les tests ;
//! * **exécution NON OBSERVÉE** — aucun binaire Windows n'a été lié ni lancé : ni
//!   Wine, ni MinGW, ni linker MSVC dans l'environnement. Le comportement à
//!   l'exécution (ACL, déplacement atomique, verrou, `VirtualLock`, **durabilité**)
//!   reste **entièrement non vérifié**.
//!
//! Aucune affirmation d'ordre fonctionnel ne doit donc être faite sur ce fichier.
//! Voir `SECURITY.md` §4.3 et 4.4, et les limites L2, L9.
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
// NOTE DE CORRECTION. Ce commentaire justifiait une surface FFI réduite à deux
// appels (`MoveFileExW`, `LockFileEx`) par le fait que le fichier « ne peut pas
// être compilé dans l'environnement de développement ». La cible Windows est
// désormais installée et le fichier compile : cette justification n'a plus lieu
// d'être, mais la réduction de surface reste un principe.
//
// La phase 4 ajoute délibérément une surface FFI plus large (création exclusive,
// DACL, énumération, suppression). C'est un coût assumé : sans DACL explicite, les
// fichiers sensibles neufs — clé de récupération, export en clair, sauvegarde,
// blobs, temporaires — reposeraient sur les ACL héritées du profil, c'est-à-dire
// sur une garantie qui disparaît dès que le fichier est créé hors du profil
// (dossier partagé, racine d'un disque). Une surface plus large mais **compilée**
// est préférable à une garantie silencieusement absente.
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

// ---------------------------------------------------------------------------
// Création, lecture, suppression et durabilité — phase 4.
//
// NON VÉRIFIÉ À L'EXÉCUTION. Ce bloc est compilé par
// `cargo check --target x86_64-pc-windows-msvc` (signatures et types validés par
// le compilateur) mais n'a **jamais tourné** : aucun binaire Windows n'est lié ni
// lancé dans l'environnement de développement. Voir SECURITY.md, limites L2 et L9.
//
// Différence structurelle avec Unix, qui gouverne tout ce bloc : Windows n'a pas
// de famille `*at`. On ne peut donc pas tenir un descripteur de répertoire et
// opérer relativement à lui. Chaque chemin est vérifié **avant** l'opération, ce
// qui laisse une fenêtre de course — la protection **n'est pas équivalente** à
// celle d'Unix, et n'est pas présentée comme telle.
// ---------------------------------------------------------------------------

use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, GetTokenInformation, InitializeSecurityDescriptor, NO_INHERITANCE, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DeleteFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FindClose, FindFirstFileW, FindNextFileW,
    GetFileAttributesW, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, RemoveDirectoryW, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::fs::Durability;

/// Ferme un descripteur de jeton à la destruction.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: le descripteur provient de `OpenProcessToken` et n'est fermé
        // qu'ici. Un échec de `CloseHandle` n'a pas de remède utile.
        unsafe { CloseHandle(self.0) };
    }
}

/// Descripteur de sécurité privé : une seule ACE, pour l'utilisateur courant.
///
/// La DACL est **protégée** (`SE_DACL_PROTECTED`) : aucune ACE héritée du
/// répertoire parent n'y est ajoutée. C'est ce qui rend la restriction
/// indépendante de l'endroit où le fichier est créé — un répertoire partagé ou la
/// racine d'un disque n'élargissent pas les droits.
struct PrivateSecurity {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    acl: *mut ACL,
}

impl Drop for PrivateSecurity {
    fn drop(&mut self) {
        // SAFETY: l'ACL vient de `SetEntriesInAclW`, qui l'alloue par le
        // allocateur local ; `LocalFree` est la libération documentée. Le
        // descripteur, lui, est possédé par le `Box` et libéré automatiquement.
        unsafe {
            if !self.acl.is_null() {
                LocalFree(self.acl.cast());
            }
        }
    }
}

impl PrivateSecurity {
    /// Attributs à passer aux appels de création.
    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: (&raw mut *self.descriptor).cast(),
            bInheritHandle: 0,
        }
    }
}

/// Construit une DACL n'accordant le contrôle total qu'à l'utilisateur courant.
///
/// # Séquence
/// jeton du processus → SID de l'utilisateur → `EXPLICIT_ACCESS_W` (une ACE,
/// `GENERIC_ALL`, `SET_ACCESS`, sans héritage) → `SetEntriesInAclW` → descripteur
/// de sécurité → DACL protégée.
///
/// # Pourquoi une DACL explicite plutôt que les ACL héritées
/// Les ACL héritées du profil utilisateur sont correctes dans le cas nominal et
/// **fausses** dès que le fichier est créé ailleurs (dossier partagé, racine d'un
/// disque). Poser la DACL nous-mêmes rend la restriction indépendante de
/// l'emplacement.
///
/// # Échec fermé
/// Toute étape en échec fait échouer l'appel : on préfère **ne pas créer** le
/// fichier plutôt que de le créer avec des droits plus larges que voulu.
fn private_security() -> io::Result<PrivateSecurity> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` est une variable vivante et inscriptible.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = TokenHandle(token);

    // Premier appel : la taille nécessaire. L'échec est attendu, c'est `needed` qui
    // porte l'information.
    let mut needed: u32 = 0;
    // SAFETY: le tampon nul est explicitement autorisé pour interroger la taille.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    // Tampon aligné sur `usize` : `TOKEN_USER` contient des pointeurs, et un
    // `Vec<u8>` (alignement 1) rendrait la relecture indéfinie.
    let words = usize::try_from(needed)
        .unwrap_or(0)
        .div_ceil(size_of::<usize>().max(1));
    let mut buffer: Vec<usize> = vec![0; words];
    // SAFETY: le tampon est au moins aussi grand que `needed` octets et
    // correctement aligné.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: le tampon contient un `TOKEN_USER` écrit par le noyau, et il reste
    // vivant jusqu'à la fin de la fonction — donc pendant tout usage du SID.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    };

    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `access` décrit une ACE valide et vivante ; `acl` est inscriptible.
    // L'absence d'ACL d'entrée est signalée par un pointeur nul.
    if unsafe { SetEntriesInAclW(1, &raw const access, std::ptr::null(), &raw mut acl) }
        != ERROR_SUCCESS
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `SECURITY_DESCRIPTOR` est une structure de pointeurs et d'entiers ;
    // la valeur nulle est un état de départ valide avant `Initialize`.
    let mut descriptor = Box::new(unsafe { std::mem::zeroed::<SECURITY_DESCRIPTOR>() });

    // SAFETY: `descriptor` est alloué sur le tas et correctement aligné.
    if unsafe {
        InitializeSecurityDescriptor((&raw mut *descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // `1` = la DACL est présente, `0` = elle n'est pas héritée par défaut.
    // SAFETY: le descripteur vient d'être initialisé, l'ACL est valide.
    if unsafe { SetSecurityDescriptorDacl((&raw mut *descriptor).cast(), 1, acl, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // Sans cette ligne, le noyau fusionnerait la DACL avec les ACE héritées du
    // parent : la restriction dépendrait alors de l'emplacement du fichier.
    // SAFETY: le descripteur est initialisé et la DACL a été posée.
    if unsafe {
        SetSecurityDescriptorControl(
            (&raw mut *descriptor).cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(PrivateSecurity { descriptor, acl })
}

/// Crée un fichier **neuf**, avec une DACL restrictive, sans jamais écraser.
///
/// `CREATE_NEW` joue le rôle de `O_CREAT|O_EXCL` : le contrôle d'existence et la
/// création sont **un seul appel**, donc sans fenêtre entre les deux.
///
/// # Non vérifié
/// La DACL est posée par `SECURITY_ATTRIBUTES` **dans l'appel de création**, ce qui
/// évite toute fenêtre où le fichier existerait avec les droits hérités. **Le
/// comportement à l'exécution n'a jamais été observé.**
pub fn create_private_file(target: &Path) -> io::Result<File> {
    let (dir, _name) = split_target(target)?;
    crate::fs::ensure_no_symlink_components(&dir)?;

    let mut security = private_security()?;
    let attributes = security.attributes();
    let wide = to_wide(target)?;

    // SAFETY: `wide` est une chaîne UTF-16 terminée par un nul et vivante ;
    // `attributes` référence un descripteur vivant jusqu'à la fin de l'appel.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` est un descripteur valide dont la propriété est transférée.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Crée un répertoire privé, avec une DACL restrictive.
///
/// Rend [`Durability::FileOnly`] : Windows n'offre pas, via cette API, la
/// synchronisation de l'entrée de répertoire parente qui rendrait le nom durable
/// sur Unix.
pub fn create_dir_private(target: &Path) -> io::Result<Durability> {
    let (dir, _name) = split_target(target)?;
    crate::fs::ensure_no_symlink_components(&dir)?;

    let mut security = private_security()?;
    let attributes = security.attributes();
    let wide = to_wide(target)?;

    // SAFETY: `wide` est valide et vivante ; `attributes` référence un descripteur
    // vivant. `CreateDirectoryW` échoue si l'entrée existe déjà.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Durability::FileOnly)
}

/// Supprime un fichier. Échoue sur un répertoire, ce qui est voulu.
pub fn remove_file(target: &Path) -> io::Result<()> {
    let (dir, _name) = split_target(target)?;
    crate::fs::ensure_no_symlink_components(&dir)?;
    let wide = to_wide(target)?;
    // SAFETY: `wide` est une chaîne UTF-16 valide et vivante.
    if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Supprime un répertoire **vide**. Échoue s'il contient encore quelque chose.
pub fn remove_dir(target: &Path) -> io::Result<()> {
    let (dir, _name) = split_target(target)?;
    crate::fs::ensure_no_symlink_components(&dir)?;
    let wide = to_wide(target)?;
    // SAFETY: `wide` est une chaîne UTF-16 valide et vivante.
    if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Extrait le nom d'un `cFileName` terminé par un nul.
fn find_data_name(data: &WIN32_FIND_DATAW) -> std::ffi::OsString {
    let end = data
        .cFileName
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(data.cFileName.len());
    std::ffi::OsString::from_wide(&data.cFileName[..end])
}

/// Liste les noms des entrées d'un répertoire.
///
/// # Limites assumées, propres à Windows
/// * le chemin est vérifié **avant** l'énumération, sans descripteur tenu : la
///   fenêtre de course habituelle de cette plateforme s'applique ;
/// * le motif de recherche est construit par concaténation, donc un nom de
///   répertoire contenant `*` ou `?` élargit la recherche. C'est sans danger ici :
///   l'appelant ne retient que les noms ayant exactement la forme d'un nom de blob.
pub fn list_dir(target: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    crate::fs::ensure_no_symlink_components(target)?;

    let mut pattern = target.to_path_buf();
    pattern.push("*");
    let wide = to_wide(&pattern)?;

    // SAFETY: `WIN32_FIND_DATAW` est une structure de POD ; la valeur nulle est un
    // état de départ valide.
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` est valide et vivante ; `data` est vivant et inscriptible.
    let handle = unsafe { FindFirstFileW(wide.as_ptr(), &raw mut data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let mut names = Vec::new();
    loop {
        let name = find_data_name(&data);
        if name != "." && name != ".." {
            names.push(name);
        }
        // SAFETY: `handle` provient de `FindFirstFileW` et `data` est inscriptible.
        if unsafe { FindNextFileW(handle, &raw mut data) } == 0 {
            break;
        }
    }
    // SAFETY: `handle` provient de `FindFirstFileW` et n'est plus utilisé ensuite.
    unsafe { FindClose(handle) };

    Ok(names)
}

/// Ouvre un fichier ordinaire en lecture seule.
///
/// `FILE_FLAG_OPEN_REPARSE_POINT` empêche de suivre un lien au **dernier**
/// composant — les composants intermédiaires, eux, ne sont couverts que par la
/// vérification préalable.
pub fn open_read(target: &Path) -> io::Result<File> {
    let (dir, _name) = split_target(target)?;
    crate::fs::ensure_no_symlink_components(&dir)?;
    let wide = to_wide(target)?;

    // SAFETY: `wide` est valide et vivante ; aucun attribut de sécurité n'est
    // demandé pour une ouverture en lecture.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` est un descripteur valide dont la propriété est transférée.
    let file = unsafe { File::from_raw_handle(handle) };

    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "la cible n'est pas un fichier ordinaire",
        ));
    }
    Ok(file)
}

/// Lit un fichier entier, en refusant de dépasser `max_len` octets.
///
/// La borne est appliquée **pendant** la lecture, jamais déduite d'une taille
/// annoncée par le fichier.
pub fn read_file(target: &Path, max_len: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut file = open_read(target)?;
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
    let mut buffer = Vec::new();
    let mut limited = (&mut file).take(limit);
    limited.read_to_end(&mut buffer)?;

    if buffer.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("le fichier dépasse la taille maximale de {max_len} octets"),
        ));
    }
    Ok(buffer)
}

/// Vrai si l'entrée existe.
///
/// # Usage
/// Énumération et rapport uniquement — jamais comme garde avant une création.
#[must_use]
pub fn path_exists(target: &Path) -> bool {
    let Ok(wide) = to_wide(target) else {
        return false;
    };
    // SAFETY: `wide` est une chaîne UTF-16 valide et vivante.
    unsafe { GetFileAttributesW(wide.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}

/// Rend durable le contenu du fichier — et **seulement** son contenu.
///
/// Rend toujours [`Durability::FileOnly`] : il n'existe pas, sous cette forme, de
/// synchronisation de l'entrée de répertoire parente. La persistance du **nom**
/// n'est donc pas revendiquée, et le niveau réduit est rapporté à l'utilisateur
/// plutôt que dissimulé.
///
/// L'absence de cette capacité **n'est pas une erreur** : le fichier est
/// parfaitement utilisable, seule une coupure de courant peut faire disparaître son
/// nom — ce que `attach verify` détecte.
pub fn make_durable(file: &File, _dir: &Path) -> io::Result<Durability> {
    // `sync_all` est `FlushFileBuffers` sur le descripteur.
    file.sync_all()?;
    Ok(Durability::FileOnly)
}

/// Sous Windows, la persistance du **nom** dans le répertoire n'est pas revendiquée.
///
/// `FlushFileBuffers` sur un descripteur de répertoire exige
/// `FILE_FLAG_BACKUP_SEMANTICS`, et NTFS n'offre pas la même sémantique
/// d'ordonnancement que `fsync` sur un répertoire. Le niveau réduit est **rendu**, et
/// rapporté à l'utilisateur à l'ouverture du coffre.
///
/// **NON VÉRIFIÉ À L'EXÉCUTION.**
pub(crate) const fn platform_durability() -> Durability {
    Durability::FileOnly
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
