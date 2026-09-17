//! Backend Linux/macOS (`unix`) pour le verrouillage mémoire.
//!
//! Toutes les fonctions prennent une adresse et une longueur et n'accèdent jamais
//! au contenu de la zone. Les erreurs du système sont remontées telles quelles :
//! c'est à l'appelant de décider si l'échec est acceptable (il l'est presque
//! toujours, sauf dégradation à signaler).

use std::io;

/// `mlock(2)` — interdit au noyau d'écrire ces pages dans l'espace d'échange.
///
/// # Erreurs
/// `ENOMEM` si la limite `RLIMIT_MEMLOCK` est dépassée (fréquent sans privilèges),
/// `EPERM` si le processus n'y est pas autorisé.
pub fn lock_region(addr: *const u8, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: `addr` provient d'un slice vivant chez l'appelant et `len` en est la
    // longueur, donc la zone [addr, addr+len) est allouée et valide pour toute la
    // durée de l'appel. `mlock` ne lit ni n'écrit le contenu de la zone : elle ne
    // change que l'état des pages dans la table de pages du noyau. Le pointeur est
    // converti en `*mut c_void` uniquement parce que la signature C de `mlock` est
    // non-constante ; aucun écrit n'est effectué.
    let rc = unsafe { libc::mlock(addr.cast::<libc::c_void>().cast_mut(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `munlock(2)` — annule [`lock_region`].
pub fn unlock_region(addr: *const u8, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: mêmes garanties que dans `lock_region`.
    let rc = unsafe { libc::munlock(addr.cast::<libc::c_void>().cast_mut(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `madvise(MADV_DONTDUMP)` — exclut la zone des vidages mémoire.
///
/// L'option n'existe pas sur les noyaux Linux antérieurs à 3.4 et n'existe pas du
/// tout sur macOS, où l'appel échoue. L'échec doit être traité comme non bloquant.
///
/// L'alignement sur une page n'est pas exigé : le noyau arrondit vers l'extérieur.
/// `madvise` échoue toutefois si la zone déborde d'un mapping, ce qui explique
/// qu'on tolère l'erreur plutôt que de la considérer comme anormale.
pub fn exclude_from_dump(addr: *const u8, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `addr`/`len` décrivent un slice vivant chez l'appelant. `madvise`
        // ne touche pas au contenu de la zone.
        let rc = unsafe {
            libc::madvise(
                addr.cast::<libc::c_void>().cast_mut(),
                len,
                libc::MADV_DONTDUMP,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MADV_DONTDUMP n'existe pas sur cette plateforme",
        ))
    }
}

/// Désactive les vidages mémoire du processus.
pub(crate) fn disable_core_dumps() -> crate::process::HardeningOutcome {
    use crate::process::HardeningOutcome;
    // SAFETY: `setrlimit` reçoit un pointeur vers une structure `rlimit` initialisée
    // et vivante pour la durée de l'appel. Réduire une limite est toujours permis
    // sans privilèges ; seul l'augmenter exigerait CAP_SYS_RESOURCE, et nous ne
    // faisons que réduire à zéro.
    let rc = unsafe {
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        )
    };
    if rc == 0 {
        HardeningOutcome::Applied
    } else {
        HardeningOutcome::Failed
    }
}

/// Rend le processus non « vidable ».
///
/// Sur Linux, `prctl(PR_SET_DUMPABLE, 0)` a deux effets utiles :
/// 1. un autre processus du **même utilisateur** ne peut plus s'attacher via
///    `ptrace(2)` ni lire `/proc/<pid>/mem` ;
/// 2. plus aucun vidage mémoire n'est produit pour ce processus.
///
/// `root` n'est pas concerné : c'est une limite du système, pas de cette fonction.
pub(crate) fn restrict_ptrace() -> crate::process::HardeningOutcome {
    use crate::process::HardeningOutcome;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl` avec une option numérique et des scalaires ne déréférence
        // aucun pointeur invalide. L'appel ne modifie qu'un attribut du processus
        // courant.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc == 0 {
            HardeningOutcome::Applied
        } else {
            HardeningOutcome::Failed
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        HardeningOutcome::Unsupported
    }
}

// ---------------------------------------------------------------------------
// Écriture atomique, verrouillage et permissions.
// ---------------------------------------------------------------------------

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::fs::Durability;

/// Convertit un chemin en chaîne C, en refusant les octets nuls.
///
/// Un octet nul dans un chemin tronquerait silencieusement la chaîne côté noyau :
/// `"coffre\0.plk"` deviendrait `"coffre"`. C'est une différence dangereuse entre
/// ce que le programme croit manipuler et ce que le système ouvre réellement.
fn to_cstring(path: &OsStr, what: &'static str) -> io::Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} contient un octet nul, ce qui tronquerait le chemin côté noyau"),
        )
    })
}

/// Ouvre le répertoire `dir` en refusant tout lien symbolique sur **l'un
/// quelconque** de ses composants, intermédiaires compris.
///
/// # Pourquoi une marche composant par composant
///
/// Les approches ont été comparées avant de retenir celle-ci :
///
/// | Approche | Sécurité | Portabilité | Complexité |
/// |---|---|---|---|
/// | `openat2(RESOLVE_NO_SYMLINKS)` | maximale, atomique | **Linux ≥ 5.6 seulement**, numéro d'appel par architecture, absent de `libc` | faible mais FFI brute + détection de disponibilité |
/// | vérification `lstat` préalable | **faible** : TOCTOU entre la vérification et l'ouverture | totale | faible |
/// | refus global de tout lien | élevée | totale | faible, mais casse les dispositions légitimes (`/home` symbolique sur certaines distributions) |
/// | **marche avec descripteurs tenus** | élevée : chaque composant est vérifié *et* retenu | POSIX, avec un analogue Windows (`FILE_FLAG_OPEN_REPARSE_POINT`) | moyenne |
///
/// La marche est retenue parce qu'elle est la seule à être à la fois sûre — les
/// descripteurs ouverts garantissent qu'aucun composant ne peut être remplacé
/// après vérification — et transposable à Windows, où `openat2` n'existe pas.
///
/// # `O_NOFOLLOW` seul ne suffit pas
///
/// `O_NOFOLLOW` ne s'applique qu'au **dernier** composant d'un chemin. C'est
/// précisément la limite que l'audit de la phase 1 a démontrée : écrire dans
/// `a/b/coffre.plk` où `a` est un lien symbolique écrivait chez l'attaquant. Ici,
/// chaque composant est ouvert avec `O_NOFOLLOW` et depuis le descripteur du
/// précédent, donc un lien symbolique n'importe où dans le chemin fait échouer
/// l'ouverture.
///
/// # Limite assumée
///
/// Chaque composant est ouvert en lecture, ce qui exige le droit de lecture sur
/// chaque répertoire traversé. Un répertoire traversable mais non lisible (mode
/// `--x`) est refusé. C'est le cas rare : les répertoires de données personnelles
/// sont normalement lisibles par leur propriétaire.
///
/// # Erreurs
/// `io::ErrorKind::InvalidInput` si un composant est un lien symbolique, avec un
/// message nommant le composant fautif et le remède.
pub fn open_dir_no_symlinks(dir: &Path) -> io::Result<File> {
    use std::path::Component;

    // Ancrage explicite : la racine pour un chemin absolu, le répertoire courant
    // sinon. Tout le reste est résolu **relativement** à cet ancrage, jamais par le
    // noyau à partir du chemin complet.
    let anchor = if dir.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };

    let anchor_c = to_cstring(anchor.as_os_str(), "l'ancrage du chemin")?;
    // SAFETY: `anchor_c` est une chaîne C valide et vivante ; les drapeaux sont des
    // constantes entières. L'ancrage est une constante du programme, pas une donnée
    // d'entrée : il ne peut pas être un lien symbolique.
    let fd = unsafe {
        libc::open(
            anchor_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être retourné par `open` et n'est détenu par personne.
    let mut current = unsafe { File::from_raw_fd(fd) };

    for component in dir.components() {
        let name = match component {
            // L'ancrage est déjà ouvert, et un préfixe Windows n'existe pas ici.
            Component::RootDir | Component::CurDir | Component::Prefix(_) => continue,
            // `..` est une entrée de répertoire ordinaire, pas un lien : le refuser
            // casserait des chemins relatifs légitimes. `O_NOFOLLOW` ne s'y applique
            // pas, et le descripteur du parent garantit qu'on remonte bien depuis le
            // répertoire vérifié.
            Component::ParentDir => OsString::from(".."),
            Component::Normal(name) => name.to_os_string(),
        };

        let name_c = to_cstring(&name, "un composant du chemin")?;
        // SAFETY: `current` détient un descripteur de répertoire ouvert ; `name_c`
        // est une chaîne C valide et vivante. `O_NOFOLLOW` fait échouer l'ouverture
        // sur un lien symbolique, et `O_DIRECTORY` sur tout ce qui n'est pas un
        // répertoire.
        let next = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };

        if next < 0 {
            let err = io::Error::last_os_error();
            // Linux renvoie `ELOOP` ou `ENOTDIR` selon la version lorsqu'un lien
            // symbolique est rencontré avec `O_NOFOLLOW|O_DIRECTORY`. On lève le
            // doute en interrogeant l'entrée sans la suivre, afin de produire un
            // message exact plutôt qu'une supposition.
            let is_symlink = is_symlink_at(current.as_raw_fd(), &name_c);
            let _ = err;
            return Err(if is_symlink {
                symlink_component_error(&name)
            } else {
                err
            });
        }

        // SAFETY: `next` vient d'être retourné par `openat` ; l'ancien descripteur
        // est fermé par la destruction de `current`.
        current = unsafe { File::from_raw_fd(next) };
    }

    Ok(current)
}

/// Indique si l'entrée nommée, relative à `dir_fd`, est un lien symbolique.
///
/// N'échoue jamais : en cas d'erreur, on répond « non » et l'appelant produira
/// l'erreur d'origine, qui reste correcte.
fn is_symlink_at(dir_fd: RawFd, name: &CString) -> bool {
    // SAFETY: `dir_fd` est un descripteur de répertoire ouvert et `name` une chaîne
    // C valide. `fstatat` remplit `stat` en cas de succès ; on ne lit les champs
    // que dans ce cas.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir_fd,
            name.as_ptr(),
            &raw mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    rc == 0 && (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

/// Construit l'erreur signalant un composant symbolique, avec le remède.
fn symlink_component_error(name: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "le chemin traverse un lien symbolique au composant « {} ». Par sécurité,              Passlock refuse d'écrire à travers un lien qu'il n'a pas créé : un attaquant              disposant du droit d'écriture sur un répertoire parent pourrait rediriger le              coffre. Remède : passez le chemin résolu (`realpath`) plutôt que le chemin              symbolique.",
            name.to_string_lossy()
        ),
    )
}

/// Découpe un chemin cible en (répertoire, nom de fichier).
fn split_target(target: &Path) -> io::Result<(PathBuf, OsString)> {
    let name = target.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "le chemin cible ne désigne pas un fichier",
        )
    })?;
    // `parent()` retourne `Some("")` pour un chemin relatif sans répertoire :
    // on retombe alors sur le répertoire courant.
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((dir, name.to_os_string()))
}

/// Écrit `data` dans `target` de façon atomique.
pub fn write_atomic(target: &Path, temp_suffix: &str, data: &[u8]) -> io::Result<()> {
    let (dir, file_name) = split_target(target)?;

    // Le répertoire est ouvert par une marche qui refuse tout composant
    // symbolique, intermédiaires compris — `O_NOFOLLOW` seul ne protégeait que le
    // dernier. Le descripteur obtenu sert de base à `openat` et `renameat`, ce qui
    // garantit qu'aucun composant ne peut être remplacé après vérification.
    let dir_guard = open_dir_no_symlinks(&dir)?;
    let dir_fd = dir_guard.as_raw_fd();

    // Nom temporaire imprévisible. Le point initial le rend invisible dans un
    // listage ordinaire, ce qui évite d'attirer l'attention sur un fichier
    // présentant un coffre à moitié écrit.
    let mut temp_name = OsString::from(".");
    temp_name.push(&file_name);
    temp_name.push(".tmp-");
    temp_name.push(temp_suffix);

    let temp_c = to_cstring(&temp_name, "le nom du fichier temporaire")?;
    let target_c = to_cstring(&file_name, "le nom du fichier cible")?;

    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `temp_c` est valide et vivante ; `dir_fd` est un descripteur de
    // répertoire ouvert. Le mode 0600 est appliqué par le noyau *à la création*,
    // ce qui évite toute fenêtre où le fichier existerait avec les permissions de
    // l'umask. `O_EXCL` garantit qu'on ne suit ni ne réutilise un fichier existant,
    // et `O_NOFOLLOW` qu'on ne suit pas un lien symbolique pré-créé.
    let fd = unsafe { libc::openat(dir_fd, temp_c.as_ptr(), flags, 0o600_u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être retourné par `openat` et n'est détenu par personne.
    // Le `File` prend possession du descripteur et le fermera à sa destruction,
    // y compris si une écriture échoue et que la fonction sort par `?`.
    let mut file = unsafe { File::from_raw_fd(fd) };

    if let Err(err) = file.write_all(data) {
        // Le temporaire est supprimé pour ne pas laisser de résidu chiffré traîner
        // dans le répertoire. L'échec de la suppression n'est pas remonté : l'erreur
        // d'écriture est la cause première et c'est elle qui doit être signalée.
        drop(file);
        let _ = libc_remove(dir_fd, &target_c, &temp_c);
        return Err(err);
    }

    // `fsync` avant le renommage : sans lui, le renommage pourrait devenir
    // persistant avant que le contenu ne le soit, et une coupure de courant
    // laisserait un coffre tronqué à la place d'un coffre valide.
    // SAFETY: `file` détient un descripteur ouvert.
    if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
        let err = io::Error::last_os_error();
        drop(file);
        let _ = libc_remove(dir_fd, &target_c, &temp_c);
        return Err(err);
    }

    // Fermer avant de renommer évite de laisser un descripteur ouvert sur un inode
    // qui n'est plus nommé.
    drop(file);

    // SAFETY: les deux chaînes C sont valides et vivantes, et `dir_fd` désigne le
    // répertoire des deux entrées. `renameat` est atomique : un observateur voit
    // soit l'ancien fichier, soit le nouveau.
    if unsafe { libc::renameat(dir_fd, temp_c.as_ptr(), dir_fd, target_c.as_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        let _ = libc_remove(dir_fd, &target_c, &temp_c);
        return Err(err);
    }

    // Le renommage n'est persistant qu'après `fsync` du répertoire.
    // SAFETY: `dir_fd` est un descripteur de répertoire ouvert.
    if unsafe { libc::fsync(dir_fd) } != 0 {
        // Le fichier cible est déjà correct : on ne peut pas annuler le renommage.
        // On signale l'échec sans prétendre que rien ne s'est passé.
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Supprime une entrée temporaire, en ignorant l'échec.
fn libc_remove(dir_fd: RawFd, _target: &CString, temp: &CString) -> io::Result<()> {
    // SAFETY: `temp` est une chaîne C valide et `dir_fd` un descripteur de
    // répertoire ouvert. On ne supprime que le nom temporaire, jamais la cible.
    let rc = unsafe { libc::unlinkat(dir_fd, temp.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// Création, lecture, suppression et durabilité — phase 4.
//
// Ces fonctions partagent toutes la même garantie de chemin : le répertoire parent
// est ouvert par `open_dir_no_symlinks`, donc par une marche qui tient un
// descripteur à chaque étape et refuse `O_NOFOLLOW` sur chacune. Le nom est ensuite
// résolu **relativement à ce descripteur**, jamais à partir du chemin complet : un
// composant ne peut donc pas être remplacé entre la vérification et l'opération.
// ---------------------------------------------------------------------------

/// Ouvre le répertoire parent et rend `(descripteur, nom, nom_brut)`.
///
/// Le descripteur doit rester vivant pendant toute l'opération : il est ce qui
/// garantit qu'aucun composant du chemin n'a été remplacé.
fn open_parent_and_name(target: &Path) -> io::Result<(File, CString, OsString)> {
    let (dir, name) = split_target(target)?;
    let guard = open_dir_no_symlinks(&dir)?;
    let name_c = to_cstring(&name, "le nom du fichier")?;
    Ok((guard, name_c, name))
}

/// Crée un fichier **neuf**, en mode 0600, sans jamais écraser.
///
/// `O_CREAT|O_EXCL` rendent le contrôle d'existence et la création **atomiques** :
/// il n'existe aucune fenêtre pendant laquelle un autre processus pourrait créer
/// l'entrée, et aucun pré-contrôle n'est donc nécessaire. `O_NOFOLLOW` refuse un
/// lien symbolique pré-créé au nom exact de la cible.
///
/// Le mode est posé par le noyau **à la création**, ce qui évite toute fenêtre où le
/// fichier existerait avec les permissions de l'`umask`.
///
/// # Erreurs
/// `AlreadyExists` si la cible existe déjà ; l'erreur du système sinon.
pub fn create_private_file(target: &Path) -> io::Result<File> {
    let (dir_guard, name_c, _name) = open_parent_and_name(target)?;

    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `name_c` est une chaîne C valide et vivante, et `dir_guard` détient un
    // descripteur de répertoire ouvert pour toute la durée de l'appel. Le mode 0600
    // est appliqué à la création. Aucun pré-contrôle n'a lieu : `O_EXCL` fait tout.
    let fd = unsafe { libc::openat(dir_guard.as_raw_fd(), name_c.as_ptr(), flags, 0o600_u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être retourné par `openat` et n'est détenu par personne.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Crée un répertoire privé (0700) et rend durable son entrée dans le parent.
///
/// # Erreurs
/// `AlreadyExists` si la cible existe déjà ; l'erreur du système sinon.
pub fn create_dir_private(target: &Path) -> io::Result<Durability> {
    let (dir_guard, name_c, _name) = open_parent_and_name(target)?;
    // SAFETY: `name_c` est valide et vivante ; `dir_guard` détient le descripteur du
    // parent. `mkdirat` échoue si l'entrée existe, ce qui évite d'adopter un
    // répertoire pré-créé par un tiers.
    if unsafe { libc::mkdirat(dir_guard.as_raw_fd(), name_c.as_ptr(), 0o700_u32) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Sans `fsync` du parent, la création du répertoire n'est pas durable : après une
    // coupure, l'entrée peut manquer alors que les fichiers qu'elle contient, eux,
    // sont durablement écrits — ils deviendraient inatteignables.
    if unsafe { libc::fsync(dir_guard.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Durability::DirectoryEntrySynced)
}

/// Supprime un fichier, sans suivre de lien symbolique.
///
/// `unlinkat` **sans** `AT_REMOVEDIR` refuse un répertoire : une cible qui serait un
/// répertoire n'est donc jamais supprimée par erreur.
///
/// Aucune synchronisation du parent : après une coupure, l'entrée peut réapparaître,
/// ce qui produit un **orphelin** — inoffensif — et non une donnée manquante.
pub fn remove_file(target: &Path) -> io::Result<()> {
    let (dir_guard, name_c, _name) = open_parent_and_name(target)?;
    // SAFETY: `name_c` est valide et vivante ; `dir_guard` détient le descripteur du
    // parent, donc l'entrée visée est bien celle du répertoire vérifié.
    if unsafe { libc::unlinkat(dir_guard.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Supprime un répertoire **vide**.
///
/// `AT_REMOVEDIR` refuse un répertoire non vide : on ne peut donc pas effacer par
/// accident un répertoire qui contient encore quelque chose.
pub fn remove_dir(target: &Path) -> io::Result<()> {
    let (dir_guard, name_c, _name) = open_parent_and_name(target)?;
    // SAFETY: identique à `remove_file` ; `AT_REMOVEDIR` restreint l'opération aux
    // répertoires, et le noyau refuse un répertoire non vide.
    if unsafe { libc::unlinkat(dir_guard.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Liste les noms des entrées d'un répertoire, lu sur le descripteur vérifié.
///
/// # Limite assumée
///
/// `readdir` ne distingue pas une erreur de lecture de la fin de l'énumération :
/// l'erreur n'est donc pas remontée. La conséquence est une liste **tronquée**, donc
/// plus courte que la réalité — et pour un ramasse-miettes qui supprime « ce qui est
/// présent et non référencé », cela signifie **moins** de suppressions. Le mode de
/// défaillance va dans le sens sûr, ce qui rend la limite acceptable ici.
pub fn list_dir(target: &Path) -> io::Result<Vec<OsString>> {
    let dir_guard = open_dir_no_symlinks(target)?;

    // `fdopendir` prend possession du descripteur et `closedir` le fermera : on lui
    // donne donc un `dup`, pour que le `File` garde le sien.
    // SAFETY: `dir_guard` détient un descripteur ouvert.
    let duplicated = unsafe { libc::dup(dir_guard.as_raw_fd()) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicated` est un descripteur de répertoire ouvert dont personne
    // d'autre ne détient la propriété.
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `duplicated` n'a pas été adopté par `fdopendir`, qui a échoué.
        unsafe { libc::close(duplicated) };
        return Err(err);
    }

    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` est un flux de répertoire ouvert.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `readdir` a rempli `d_name`, qui est un tableau d'octets terminé
        // par un nul et vit aussi longtemps que l'entrée du flux.
        let raw = unsafe { (*entry).d_name.as_ptr() };
        // SAFETY: `raw` est une chaîne C valide terminée par un nul.
        let name = unsafe { std::ffi::CStr::from_ptr(raw) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    // SAFETY: `stream` a été retourné par `fdopendir` et n'est pas utilisé ensuite ;
    // `closedir` ferme aussi le descripteur dupliqué.
    unsafe { libc::closedir(stream) };

    Ok(names)
}

/// Ouvre un fichier ordinaire en lecture seule, sans suivre de lien symbolique.
///
/// Tout ce qui n'est pas un fichier ordinaire est refusé : lire un FIFO bloquerait
/// indéfiniment, et un répertoire n'a pas de contenu à lire.
pub fn open_read(target: &Path) -> io::Result<File> {
    let (dir_guard, name_c, _name) = open_parent_and_name(target)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `name_c` est valide et vivante ; `dir_guard` détient le parent.
    let fd = unsafe { libc::openat(dir_guard.as_raw_fd(), name_c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être retourné par `openat` et n'est détenu par personne.
    let file = unsafe { File::from_raw_fd(fd) };

    let metadata = file.metadata()?;
    if !metadata.is_file() {
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
/// annoncée par le fichier : un fichier qui grossirait entre l'ouverture et la lecture
/// est donc arrêté net, et non suivi.
///
/// # Erreurs
/// `InvalidData` si le contenu dépasse `max_len`.
pub fn read_file(target: &Path, max_len: usize) -> io::Result<Vec<u8>> {
    let mut file = open_read(target)?;

    // Un octet de plus que la borne suffit à constater un dépassement.
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

/// Vrai si l'entrée existe, **sans la suivre**.
///
/// Un lien symbolique existant compte comme existant : c'est bien l'entrée de
/// répertoire qui est observée, pas sa cible.
///
/// # Usage
/// Énumération et rapport uniquement — jamais comme garde avant une création.
#[must_use]
pub fn path_exists(target: &Path) -> bool {
    let Ok((dir_guard, name_c, _name)) = open_parent_and_name(target) else {
        return false;
    };
    // SAFETY: `stat_buf` est une zone allouée et inscriptible de la taille attendue.
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `name_c` est valide et vivante ; `dir_guard` détient le parent ;
    // `stat_buf` est valide pour écriture. `AT_SYMLINK_NOFOLLOW` empêche de suivre un
    // lien : l'entrée elle-même est examinée.
    let rc = unsafe {
        libc::fstatat(
            dir_guard.as_raw_fd(),
            name_c.as_ptr(),
            &raw mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    rc == 0
}

/// `fsync` du fichier : le contenu devient durable.
fn sync_file(file: &File) -> io::Result<()> {
    // SAFETY: `file` détient un descripteur ouvert.
    if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fsync` du répertoire : **l'entrée de répertoire** devient durable.
///
/// C'est l'opération que `write_atomic` exécute déjà après son `renameat`. Elle est
/// extraite sous un nom parce que le même besoin apparaît hors de `write_atomic` :
/// `fsync` d'un fichier ne rend pas durable le **nom** qui le désigne, et une coupure
/// peut donc perdre l'entrée tout en conservant le contenu.
fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir_guard = open_dir_no_symlinks(dir)?;
    // SAFETY: `dir_guard` détient un descripteur de répertoire ouvert ; `fsync` sur un
    // répertoire est valide sous Linux et synchronise ses entrées.
    if unsafe { libc::fsync(dir_guard.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Rend durable ce qui vient d'être écrit dans `dir`.
///
/// Sous Unix, le contenu **et** le nom le deviennent : `fsync` du fichier, puis
/// `fsync` du répertoire parent. Le niveau retourné est toujours
/// [`Durability::DirectoryEntrySynced`].
///
/// # Erreurs
/// Toute erreur réelle du système. L'absence de capacité, elle, n'est pas une erreur :
/// c'est pourquoi cette fonction ne rend pas `Unsupported` — voir [`Durability`].
pub fn make_durable(file: &File, dir: &Path) -> io::Result<Durability> {
    sync_file(file)?;
    sync_dir(dir)?;
    Ok(Durability::DirectoryEntrySynced)
}

/// Sous Unix, la synchronisation de l'entrée de répertoire est disponible.
///
/// Un test vérifie que cette déclaration et ce que [`make_durable`] retourne
/// réellement ne peuvent pas diverger.
pub(crate) const fn platform_durability() -> Durability {
    Durability::DirectoryEntrySynced
}

/// Verrou exclusif sur un coffre.
///
/// Le champ `file` n'est jamais lu directement : il est conservé pour que le
/// descripteur reste ouvert, ce qui **maintient** le verrou. Sa destruction ferme le
/// descripteur et libère le verrou — comportement documenté de `flock`, et c'est ce
/// qui garantit la libération même si le processus se termine brutalement.
#[derive(Debug)]
pub struct FileLock {
    file: File,
    path: PathBuf,
}

impl FileLock {
    /// Acquiert un verrou exclusif non bloquant associé à `target`.
    ///
    /// # Erreurs
    /// [`io::ErrorKind::WouldBlock`] si un autre processus détient déjà le verrou.
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

        let lock_c = to_cstring(lock_path.as_os_str(), "le chemin du verrou")?;
        // `O_NOFOLLOW` empêche de suivre un lien symbolique pré-créé à cet
        // emplacement. On n'utilise pas `O_EXCL` : le verrou doit pouvoir être
        // réutilisé après la fin d'une session précédente.
        // SAFETY: `lock_c` est valide et vivante pour la durée de l'appel.
        let fd = unsafe {
            libc::open(
                lock_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600_u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` vient d'être retourné par `open` et n'est détenu par personne.
        let file = unsafe { File::from_raw_fd(fd) };

        // Vérification que l'on a bien ouvert un fichier ordinaire : `O_NOFOLLOW`
        // couvre le lien symbolique sur le dernier composant, mais pas un
        // répertoire ou un périphérique portant ce nom.
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "l'emplacement du verrou n'est pas un fichier ordinaire",
            ));
        }

        // SAFETY: `file` détient un descripteur ouvert ; `flock` n'agit que sur ce
        // descripteur. `LOCK_NB` évite de bloquer indéfiniment.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            file,
            path: lock_path,
        })
    }

    /// Chemin du fichier de verrou, pour l'afficher en cas de conflit.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // La fermeture du descripteur (par la destruction du `File`) libère le
        // verrou : c'est un comportement documenté de `flock`, et c'est ce qui
        // garantit la libération même si le processus se termine brutalement.
        // On pose explicitement `LOCK_UN` pour rendre l'intention lisible sans
        // dépendre de ce seul mécanisme.
        // SAFETY: le descripteur est encore ouvert à ce stade du `Drop`.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Corrige les permissions si elles permettent un accès autre que par le
/// propriétaire.
pub fn verify_private(path: &Path) -> io::Result<bool> {
    // `symlink_metadata` ne suit pas les liens : on veut connaître le mode de
    // l'entrée elle-même. Un lien symbolique à cet emplacement est de toute façon
    // refusé plus loin, parce que ce n'est pas un fichier ordinaire.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "le coffre n'est pas un fichier ordinaire",
        ));
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        // Rien à faire : ni le groupe ni les autres n'ont de droit. Un mode plus
        // restrictif que 0600 (0400 par exemple) est acceptable.
        return Ok(false);
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    // On relit pour vérifier que la correction a bien été appliquée. Sur un
    // système de fichiers qui ne gère pas les permissions (FAT32, exFAT), l'appel
    // réussit sans effet : sans cette relecture, on annoncerait une protection
    // inexistante.
    let after = std::fs::symlink_metadata(path)?.permissions().mode() & 0o777;
    if after & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "le système de fichiers refuse de restreindre les permissions \
                 (mode obtenu {after:o}) : le coffre reste accessible à d'autres \
                 utilisateurs. Déplacez-le sur un système de fichiers gérant les \
                 permissions."
            ),
        ));
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Contrôle du terminal.
// ---------------------------------------------------------------------------

/// Vrai si l'entrée standard est un terminal.
pub(crate) fn stdin_is_terminal() -> bool {
    // SAFETY: `isatty` prend un descripteur entier et ne déréférence rien.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Désactive l'écho du terminal tant que la valeur existe.
pub struct EchoGuard {
    fd: RawFd,
    original: libc::termios,
}

impl EchoGuard {
    /// Désactive l'écho sur le descripteur d'entrée standard.
    ///
    /// # Erreurs
    /// `io::ErrorKind::NotConnected` si l'entrée standard n'est pas un terminal.
    pub fn disable() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;

        // SAFETY: `termios` est une structure de type C sans pointeur ; l'initialiser
        // à zéro est valide et `tcgetattr` la remplit entièrement en cas de succès.
        let mut current: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` est un descripteur valide et `current` est vivant.
        if unsafe { libc::tcgetattr(fd, &raw mut current) } != 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                if err.raw_os_error() == Some(libc::ENOTTY) {
                    io::ErrorKind::NotConnected
                } else {
                    err.kind()
                },
                format!("impossible de lire le mode du terminal : {err}"),
            ));
        }

        let original = current;
        current.c_lflag &= !libc::ECHO;

        // `TCSAFLUSH` vide aussi les entrées déjà tapées : sans cela, une frappe
        // anticipée pendant l'affichage de l'invite resterait dans le tampon du
        // terminal et pourrait être lue comme un début de mot de passe.
        // SAFETY: mêmes garanties que ci-dessus ; `current` est correctement rempli.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const current) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, original })
    }
}

impl std::fmt::Debug for EchoGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EchoGuard { echo: désactivé }")
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: `self.original` a été rempli par un `tcgetattr` réussi et
        // `self.fd` est le descripteur sur lequel il a été lu.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &raw const self.original);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests unitaires des primitives **privées** de durabilité.
    //!
    //! `sync_file` et `sync_dir` ne sont pas publiques : elles sont des détails
    //! d'implémentation de `make_durable`. Un test d'intégration ne peut donc pas les
    //! atteindre, et c'est voulu — c'est ce qui rend impossible le scénario
    //! « `sync_dir` rend `Unsupported`, on ignore l'erreur ». Les éprouver
    //! directement demande donc un test unitaire, ici même.

    use super::{sync_dir, sync_file};
    use std::fs::File;
    use std::io::Write as _;

    #[test]
    fn sync_file_succeeds_on_an_open_file() {
        let dir = tempfile::tempdir().expect("répertoire temporaire");
        let path = dir.path().join("fichier");
        let mut file = File::create(&path).expect("création");
        file.write_all(b"contenu").expect("écriture");

        sync_file(&file).expect("fsync d'un fichier ouvert");
    }

    #[test]
    fn sync_dir_succeeds_on_a_directory() {
        let dir = tempfile::tempdir().expect("répertoire temporaire");

        sync_dir(dir.path()).expect("fsync d'un descripteur de répertoire");
    }

    #[test]
    fn sync_dir_refuses_a_path_that_is_not_a_directory() {
        let dir = tempfile::tempdir().expect("répertoire temporaire");
        let path = dir.path().join("fichier");
        File::create(&path).expect("création");

        assert!(
            sync_dir(&path).is_err(),
            "un fichier n'est pas un répertoire : l'ouverture doit échouer"
        );
    }
}
