//! Écriture atomique, verrouillage de fichier et permissions, façade portable.
//!
//! # Le protocole d'écriture, et pourquoi il est plus long qu'un `fs::write`
//!
//! ```text
//!   1. ouvrir le répertoire cible avec O_DIRECTORY|O_NOFOLLOW
//!   2. créer « .<nom>.tmp-<suffixe aléatoire> » dans ce répertoire,
//!      avec O_CREAT|O_EXCL|O_NOFOLLOW et le mode 0600 dès la création
//!   3. écrire, puis fsync du fichier
//!   4. renommer le temporaire sur la cible
//!   5. fsync du répertoire
//!   6. relâcher le verrou
//! ```
//!
//! Chaque étape répond à une attaque précise :
//!
//! | Étape | Attaque contrée |
//! |---|---|
//! | `O_NOFOLLOW` sur le répertoire | Le répertoire cible remplacé par un lien symbolique |
//! | Nom temporaire aléatoire + `O_EXCL` | Pré-création d'un lien symbolique à un emplacement prévisible |
//! | Mode `0600` **à la création** | Fenêtre pendant laquelle le fichier existe avec les permissions de l'`umask` |
//! | `fsync` avant renommage | Coupure de courant : un contenu non encore écrit devient visible |
//! | Renommage plutôt que copie | État intermédiaire : le coffre n'est jamais partiellement écrit |
//! | `fsync` du répertoire | Le renommage lui-même n'est pas persistant |
//! | Verrou exclusif | Deux instances qui écrasent mutuellement leur travail |
//!
//! ## Ce que ce module ne protège pas
//!
//! * Un attaquant qui contrôle un **composant intermédiaire** du chemin — par
//!   exemple `~/a/b/coffre.plk` où `~/a` est un lien symbolique. Seule une marche
//!   composant par composant ou `openat2(RESOLVE_NO_SYMLINKS)` répondrait
//!   complètement. Non implémenté, documenté comme limite connue.
//! * Un attaquant disposant de `root`, qui contourne toute vérification.
//!
//! ## Systèmes de fichiers sans permissions
//!
//! Sur FAT32/exFAT (fréquent sur clé USB), le mode `0600` est **sans effet** :
//! l'appel réussit mais les permissions ne sont pas appliquées. Laisser croire à
//! une protection inexistante serait pire que de ne pas en avoir, d'où
//! [`verify_private`] qui relit et compare après écriture.

use std::io;
use std::path::Path;

/// Écrit `data` dans `target` de façon atomique.
///
/// `temp_suffix` doit être une chaîne **aléatoire** fournie par l'appelant. Ce
/// module ne génère pas d'aléa : il n'a pas accès au générateur du système et ne
/// veut pas en introduire un second. Le suffixe empêche la pré-création d'un lien
/// symbolique à un nom devinable.
///
/// À la sortie, `target` contient soit son contenu précédent intact, soit le
/// nouveau contenu complet. Aucun état intermédiaire n'est observable, y compris
/// après une coupure de courant ou un `kill -9` pendant l'écriture.
///
/// # Erreurs
/// * `io::ErrorKind::InvalidInput` si le chemin ne désigne pas un fichier dans un
///   répertoire, ou s'il contient un octet nul ;
/// * `io::ErrorKind::AlreadyExists` si le nom temporaire existe déjà — ce qui
///   signale soit une collision de suffixe aléatoire, soit une tentative de
///   pré-création ;
/// * l'erreur du système pour toute autre défaillance.
pub use crate::backend::write_atomic;

/// Verrou exclusif empêchant deux instances d'écrire le même coffre.
///
/// Le verrou est pris sur un fichier annexe `<coffre>.lock` et non sur le coffre
/// lui-même. La raison est technique : l'écriture atomique **remplace** le fichier
/// (le renommage crée un nouvel inode), donc un verrou posé sur le coffre serait
/// perdu au premier enregistrement, silencieusement.
///
/// Le verrou est libéré à la destruction de la valeur, et de toute façon par la
/// fermeture du descripteur.
pub use crate::backend::FileLock;

/// Corrige les permissions de `path` si elles permettent un accès autre que par
/// le propriétaire.
///
/// Un coffre copié depuis une sauvegarde ou restauré par un outil tiers peut avoir
/// des permissions trop ouvertes. Refuser de l'ouvrir serait brutal, l'ouvrir
/// silencieusement laisserait le coffre exposé : on corrige et on le signale.
///
/// # Retour
/// `Ok(true)` si les permissions ont été corrigées, `Ok(false)` si elles étaient
/// déjà restrictives, `Ok(false)` également si le système de fichiers ne gère pas
/// les permissions (le mode lu et le mode écrit seront alors identiques).
///
/// # Erreurs
/// Propage l'erreur du système.
pub use crate::backend::verify_private;

/// Ouvre un répertoire en refusant tout lien symbolique sur l'un de ses
/// composants, **intermédiaires compris**.
///
/// Retourne un descripteur utilisable comme base pour `openat` et `renameat`, ce
/// qui garantit qu'aucun composant ne peut être remplacé après vérification : c'est
/// ce qui distingue cette approche d'une simple vérification préalable.
///
/// Disponible sur Unix uniquement. Windows n'a pas d'équivalent de la famille
/// `*at` : sa variante est [`ensure_no_symlink_components`], appelée en amont de
/// l'opération, avec la course résiduelle documentée.
#[cfg(unix)]
pub use crate::backend::open_dir_no_symlinks;

/// Refuse un chemin dont l'un des composants est un lien symbolique.
///
/// # Portabilité, et honnêteté sur la garantie
///
/// Cette fonction n'utilise que la bibliothèque standard, donc elle fonctionne
/// partout — y compris sur Windows, où elle s'appuie sur l'attribut de point
/// d'analyse plutôt que sur `FileType::is_symlink`.
///
/// **Mais elle est sujette à une course** : la vérification et l'opération qui la
/// suit sont deux actions distinctes, et rien n'empêche le remplacement d'un
/// composant entre les deux. Elle ne doit donc pas être présentée comme équivalente
/// à [`open_dir_no_symlinks`].
///
/// Sur Unix, `write_atomic` utilise la marche avec descripteurs et **n'a pas
/// besoin** de cette fonction. Elle existe pour Windows, et pour les appelants qui
/// doivent vérifier un chemin indépendamment d'une écriture.
///
/// # Erreurs
/// `io::ErrorKind::InvalidInput` si un composant est un lien symbolique, avec un
/// message nommant le composant fautif et le remède.
pub fn ensure_no_symlink_components(dir: &Path) -> io::Result<()> {
    use std::path::Component;

    let mut current = std::path::PathBuf::new();

    for component in dir.components() {
        current.push(component.as_os_str());

        match component {
            // `..` est une entrée de répertoire ordinaire, jamais un lien.
            // Ces composants ne désignent aucune entrée à vérifier : la racine et
            // le répertoire courant ne sont pas des entrées, `..` n'est jamais un
            // lien, et un préfixe Windows n'existe pas ici. L'arm est la dernière
            // expression de la boucle, un `continue` explicite serait redondant.
            Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_) => {}
            Component::Normal(name) => match std::fs::symlink_metadata(&current) {
                Ok(metadata) if is_reparse_point(&metadata) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "le chemin traverse un lien symbolique au composant « {} ». Par \
                             sécurité, Passlock refuse d'écrire à travers un lien qu'il n'a pas \
                             créé : un attaquant disposant du droit d'écriture sur un répertoire \
                             parent pourrait rediriger le coffre. Remède : passez le chemin \
                             résolu plutôt que le chemin symbolique.",
                            name.to_string_lossy()
                        ),
                    ));
                }
                Ok(_) => {}
                // Un composant inexistant interrompt la vérification : les suivants
                // n'existent pas davantage, et la création se fera dans un répertoire
                // dont tous les ancêtres existants ont été vérifiés.
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(err),
            },
        }
    }

    Ok(())
}

/// Vrai si l'entrée est un lien symbolique ou un point d'analyse.
///
/// # Pourquoi ce n'est pas simplement `FileType::is_symlink`
///
/// Sur Windows, `is_symlink` ne reconnaît pas les **points de jonction** ni
/// certains points d'analyse, alors qu'ils redirigent tout autant. Vérifier
/// l'attribut `FILE_ATTRIBUTE_REPARSE_POINT` couvre la famille entière.
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        /// `FILE_ATTRIBUTE_REPARSE_POINT` : l'entrée possède un point d'analyse.
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

/// Répertoire d'état local à l'application (sentinelle anti-rollback).
///
/// ## Pourquoi ce n'est pas le répertoire du coffre
///
/// La sentinelle détecte qu'un coffre a **reculé** de génération. Si elle vivait à
/// côté du coffre, un attaquant capable d'écrire le coffre pourrait écrire la
/// sentinelle du même geste et la détection ne vaudrait rien. Elle est donc placée
/// dans le répertoire de configuration de l'utilisateur, sur un volume distinct
/// lorsque le coffre est sur une clé USB.
///
/// # Erreurs
/// [`io::ErrorKind::NotFound`] si aucune variable d'environnement ne permet de
/// déterminer un répertoire de configuration.
pub fn app_state_dir() -> io::Result<std::path::PathBuf> {
    // Déterminé à partir de variables d'environnement standard. On évite
    // volontairement une dépendance supplémentaire pour trois variables.
    #[cfg(unix)]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
            let base = std::path::PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("passlock"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(std::path::PathBuf::from(home)
                .join(".config")
                .join("passlock"));
        }
    }

    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(std::path::PathBuf::from(appdata).join("Passlock"));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "impossible de déterminer le répertoire de configuration de l'utilisateur",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn app_state_dir_is_absolute_when_available() {
        match app_state_dir() {
            Ok(path) => assert!(
                path.is_absolute(),
                "répertoire d'état non absolu : {path:?}"
            ),
            // Cas légitime dans un environnement sans HOME ni XDG_CONFIG_HOME.
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn app_state_dir_is_not_the_vault_directory() {
        // La sentinelle doit vivre ailleurs que le coffre, sinon un attaquant qui
        // écrit le coffre écrit aussi la sentinelle. On vérifie ici la propriété
        // structurelle : le chemin ne dépend pas du répertoire courant.
        if let Ok(path) = app_state_dir() {
            let cwd = std::env::current_dir().expect("répertoire courant");
            assert!(
                !path.starts_with(&cwd) || path.starts_with(cwd.join(".config")),
                "répertoire d'état ancré dans le répertoire courant : {path:?}"
            );
            let _ = Path::new("");
        }
    }
}
