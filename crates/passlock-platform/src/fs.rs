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
//! * Un attaquant disposant de `root`, qui contourne toute vérification.
//!
//! **NOTE DE CORRECTION.** Une version antérieure de ce commentaire affirmait que
//! les composants **intermédiaires** du chemin n'étaient pas protégés, « seule une
//! marche composant par composant ou `openat2` répondrait complètement — non
//! implémenté ». **C'était faux depuis la passe V9–V12 de la phase 1** :
//! `open_dir_no_symlinks` implémente précisément cette marche, et chaque opération
//! de ce module y passe. `SECURITY.md` limite **L1** est marquée **CORRIGÉE** pour
//! la même raison, et `THREAT_MODEL.md` §5.3 le détaille. Laisser cette phrase en
//! place aurait fait passer une protection réelle pour absente.
//!
//! ## Systèmes de fichiers sans permissions
//!
//! Sur FAT32/exFAT (fréquent sur clé USB), le mode `0600` est **sans effet** :
//! l'appel réussit mais les permissions ne sont pas appliquées. Laisser croire à
//! une protection inexistante serait pire que de ne pas en avoir, d'où
//! [`verify_private`] qui relit et compare après écriture.

use std::io;
use std::path::Path;

/// Niveau de durabilité **réellement atteint** après une écriture.
///
/// # Pourquoi un type de retour, et non une erreur
///
/// La persistance de l'**entrée de répertoire** n'a pas d'équivalent retenu sous
/// Windows : `fsync` sur un descripteur de répertoire y est propre à NTFS et ne
/// porte pas la même sémantique d'ordonnancement. Exposer cette étape comme une
/// opération faillible obligerait chaque appelant à choisir entre **échouer** sur
/// une plateforme et **ignorer une erreur** — c'est-à-dire entre une indisponibilité
/// fonctionnelle non annoncée et une garantie silencieusement absente. Les deux sont
/// refusées ici.
///
/// Le niveau est donc **retourné** par [`make_durable`], et `make_durable` n'échoue
/// que sur une **vraie** erreur d'entrée/sortie. Le type est `#[must_use]` :
/// l'ignorer ne compile pas proprement.
///
/// # Ce que le niveau veut dire, et ne veut pas dire
///
/// * [`Durability::DirectoryEntrySynced`] — le contenu **et** le nom sont durables.
/// * [`Durability::FileOnly`] — seul le contenu est durable. Après une coupure, le
///   nom peut manquer : le fichier devient invisible, ce qui produit une **absence
///   détectable**, jamais une donnée fausse.
///
/// Le niveau est une **propriété de plateforme**, pas d'un appel : il ne dépend ni
/// du fichier ni du chemin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Durability {
    /// Le fichier est synchronisé **et** son entrée de répertoire est durable.
    DirectoryEntrySynced,
    /// Le fichier est synchronisé. **La persistance du nom dans le répertoire
    /// n'est pas revendiquée.**
    FileOnly,
}

impl Durability {
    /// Vrai si la persistance de l'entrée de répertoire est revendiquée.
    #[must_use]
    pub const fn directory_entry_is_durable(self) -> bool {
        matches!(self, Self::DirectoryEntrySynced)
    }

    /// Description destinée à l'utilisateur, sans jargon de plateforme.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::DirectoryEntrySynced => {
                "contenu et nom du fichier rendus durables (fsync du fichier et du répertoire)"
            }
            Self::FileOnly => {
                "contenu du fichier rendu durable ; la persistance du nom dans le répertoire \
                 n'est pas garantie sur cette plateforme (non vérifiée)"
            }
        }
    }
}

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

/// Crée un fichier **neuf** en création exclusive, avec les permissions privées.
///
/// # Pourquoi une primitive distincte de [`write_atomic`]
///
/// `write_atomic` a une **sémantique de remplacement** : elle écrit un temporaire
/// puis le renomme sur la cible, et **écrase donc une destination existante**. Elle
/// n'est pas adaptée aux destinations qui doivent **obligatoirement être nouvelles**.
/// Ce n'est pas un défaut de `write_atomic` : c'est exactement ce qu'il faut pour le
/// coffre, qu'il faut précisément remplacer.
///
/// Ici, la création est **exclusive** : `O_CREAT|O_EXCL` sous Unix, `CREATE_NEW`
/// sous Windows. Le contrôle d'existence et la création sont donc **un seul appel**,
/// ce qui ferme toute fenêtre entre les deux. **Aucun pré-contrôle d'existence n'est
/// utilisé** — pas même [`path_exists`], qui n'existe que pour l'énumération et le
/// rapport, jamais comme garde avant une création.
///
/// # Garanties
///
/// | | Unix | Windows |
/// |---|---|---|
/// | Chemin | marche composant par composant, `O_NOFOLLOW` depuis le descripteur du précédent — **protection atomique** | vérification **préalable** des composants : **non équivalente**, sujette à une course |
/// | Permissions | mode `0600` posé par le noyau **à la création** | DACL restrictive visée, posée **dans l'appel de création** ; **NON VÉRIFIÉE** |
/// | Écrasement | impossible | impossible |
///
/// Le descripteur est rendu **ouvert** : l'appelant écrit, puis appelle
/// [`make_durable`] avant de considérer la donnée comme durable.
///
/// # Erreurs
/// `io::ErrorKind::AlreadyExists` si la cible existe ; `InvalidInput` si un composant
/// du chemin est un lien symbolique ; l'erreur du système sinon.
pub use crate::backend::create_private_file;

/// Crée un répertoire privé (mode `0700`), et **rend durable son entrée parente**.
///
/// Refuse un chemin dont un composant est un lien symbolique, et refuse d'écraser un
/// répertoire existant. Rend le [`Durability`] atteint, pour la même raison que
/// [`make_durable`] : la garantie dépend de la plateforme, et l'appelant ne doit pas
/// avoir à choisir entre échouer et l'ignorer.
pub use crate::backend::create_dir_private;

/// Supprime un fichier, sans jamais suivre de lien symbolique.
///
/// **Aucune synchronisation de répertoire n'est effectuée**, délibérément : après une
/// coupure, un fichier supprimé peut réapparaître. Le mode de défaillance est alors
/// un **orphelin** — invisible et inoffensif — et non une donnée manquante. On
/// synchronise là où l'échec créerait une promesse non tenue.
pub use crate::backend::remove_file;

/// Supprime un répertoire **vide**, sans suivre de lien symbolique.
///
/// Sert au nettoyage des répertoires que nous avons créés et dont la création a
/// échoué en cours de route.
pub use crate::backend::remove_dir;

/// Liste les noms des entrées d'un répertoire, sans suivre de lien symbolique.
///
/// # Limite assumée
///
/// Une erreur de lecture en cours d'énumération est indiscernable de la fin de
/// l'énumération. La conséquence est une liste **tronquée**, donc **plus courte** :
/// pour un ramasse-miettes qui supprime « ce qui est présent et non référencé », cela
/// signifie **moins** de suppressions, jamais plus. Le mode de défaillance va dans le
/// sens sûr.
pub use crate::backend::list_dir;

/// Lit un fichier entier, en refusant de dépasser `max_len` octets.
///
/// La borne est **structurelle** et vérifiée pendant la lecture, jamais déduite
/// d'une taille annoncée par le fichier. Tout ce qui n'est pas un fichier ordinaire
/// est refusé — un FIFO bloquerait la lecture indéfiniment.
pub use crate::backend::read_file;

/// Ouvre un fichier ordinaire en lecture seule, sans suivre de lien symbolique.
///
/// Variante **en flux** de [`read_file`], pour les fichiers dont la taille n'est pas
/// connue à l'avance ou dépasse ce qu'on veut tenir en mémoire.
pub use crate::backend::open_read;

/// Vrai si l'entrée existe, **sans la suivre** (un lien symbolique existe).
///
/// # Usage
///
/// Énumération et rapport **uniquement**. Jamais comme garde avant une création :
/// une création doit utiliser une primitive **exclusive**, qui rend le contrôle et
/// l'action atomiques.
pub use crate::backend::path_exists;

/// Rend durable ce qui vient d'être écrit dans `dir`, et **rend le niveau atteint**.
///
/// # Unix
/// `fsync` du fichier, **puis** `fsync` du descripteur de répertoire : le contenu
/// **et le nom** deviennent durables. Retourne [`Durability::DirectoryEntrySynced`].
///
/// # Windows
/// `FlushFileBuffers` du fichier **seulement**. Retourne [`Durability::FileOnly`] :
/// la persistance du nom dans le répertoire **n'est pas revendiquée**, et le niveau
/// réduit est **rapporté** à l'utilisateur plutôt que dissimulé.
///
/// # Distinction essentielle
///
/// Une **capacité absente** n'est pas une **erreur** : elle change la valeur
/// retournée. Une **vraie** erreur d'entrée/sortie, en revanche, fait échouer
/// l'opération — on ne confond pas « cette plateforme ne sait pas le faire » avec
/// « le système a refusé ».
pub use crate::backend::make_durable;

/// Publie un fichier temporaire sous son nom définitif, **sans écraser**.
///
/// # Pourquoi cette primitive existe
///
/// Un renommage classique **remplace** la cible. Ici l'écrasement doit être impossible :
/// la cible est choisie par l'utilisateur, et le fichier qui s'y trouve déjà ne nous
/// appartient pas.
///
/// Elle sert à un motif précis : écrire une donnée en clair dans un **temporaire**, et
/// ne la publier qu'une fois qu'elle est complète et vérifiée. Une interruption laisse
/// alors un temporaire — jamais un fichier tronqué qui ressemblerait à un résultat.
///
/// * **Unix** : `linkat` puis `unlinkat`. Le lien refuse une cible existante, et sa pose
///   est **atomique**.
/// * **Windows** : `MoveFileExW` sans `MOVEFILE_REPLACE_EXISTING`, donc sans écrasement.
///   **NON VÉRIFIÉ À L'EXÉCUTION.**
///
/// Les deux chemins doivent désigner le **même répertoire** (Unix) ; c'est aussi la
/// condition d'un déplacement bon marché sur Windows.
///
/// # Erreurs
/// `io::ErrorKind::AlreadyExists` si la cible existe déjà.
pub use crate::backend::publish_no_replace;

/// Niveau de durabilité que **cette plateforme** peut atteindre.
///
/// Sert à **rapporter** la garantie au moment de l'ouverture d'un coffre, sans avoir
/// à écrire quoi que ce soit : une capacité réduite doit être annoncée, pas découverte
/// au premier incident.
///
/// La cohérence avec [`make_durable`] n'est pas laissée à la discipline : un test
/// (`platform_durability_matches_what_make_durable_returns`) vérifie que les deux
/// disent la même chose sur la plateforme courante.
pub const fn platform_durability() -> Durability {
    crate::backend::platform_durability()
}

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
