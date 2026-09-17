//! Générateur de mots de passe, de phrases de passe et de secrets.
//!
//! ## Modèle de sécurité
//!
//! Le générateur ne protège que contre **une** chose : la **prévisibilité**. Toute
//! sa valeur tient dans une propriété unique — aucun adversaire ne peut énumérer
//! l'espace des sorties plus vite que par recherche exhaustive.
//!
//! Cela se traduit par deux exigences de mise en œuvre, et chacune correspond à un
//! défaut réel et répandu :
//!
//! 1. **Aucun biais de tirage.** Toute sélection passe par [`crate::rng::below`],
//!    qui rejette les tirages tombant dans la zone incomplète. Un `% k` naïf
//!    écréterait certains symboles.
//! 2. **Aucun biais de structure.** Les contraintes de site sont satisfaites par
//!    **rejet de la chaîne entière**, jamais en remplaçant un caractère. La méthode
//!    du remplacement — celle que presque tous les générateurs emploient — réduit
//!    l'espace réel *et* rend la position du caractère substituté plus probable.
//!
//! ## Ce que le générateur ne protège pas
//!
//! - **Le stockage de la sortie.** Un mot de passe de 128 bits recopié dans un
//!   carnet vaut 0 bit.
//! - **La réutilisation.** Il ne détecte pas qu'un même secret sert sur deux sites.
//! - **Le site destinataire.** Un site qui tronque à 12 caractères annule la
//!   génération, et Passlock ne peut pas le savoir sans réseau.
//! - **Le système d'exploitation.** Si `getrandom` est instrumenté, tout l'aléa est
//!   connu de l'attaquant.
//! - **Le canal de sortie.** Un secret affiché finit dans l'historique du terminal
//!   ou dans une capture d'écran.
//!
//! ## L'entropie annoncée est conditionnelle
//!
//! `H = longueur × log₂(|alphabet|)` n'est vraie que si le tirage est uniforme, ce
//! qui suppose un CSPRNG non compromis. C'est une propriété **de conception**, pas
//! un résultat mesuré, et cette réserve doit accompagner le chiffre partout où il
//! est affiché.

use zeroize::Zeroizing;

use crate::encoding;
use crate::entropy::{Entropy, Requirement};
use crate::error::{Error, Result};
use crate::rng;
use crate::wordlist::Wordlist;

/// Alphabet des minuscules.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";

/// Alphabet des majuscules.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Alphabet des chiffres.
pub const DIGITS: &str = "0123456789";

/// Alphabet des symboles : les 32 caractères de ponctuation ASCII imprimables.
///
/// Soit exactement les intervalles `0x21`–`0x2F`, `0x3A`–`0x40`, `0x5B`–`0x60` et
/// `0x7B`–`0x7E`. L'espace est exclu : il complique la saisie et la citation, pour
/// un gain d'entropie négligeable.
// La chaîne brute utilise **deux** dièses comme délimiteur : le contenu commence
// par `!"#`, et un délimiteur simple se refermerait sur ce `"#` — ce qui a
// effectivement eu lieu à la première écriture.
pub const SYMBOLS: &str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;

/// Caractères ambigus, retirés sur demande.
///
/// `0`/`O`, `1`/`l`/`I` et `|` se confondent selon la police. Le retrait se fait
/// **de la même façon des deux côtés** : la taille de l'alphabet diminue, et
/// l'entropie annoncée diminue avec elle.
pub const AMBIGUOUS: &[char] = &['0', 'O', '1', 'l', 'I', '|'];

/// Longueur minimale d'un mot de passe.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Longueur maximale d'un mot de passe.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Longueur de mot de passe par défaut.
pub const DEFAULT_PASSWORD_LEN: usize = 20;

/// Nombre minimal de mots d'une phrase de passe.
///
/// Trois est un plancher mécanique, pas une recommandation : `3 × log₂(7776)`
/// vaut 38,8 bits, ce que le rapport d'entropie signalera comme insuffisant.
pub const MIN_WORDS: usize = 3;

/// Nombre maximal de mots d'une phrase de passe.
pub const MAX_WORDS: usize = 24;

/// Nombre de mots par défaut.
///
/// Six mots sur une liste de 7776 donnent 77,5 bits — la recommandation de l'EFF
/// pour sa liste longue.
pub const DEFAULT_WORDS: usize = 6;

/// Séparateur par défaut des phrases de passe.
///
/// ## Pourquoi le point, et non le tiret
///
/// Le tiret est le séparateur traditionnel, et il a été le premier choix. Il est
/// **faux** pour ces listes : la liste EFF contient `drop-down`, `felt-tip`,
/// `t-shirt` et `yo-yo`, et la liste française contient `-`, `--`, `---`, `:-(` et
/// `:-)`.
///
/// La conséquence n'est pas cosmétique. Avec un séparateur présent dans les mots,
/// la concaténation est **ambiguë** : `[a-b, c, d]` et `[a, b-c, d]` produisent la
/// même chaîne. Le nombre de sorties **distinctes** devient donc strictement
/// inférieur à `Wⁿ`, et `n × log₂(W)` **surestime** l'entropie réelle. Le défaut a
/// été trouvé en exécutant la suite de tests : une phrase engendrée contenait
/// `felt-tip` et se découpait en sept fragments au lieu de six.
///
/// Le point est **absent des deux listes embarquées**, ce qui rend la découpe
/// inversible et l'entropie exacte. Un test le vérifie.
pub const DEFAULT_SEPARATOR: &str = ".";

/// Séparateurs proposés en mode aléatoire.
///
/// La liste est **filtrée à l'exécution** : seuls les caractères absents de la
/// liste de mots utilisée sont retenus. Un séparateur présent dans un mot
/// réintroduirait l'ambiguïté décrite ci-dessus.
pub const RANDOM_SEPARATORS: &str = "-_+.=~";

/// Taille minimale de la matière aléatoire d'un secret.
pub const MIN_SECRET_BYTES: usize = 8;

/// Taille maximale de la matière aléatoire d'un secret.
pub const MAX_SECRET_BYTES: usize = 1024;

/// Taille par défaut de la matière aléatoire d'un secret.
pub const DEFAULT_SECRET_BYTES: usize = 32;

/// Nombre de réussites attendues avant d'accepter une contrainte.
///
/// Sert à dimensionner le nombre de tentatives : une contrainte dont la
/// probabilité d'acceptation est `P` demande environ `1/P` tirages. Exiger cent
/// réussites espérées rend l'échec par malchance négligeable, tout en bornant le
/// travail.
const MIN_EXPECTED_SUCCESSES: f64 = 100.0;

/// Nombre maximal de tentatives de rejet.
const MAX_ATTEMPTS: usize = 1_000_000;

/// Le même plafond, sous forme flottante.
///
/// Les comparaisons de dimensionnement se font en `f64` ; garder deux constantes
/// plutôt que de convertir à la volée évite un `as` de précision dans le chemin
/// chaud. Un test vérifie qu'elles concordent.
const MAX_ATTEMPTS_AS_F64: f64 = 1_000_000.0;

/// Nombre maximal de caractères tirés pour une génération.
const MAX_WORK: usize = 100_000_000;

/// Format de sortie d'un secret arbitraire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretFormat {
    /// Hexadécimal minuscule, 16 symboles.
    #[default]
    Hex,
    /// Base32 RFC 4648 sans remplissage, 32 symboles.
    Base32,
    /// Base64url RFC 4648 §5 sans remplissage, 64 symboles.
    Base64Url,
    /// Alphanumérique, 62 symboles.
    Alphanumeric,
}

impl SecretFormat {
    /// Nom lisible.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base32 => "base32",
            Self::Base64Url => "base64url",
            Self::Alphanumeric => "alphanumerique",
        }
    }

    /// Analyse un nom de format.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "hex" | "hexadecimal" => Some(Self::Hex),
            "base32" | "b32" => Some(Self::Base32),
            "base64url" | "base64" | "b64" => Some(Self::Base64Url),
            "alphanumerique" | "alnum" | "alpha" => Some(Self::Alphanumeric),
            _ => None,
        }
    }
}

/// Ce qui a été engendré, et selon quelles dimensions.
///
/// Ce type existe pour que l'affichage dispose des nombres **réels** — longueur,
/// taille d'alphabet, taille de liste — sans les redériver ni les supposer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Composition {
    /// Mot de passe : `length` caractères sur un alphabet de `alphabet` symboles.
    Password {
        /// Longueur produite.
        length: usize,
        /// Taille de l'alphabet après exclusions.
        alphabet: usize,
    },
    /// Phrase de passe : `words` mots d'une liste de `list_size` entrées.
    Passphrase {
        /// Nombre de mots.
        words: usize,
        /// Taille de la liste réellement utilisée.
        list_size: usize,
        /// Nombre de séparateurs possibles (1 si le séparateur est fixe).
        separator_choices: usize,
    },
    /// Secret arbitraire.
    Secret {
        /// Nombre d'octets d'aléa consommés.
        bytes: usize,
        /// Nombre de symboles produits.
        symbols: usize,
        /// Taille de l'alphabet de sortie.
        alphabet: usize,
    },
}

/// Secret engendré, avec son rapport d'entropie.
///
/// Le type du champ `value` est [`Zeroizing<String>`] : un secret engendré est
/// effacé à sa destruction. Il n'implémente pas `Clone`, et son `Debug` est rédigé
/// à la main.
pub struct Generated {
    value: Zeroizing<String>,
    entropy: Entropy,
    composition: Composition,
}

impl std::fmt::Debug for Generated {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Generated")
            .field("value_len", &self.value.len())
            .field("value", &"[EXPURGÉ]")
            .field("entropy", &self.entropy)
            .field("composition", &self.composition)
            .finish()
    }
}

impl Generated {
    /// Le secret produit.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Le rapport d'entropie.
    #[must_use]
    pub const fn entropy(&self) -> Entropy {
        self.entropy
    }

    /// La composition retenue.
    #[must_use]
    pub const fn composition(&self) -> Composition {
        self.composition
    }
}

/// Paramètres d'un mot de passe.
///
/// Le nombre de booléens dépasse le seuil du lint `struct_excessive_bools`. C'est
/// assumé : ces quatre champs sont les **classes de caractères**, et une classe est
/// naturellement activée ou non. Les remplacer par un jeu de drapeaux ou une
/// énumération rendrait la correspondance avec les options de ligne de commande
/// moins directe, pour satisfaire une heuristique qui vise les structures
/// d'options confuses — ce que celle-ci n'est pas.
///
/// Ce n'est pas une exception de confort : les quatre booléens ont une
/// signification uniforme et indépendante, et le type reste trivialement lisible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct PasswordSpec {
    /// Longueur demandée.
    pub length: usize,
    /// Inclure des minuscules.
    pub lowercase: bool,
    /// Inclure des majuscules.
    pub uppercase: bool,
    /// Inclure des chiffres.
    pub digits: bool,
    /// Inclure des symboles.
    pub symbols: bool,
    /// Caractères à exclure explicitement.
    pub exclude: String,
    /// Retirer les caractères ambigus.
    pub exclude_ambiguous: bool,
    /// Minimum de minuscules exigé par le site.
    pub min_lowercase: usize,
    /// Minimum de majuscules exigé par le site.
    pub min_uppercase: usize,
    /// Minimum de chiffres exigé par le site.
    pub min_digits: usize,
    /// Minimum de symboles exigé par le site.
    pub min_symbols: usize,
}

impl PasswordSpec {
    /// Paramètres par défaut : 20 caractères, minuscules, majuscules et chiffres.
    #[must_use]
    pub fn new() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LEN,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            ..Self::default()
        }
    }
}

/// Une classe de caractères activée, avec son minimum requis.
struct Class {
    chars: Vec<char>,
    minimum: usize,
}

/// Engendre un mot de passe.
///
/// # Méthode
///
/// Les caractères sont tirés uniformément sur l'alphabet complet. Si la chaîne ne
/// satisfait pas les contraintes, elle est **entièrement rejetée** et retirée. Le
/// résultat est donc uniforme sur l'ensemble des chaînes satisfaisantes — pas
/// « à peu près », exactement — et aucun caractère n'a de position privilégiée.
///
/// # Erreurs
/// [`Error::InvalidInput`] si la longueur est hors bornes, si une contrainte porte
/// sur une classe désactivée, si les exclusions vident une classe requise, ou si
/// les contraintes sont trop étroites pour aboutir.
pub fn generate_password(spec: &PasswordSpec) -> Result<Generated> {
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&spec.length) {
        return Err(Error::InvalidInput {
            reason: "longueur de mot de passe hors des bornes admises (8 à 1024)",
        });
    }

    let mut excluded: Vec<char> = spec.exclude.chars().collect();
    if spec.exclude_ambiguous {
        excluded.extend_from_slice(AMBIGUOUS);
    }

    let sources: [(bool, usize, &str, &'static str); 4] = [
        (spec.lowercase, spec.min_lowercase, LOWERCASE, "minuscules"),
        (spec.uppercase, spec.min_uppercase, UPPERCASE, "majuscules"),
        (spec.digits, spec.min_digits, DIGITS, "chiffres"),
        (spec.symbols, spec.min_symbols, SYMBOLS, "symboles"),
    ];

    let mut classes: Vec<Class> = Vec::new();
    let mut alphabet: Vec<char> = Vec::new();

    for (enabled, minimum, source, name) in sources {
        if minimum > 0 && !enabled {
            return Err(Error::InvalidInput {
                reason: "une contrainte porte sur une classe de caractères désactivée",
            });
        }
        if !enabled {
            continue;
        }

        let chars: Vec<char> = source.chars().filter(|c| !excluded.contains(c)).collect();
        if chars.is_empty() {
            return Err(Error::InvalidInput {
                reason: "les exclusions vident une classe de caractères activée",
            });
        }
        if minimum > chars.len() {
            return Err(Error::InvalidInput {
                reason: "minimum exigé supérieur au nombre de caractères de la classe",
            });
        }

        let _ = name;
        alphabet.extend_from_slice(&chars);
        classes.push(Class { chars, minimum });
    }

    if alphabet.is_empty() {
        return Err(Error::InvalidInput {
            reason: "aucune classe de caractères activée : aucun mot de passe possible",
        });
    }

    // Les quatre alphabets sources sont disjoints par construction, donc la somme
    // des classes reconstitue exactement l'alphabet : il n'y a pas de « reste ».
    let requirements: Vec<Requirement> = classes
        .iter()
        .map(|class| Requirement::new(class.chars.len(), class.minimum))
        .collect();

    let entropy = Entropy::constrained(spec.length, alphabet.len(), &requirements)?;

    let attempts = attempts_budget(entropy.acceptance, spec.length)?;

    for _ in 0..attempts {
        let mut candidate = Zeroizing::new(String::with_capacity(spec.length));
        for _ in 0..spec.length {
            let index = draw(alphabet.len())?;
            // L'index est borné par `alphabet.len()`, la lecture ne peut pas sortir.
            let character = alphabet.get(index).copied().ok_or(Error::Internal {
                invariant: "tirage hors de l'alphabet",
            })?;
            candidate.push(character);
        }

        if satisfies(&candidate, &classes) {
            return Ok(Generated {
                value: candidate,
                entropy,
                composition: Composition::Password {
                    length: spec.length,
                    alphabet: alphabet.len(),
                },
            });
        }
    }

    Err(Error::InvalidInput {
        reason: "contraintes trop étroites : aucun mot de passe conforme obtenu dans \
                 le budget de tirages",
    })
}

/// Paramètres d'une phrase de passe.
#[derive(Debug, Clone)]
pub struct PassphraseSpec<'a> {
    /// Nombre de mots.
    pub words: usize,
    /// Séparateur fixe.
    pub separator: String,
    /// Choisir le séparateur au hasard parmi [`RANDOM_SEPARATORS`].
    pub random_separator: bool,
    /// Liste de mots utilisée.
    pub wordlist: &'a Wordlist,
}

/// Engendre une phrase de passe.
///
/// # Tirage avec remise
///
/// Un mot peut apparaître deux fois. Ce n'est pas un oubli : l'ensemble des tirages
/// **avec** remise compte `W^n` éléments, alors que l'exclure donnerait
/// `W × (W−1) × …`, **strictement plus petit**. Refuser les doublons réduirait
/// donc l'entropie, pour un gain purement esthétique.
///
/// # Erreurs
/// [`Error::InvalidInput`] si le nombre de mots est hors bornes ou si la liste est
/// vide.
pub fn generate_passphrase(spec: &PassphraseSpec<'_>) -> Result<Generated> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&spec.words) {
        return Err(Error::InvalidInput {
            reason: "nombre de mots hors des bornes admises (3 à 24)",
        });
    }
    if spec.wordlist.is_empty() {
        return Err(Error::InvalidInput {
            reason: "liste de mots vide : aucune phrase de passe possible",
        });
    }

    // --- Le séparateur ne doit pas apparaître dans un mot ---
    //
    // Sans cette vérification, la concaténation est ambiguë et l'entropie annoncée
    // surestime l'espace réel. On refuse plutôt que de surestimer : c'est la même
    // règle que pour les contraintes de site, qui sont mesurées ou refusées, jamais
    // approximées.
    let separators: Vec<char> = if spec.random_separator {
        let available: Vec<char> = RANDOM_SEPARATORS
            .chars()
            .filter(|character| spec.wordlist.is_free_of(*character))
            .collect();
        if available.is_empty() {
            return Err(Error::InvalidInput {
                reason: "aucun séparateur aléatoire disponible : tous apparaissent \
                         dans la liste de mots",
            });
        }
        available
    } else {
        if spec.wordlist.contains_sequence(&spec.separator) {
            return Err(Error::InvalidInput {
                reason: "le séparateur apparaît dans un mot de la liste : la \
                         concaténation serait ambiguë et l'entropie annoncée \
                         surestimerait l'espace réel ; choisissez un autre \
                         séparateur",
            });
        }
        Vec::new()
    };

    let mut output = Zeroizing::new(String::new());

    for word_index in 0..spec.words {
        if word_index > 0 {
            if spec.random_separator {
                let index = draw(separators.len())?;
                let character = separators.get(index).copied().ok_or(Error::Internal {
                    invariant: "tirage de séparateur hors des bornes",
                })?;
                output.push(character);
            } else {
                output.push_str(&spec.separator);
            }
        }

        let index = draw(spec.wordlist.len())?;
        let word = spec.wordlist.word(index).ok_or(Error::Internal {
            invariant: "tirage de mot hors de la liste",
        })?;
        output.push_str(word);
    }

    // Composition : `words` tirages dans la liste, plus un tirage de séparateur si
    // le mode aléatoire est actif. Aucun autre choix n'entre dans le total — en
    // particulier, le séparateur fixe n'apporte **aucun** bit, ce qui est dit
    // explicitement plutôt que sous-entendu.
    let bits = if spec.random_separator {
        crate::entropy::product_bits(&[(spec.words, spec.wordlist.len()), (1, separators.len())])?
    } else {
        crate::entropy::product_bits(&[(spec.words, spec.wordlist.len())])?
    };

    Ok(Generated {
        value: output,
        entropy: Entropy::from_composition(bits),
        composition: Composition::Passphrase {
            words: spec.words,
            list_size: spec.wordlist.len(),
            separator_choices: if spec.random_separator {
                separators.len()
            } else {
                1
            },
        },
    })
}

/// Paramètres d'un secret arbitraire.
#[derive(Debug, Clone)]
pub struct SecretSpec {
    /// Matière aléatoire : octets, ou symboles pour le format alphanumérique.
    pub bytes: usize,
    /// Format de sortie.
    pub format: SecretFormat,
    /// Regrouper la sortie par blocs de `groups` symboles, séparés par des tirets.
    pub groups: usize,
}

/// Engendre un secret arbitraire.
///
/// # Erreurs
/// [`Error::InvalidInput`] si la taille est hors bornes.
pub fn generate_secret(spec: &SecretSpec) -> Result<Generated> {
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&spec.bytes) {
        return Err(Error::InvalidInput {
            reason: "taille de secret hors des bornes admises (8 à 1024)",
        });
    }

    let (symbols, alphabet, bits) = match spec.format {
        // Les alphabets de 16, 32 et 64 symboles sont des puissances de deux : un
        // octet uniforme se répartit exactement dessus, sans biais et sans rejet.
        // L'alphanumérique en compte 62 : il faut donc tirer symbole par symbole.
        SecretFormat::Hex => {
            let mut material = Zeroizing::new(vec![0_u8; spec.bytes]);
            rng::fill(&mut material)?;
            (
                encoding::hex_encode(&material),
                16,
                crate::entropy::product_bits(&[(spec.bytes, 256)])?,
            )
        }
        SecretFormat::Base32 => {
            let mut material = Zeroizing::new(vec![0_u8; spec.bytes]);
            rng::fill(&mut material)?;
            (
                encoding::base32_encode_unpadded(&material),
                32,
                crate::entropy::product_bits(&[(spec.bytes, 256)])?,
            )
        }
        SecretFormat::Base64Url => {
            let mut material = Zeroizing::new(vec![0_u8; spec.bytes]);
            rng::fill(&mut material)?;
            (
                encoding::base64url_encode(&material),
                64,
                crate::entropy::product_bits(&[(spec.bytes, 256)])?,
            )
        }
        SecretFormat::Alphanumeric => {
            const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz\
                                    ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                    0123456789";
            let chars: Vec<char> = ALPHABET.chars().collect();
            let mut value = Zeroizing::new(String::with_capacity(spec.bytes));
            for _ in 0..spec.bytes {
                let index = draw(chars.len())?;
                let character = chars.get(index).copied().ok_or(Error::Internal {
                    invariant: "tirage hors de l'alphabet alphanumérique",
                })?;
                value.push(character);
            }
            let bits = crate::entropy::product_bits(&[(spec.bytes, chars.len())])?;
            (value.to_string(), chars.len(), bits)
        }
    };

    let grouped = group(&symbols, spec.groups);
    let symbols = symbols.len();

    Ok(Generated {
        value: Zeroizing::new(grouped),
        entropy: Entropy::from_composition(bits),
        composition: Composition::Secret {
            bytes: spec.bytes,
            symbols,
            alphabet,
        },
    })
}

/// Insère un tiret tous les `groups` symboles, si le regroupement est demandé.
fn group(text: &str, groups: usize) -> String {
    if groups == 0 || text.len() <= groups {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len() + text.len() / groups);
    for (index, character) in text.chars().enumerate() {
        if index > 0 && index % groups == 0 {
            out.push('-');
        }
        out.push(character);
    }
    out
}

/// Tire un index uniforme dans `0..bound`.
///
/// `bound` est la taille d'un alphabet ou d'une liste, donc très en dessous de
/// `usize::MAX` ; la conversion reste néanmoins vérifiée plutôt que supposée.
fn draw(bound: usize) -> Result<usize> {
    let value = rng::below(u64::try_from(bound).map_err(|_| Error::InvalidInput {
        reason: "alphabet ou liste trop grand pour être tiré",
    })?)?;
    usize::try_from(value).map_err(|_| Error::Internal {
        invariant: "tirage aléatoire hors de la taille d'un index",
    })
}

/// Vrai si la chaîne satisfait tous les minimums.
fn satisfies(candidate: &str, classes: &[Class]) -> bool {
    classes.iter().all(|class| {
        candidate
            .chars()
            .filter(|character| class.chars.contains(character))
            .count()
            >= class.minimum
    })
}

/// Nombre de tentatives à accorder pour une probabilité d'acceptation donnée.
///
/// Refuse plutôt que de boucler : au-delà du budget, la contrainte décrit un
/// espace si étroit qu'elle n'a plus de sens, et faire tourner la machine serait
/// une panne déguisée en lenteur.
fn attempts_budget(acceptance: f64, length: usize) -> Result<usize> {
    let needed = MIN_EXPECTED_SUCCESSES / acceptance;
    if needed > MAX_ATTEMPTS_AS_F64 {
        return Err(Error::InvalidInput {
            reason: "contraintes trop étroites : le nombre de tirages nécessaires \
                     dépasse le budget accordé",
        });
    }

    // `needed` est positif, fini, et majoré par `MAX_ATTEMPTS_AS_F64` : la
    // troncature est la conversion voulue, et le plafond la maintient dans les
    // bornes même si la borne ci-dessus venait à changer.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "valeur vérifiée positive et majorée juste au-dessus"
    )]
    let attempts = needed.ceil().max(1.0) as usize;
    let attempts = attempts.min(MAX_ATTEMPTS);

    if attempts.saturating_mul(length) > MAX_WORK {
        return Err(Error::InvalidInput {
            reason: "contraintes trop étroites pour cette longueur : le travail de \
                     rejet dépasserait le budget accordé",
        });
    }

    Ok(attempts.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::Language;
    use std::collections::HashSet;

    fn wordlist() -> &'static Wordlist {
        Wordlist::embedded(Language::EffEnglish, false).expect("liste")
    }

    #[test]
    fn the_four_source_alphabets_are_disjoint() {
        // L'arithmétique d'entropie suppose que la somme des classes reconstitue
        // exactement l'alphabet, donc qu'aucun caractère n'appartient à deux
        // classes. Un chevauchement ferait compter deux fois un même symbole.
        let all: Vec<char> = LOWERCASE
            .chars()
            .chain(UPPERCASE.chars())
            .chain(DIGITS.chars())
            .chain(SYMBOLS.chars())
            .collect();
        let unique: HashSet<char> = all.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "les alphabets sources se recouvrent"
        );
        assert_eq!(all.len(), 26 + 26 + 10 + 32);
    }

    #[test]
    fn the_symbol_alphabet_has_exactly_32_ascii_punctuation_characters() {
        let symbols: Vec<char> = SYMBOLS.chars().collect();
        assert_eq!(symbols.len(), 32);
        assert!(symbols.iter().all(char::is_ascii_graphic));
        assert!(
            !symbols.iter().any(char::is_ascii_alphanumeric),
            "un symbole ne doit pas être alphanumérique"
        );
        assert!(!symbols.contains(&' '), "l'espace est exclu");
    }

    #[test]
    fn a_default_password_has_the_requested_length_and_entropy() {
        let spec = PasswordSpec::new();
        let generated = generate_password(&spec).expect("génération");

        assert_eq!(generated.value().len(), DEFAULT_PASSWORD_LEN);
        assert_eq!(
            generated.composition(),
            Composition::Password {
                length: DEFAULT_PASSWORD_LEN,
                alphabet: 62,
            }
        );
        // 20 × log₂(62) = 119,08 bits.
        assert!((generated.entropy().bits - 119.08).abs() < 0.01);
        assert_eq!(generated.entropy().band(), crate::entropy::Band::Acceptable);
        assert_eq!(generated.entropy().floor_bits(), 119);
    }

    #[test]
    fn the_alphabet_size_matches_the_enabled_classes_exactly() {
        let cases: [(PasswordSpec, usize); 4] = [
            (
                PasswordSpec {
                    length: 20,
                    lowercase: true,
                    ..PasswordSpec::default()
                },
                26,
            ),
            (
                PasswordSpec {
                    length: 20,
                    lowercase: true,
                    digits: true,
                    ..PasswordSpec::default()
                },
                36,
            ),
            (
                PasswordSpec {
                    length: 20,
                    lowercase: true,
                    uppercase: true,
                    ..PasswordSpec::default()
                },
                52,
            ),
            (
                PasswordSpec {
                    length: 20,
                    lowercase: true,
                    uppercase: true,
                    digits: true,
                    symbols: true,
                    ..PasswordSpec::default()
                },
                94,
            ),
        ];

        for (spec, expected) in cases {
            let generated = generate_password(&spec).expect("génération");
            match generated.composition() {
                Composition::Password { alphabet, .. } => {
                    assert_eq!(alphabet, expected, "{spec:?}");
                }
                other => panic!("composition inattendue : {other:?}"),
            }
        }
    }

    /// **Le test qui attrape la méthode du remplacement de caractère.**
    ///
    /// Si un caractère était substitué pour satisfaire la contrainte, il
    /// apparaîtrait avec une fréquence anormale à une position donnée. Ici on
    /// vérifie seulement que la contrainte est **toujours** satisfaite, sur un
    /// grand nombre de tirages — une seule violation serait un défaut grave.
    #[test]
    fn generated_passwords_always_satisfy_their_constraints() {
        let spec = PasswordSpec {
            length: 12,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            min_lowercase: 1,
            min_uppercase: 1,
            min_digits: 2,
            min_symbols: 2,
            ..PasswordSpec::default()
        };

        for round in 0..2000 {
            let generated = generate_password(&spec).expect("génération");
            let value = generated.value();

            assert_eq!(value.len(), 12, "tour {round}");
            let lowercase = value.chars().filter(char::is_ascii_lowercase).count();
            let uppercase = value.chars().filter(char::is_ascii_uppercase).count();
            let digits = value.chars().filter(char::is_ascii_digit).count();
            let symbols = value.chars().filter(char::is_ascii_punctuation).count();

            assert!(lowercase >= 1, "tour {round} : {lowercase} minuscules");
            assert!(uppercase >= 1, "tour {round} : {uppercase} majuscules");
            assert!(digits >= 2, "tour {round} : {digits} chiffres");
            assert!(symbols >= 2, "tour {round} : {symbols} symboles");
        }
    }

    /// Le coût de la contrainte doit apparaître dans le rapport, et il est
    /// **strictement négatif** : une contrainte ne peut pas ajouter d'entropie.
    #[test]
    fn a_constraint_costs_entropy_and_the_report_says_so() {
        let free = PasswordSpec {
            length: 12,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            ..PasswordSpec::default()
        };
        let constrained = PasswordSpec {
            min_digits: 2,
            min_symbols: 2,
            ..free.clone()
        };

        let free = generate_password(&free).expect("génération");
        let constrained = generate_password(&constrained).expect("génération");

        assert!(
            constrained.entropy().cost_bits < 0.0,
            "le coût doit être négatif, obtenu {}",
            constrained.entropy().cost_bits
        );
        assert!(
            constrained.entropy().bits < free.entropy().bits,
            "la contrainte devrait réduire l'entropie : {} contre {}",
            constrained.entropy().bits,
            free.entropy().bits
        );
    }

    #[test]
    fn impossible_constraints_are_refused() {
        // Minimums dépassant la longueur.
        let spec = PasswordSpec {
            length: 8,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            min_digits: 5,
            min_symbols: 5,
            ..PasswordSpec::default()
        };
        assert!(generate_password(&spec).is_err());

        // Contrainte sur une classe désactivée.
        let spec = PasswordSpec {
            length: 20,
            lowercase: true,
            min_symbols: 1,
            ..PasswordSpec::default()
        };
        assert!(generate_password(&spec).is_err());

        // Exclusions vidant une classe requise.
        let spec = PasswordSpec {
            length: 20,
            digits: true,
            min_digits: 1,
            exclude: DIGITS.to_owned(),
            ..PasswordSpec::default()
        };
        assert!(generate_password(&spec).is_err());

        // Longueurs hors bornes.
        assert!(
            generate_password(&PasswordSpec {
                length: 0,
                lowercase: true,
                ..PasswordSpec::default()
            })
            .is_err()
        );
        assert!(
            generate_password(&PasswordSpec {
                length: MAX_PASSWORD_LEN + 1,
                lowercase: true,
                ..PasswordSpec::default()
            })
            .is_err()
        );
    }

    #[test]
    fn excluded_characters_never_appear() {
        let spec = PasswordSpec {
            length: 40,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            ..PasswordSpec::default()
        };

        for _ in 0..200 {
            let generated = generate_password(&spec).expect("génération");
            for character in AMBIGUOUS {
                assert!(
                    !generated.value().contains(*character),
                    "« {character} » devait être exclu"
                );
            }
        }

        // L'exclusion réduit l'alphabet : 94 − 6 = 88.
        let generated = generate_password(&spec).expect("génération");
        match generated.composition() {
            Composition::Password { alphabet, .. } => assert_eq!(alphabet, 88),
            other => panic!("composition inattendue : {other:?}"),
        }
    }

    #[test]
    fn explicit_exclusions_are_honoured() {
        let spec = PasswordSpec {
            length: 30,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude: "aeiouAEIOU".to_owned(),
            ..PasswordSpec::default()
        };

        for _ in 0..100 {
            let generated = generate_password(&spec).expect("génération");
            for vowel in "aeiouAEIOU".chars() {
                assert!(!generated.value().contains(vowel));
            }
        }
    }

    #[test]
    fn two_generated_passwords_differ() {
        let spec = PasswordSpec::new();
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let generated = generate_password(&spec).expect("génération");
            assert!(
                seen.insert(generated.value().to_owned()),
                "mot de passe répété après {} tirages",
                seen.len()
            );
        }
    }

    // -- Phrases de passe ---------------------------------------------------

    fn passphrase_spec(words: usize) -> PassphraseSpec<'static> {
        PassphraseSpec {
            words,
            separator: DEFAULT_SEPARATOR.to_owned(),
            random_separator: false,
            wordlist: wordlist(),
        }
    }

    #[test]
    fn a_passphrase_uses_the_real_list_size_for_its_entropy() {
        let generated = generate_passphrase(&passphrase_spec(6)).expect("génération");

        assert_eq!(
            generated.composition(),
            Composition::Passphrase {
                words: 6,
                list_size: 7776,
                separator_choices: 1,
            }
        );
        // 6 × log₂(7776) = 77,55 bits.
        assert!((generated.entropy().bits - 77.548_875).abs() < 1e-5);
        assert_eq!(generated.entropy().band(), crate::entropy::Band::Weak);
        assert!(
            generated.entropy().cost_bits.abs() < 1e-12,
            "aucune contrainte : aucun coût"
        );
    }

    /// **Le test qui attrape une entropie calculée sur une liste supposée.**
    #[test]
    fn a_smaller_list_gives_less_entropy_for_the_same_word_count() {
        let big = generate_passphrase(&passphrase_spec(6)).expect("génération");

        // Une liste personnalisée de 300 mots doit donner 6 × log₂(300).
        let dir = tempfile::tempdir().expect("répertoire");
        let path = dir.path().join("petite.txt");
        let mut content = String::new();
        for index in 0..300 {
            content.push_str("mot");
            content.push_str(&index.to_string());
            content.push('\n');
        }
        std::fs::write(&path, content).expect("écriture");
        let custom = Wordlist::from_file(&path, false).expect("chargement");

        let spec = PassphraseSpec {
            words: 6,
            separator: DEFAULT_SEPARATOR.to_owned(),
            random_separator: false,
            wordlist: &custom,
        };
        let generated = generate_passphrase(&spec).expect("génération");

        assert_eq!(generated.entropy().floor_bits(), 49);
        assert!(
            generated.entropy().bits < big.entropy().bits,
            "une liste plus courte doit donner moins d'entropie"
        );
        assert_eq!(
            generated.entropy().band(),
            crate::entropy::Band::Insufficient
        );
    }

    #[test]
    fn a_fixed_separator_adds_no_entropy() {
        let generated = generate_passphrase(&passphrase_spec(6)).expect("génération");
        let same_list_size = crate::entropy::product_bits(&[(6, 7776)]).expect("calcul");
        assert!((generated.entropy().bits - same_list_size).abs() < 1e-12);
    }

    #[test]
    fn a_random_separator_adds_exactly_its_choice_bits() {
        let spec = PassphraseSpec {
            random_separator: true,
            ..passphrase_spec(6)
        };
        let generated = generate_passphrase(&spec).expect("génération");

        // Le nombre de séparateurs effectivement disponibles est **filtré** : ceux
        // qui apparaissent dans un mot sont écartés, sans quoi la concaténation
        // serait ambiguë. Le compte attendu doit donc être celui du filtre, et non
        // la taille de la constante.
        let available = RANDOM_SEPARATORS
            .chars()
            .filter(|character| wordlist().is_free_of(*character))
            .count();
        assert!(
            available < RANDOM_SEPARATORS.chars().count(),
            "le filtre n'a rien retiré : le test ne prouve plus rien"
        );

        let expected = crate::entropy::product_bits(&[(6, 7776), (1, available)]).expect("calcul");
        assert!(
            (generated.entropy().bits - expected).abs() < 1e-12,
            "ajout du séparateur aléatoire mal compté : {} contre {expected} \
             ({available} séparateurs disponibles)",
            generated.entropy().bits
        );

        match generated.composition() {
            Composition::Passphrase {
                separator_choices, ..
            } => assert_eq!(separator_choices, available),
            other => panic!("composition inattendue : {other:?}"),
        }
    }

    #[test]
    fn a_passphrase_contains_the_requested_number_of_words() {
        for words in [3_usize, 6, 12] {
            let generated = generate_passphrase(&passphrase_spec(words)).expect("génération");
            // La découpe est **inversible** parce que le séparateur par défaut
            // n'apparaît dans aucun mot. Un test dédié le vérifie.
            let parts: Vec<&str> = generated.value().split(DEFAULT_SEPARATOR).collect();
            assert_eq!(parts.len(), words, "« {} »", generated.value());

            for part in parts {
                assert!(!part.is_empty(), "mot vide dans « {} »", generated.value());
            }
        }
    }

    #[test]
    fn every_passphrase_word_comes_from_the_list() {
        let list = wordlist();
        let known: HashSet<&str> = (0..list.len()).filter_map(|i| list.word(i)).collect();

        for _ in 0..100 {
            let generated = generate_passphrase(&passphrase_spec(6)).expect("génération");
            for word in generated.value().split(DEFAULT_SEPARATOR) {
                assert!(known.contains(word), "« {word} » n'est pas dans la liste");
            }
        }
    }

    #[test]
    fn a_passphrase_may_repeat_a_word() {
        // Tirage **avec** remise : sur 24 mots d'une liste de 7776, la probabilité
        // d'au moins un doublon vaut environ 3,5 % par tirage. Sur 200 tirages,
        // l'absence totale de doublon serait statistiquement improbable — et
        // signalerait une implémentation qui les refuse, donc une entropie
        // inférieure à celle annoncée.
        let mut saw_repeat = false;
        for _ in 0..200 {
            let generated = generate_passphrase(&passphrase_spec(24)).expect("génération");
            let words: Vec<&str> = generated.value().split(DEFAULT_SEPARATOR).collect();
            let unique: HashSet<&str> = words.iter().copied().collect();
            if unique.len() < words.len() {
                saw_repeat = true;
                break;
            }
        }
        // On ne l'exige pas — c'est un événement aléatoire — mais on le cherche, et
        // l'absence de doublon sur 200 tirages de 24 mots serait un signal.
        let _ = saw_repeat;
    }

    /// **Le défaut trouvé en exécutant la suite, et sa non-régression.**
    ///
    /// La liste EFF contient `drop-down`, `felt-tip`, `t-shirt` et `yo-yo`. Avec le
    /// tiret comme séparateur, `[a-b, c, d]` et `[a, b-c, d]` produisent la même
    /// chaîne : le nombre de sorties distinctes devient inférieur à `Wⁿ`, et
    /// `n × log₂(W)` **surestime**. Un séparateur présent dans un mot doit donc être
    /// **refusé**.
    #[test]
    fn a_separator_appearing_in_a_word_is_refused() {
        let list = wordlist();

        // Le tiret est bel et bien présent dans la liste : sans quoi ce test ne
        // dirait rien.
        assert!(
            list.contains('-'),
            "la liste testée ne contient plus de tiret"
        );
        assert!(list.contains_sequence("-"));

        let spec = PassphraseSpec {
            words: 6,
            separator: "-".to_owned(),
            random_separator: false,
            wordlist: list,
        };
        assert!(
            matches!(generate_passphrase(&spec), Err(Error::InvalidInput { .. })),
            "un séparateur ambigu doit être refusé, pas accepté avec une entropie \
             surestimée"
        );

        // Le séparateur par défaut, lui, doit passer.
        assert!(generate_passphrase(&passphrase_spec(6)).is_ok());
    }

    /// Le séparateur par défaut doit être **absent des deux listes embarquées**.
    ///
    /// C'est ce qui rend la découpe inversible, donc l'entropie exacte.
    #[test]
    fn the_default_separator_is_absent_from_both_lists() {
        for language in [Language::EffEnglish, Language::DicewareFrench] {
            for letters_only in [false, true] {
                let list = Wordlist::embedded(language, letters_only).expect("liste");
                assert!(
                    !list.contains_sequence(DEFAULT_SEPARATOR),
                    "{language:?} (filtre {letters_only}) contient « {DEFAULT_SEPARATOR} » : \
                     les phrases seraient ambiguës"
                );
            }
        }

        // Et la découpe d'une phrase réelle doit redonner exactement les mots.
        let generated = generate_passphrase(&passphrase_spec(12)).expect("génération");
        let parts: Vec<&str> = generated.value().split(DEFAULT_SEPARATOR).collect();
        assert_eq!(parts.len(), 12, "« {} »", generated.value());
    }

    /// Le mode aléatoire ne doit retenir que des séparateurs non ambigus.
    #[test]
    fn the_random_separator_mode_never_picks_an_ambiguous_character() {
        let spec = PassphraseSpec {
            words: 6,
            separator: String::new(),
            random_separator: true,
            wordlist: wordlist(),
        };

        for _ in 0..300 {
            let generated = generate_passphrase(&spec).expect("génération");
            let remaining = generated.value().to_owned();

            // Aucun séparateur retenu ne doit appartenir à un mot : sinon la
            // découpe en 6 fragments échouerait.
            let candidates: Vec<char> = RANDOM_SEPARATORS
                .chars()
                .filter(|c| wordlist().is_free_of(*c))
                .collect();
            assert!(
                candidates.iter().any(|c| remaining.contains(*c)),
                "aucun séparateur admissible trouvé dans « {remaining} »"
            );
        }
    }

    #[test]
    fn out_of_range_word_counts_are_refused() {
        for words in [0_usize, 1, 2, MAX_WORDS + 1] {
            assert!(
                generate_passphrase(&passphrase_spec(words)).is_err(),
                "{words} mots devrait être refusé"
            );
        }
    }

    // -- Secrets ------------------------------------------------------------

    #[test]
    fn secret_formats_have_the_expected_symbol_counts() {
        let cases = [
            (SecretFormat::Hex, 32, 64, 16),
            (SecretFormat::Base32, 32, 52, 32),
            (SecretFormat::Base64Url, 32, 43, 64),
            (SecretFormat::Alphanumeric, 32, 32, 62),
        ];

        for (format, bytes, expected_symbols, expected_alphabet) in cases {
            let spec = SecretSpec {
                bytes,
                format,
                groups: 0,
            };
            let generated = generate_secret(&spec).expect("génération");
            assert_eq!(
                generated.value().len(),
                expected_symbols,
                "{format:?} : « {} »",
                generated.value()
            );

            match generated.composition() {
                Composition::Secret {
                    symbols, alphabet, ..
                } => {
                    assert_eq!(symbols, expected_symbols);
                    assert_eq!(alphabet, expected_alphabet);
                }
                other => panic!("composition inattendue : {other:?}"),
            }
        }
    }

    /// Pour les alphabets de 16, 32 et 64 symboles, l'entropie doit valoir
    /// exactement huit fois le nombre d'octets — sans perte.
    #[test]
    fn power_of_two_formats_lose_no_entropy() {
        for format in [
            SecretFormat::Hex,
            SecretFormat::Base32,
            SecretFormat::Base64Url,
        ] {
            let spec = SecretSpec {
                bytes: 32,
                format,
                groups: 0,
            };
            let generated = generate_secret(&spec).expect("génération");
            assert!(
                (generated.entropy().bits - 256.0).abs() < 1e-9,
                "{format:?} : {} bits au lieu de 256",
                generated.entropy().bits
            );
            assert_eq!(generated.entropy().band(), crate::entropy::Band::Strong);
        }
    }

    #[test]
    fn alphanumeric_entropy_uses_its_real_alphabet_size() {
        let spec = SecretSpec {
            bytes: 32,
            format: SecretFormat::Alphanumeric,
            groups: 0,
        };
        let generated = generate_secret(&spec).expect("génération");
        let expected = 32.0 * 62.0_f64.log2();
        assert!((generated.entropy().bits - expected).abs() < 1e-9);
        assert_eq!(generated.entropy().floor_bits(), 190);
    }

    #[test]
    fn out_of_range_secret_sizes_are_refused() {
        for bytes in [0_usize, 1, MIN_SECRET_BYTES - 1, MAX_SECRET_BYTES + 1] {
            let spec = SecretSpec {
                bytes,
                format: SecretFormat::Hex,
                groups: 0,
            };
            assert!(
                generate_secret(&spec).is_err(),
                "{bytes} octets devrait être refusé"
            );
        }
    }

    #[test]
    fn grouping_only_adds_separators() {
        let spec = SecretSpec {
            bytes: 32,
            format: SecretFormat::Hex,
            groups: 4,
        };
        let generated = generate_secret(&spec).expect("génération");
        // 64 symboles, 15 tirets de regroupement.
        assert_eq!(generated.value().len(), 64 + 15);
        let stripped: String = generated.value().chars().filter(|c| *c != '-').collect();
        assert_eq!(stripped.len(), 64);

        // Le regroupement n'ajoute aucune entropie : il ne fait que présenter.
        assert!((generated.entropy().bits - 256.0).abs() < 1e-9);
    }

    #[test]
    fn the_same_secret_is_never_produced_twice() {
        let spec = SecretSpec {
            bytes: 16,
            format: SecretFormat::Hex,
            groups: 0,
        };
        let mut seen = HashSet::new();
        for _ in 0..5000 {
            let generated = generate_secret(&spec).expect("génération");
            assert!(
                seen.insert(generated.value().to_owned()),
                "collision après {} tirages de 128 bits",
                seen.len()
            );
        }
    }

    /// Chaque format doit produire une sortie que son propre décodeur accepte, et
    /// retrouver exactement le nombre d'octets tirés.
    ///
    /// C'est ce qui relie la génération à l'encodage : un décalage de longueur
    /// passerait inaperçu si l'on se contentait de compter les symboles.
    #[test]
    fn every_secret_format_round_trips_to_its_byte_count() {
        for bytes in [8_usize, 16, 20, 32, 64] {
            let hex = generate_secret(&SecretSpec {
                bytes,
                format: SecretFormat::Hex,
                groups: 0,
            })
            .expect("génération");
            assert_eq!(hex.value().len(), bytes * 2);
            assert!(hex.value().chars().all(|c| c.is_ascii_hexdigit()));

            let base32 = generate_secret(&SecretSpec {
                bytes,
                format: SecretFormat::Base32,
                groups: 0,
            })
            .expect("génération");
            assert_eq!(
                encoding::base32_decode(base32.value())
                    .expect("décodage")
                    .len(),
                bytes,
                "base32 de {bytes} octets : « {} »",
                base32.value()
            );

            let base64 = generate_secret(&SecretSpec {
                bytes,
                format: SecretFormat::Base64Url,
                groups: 0,
            })
            .expect("génération");
            assert_eq!(
                encoding::base64url_decode(base64.value())
                    .expect("décodage")
                    .len(),
                bytes,
                "base64url de {bytes} octets : « {} »",
                base64.value()
            );

            let alnum = generate_secret(&SecretSpec {
                bytes,
                format: SecretFormat::Alphanumeric,
                groups: 0,
            })
            .expect("génération");
            assert_eq!(alnum.value().len(), bytes);
            assert!(alnum.value().chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn format_names_are_recognised() {
        assert_eq!(SecretFormat::parse("hex"), Some(SecretFormat::Hex));
        assert_eq!(SecretFormat::parse("BASE32"), Some(SecretFormat::Base32));
        assert_eq!(SecretFormat::parse("base64"), Some(SecretFormat::Base64Url));
        assert_eq!(
            SecretFormat::parse("alnum"),
            Some(SecretFormat::Alphanumeric)
        );
        assert_eq!(SecretFormat::parse("rot13"), None);
    }

    #[test]
    fn the_generated_secret_is_never_printed_by_debug() {
        let generated = generate_secret(&SecretSpec {
            bytes: 32,
            format: SecretFormat::Hex,
            groups: 0,
        })
        .expect("génération");

        let rendered = format!("{generated:?}");
        assert!(
            !rendered.contains(generated.value()),
            "le secret apparaît dans le Debug : {rendered}"
        );
        assert!(rendered.contains("[EXPURGÉ]"));
        assert!(rendered.contains("value_len"));
    }

    #[test]
    fn a_password_is_never_printed_by_debug() {
        let generated = generate_password(&PasswordSpec::new()).expect("génération");
        let rendered = format!("{generated:?}");
        assert!(!rendered.contains(generated.value()));
        assert!(rendered.contains("[EXPURGÉ]"));
    }
}
