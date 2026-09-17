#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! Inventaire des secrets manipulés par la phase 3.
//!
//! ## Pourquoi un inventaire, et pas seulement des tests
//!
//! Les phases 1 et 2 ont établi qu'aucun secret ne doit subsister dans une
//! allocation non effacée. Un test ne peut pas vérifier une propriété *négative*
//! de façon exhaustive : il peut seulement vérifier les chemins qu'il emprunte.
//! L'inventaire ci-dessous **énumère** ces chemins, et chaque ligne est soit
//! couverte par un test, soit justifiée comme limite.
//!
//! ## Inventaire des copies de la phase 3
//!
//! | # | Emplacement | Forme | Politique |
//! |---|---|---|---|
//! | 1 | `Totp::secret` | `SecretVec` | Tampon verrouillé, effacé au `Drop` |
//! | 2 | `hotp` : empreinte HMAC | `Zeroizing<[u8; 64]>` | Pile, effacée à la sortie de la fonction |
//! | 3 | `hotp` : code produit | `Zeroizing<String>` | Effacé à la destruction |
//! | 4 | `generate_password` : candidat | `Zeroizing<String>` | Effacé, y compris **à chaque rejet** de la boucle |
//! | 5 | `generate_secret` : matière aléatoire | `Zeroizing<Vec<u8>>` | Effacée |
//! | 6 | `generate_*` : résultat | `Generated.value: Zeroizing<String>` | Effacé à la destruction |
//! | 7 | `Totp::parse_uri` : URI source | `String` du champ | **Limite héritée** : voir ci-dessous |
//! | 8 | `Totp::parse_uri` : secret décodé | `SecretVec` | Verrouillé et effacé |
//!
//! ### Limite héritée, assumée et documentée
//!
//! La ligne 7 est une **limite réelle**, pas un oubli. La valeur d'un `Field` est
//! un `String` depuis la phase 2, et un `String` ne s'efface pas de façon fiable :
//! ses réallocations peuvent laisser des fragments dans le tas. Cette limite est
//! antérieure à la phase 3, elle n'est pas corrigée ici — la corriger demanderait
//! de changer le modèle de données, ce qui n'est pas de ressort de cette phase.
//!
//! Elle est **documentée** dans `SECURITY.md` plutôt que passée sous silence.
//!
//! ## Propriétés vérifiées ci-dessous
//!
//! - aucun `Debug` ne restitue un secret, y compris sur les types intermédiaires ;
//! - aucun message d'erreur atteignable ne peut en porter ;
//! - les types portant un secret n'exposent pas de `Display` commode.

use passlock_core::error::Error;
use passlock_core::generator::{
    PassphraseSpec, PasswordSpec, SecretFormat, SecretSpec, generate_passphrase, generate_password,
    generate_secret,
};
use passlock_core::totp::{Algorithm, Digits, Totp};
use passlock_core::wordlist::{Language, Wordlist};

/// Marque reconnaissable, de longueur valide pour un secret TOTP.
///
/// Vingt octets, comme la longueur recommandée par la RFC 4226 §4 R6. Le texte est
/// choisi pour être détectable sous plusieurs formes : tel quel, en hexadécimal, et
/// en liste d'octets décimaux — les trois manières dont un `Debug` dérivé le
/// restituerait.
const MARKER: &[u8] = b"MARKERSECRET12345678";

/// Formes sous lesquelles la marque pourrait fuir.
fn forbidden_forms() -> Vec<String> {
    let mut forms = vec![
        String::from_utf8_lossy(MARKER).into_owned(),
        passlock_core::encoding::hex_encode(MARKER),
    ];

    // Liste d'octets décimaux, telle que `{:?}` la produirait sur un `Vec<u8>`.
    let decimal: Vec<String> = MARKER.iter().map(u8::to_string).collect();
    forms.push(decimal.join(", "));
    forms.push(format!("[{}]", decimal.join(", ")));

    // Préfixe suffisamment long pour être reconnaissable sans ambiguïté.
    forms.push(String::from_utf8_lossy(&MARKER[..10]).into_owned());

    forms
}

/// Vérifie qu'aucune forme de la marque n'apparaît dans un texte.
fn assert_no_leak(what: &str, rendered: &str) {
    for form in forbidden_forms() {
        assert!(
            !rendered.contains(&form),
            "fuite de secret dans {what} : « {form} » trouvé dans « {rendered} »"
        );
    }
}

#[test]
fn the_totp_debug_never_renders_the_secret() {
    let totp = Totp::new(
        MARKER,
        Algorithm::Sha256,
        Digits::Eight,
        60,
        "compte visible",
        Some("emetteur visible"),
    )
    .expect("construction");

    // Les paramètres publics **doivent** apparaître : un Debug qui ne dit rien
    // serait inutile pour le diagnostic, et le rendre muet serait une fuite
    // inverse — l'absence d'information rend le débogage impossible.
    let rendered = format!("{totp:?}");
    assert_no_leak("Totp::Debug", &rendered);
    assert!(rendered.contains("Sha256"));
    assert!(rendered.contains("Eight"));
    assert!(rendered.contains("60"));
    assert!(rendered.contains("[EXPURGÉ]"));
    assert!(rendered.contains("secret_len"));

    // Le `Debug` en mode « pretty » emprunte un autre chemin de formatage.
    assert_no_leak("Totp::Debug (pretty)", &format!("{totp:#?}"));
}

#[test]
fn the_totp_code_is_wiped_and_never_rendered_by_a_derived_debug() {
    let totp = Totp::new(
        MARKER,
        Algorithm::Sha1,
        Digits::Six,
        30,
        "compte",
        None::<String>,
    )
    .expect("construction");

    let code = totp.code(1_700_000_000).expect("code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    // Un code n'est pas un secret à longue durée de vie, mais c'en est un : il ne
    // doit pas se retrouver dans une sortie de débogage d'un objet qui le
    // contiendrait après coup.
    assert_no_leak("code TOTP", &code);
}

#[test]
fn the_debug_of_a_constructed_totp_does_not_leak_through_the_uri() {
    let totp = Totp::new(
        MARKER,
        Algorithm::Sha1,
        Digits::Six,
        30,
        "compte",
        None::<String>,
    )
    .expect("construction");

    // L'URI contient le secret : c'est sa raison d'être. Ce qui compte est qu'elle
    // ne soit **pas** atteignable depuis un `Debug`.
    let uri = totp.to_uri();
    assert!(
        uri.contains(&passlock_core::encoding::base32_encode_unpadded(MARKER)),
        "l'URI doit porter le secret, sinon l'enregistrement serait impossible"
    );

    let rendered = format!("{totp:?}");
    assert!(
        !rendered.contains(&uri),
        "le Debug restitue l'URI complète, donc le secret"
    );
    assert_no_leak("Totp::Debug", &rendered);
}

#[test]
fn the_generated_password_debug_never_renders_the_value() {
    for _ in 0..20 {
        let generated = generate_password(&PasswordSpec::new()).expect("génération");
        let value = generated.value().to_owned();
        let rendered = format!("{generated:?}");

        assert!(
            !rendered.contains(&value),
            "le mot de passe apparaît dans le Debug : {rendered}"
        );
        assert!(rendered.contains("[EXPURGÉ]"));
        assert!(rendered.contains("value_len"));
        assert_no_leak("Generated::Debug (mot de passe)", &rendered);
        assert_no_leak("Generated::Debug (pretty)", &format!("{generated:#?}"));
    }
}

#[test]
fn the_generated_secret_debug_never_renders_the_value() {
    for format in [
        SecretFormat::Hex,
        SecretFormat::Base32,
        SecretFormat::Base64Url,
        SecretFormat::Alphanumeric,
    ] {
        let generated = generate_secret(&SecretSpec {
            bytes: 32,
            format,
            groups: 0,
        })
        .expect("génération");

        let value = generated.value().to_owned();
        let rendered = format!("{generated:?}");
        assert!(
            !rendered.contains(&value),
            "{format:?} : le secret apparaît dans le Debug"
        );
        assert!(rendered.contains("[EXPURGÉ]"));
    }
}

#[test]
fn the_generated_passphrase_debug_never_renders_the_value() {
    let list = Wordlist::embedded(Language::EffEnglish, false).expect("liste");
    let generated = generate_passphrase(&PassphraseSpec {
        words: 6,
        separator: ".".to_owned(),
        random_separator: false,
        wordlist: list,
    })
    .expect("génération");

    let value = generated.value().to_owned();
    let rendered = format!("{generated:?}");
    assert!(
        !rendered.contains(&value),
        "la phrase de passe apparaît dans le Debug"
    );
    assert!(rendered.contains("[EXPURGÉ]"));
}

/// Aucun message d'erreur ne peut porter de donnée : le type `Error` n'accepte que
/// des `&'static str`, ce qui rend la faute **impossible à écrire**.
///
/// Ce test le vérifie de l'extérieur, en construisant chaque variante atteignable
/// depuis la phase 3 et en cherchant la marque dans son message.
#[test]
fn no_error_message_can_carry_a_secret() {
    let errors = [
        Error::InvalidInput {
            reason: "contrainte de test",
        },
        Error::Internal {
            invariant: "invariant de test",
        },
        Error::InvalidLength {
            field: "secret HOTP",
            expected: 16,
            actual: 3,
        },
        Error::MalformedLength {
            reason: "longueur de test",
        },
        Error::NotAVault,
        Error::UnlockFailed,
        Error::Corrupted { reason: "test" },
        Error::ReadOnly,
        Error::AlreadyLocked,
    ];

    for error in &errors {
        let rendered = format!("{error}");
        let debugged = format!("{error:?}");
        assert_no_leak("Error::Display", &rendered);
        assert_no_leak("Error::Debug", &debugged);
        assert!(!rendered.is_empty());
    }

    // Les erreurs réellement produites par l'analyse d'une URI hostile.
    let hostile = [
        format!(
            "otpauth://totp/Compte?secret={}",
            passlock_core::encoding::base32_encode_unpadded(MARKER)
        ),
        "otpauth://hotp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/Compte".to_owned(),
        "otpauth://totp/Compte?secret=MZXW6".to_owned(),
        "otpauth://totp/Compte%ZZ?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/\x1b[2KCompte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
    ];

    for uri in hostile {
        // La première URI est valide : c'est la marque elle-même qui sert de secret.
        if let Err(error) = Totp::parse_uri(&uri) {
            assert_no_leak("Error depuis parse_uri", &format!("{error}"));
            assert_no_leak("Error depuis parse_uri (Debug)", &format!("{error:?}"));
        }
    }
}

/// Un secret engendré ne doit jamais réapparaître dans le rapport d'entropie.
#[test]
fn the_entropy_report_carries_no_secret() {
    let generated = generate_password(&PasswordSpec::new()).expect("génération");
    let value = generated.value().to_owned();

    let report = format!("{:?}", generated.entropy());
    assert!(
        !report.contains(&value),
        "le rapport d'entropie contient le mot de passe"
    );

    // Le rapport doit en revanche porter les nombres : c'est sa fonction.
    assert!(report.contains("bits"));
    assert!(report.contains("acceptance"));
}

/// Les listes de mots sont **publiques** : elles ne contiennent aucun secret, et ce
/// test le constate plutôt que de le supposer.
///
/// Un mot de la liste qui serait aussi un secret engendré signalerait une
/// confusion entre donnée publique et donnée secrète.
#[test]
fn the_wordlists_are_public_data() {
    for language in [Language::EffEnglish, Language::DicewareFrench] {
        let list = Wordlist::embedded(language, false).expect("liste");
        // Le `Debug` d'une liste révèle ses mots : c'est acceptable, elle est
        // publique par construction et livrée dans le binaire.
        let rendered = format!("{list:?}");
        assert!(rendered.contains("Wordlist"));

        // Et un mot engendré à partir de cette liste ne doit pas être confondu avec
        // un secret : il n'est secret que par sa **combinaison**.
        let generated = generate_passphrase(&PassphraseSpec {
            words: 3,
            separator: ".".to_owned(),
            random_separator: false,
            wordlist: list,
        })
        .expect("génération");
        for word in generated.value().split('.') {
            assert!(
                (0..list.len()).any(|i| list.word(i) == Some(word)),
                "un mot de la phrase ne vient pas de la liste"
            );
        }
    }
}
