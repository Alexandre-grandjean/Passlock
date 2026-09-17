#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! Campagne d'entrées hostiles sur l'analyse d'URI `otpauth://`.
//!
//! ## Ce qui est cherché
//!
//! L'analyseur traite du texte **authentifié mais non fiable** : il vient d'un
//! champ du coffre, donc il a été validé par l'AEAD, mais rien ne garantit qu'il a
//! été *écrit* par ce programme. Il peut venir d'un import, d'une version
//! antérieure, ou avoir été forgé par quiconque détient la clé.
//!
//! Trois propriétés sont éprouvées :
//!
//! 1. **Aucune panique**, quelle que soit l'entrée — y compris binaire, tronquée
//!    au milieu d'un caractère multi-octets, ou composée uniquement de
//!    métacaractères d'URI ;
//! 2. **Aucune acceptation indue** : une entrée malformée doit être refusée, pas
//!    « réparée » ;
//! 3. **Aucune allocation non bornée** : une entrée de taille arbitraire est
//!    refusée avant tout travail.
//!
//! ## Ce que cette campagne ne prouve pas
//!
//! Une campagne aléatoire ne prouve pas l'absence de panique : elle en diminue la
//! probabilité. Une cible `cargo-fuzz` couvre le même code de façon plus
//! systématique, mais son exécution est rapportée séparément — et si elle n'a pas
//! eu lieu, elle est marquée comme telle.

use passlock_core::totp::{Algorithm, Digits, MAX_URI_LEN, Totp};

/// Générateur déterministe.
///
/// Volontairement distinct de ceux des autres harnais : un générateur partagé
/// produirait les mêmes séquences, donc les mêmes angles morts.
struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed ^ 0x5DEE_CE66_D1CE_4E5B)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0xA24B_AED4_963E_E407)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() >> 11) as usize % bound
        }
    }
}

/// Jeu de caractères biaisé vers les métacaractères d'URI.
///
/// Un tirage uniforme sur les octets produirait presque toujours une chaîne
/// refusée dès le premier caractère, ce qui n'exercerait pas le corps de
/// l'analyseur. Ce jeu concentre au contraire les caractères qui y mènent :
/// séparateurs, échappements, et octets de continuation UTF-8.
const URI_ALPHABET: &[u8] =
    b"otpauth://totp/ABCZ2345?&=%-_.+:@!#$*[]{}|\\\"'`<>~^\x1b\x07\x00\xff\x80\n\r\t ";

/// Construit une chaîne à partir d'octets arbitraires, en tolérant l'UTF-8 invalide.
///
/// On passe par `from_utf8_lossy` : la chaîne résultante n'est pas celle des octets
/// d'origine, mais elle est valide et contient le même genre de séquences.
fn random_string(rng: &mut Prng, len: usize) -> String {
    let bytes: Vec<u8> = (0..len)
        .map(|_| URI_ALPHABET[rng.below(URI_ALPHABET.len())])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Vingt mille chaînes aléatoires, plus les préfixes valides connus.
///
/// L'assertion n'est pas « l'analyse réussit » — presque toutes doivent échouer —
/// mais « l'analyse **rend un verdict** » : ni panique, ni boucle infinie.
#[test]
fn twenty_thousand_random_inputs_never_panic() {
    let mut rng = Prng::new(0x1234_5678_9ABC_DEF0);
    let prefixes = [
        "",
        "otpauth://",
        "otpauth://totp",
        "otpauth://totp/",
        "otpauth://totp/Compte?",
        "otpauth://totp/Compte?secret=",
        "otpauth://hotp/Compte?secret=",
    ];

    let mut accepted = 0_usize;

    for round in 0..20_000 {
        let prefix = prefixes[rng.below(prefixes.len())];
        let length = rng.below(80);
        let body = random_string(&mut rng, length);

        // Deux formes : préfixe valide suivi d'un corps hostile, ou corps seul.
        let candidate = if round % 2 == 0 {
            format!("{prefix}{body}")
        } else {
            body
        };

        if Totp::parse_uri(&candidate).is_ok() {
            accepted += 1;
        }
    }

    // Une acceptation ne serait pas un défaut en soi — une chaîne aléatoire peut
    // être une URI valide — mais un taux élevé signalerait un analyseur trop
    // permissif. Le jeu de caractères étant saturé de métacaractères, l'immense
    // majorité doit être refusée.
    assert!(
        accepted < 100,
        "{accepted} chaînes aléatoires acceptées sur 20 000 : analyseur trop permissif"
    );
}

/// Toutes les troncatures d'une URI valide.
///
/// La méthode est celle employée en phase 2 sur l'archive : une troncature est le
/// moyen le plus simple de faire sortir un analyseur de ses bornes.
#[test]
fn every_truncation_of_a_valid_uri_is_handled() {
    let uri = "otpauth://totp/Exemple:alice@exemple.fr\
               ?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
               &issuer=Exemple&algorithm=SHA256&digits=8&period=60";

    // L'URI complète doit être acceptée : sans quoi le test ne dirait rien.
    assert!(Totp::parse_uri(uri).is_ok());

    for cut in 0..uri.len() {
        if !uri.is_char_boundary(cut) {
            continue;
        }
        // Le seul critère : rendre un verdict plutôt que paniquer.
        let _ = Totp::parse_uri(&uri[..cut]);
    }
}

/// Les caractères de contrôle doivent être refusés **à l'entrée**.
///
/// ## Pourquoi c'est une défense de sécurité et non une coquetterie
///
/// Une séquence d'échappement ANSI imprimée telle quelle réécrit le tampon de
/// l'écran. Un libellé contrôlé par un attaquant — via une entrée importée —
/// pourrait donc faire afficher à l'utilisateur un **code qui n'est pas celui qui a
/// été produit**. Refuser à l'analyse protège tous les usages présents et futurs ;
/// échapper à l'affichage serait une défense au point d'usage, qu'un futur site
/// d'affichage oublierait.
#[test]
fn terminal_escape_sequences_are_refused_in_labels_and_issuers() {
    let attacks = [
        // Effacer la ligne, revenir au début, réécrire un faux code.
        "Exemple\x1b[2K\x1b[G  Code : 00000000",
        // Modifier le titre de la fenêtre.
        "Exemple\x1b]0;pwned\x07",
        // Déplacer le curseur.
        "Exemple\x1b[10;10H",
        // Retour chariot : réécrit la ligne sans séquence CSI.
        "Exemple\rcode faux",
        // Retour arrière : efface visuellement ce qui précède.
        "Exemple\x08\x08\x08\x08",
        // Saut de ligne : décaler tout l'affichage suivant.
        "Exemple\nligne",
        // Tabulation verticale.
        "Exemple\x0b",
    ];

    for attack in attacks {
        let uri = format!(
            "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            percent_encode_for_test(attack)
        );
        assert!(
            Totp::parse_uri(&uri).is_err(),
            "séquence de contrôle acceptée dans le libellé : {attack:?}"
        );

        // Le même contenu dans l'émetteur doit être refusé de la même façon.
        let uri = format!(
            "otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer={}",
            percent_encode_for_test(attack)
        );
        assert!(
            Totp::parse_uri(&uri).is_err(),
            "séquence de contrôle acceptée dans l'émetteur : {attack:?}"
        );
    }
}

/// Échappement pourcent, pour amener une chaîne de contrôle jusqu'à l'analyseur.
fn percent_encode_for_test(input: &str) -> String {
    input
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Une URI de taille arbitraire est refusée **avant** tout travail.
#[test]
fn oversized_uris_are_refused_before_analysis() {
    for multiplier in [1_usize, 2, 10, 100] {
        let uri = format!(
            "otpauth://totp/Compte?secret={}",
            "A".repeat(MAX_URI_LEN * multiplier)
        );
        assert!(
            Totp::parse_uri(&uri).is_err(),
            "URI de {} octets acceptée",
            uri.len()
        );
    }

    // Juste sous la borne : acceptée ou refusée pour une autre raison, mais traitée.
    let uri = format!(
        "otpauth://totp/Compte?secret={}",
        "A".repeat(MAX_URI_LEN - 64)
    );
    let _ = Totp::parse_uri(&uri);
}

/// Un secret d'une longueur hors bornes doit être refusé, jamais complété.
///
/// « Réparer » un secret trop court produirait des codes que le serveur ne
/// reconnaîtrait pas, en donnant l'illusion que tout fonctionne.
#[test]
fn secrets_of_every_length_around_the_floor_are_judged_exactly() {
    use passlock_core::encoding;

    for bytes in 0..24_usize {
        let encoded = encoding::base32_encode_unpadded(&vec![0x5A_u8; bytes]);
        let uri = format!("otpauth://totp/Compte?secret={encoded}");
        let outcome = Totp::parse_uri(&uri);

        match bytes {
            0..=15 => assert!(
                outcome.is_err(),
                "un secret de {bytes} octets ({}) doit être refusé : la RFC 4226 §4 \
                 R6 en exige au moins 16",
                bytes * 8
            ),
            16..=23 => assert!(
                outcome.is_ok(),
                "un secret de {bytes} octets doit être accepté"
            ),
            _ => unreachable!(),
        }
    }

    // Au-delà du plafond.
    let encoded = encoding::base32_encode_unpadded(&[0x5A_u8; 129]);
    assert!(Totp::parse_uri(&format!("otpauth://totp/Compte?secret={encoded}")).is_err());
}

/// Les paramètres numériques sont bornés des deux côtés.
#[test]
fn numeric_parameters_are_bounded_on_both_sides() {
    let base = "otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    // `digits` : seuls 6 et 8 sont acceptés.
    for digits in 0..=10_u32 {
        let uri = format!("{base}&digits={digits}");
        let outcome = Totp::parse_uri(&uri);
        match digits {
            6 | 8 => assert!(outcome.is_ok(), "digits={digits} devrait être accepté"),
            _ => assert!(outcome.is_err(), "digits={digits} devrait être refusé"),
        }
    }

    // `period` : de 1 à 600.
    for period in [0_u32, 1, 2, 30, 300, 599, 600, 601, 1000] {
        let uri = format!("{base}&period={period}");
        let outcome = Totp::parse_uri(&uri);
        match period {
            1..=600 => assert!(outcome.is_ok(), "period={period} devrait être accepté"),
            _ => assert!(outcome.is_err(), "period={period} devrait être refusé"),
        }
    }
}

/// Un aller-retour complet doit préserver **tous** les paramètres.
///
/// Sans ce test, une URI pourrait être relue avec des valeurs par défaut sans que
/// rien ne le signale : le code produit serait alors simplement faux.
#[test]
fn a_round_trip_preserves_every_parameter() {
    let algorithms = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512];
    let digits = [Digits::Six, Digits::Eight];
    let periods = [1_u32, 30, 60, 600];
    let labels = ["alice", "a.b+c", "utilisateur avec espaces", "é"];
    let issuers = [None, Some("Exemple"), Some("Banque & Cie"), Some("éè")];

    let mut rounds = 0_usize;

    for algorithm in algorithms {
        for digit in digits {
            for period in periods {
                for label in labels {
                    for issuer in issuers {
                        let original = Totp::new(
                            b"12345678901234567890",
                            algorithm,
                            digit,
                            period,
                            label,
                            issuer,
                        )
                        .expect("construction");

                        let uri = original.to_uri();
                        let parsed = Totp::parse_uri(&uri).unwrap_or_else(|err| {
                            panic!("notre propre URI refusée « {uri} » : {err}")
                        });

                        assert_eq!(parsed.algorithm(), algorithm);
                        assert_eq!(parsed.digits(), digit);
                        assert_eq!(parsed.period(), period);
                        assert_eq!(parsed.label(), label, "URI « {uri} »");
                        assert_eq!(parsed.issuer(), issuer, "URI « {uri} »");

                        // Le secret survit à l'aller-retour, donc les codes aussi.
                        assert_eq!(
                            *original.code(1_700_000_000).expect("code"),
                            *parsed.code(1_700_000_000).expect("code")
                        );

                        rounds += 1;
                    }
                }
            }
        }
    }

    assert_eq!(rounds, 3 * 2 * 4 * 4 * 4);
}

/// Deux URI distinctes ne doivent jamais désigner le même secret.
///
/// Une collision signalerait une perte d'information à l'encodage — par exemple un
/// remplissage Base32 mal retiré.
#[test]
fn distinct_secrets_never_collide_through_the_uri() {
    let mut seen = std::collections::HashSet::new();

    for byte in 0_u8..=255 {
        let secret = [byte; 20];
        let totp = Totp::new(
            &secret,
            Algorithm::Sha1,
            Digits::Six,
            30,
            "t",
            None::<String>,
        )
        .expect("construction");
        let uri = totp.to_uri();

        let parsed = Totp::parse_uri(&uri).expect("analyse");
        assert_eq!(parsed.secret_len(), 20);
        assert!(
            seen.insert(uri),
            "deux secrets distincts produisent la même URI (octet {byte})"
        );
    }
}
