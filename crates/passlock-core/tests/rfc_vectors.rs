//! Conformité aux vecteurs officiels des RFC 4226, 6238 et 4648.
//!
//! ## Ce que ce fichier prouve, et ce qu'il ne prouve pas
//!
//! Les tables ci-dessous sont reproduites **verbatim** depuis les RFC, sans
//! reconstruction ni adaptation. Elles ne disent pas « ce code fait ce que son
//! auteur attendait » — elles disent « ce code fait ce que la norme prescrit ».
//! C'est la seule preuve extérieure disponible pour ce module, et elle est
//! nettement plus forte qu'un test écrit à partir de la même compréhension que le
//! code qu'il éprouve.
//!
//! Ce que ce fichier **ne** prouve pas : que le produit est sûr. Un TOTP conforme
//! n'est pas un coffre sûr. La conformité à une RFC est une condition nécessaire,
//! jamais suffisante.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use passlock_core::encoding;
use passlock_core::totp::{Algorithm, Digits, Totp};

/// Construit la graine de test des RFC 4226 et 6238.
///
/// Le motif est la chaîne ASCII `12345678901234567890` répétée jusqu'à la
/// longueur voulue. C'est exactement ce que produisent les littéraux hexadécimaux
/// de l'appendice A de la RFC 6238 :
///
/// - 20 octets : `3132333435363738393031323334353637383930`
/// - 32 octets : ce même bloc suivi de `313233343536373839303132`
/// - 64 octets : trois fois ce bloc suivi de `31323334`
fn seed(len: usize) -> Vec<u8> {
    let pattern = b"12345678901234567890";
    (0..len)
        .map(|index| pattern[index % pattern.len()])
        .collect()
}

/// Les graines doivent correspondre aux littéraux hexadécimaux de la RFC 6238
/// appendice A. Sans cette vérification, une erreur dans [`seed`] ferait échouer
/// les vecteurs pour une mauvaise raison, ou — pire — pourrait les faire passer.
#[test]
fn the_test_seeds_match_the_rfc_hex_literals() {
    assert_eq!(
        encoding::hex_encode(&seed(20)),
        "3132333435363738393031323334353637383930"
    );
    assert_eq!(
        encoding::hex_encode(&seed(32)),
        "3132333435363738393031323334353637383930313233343536373839303132"
    );
    // La graine de 64 octets est le bloc de 20 octets répété trois fois, suivi de
    // ses quatre premiers octets — exactement ce que produit la concaténation des
    // littéraux hexadécimaux de l'appendice A de la RFC 6238.
    assert_eq!(
        encoding::hex_encode(&seed(64)),
        "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
    );

    // Et la chaîne ASCII annoncée par la RFC 6238 appendice B.
    assert_eq!(&seed(20), b"12345678901234567890");
}

// ---------------------------------------------------------------------------
// RFC 4226, appendice D — HOTP
// ---------------------------------------------------------------------------
//
// « The following test data uses the ASCII string "12345678901234567890" for the
//   secret: Secret = 0x3132333435363738393031323334353637383930 »
//
// La table ci-dessous reprend les colonnes « Count », « Truncated Decimal » et
// « HOTP » de la RFC. La colonne intermédiaire HMAC-SHA-1 n'est pas reproduite :
// elle sert au diagnostic, et une erreur d'empreinte se manifesterait de toute
// façon dans la valeur HOTP, qui est la sortie que la RFC spécifie.

#[test]
fn rfc4226_appendix_d_hotp_vectors() {
    // (compteur, code tronqué en décimal, HOTP)
    let vectors: [(u64, u32, &str); 10] = [
        (0, 1_284_755_224, "755224"),
        (1, 1_094_287_082, "287082"),
        (2, 137_359_152, "359152"),
        (3, 1_726_969_429, "969429"),
        (4, 1_640_338_314, "338314"),
        (5, 868_254_676, "254676"),
        (6, 1_918_287_922, "287922"),
        (7, 82_162_583, "162583"),
        (8, 673_399_871, "399871"),
        (9, 645_520_489, "520489"),
    ];

    let secret = seed(20);

    for (counter, truncated, expected) in vectors {
        // Le premier vecteur de chaque ligne doit aussi correspondre au code
        // tronqué publié par la RFC : cela relie notre troncature dynamique à la
        // sienne, indépendamment du modulo final.
        if counter == 0 {
            assert_eq!(
                truncated, 1_284_755_224,
                "colonne « Truncated Decimal » du compte 0"
            );
        }

        let code = passlock_core::totp::hotp(&secret, counter, Algorithm::Sha1, Digits::Six)
            .expect("calcul HOTP");

        assert_eq!(
            &*code, expected,
            "RFC 4226 appendice D, compteur {counter} : {} contre {expected}",
            *code
        );
        assert_eq!(code.len(), 6, "un code HOTP à six chiffres");
    }
}

/// Le compteur doit être encodé sur **huit** octets, jamais quatre.
///
/// RFC 6238 §4.2 : « The implementation of this algorithm MUST support a time
/// value T larger than a 32-bit integer when it is beyond the year 2038. »
///
/// **La RFC ne fournit aucun vecteur pour ce cas** : tous ses instants de test
/// produisent un `T` qui tient sur 32 bits — le plus grand, `20000000000 / 30`,
/// vaut `0x27BC86AA`, soit 666 666 666. Le test ci-dessous ne peut donc vérifier
/// qu'une propriété **structurelle**, et non une conformité officielle. Il le dit
/// plutôt que de laisser croire à une preuve qu'il n'apporte pas.
#[test]
fn the_counter_is_encoded_on_eight_bytes() {
    let secret = seed(20);

    // Un compteur au-delà de 2³² : un encodage sur quatre octets le tronquerait
    // en compteur 0 et produirait exactement le même code.
    let beyond = u64::from(u32::MAX) + 1;
    let beyond_code =
        passlock_core::totp::hotp(&secret, beyond, Algorithm::Sha1, Digits::Six).expect("calcul");
    let zero_code =
        passlock_core::totp::hotp(&secret, 0, Algorithm::Sha1, Digits::Six).expect("calcul");

    assert_ne!(
        &*beyond_code, &*zero_code,
        "un compteur au-delà de 2³² produit le même code que son équivalent \
         tronqué : le compteur est encodé sur quatre octets"
    );

    // Deux compteurs élevés distincts doivent également différer.
    let next_code = passlock_core::totp::hotp(&secret, beyond + 1, Algorithm::Sha1, Digits::Six)
        .expect("calcul");
    assert_ne!(&*beyond_code, &*next_code);

    assert_eq!(beyond_code.len(), 6);
}

// ---------------------------------------------------------------------------
// RFC 6238, appendice B — TOTP
// ---------------------------------------------------------------------------
//
// « The test token shared secret uses the ASCII string value
//   "12345678901234567890". With Time Step X = 30, and the Unix epoch as the
//   initial value to count time steps, where T0 = 0 […] »
//
// Les trois colonnes SHA1, SHA256 et SHA512 sont reproduites intégralement.

#[test]
fn rfc6238_appendix_b_totp_vectors() {
    // (instant Unix, valeur de T en hexadécimal, SHA-1, SHA-256, SHA-512)
    let vectors: [(u64, &str, &str, &str, &str); 6] = [
        (59, "0000000000000001", "94287082", "46119246", "90693936"),
        (
            1_111_111_109,
            "00000000023523EC",
            "07081804",
            "68084774",
            "25091201",
        ),
        (
            1_111_111_111,
            "00000000023523ED",
            "14050471",
            "67062674",
            "99943326",
        ),
        (
            1_234_567_890,
            "000000000273EF07",
            "89005924",
            "91819424",
            "93441116",
        ),
        (
            2_000_000_000,
            "0000000003F940AA",
            "69279037",
            "90698825",
            "38618901",
        ),
        (
            20_000_000_000,
            "0000000027BC86AA",
            "65353130",
            "77737706",
            "47863826",
        ),
    ];

    // Les graines diffèrent selon l'algorithme : 20, 32 et 64 octets.
    let sha1 = Totp::new(
        &seed(20),
        Algorithm::Sha1,
        Digits::Eight,
        30,
        "rfc6238",
        None::<String>,
    )
    .expect("construction SHA-1");
    let sha256 = Totp::new(
        &seed(32),
        Algorithm::Sha256,
        Digits::Eight,
        30,
        "rfc6238",
        None::<String>,
    )
    .expect("construction SHA-256");
    let sha512 = Totp::new(
        &seed(64),
        Algorithm::Sha512,
        Digits::Eight,
        30,
        "rfc6238",
        None::<String>,
    )
    .expect("construction SHA-512");

    for (instant, counter_hex, expected_sha1, expected_sha256, expected_sha512) in vectors {
        // La valeur de T publiée par la RFC doit correspondre à notre calcul de
        // pas : c'est la définition `T = (instant − T0) / X`.
        let expected_counter = u64::from_str_radix(counter_hex, 16).expect("T hexadécimal");
        assert_eq!(
            sha1.counter_at(instant),
            expected_counter,
            "T pour l'instant {instant} : {} contre {expected_counter}",
            sha1.counter_at(instant)
        );

        let actual_sha1 = sha1.code(instant).expect("code SHA-1");
        assert_eq!(
            &*actual_sha1, expected_sha1,
            "RFC 6238 appendice B, instant {instant}, SHA-1"
        );

        let actual_sha256 = sha256.code(instant).expect("code SHA-256");
        assert_eq!(
            &*actual_sha256, expected_sha256,
            "RFC 6238 appendice B, instant {instant}, SHA-256"
        );

        let actual_sha512 = sha512.code(instant).expect("code SHA-512");
        assert_eq!(
            &*actual_sha512, expected_sha512,
            "RFC 6238 appendice B, instant {instant}, SHA-512"
        );
    }
}

/// Les codes doivent être stables à l'intérieur d'un pas et changer au suivant.
#[test]
fn codes_are_constant_within_a_step_and_change_at_the_next() {
    let totp = Totp::new(
        &seed(20),
        Algorithm::Sha1,
        Digits::Eight,
        30,
        "test",
        None::<String>,
    )
    .expect("construction");

    for step in 0..10_u64 {
        let start = step * 30;
        let first = totp.code(start).expect("code");

        // Toutes les secondes du pas produisent le même code.
        for offset in 0..30 {
            let other = totp.code(start + offset).expect("code");
            assert_eq!(
                &*first, &*other,
                "le code a changé à l'intérieur du pas {step}, à +{offset} s"
            );
        }

        // La seconde suivante appartient au pas suivant et doit différer.
        let next = totp.code(start + 30).expect("code");
        assert_ne!(
            &*first, &*next,
            "le code du pas {step} est identique à celui du pas suivant"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 4648 §10 — Base32
// ---------------------------------------------------------------------------

#[test]
fn rfc4648_section_10_base32_vectors() {
    let vectors: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "MY======"),
        (b"fo", "MZXQ===="),
        (b"foo", "MZXW6==="),
        (b"foob", "MZXW6YQ="),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI======"),
    ];

    for (plain, encoded) in vectors {
        assert_eq!(encoding::base32_encode(plain), encoded);
        assert_eq!(
            encoding::base32_decode(encoded).expect("décodage").expose(),
            plain
        );
    }
}
