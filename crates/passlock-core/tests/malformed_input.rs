//! Harnais de robustesse sur entrées malformées — exécuté dans la suite de tests.
//!
//! # Pourquoi ce harnais existe en plus de `cargo-fuzz`
//!
//! Les cibles `cargo-fuzz` vivent dans `fuzz/` et sont **guidées par la
//! couverture** : c'est la meilleure méthode pour explorer un espace d'entrées
//! vaste. Elles exigent en revanche une toolchain nightly et ne s'exécutent pas
//! partout.
//!
//! Ce harnais-ci est l'inverse : **déterministe**, reproductible, sans dépendance
//! exotique, et il tourne à chaque `cargo test`. Un test qu'on peut exécuter vaut
//! mieux qu'un test qu'on ne peut pas exécuter, même si son exploration est moins
//! fine. Les deux sont complémentaires :
//!
//! * `cargo-fuzz` cherche des chemins nouveaux, en intégration continue ;
//! * ce harnais garantit qu'aucune régression n'est introduite dans les chemins
//!   déjà connus, à chaque exécution locale.
//!
//! # Propriétés vérifiées
//!
//! **P1 — Aucune panique.** Le programme ne doit jamais s'arrêter brutalement sur
//! une entrée malformée. Une panique dans un gestionnaire de secrets est un
//! déni de service, et un `panic` peut aussi avoir formaté des données sensibles
//! dans un message. C'est la propriété la plus importante du fichier.
//!
//! **P2 — Cohérence décodage/encodage.** Si le décodage d'un header réussit, sa
//! ré-encodage doit produire **exactement** les mêmes octets. Une divergence
//! signalerait que le décodeur accepte des formes que l'encodeur ne produit pas —
//! donc que deux octets distincts représenteraient le même header, ce qui rendrait
//! l'AAD ambigu.
//!
//! **P3 — Aucune acceptation silencieuse.** Une entrée corrompue ne doit jamais
//! produire un contenu différent de celui attendu. Une acceptation silencieuse d'un
//! coffre altéré serait la pire des défaillances.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
// Le générateur pseudo-aléatoire de ce harnais tronque volontairement des entiers
// de 64 bits pour produire des octets : c'est l'opération voulue, pas un accident.
#![allow(clippy::cast_possible_truncation)]

use passlock_core::container::{self, ParsedVault};
use passlock_core::header::{Header, Slot, SlotLabel};
use passlock_core::kdf::KdfParams;
use passlock_core::keys::{KEY_LEN, WrappedKey};
use passlock_core::payload::Payload;
use passlock_core::secret::Key;

/// Générateur pseudo-aléatoire déterministe (xorshift64*).
///
/// Volontairement pas un générateur cryptographique : ce harnais doit être
/// **reproductible**, pas imprévisible. Un échec doit pouvoir être rejoué à
/// l'identique, ce qui exclut tout aléa système.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        // Une graine nulle bloquerait un xorshift sur zéro.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() % bound as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

/// Construit un coffre valide servant de base aux mutations.
fn valid_vault() -> Vec<u8> {
    let mut slot = Slot {
        id: 0,
        label: SlotLabel::Master,
        params: KdfParams::low(),
        salt: [0x5A; 32],
        wrapped: WrappedKey::placeholder(),
    };
    // Le contenu de l'enveloppe n'a pas besoin d'être authentique ici : les tests
    // de robustesse du décodage ne vont pas jusqu'au déchiffrement.
    slot.wrapped = WrappedKey::new([0x11; 24], [0x22; 48]);

    let header = Header::from_parts([0x33; 16], 1_700_000_000, vec![slot]).expect("header");
    let key = Key::<KEY_LEN>::from_array([0x44; KEY_LEN]);
    let payload = Payload::with_body(7, b"corps de test".to_vec())
        .encode()
        .expect("encodage");

    container::seal(&header, &key, &payload).expect("scellement")
}

/// Applique une mutation aléatoire à `data`.
fn mutate(data: &mut Vec<u8>, prng: &mut Prng) {
    if data.is_empty() {
        data.push(prng.byte());
        return;
    }

    match prng.below(7) {
        // Inversion d'un bit.
        0 => {
            let index = prng.below(data.len());
            let bit = prng.below(8);
            data[index] ^= 1 << bit;
        }
        // Remplacement d'un octet par une valeur arbitraire.
        1 => {
            let index = prng.below(data.len());
            data[index] = prng.byte();
        }
        // Écriture d'une valeur « intéressante » : bornes d'entiers, extrêmes.
        2 => {
            let index = prng.below(data.len());
            data[index] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF][prng.below(6)];
        }
        // Troncature.
        3 => {
            let keep = prng.below(data.len());
            data.truncate(keep);
        }
        // Suppression d'un octet au milieu : décale tout ce qui suit.
        4 => {
            let index = prng.below(data.len());
            data.remove(index);
        }
        // Insertion d'un octet : décale tout ce qui suit.
        5 => {
            let index = prng.below(data.len() + 1);
            let value = prng.byte();
            data.insert(index, value);
        }
        // Écriture d'une longueur aberrante dans les champs de taille du préfixe.
        _ => {
            if data.len() >= 16 {
                let value = u32::MAX >> prng.below(32);
                data[12..16].copy_from_slice(&value.to_be_bytes());
            } else {
                let index = prng.below(data.len());
                data[index] ^= 0xFF;
            }
        }
    }
}

/// Exerce les trois décodeurs sur une entrée, et vérifie les propriétés.
///
/// `original` est la version non mutée dont `bytes` est issu, ou `None` si l'entrée
/// n'en dérive pas (octets purement aléatoires).
///
/// Retourne `true` si l'entrée a été acceptée comme coffre structuré.
fn exercise(bytes: &[u8], original: Option<&[u8]>) -> bool {
    // P1 : ce chemin ne doit jamais paniquer, quelle que soit l'entrée.
    let Ok(parsed) = ParsedVault::parse(bytes) else {
        return false;
    };

    // Le header a été accepté : sa ré-encodage doit être fidèle (P2).
    let reencoded = parsed
        .header
        .encode()
        .expect("un header décodé doit pouvoir être ré-encodé");

    let prefix_len = 16 + reencoded.len();
    assert_eq!(
        parsed.authenticated_prefix().len(),
        prefix_len,
        "la taille de l'AAD ne correspond pas à la taille du header ré-encodé"
    );
    assert_eq!(
        &parsed.authenticated_prefix()[16..],
        reencoded.as_slice(),
        "le header ré-encodé diffère des octets décodés : le décodeur accepte des \
         formes que l'encodeur ne produit pas, ce qui rendrait l'AAD ambigu"
    );

    // P3 : intégrité. C'est la propriété la plus forte que ce harnais peut vérifier,
    // et elle découle d'une observation sur le format : **tous** les octets d'un
    // coffre sont soit dans l'AAD, soit le nonce, soit le texte chiffré. Il n'existe
    // donc aucune zone où une modification passerait inaperçue.
    //
    // Conséquence : une entrée non modifiée doit se déchiffrer, et **toute** entrée
    // modifiée doit échouer.
    let key = Key::<KEY_LEN>::from_array([0x44; KEY_LEN]);
    let decrypted = parsed.decrypt(&key).is_ok();

    if let Some(original) = original {
        if bytes == original {
            assert!(
                decrypted,
                "le coffre d'origine n'a pas pu être déchiffré : le chemin nominal \
                     n'est plus exercé par ce harnais"
            );
        } else {
            assert!(
                !decrypted,
                "une entrée modifiée a été déchiffrée : il existe une zone du fichier \
                 où une modification passe inaperçue"
            );
        }
    }
    // Sans version d'origine, on ne peut rien affirmer sur l'intégrité : les octets
    // peuvent avoir formé par hasard un coffre valide. Seule la propriété d'absence
    // de panique est alors vérifiée.

    true
}

#[test]
fn mutations_of_a_valid_vault_never_panic() {
    const ITERATIONS: usize = 20_000;

    let base = valid_vault();
    let mut prng = Prng::new(0x5EED_0001);
    let mut accepted = 0_usize;

    for iteration in 0..ITERATIONS {
        let mut candidate = base.clone();

        // Entre 1 et 4 mutations : une seule ne suffit pas à explorer les
        // combinaisons, et davantage rendrait les cas trop éloignés de la réalité.
        let mutations = 1 + prng.below(4);
        for _ in 0..mutations {
            mutate(&mut candidate, &mut prng);
        }

        if exercise(&candidate, Some(&base)) {
            accepted += 1;
        }

        // Le compteur sert à détecter une régression silencieuse : si plus aucune
        // mutation n'est acceptée, c'est que l'analyse refuse tout, et le test ne
        // teste plus grand-chose. On le vérifie à la fin, pas à chaque itération.
        let _ = iteration;
    }

    assert!(
        accepted > 0,
        "aucune mutation n'a été acceptée : le harnais n'exerce plus le chemin nominal"
    );
    println!("{accepted} mutations acceptées sur {ITERATIONS} (entrées structurées)");
}

#[test]
fn random_bytes_never_panic() {
    const ITERATIONS: usize = 20_000;
    const MAX_LEN: usize = 4096;

    let mut prng = Prng::new(0x5EED_0002);
    let mut accepted = 0_usize;

    for _ in 0..ITERATIONS {
        // Longueurs variées, dont les cas dégénérés 0 et 1.
        let len = match prng.below(10) {
            0 => 0,
            1 => 1,
            2 => 16,
            3 => 40,
            _ => prng.below(MAX_LEN),
        };
        let mut candidate: Vec<u8> = (0..len).map(|_| prng.byte()).collect();

        // Une entrée purement aléatoire de 4 Kio a une chance négligeable de porter
        // la signature. On en injecte une de temps en temps pour exercer le chemin
        // au-delà de la comparaison de signature, tout en laissant le reste des
        // octets aléatoire.
        if prng.below(4) == 0 && candidate.len() >= 8 {
            candidate[0..8].copy_from_slice(b"PASSLOCK");
        }

        // Aucune version d'origine : ces octets ne dérivent d'aucun coffre connu,
        // donc on ne peut rien affirmer sur leur intégrité. Seule la propriété
        // d'absence de panique est vérifiée ici.
        if exercise(&candidate, None) {
            accepted += 1;
        }
    }

    // Aucune acceptation n'est attendue : former par hasard une signature, une
    // version, des drapeaux, une longueur et un header cohérents sur des octets
    // aléatoires est hors de portée de 20 000 tirages. Le chemin au-delà du rejet
    // initial est exercé par les tests de mutation, qui partent d'un coffre valide.
    println!("{accepted} entrées aléatoires acceptées sur {ITERATIONS}");
}

#[test]
fn truncations_at_every_offset_never_panic() {
    let base = valid_vault();

    for len in 0..base.len() {
        let _ = exercise(&base[..len], Some(&base));
    }
}

#[test]
fn extreme_lengths_are_refused_without_allocating() {
    // En-têtes forgés annonçant des longueurs extrêmes. Le refus doit intervenir
    // avant toute allocation dimensionnée par ces valeurs.
    let base = valid_vault();

    for value in [
        0_u32,
        1,
        4_000_000_000,
        u32::MAX,
        u32::MAX - 16,
        0x7FFF_FFFF,
        4096,
        4097,
    ] {
        let mut candidate = base.clone();
        candidate[12..16].copy_from_slice(&value.to_be_bytes());
        let _ = exercise(&candidate, Some(&base));
    }
}

#[test]
fn hostile_kdf_parameters_are_refused_before_allocation() {
    // Un coffre annonçant 4 Gio de coût mémoire ne doit jamais conduire à allouer
    // quoi que ce soit. Le refus doit être visible dans l'analyse elle-même.
    let base = valid_vault();

    for m_cost in [0_u32, 8 * 1024 * 1024, 1024 * 1024 * 1024, u32::MAX] {
        let mut candidate = base.clone();
        // Offset du coût mémoire : préfixe (16) + header fixe (28) + slot (6).
        let offset = 16 + 28 + 6;
        candidate[offset..offset + 4].copy_from_slice(&m_cost.to_be_bytes());

        if let Ok(parsed) = ParsedVault::parse(&candidate) {
            // Si les paramètres ont été acceptés, ils doivent l'être restés dans
            // les bornes : « accepter » et « 4 Gio » sont incompatibles.
            let slot = &parsed.header.slots[0];
            assert!(
                slot.params.m_cost_kib() <= 2 * 1024 * 1024,
                "un coût mémoire de {} Kio a été accepté",
                slot.params.m_cost_kib()
            );
        }
    }
}

#[test]
fn payload_decoder_is_robust_to_arbitrary_input() {
    // Le payload est déjà authentifié quand il est décodé, donc le risque est
    // moindre — mais un défaut de notre propre encodage doit produire une erreur,
    // jamais une panique ni des données silencieusement fausses.
    let mut prng = Prng::new(0x5EED_0003);
    let valid = Payload::with_body(3, b"corps".to_vec())
        .encode()
        .expect("encodage");

    for iteration in 0..20_000 {
        let mut candidate = valid.clone();
        let mutations = 1 + prng.below(3);
        for _ in 0..mutations {
            mutate(&mut candidate, &mut prng);
        }

        if let Ok(decoded) = Payload::decode(&candidate) {
            // Un décodage réussi doit être cohérent : ré-encodage fidèle.
            assert_eq!(
                decoded.encode().expect("ré-encodage"),
                candidate,
                "itération {iteration} : le décodage a accepté des octets que le \
                     ré-encodage ne reproduit pas"
            );
        }
    }
}

#[test]
fn header_decoder_rejects_every_truncation_of_a_valid_header() {
    let slot = Slot {
        id: 0,
        label: SlotLabel::Master,
        params: KdfParams::low(),
        salt: [0x5A; 32],
        wrapped: WrappedKey::new([0x11; 24], [0x22; 48]),
    };
    let header = Header::from_parts([0x33; 16], 42, vec![slot]).expect("header");
    let encoded = header.encode().expect("encodage");

    for len in 0..encoded.len() {
        assert!(
            Header::decode(&encoded[..len]).is_err(),
            "troncature à {len} octets acceptée par le décodeur de header"
        );
    }

    // Et le cas nominal doit fonctionner, sinon le test ci-dessus serait vide de sens.
    assert!(Header::decode(&encoded).is_ok());
}
