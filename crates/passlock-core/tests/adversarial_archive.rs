//! Harnais adversarial du codec d'archive.
//!
//! # Ce qui est éprouvé ici, et pourquoi c'est différent des tests unitaires
//!
//! Les tests de `archive.rs` vérifient des propriétés **choisies**. Ce fichier fait
//! l'inverse : il mutile une archive valide de toutes les manières systématiques
//! possibles et vérifie qu'aucune ne produit de comportement inacceptable.
//!
//! Les deux propriétés recherchées :
//!
//! * **P1 — aucune panique, aucune allocation incontrôlée.** Un corps forgé ne doit
//!   jamais faire tomber le programme ni lui faire tenter de réserver une quantité
//!   de mémoire pilotée par son contenu.
//! * **P2 — tout ce qui est accepté est cohérent.** Si le décodeur accepte des
//!   octets, leur ré-encodage doit être **identique**. Un décodage qui accepterait
//!   une forme que l'encodage ne reproduit pas rendrait le format ambigu — et
//!   l'AAD du conteneur, qui repose sur l'encodage déterministe, deviendrait
//!   trompeuse.
//!
//! Aucune dérivation Argon2id n'intervient : ces tests travaillent sur des octets,
//! pas sur un coffre. Ils sont donc rapides et déterministes.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

use passlock_core::archive::{self, ARCHIVE_VERSION, MAX_ARCHIVE_LEN};
use passlock_core::model::{
    Archive, Entry, EntryKind, Field, FieldKind, Folder, FolderId, MAX_FIELDS_PER_ENTRY,
    MAX_HISTORY_PER_ENTRY, MAX_TAGS_PER_ENTRY, Revision, Tag, TagId,
};

/// Générateur pseudo-aléatoire déterministe (xorshift64*).
///
/// Reproductible à dessein : un échec doit pouvoir être rejoué à l'identique, ce qui
/// exclut tout aléa système.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
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
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

/// Archive représentative : plusieurs sections, des chaînes, de l'historique.
fn rich_archive() -> Archive {
    let mut archive = Archive::new(1_700_000_000);

    let root = FolderId::generate().expect("aléa");
    archive.folders.push(Folder {
        id: root,
        name: "racine".to_string(),
        parent: None,
        ordinal: 0,
    });
    archive.folders.push(Folder {
        id: FolderId::generate().expect("aléa"),
        name: "enfant".to_string(),
        parent: Some(root),
        ordinal: 1,
    });

    let tag = TagId::generate().expect("aléa");
    archive.tags.push(Tag {
        id: tag,
        name: "important".to_string(),
    });

    let mut entry = Entry::new(EntryKind::Login, "exemple.com", 1_700_000_000).expect("entrée");
    entry.subtitle = "utilisateur@exemple.com".to_string();
    entry.favorite = true;
    entry.folder = Some(root);
    entry.tags.push(tag);
    for index in 0..6_u16 {
        entry.fields.push(
            Field::new(
                format!("champ{index}"),
                FieldKind::Text,
                format!("valeur {index} avec accent é"),
                index,
            )
            .expect("champ"),
        );
    }

    let mut previous = entry.duplicate();
    previous.title = "ancien titre".to_string();
    previous.history.clear();
    entry.history.push(Revision {
        at: 1,
        snapshot: previous,
    });

    archive.entries.push(entry);
    archive
        .settings
        .push(Field::new("history_days", FieldKind::Number, "90", 0).expect("champ"));

    archive
}

/// Applique une mutation aléatoire.
fn mutate(data: &mut Vec<u8>, prng: &mut Prng) {
    if data.is_empty() {
        data.push(prng.byte());
        return;
    }

    match prng.below(7) {
        0 => {
            let index = prng.below(data.len());
            data[index] ^= 1 << prng.below(8);
        }
        1 => {
            let index = prng.below(data.len());
            data[index] = prng.byte();
        }
        2 => {
            let index = prng.below(data.len());
            data[index] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF][prng.below(6)];
        }
        3 => {
            let cut = prng.below(data.len());
            data.truncate(cut);
        }
        4 => {
            let index = prng.below(data.len());
            data.remove(index);
        }
        5 => {
            let index = prng.below(data.len() + 1);
            let value = prng.byte();
            data.insert(index, value);
        }
        // Écriture d'un compte de section : c'est la cible la plus intéressante.
        _ => {
            if data.len() >= 38 {
                let offsets = [16_usize, 20, 24, 28, 32, 36];
                let offset = offsets[prng.below(offsets.len())];
                let value = match prng.below(5) {
                    0 => u32::MAX,
                    1 => 1_000_000_000,
                    2 => 0,
                    3 => u32::try_from(data.len()).unwrap_or(u32::MAX),
                    _ => u32::from(prng.byte()),
                };
                data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            } else {
                let index = prng.below(data.len());
                data[index] ^= 0xFF;
            }
        }
    }
}

/// Exerce le décodeur et vérifie la propriété de fidélité.
///
/// # Pourquoi le message d'échec ne contient aucun octet
///
/// `assert_eq!` sur deux tranches affiche leur contenu intégral. Sur un corps de
/// coffre, cela déverserait du contenu déchiffré dans la sortie d'échec — et donc
/// dans le journal de la CI. Les comparaisons ci-dessous utilisent donc des
/// assertions sans `Debug`, avec des messages qui décrivent l'**écart** sans en
/// montrer les données.
///
/// # Pourquoi aucune comparaison avec l'entrée d'origine
///
/// Une mutation peut être un **no-op** : écrire dans un octet la valeur qu'il
/// contenait déjà. Exiger que chaque cas diffère de l'original serait donc faux. Le
/// harnais vérifie globalement qu'il mute réellement, ce qui est la propriété utile.
fn exercise(bytes: &[u8]) -> bool {
    let Ok(decoded) = archive::decode(bytes) else {
        return false;
    };

    let reencoded = archive::encode(&decoded).expect("ré-encodage");

    // P2 : un décodage réussi doit être fidèle, octet pour octet. Les messages
    // n'affichent que des **positions**, jamais le contenu : déverser un corps de
    // coffre dans une sortie d'échec le ferait atterrir dans le journal de la CI.
    assert!(
        reencoded.len() == bytes.len(),
        "le ré-encodage a produit {} octets au lieu de {} : le décodage a accepté une \
         forme que l'encodage ne reproduit pas",
        reencoded.len(),
        bytes.len()
    );

    let divergence = reencoded
        .iter()
        .zip(bytes.iter())
        .position(|(left, right)| left != right);
    assert!(
        divergence.is_none(),
        "le ré-encodage diverge à partir de l'offset {divergence:?}"
    );

    true
}

#[test]
fn mutations_of_a_valid_archive_never_panic_or_diverge() {
    const ITERATIONS: usize = 20_000;

    let base = archive::encode(&rich_archive()).expect("encodage");
    let mut prng = Prng::new(0xA2C4_0001);
    let mut accepted = 0_usize;
    let mut actually_changed = 0_usize;

    for _ in 0..ITERATIONS {
        let mut candidate = base.to_vec();
        for _ in 0..=prng.below(4) {
            mutate(&mut candidate, &mut prng);
        }

        if candidate != base.to_vec() {
            actually_changed += 1;
        }

        if exercise(&candidate) {
            accepted += 1;
        }
    }

    assert!(
        accepted > 0,
        "aucune mutation n'a été acceptée : le harnais n'exerce plus le chemin nominal"
    );
    assert!(
        actually_changed > ITERATIONS / 4,
        "seules {actually_changed} mutations sur {ITERATIONS} ont réellement modifié \
         les octets : le harnais ne teste plus rien"
    );
    println!("{accepted} mutations acceptées sur {ITERATIONS}, {actually_changed} mutantes");
}

#[test]
fn random_bytes_never_panic() {
    const ITERATIONS: usize = 20_000;

    let mut prng = Prng::new(0xA2C4_0002);
    let mut accepted = 0_usize;

    for _ in 0..ITERATIONS {
        let len = match prng.below(12) {
            0 => 0,
            1 => 1,
            2 => 20,
            3 => 40,
            4 => 41,
            _ => prng.below(2048),
        };
        let mut candidate: Vec<u8> = (0..len).map(|_| prng.byte()).collect();

        // Une signature valide de temps en temps, pour pousser le décodeur au-delà du
        // premier rejet.
        if prng.below(3) == 0 && candidate.len() >= 6 {
            candidate[0..4].copy_from_slice(b"ARC2");
            candidate[4..6].copy_from_slice(&ARCHIVE_VERSION.to_be_bytes());
        }

        if exercise(&candidate) {
            accepted += 1;
        }
    }

    println!("{accepted} entrées aléatoires acceptées sur {ITERATIONS}");
}

#[test]
fn every_truncation_of_a_valid_archive_is_refused() {
    let encoded = archive::encode(&rich_archive()).expect("encodage");
    for len in 0..encoded.len() {
        assert!(
            archive::decode(&encoded[..len]).is_err(),
            "troncature à {len} octets acceptée"
        );
    }
}

#[test]
fn every_section_count_set_to_an_absurd_value_is_refused() {
    // LE test de l'invariant d'allocation. Chacun de ces comptes dimensionnerait une
    // allocation ; aucun ne doit être accepté, et le refus doit intervenir **avant**
    // toute réservation.
    let encoded = archive::encode(&rich_archive()).expect("encodage");

    for offset in [16_usize, 20, 24, 28, 32, 36] {
        for value in [
            u32::MAX,
            u32::MAX - 1,
            2_000_000_000,
            100_000_000,
            1_000_000,
        ] {
            let mut hostile = encoded.to_vec();
            hostile[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

            assert!(
                archive::decode(&hostile).is_err(),
                "un compte de {value} à l'offset {offset} a été accepté"
            );
        }
    }
}

#[test]
fn a_count_exactly_at_the_limit_of_the_remaining_bytes_is_handled() {
    // Frontière fine : le compte reste sous la borne déclarée, mais les octets
    // présents ne suffisent pas à contenir autant d'enregistrements. C'est le cas
    // qu'une vérification de borne seule laisserait passer.
    let encoded = archive::encode(&rich_archive()).expect("encodage");

    for offset in [16_usize, 20, 24, 28, 32, 36] {
        let remaining = encoded.len() - offset - 4;
        for value in [remaining, remaining + 1, remaining.saturating_sub(1)] {
            let mut hostile = encoded.to_vec();
            hostile[offset..offset + 4]
                .copy_from_slice(&u32::try_from(value).unwrap_or(u32::MAX).to_be_bytes());

            // On accepte un refus comme un décodage cohérent, mais jamais une panique
            // ni une divergence.
            let _ = exercise(&hostile);
        }
    }
}

#[test]
fn an_archive_at_the_size_limit_boundary_is_handled() {
    let oversized = vec![0_u8; MAX_ARCHIVE_LEN + 1];
    assert!(archive::decode(&oversized).is_err());

    // Juste en dessous de la borne : le refus doit venir du contenu, pas de la
    // taille, et surtout il ne doit pas y avoir de panique.
    let at_limit = vec![0_u8; MAX_ARCHIVE_LEN];
    assert!(archive::decode(&at_limit).is_err());
}

#[test]
fn every_unknown_discriminant_is_refused() {
    // Les types d'entrée, de champ et d'événement sont des ensembles **fermés** : un
    // octet inconnu doit produire une erreur, jamais un rangement silencieux dans une
    // catégorie fourre-tout.
    let mut archive = Archive::new(0);
    archive
        .entries
        .push(Entry::new(EntryKind::Login, "x", 0).expect("entrée"));

    let encoded = archive::encode(&archive).expect("encodage");

    // Type d'entrée : après l'en-tête (40) et l'identifiant (16).
    for value in [0_u8, 10, 99, 255] {
        let mut hostile = encoded.to_vec();
        hostile[40 + 16] = value;
        assert!(
            archive::decode(&hostile).is_err(),
            "un type d'entrée de {value} a été accepté"
        );
    }
}

#[test]
fn the_recursion_invariant_holds_under_mutation() {
    // L'invariant qui borne la profondeur : l'instantané d'une révision ne peut pas
    // contenir d'historique. On le vérifie en construisant des archives où
    // l'imbrication est poussée, puis en vérifiant que rien n'est accepté au-delà
    // d'un niveau.
    let mut archive = Archive::new(0);

    let mut entry = Entry::new(EntryKind::Login, "niveau 0", 0).expect("entrée");
    let mut level1 = Entry::new(EntryKind::Login, "niveau 1", 0).expect("entrée");
    level1.id = entry.id;

    // Un instantané contenant lui-même un historique : la structure est construite
    // en mémoire, mais l'encodage doit la refuser.
    level1.history.push(Revision {
        at: 0,
        snapshot: Entry::new(EntryKind::Login, "niveau 2", 0).expect("entrée"),
    });
    entry.history.push(Revision {
        at: 1,
        snapshot: level1,
    });
    archive.entries.push(entry);

    match archive::encode(&archive) {
        // L'encodage refuse : `validate` borne la rétention et l'instantané est
        // irrégulier.
        Err(_) => {}
        // Si l'encodage passait, le décodage devrait refuser.
        Ok(bytes) => assert!(
            archive::decode(&bytes).is_err(),
            "une imbrication d'historique a été acceptée"
        ),
    }
}

#[test]
fn a_large_but_legitimate_archive_round_trips_under_mutation() {
    // À l'échelle : bornes, réallocations et cohérence tiennent-elles ?
    let mut archive = Archive::new(0);
    let tag = TagId::generate().expect("aléa");
    archive.tags.push(Tag {
        id: tag,
        name: "lot".to_string(),
    });

    for index in 0..500_u32 {
        let mut entry = Entry::new(EntryKind::Login, format!("entrée {index}"), 0).expect("entrée");
        entry.tags.push(tag);
        for field_index in 0..4_u16 {
            entry.fields.push(
                Field::new(
                    format!("champ{field_index}"),
                    FieldKind::Text,
                    format!("valeur {index}-{field_index}"),
                    field_index,
                )
                .expect("champ"),
            );
        }
        archive.entries.push(entry);
    }

    let encoded = archive::encode(&archive).expect("encodage");
    let decoded = archive::decode(&encoded).expect("décodage");
    assert_eq!(decoded.entries.len(), 500);

    // Et une mutation ponctuelle ne doit jamais produire d'incohérence acceptée.
    let mut prng = Prng::new(0xA2C4_0003);
    for _ in 0..2_000 {
        let mut candidate = encoded.to_vec();
        mutate(&mut candidate, &mut prng);
        let _ = exercise(&candidate);
    }
}

#[test]
fn the_encoder_refuses_to_produce_an_archive_it_would_reject() {
    // Symétrie encodeur/décodeur : produire une archive que notre propre décodeur
    // refuse serait un défaut qui ne se révélerait qu'à la réouverture du coffre.
    let encoded = archive::encode(&rich_archive()).expect("encodage");

    // Les bornes du modèle doivent être respectées par l'encodage.
    let mut too_many_fields = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
    for index in 0..=MAX_FIELDS_PER_ENTRY {
        too_many_fields
            .fields
            .push(Field::new(format!("c{index}"), FieldKind::Text, "v", 0).expect("champ"));
    }
    let mut archive = Archive::new(0);
    archive.entries.push(too_many_fields);
    assert!(
        archive::encode(&archive).is_err(),
        "l'encodage doit refuser un dépassement de borne"
    );

    let mut too_many_tags = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
    for _ in 0..=MAX_TAGS_PER_ENTRY {
        too_many_tags.tags.push(TagId::generate().expect("aléa"));
    }
    let mut archive = Archive::new(0);
    archive.tags = too_many_tags
        .tags
        .iter()
        .map(|id| Tag {
            id: *id,
            name: "t".to_string(),
        })
        .collect();
    archive.entries.push(too_many_tags);
    assert!(archive::encode(&archive).is_err());

    let mut too_much_history = Entry::new(EntryKind::Login, "x", 0).expect("entrée");
    for _ in 0..=MAX_HISTORY_PER_ENTRY {
        let mut snapshot = Entry::new(EntryKind::Login, "s", 0).expect("entrée");
        snapshot.id = too_much_history.id;
        too_much_history.history.push(Revision { at: 0, snapshot });
    }
    let mut archive = Archive::new(0);
    archive.entries.push(too_much_history);
    assert!(archive::encode(&archive).is_err());

    let _ = encoded;
}
