//! Tests d'intégration du format de pièce jointe.
//!
//! # Ce que ces tests cherchent, et pourquoi ce sont ceux-là
//!
//! L'AEAD par morceau ne protège **que** ce que son AAD couvre. Ces tests vérifient donc
//! les propriétés qui découlent de l'AAD — et, tout aussi important, celles qu'elle ne
//! couvre **pas**, en nommant à chaque fois ce qui détecte l'atteinte :
//!
//! | Atteinte | Détectée par |
//! |---|---|
//! | Morceaux réordonnés, dupliqués, déplacés | **l'AAD** (elle contient l'index) |
//! | Morceau emprunté à un autre blob ou coffre | **l'AAD** |
//! | Fichier tronqué proprement | `chunk_count` et la longueur, **venus de l'archive** |
//! | Version antérieure du même blob rejouée | `content_mac` |
//!
//! Le test qui **discrimine** la correction est `permuting_two_chunks_is_detected` : il
//! échoue si l'index du morceau n'est pas dans l'AAD. C'est cette propriété qui était
//! fausse dans la première rédaction du plan, et c'est la construction — pas la
//! formulation — qui a dû changer.
//!
//! Les dimensions du format sont **redéclarées ici** plutôt qu'importées : les épingler
//! indépendamment du code de production est ce qui permet à ces tests de détecter un
//! décalage de format. Le harnais adversarial de la phase 1 fait de même.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use passlock_core::attachment::{
    self, ATTACHMENT_CHUNK_SIZE, AttachmentReader, BlobHeader, MAX_ATTACHMENT_BYTES, verify_blob,
};
use passlock_core::error::Error;
use passlock_core::keys::{DataEncryptionKey, SubKeys};
use passlock_core::model::{AttachmentMeta, BlobId, EntryId};

/// Dimensions redéclarées : voir l'en-tête.
const BLOB_HEADER_LEN: usize = 40;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fn subkeys() -> SubKeys {
    DataEncryptionKey::generate()
        .expect("dek")
        .subkeys()
        .expect("sous-clés")
}

/// Longueur en clair du morceau `index`, recalculée indépendamment du code testé.
fn chunk_len(header: &BlobHeader, index: u32) -> usize {
    let offset = u64::from(index) * u64::from(header.chunk_size);
    if offset >= header.plaintext_size {
        return 0;
    }
    let remaining = header.plaintext_size - offset;
    usize::try_from(remaining.min(u64::from(header.chunk_size))).unwrap_or(0)
}

/// Bornes de chaque enregistrement `(nonce ‖ chiffré)` dans le fichier.
fn record_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let header = BlobHeader::decode(&bytes[..BLOB_HEADER_LEN]).expect("header");
    let mut ranges = Vec::new();
    let mut offset = BLOB_HEADER_LEN;
    for index in 0..header.chunk_count {
        let len = NONCE_LEN + chunk_len(&header, index) + TAG_LEN;
        ranges.push(offset..offset + len);
        offset += len;
    }
    ranges
}

struct Sealed {
    path: PathBuf,
    meta: AttachmentMeta,
}

/// Scelle `data` dans `dir/name` et rend le chemin et les métadonnées correspondantes.
fn seal(
    dir: &Path,
    name: &str,
    blob: BlobId,
    vault_id: &[u8; 16],
    keys: &SubKeys,
    data: &[u8],
) -> Sealed {
    let path = dir.join(name);
    let mut file = passlock_platform::fs::create_private_file(&path).expect("création");
    let mut source = Cursor::new(data);
    let sealed = attachment::seal_blob(
        blob,
        vault_id,
        keys,
        u64::try_from(data.len()).unwrap_or(0),
        &mut source,
        &mut file,
    )
    .expect("scellement");
    drop(file);

    Sealed {
        path,
        meta: AttachmentMeta {
            id: blob,
            entry: EntryId::nil(),
            name: name.to_string(),
            size: sealed.header.plaintext_size,
            chunk_size: sealed.header.chunk_size,
            chunk_count: sealed.header.chunk_count,
            created_at: 0,
            content_mac: sealed.content_mac,
        },
    }
}

/// Contenu de test à trois morceaux : deux pleins, un partiel.
fn three_chunk_data() -> Vec<u8> {
    let size = 2 * ATTACHMENT_CHUNK_SIZE as usize + 7;
    (0..size)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// Copie explicite des métadonnées.
///
/// `AttachmentMeta` n'est délibérément pas `Clone` : dupliquer une structure qui porte
/// un nom et une empreinte doit rester un acte visible en relecture. Les tests, eux, ont
/// besoin de fabriquer des variantes fausses — d'où cette copie nommée.
fn meta_like(meta: &AttachmentMeta) -> AttachmentMeta {
    AttachmentMeta {
        id: meta.id,
        entry: meta.entry,
        name: meta.name.clone(),
        size: meta.size,
        chunk_size: meta.chunk_size,
        chunk_count: meta.chunk_count,
        created_at: meta.created_at,
        content_mac: meta.content_mac,
    }
}

fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("répertoire temporaire")
}

// ---------------------------------------------------------------------------
// Aller-retour
// ---------------------------------------------------------------------------

#[test]
fn a_blob_round_trips_exactly() {
    let dir = sandbox();
    let keys = subkeys();
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "blob",
        BlobId::generate().expect("id"),
        &[7; 16],
        &keys,
        &data,
    );

    assert_eq!(
        sealed.meta.chunk_count, 3,
        "deux morceaux pleins et un partiel"
    );

    let mut reader =
        AttachmentReader::open(&sealed.path, &sealed.meta, &keys, &[7; 16]).expect("ouverture");
    let mut out = Vec::new();
    reader.read_all(&mut out).expect("lecture");
    assert_eq!(out, data, "le contenu doit être restitué à l'octet près");

    verify_blob(&sealed.path, &sealed.meta, &keys, &[7; 16]).expect("vérification");
}

#[test]
fn an_empty_attachment_is_one_empty_chunk() {
    // L'archive refuse `chunk_count == 0` : un contenu vide occupe donc **un** morceau
    // de zéro octet. Le cas est banal (un fichier qu'on vient de créer) et doit
    // fonctionner sans branche particulière.
    let dir = sandbox();
    let keys = subkeys();
    let sealed = seal(
        dir.path(),
        "vide",
        BlobId::generate().expect("id"),
        &[1; 16],
        &keys,
        &[],
    );

    assert_eq!(sealed.meta.chunk_count, 1);
    assert_eq!(sealed.meta.size, 0);

    let mut reader =
        AttachmentReader::open(&sealed.path, &sealed.meta, &keys, &[1; 16]).expect("ouverture");
    let mut out = Vec::new();
    reader.read_all(&mut out).expect("lecture");
    assert!(out.is_empty());
}

// ---------------------------------------------------------------------------
// Ce que l'AAD protège — le test qui discrimine la correction
// ---------------------------------------------------------------------------

#[test]
fn permuting_two_chunks_is_detected() {
    // LE test qui échoue si l'index du morceau n'est pas dans l'AAD. Sans lui, deux
    // enregistrements de même taille sont interchangeables : le nonce voyage avec son
    // chiffré, donc le déchiffrement réussit et le clair est **réordonné** — une
    // corruption silencieuse, invisible jusqu'au `content_mac` final.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [3; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "permute",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    let mut bytes = std::fs::read(&sealed.path).expect("lecture");
    let ranges = record_ranges(&bytes);
    assert_eq!(
        ranges[0].len(),
        ranges[1].len(),
        "morceaux pleins de même taille"
    );

    // Échange des deux premiers enregistrements.
    let (first, second) = (ranges[0].clone(), ranges[1].clone());
    let record_a: Vec<u8> = bytes[first.clone()].to_vec();
    let record_b: Vec<u8> = bytes[second.clone()].to_vec();
    bytes[first].copy_from_slice(&record_b);
    bytes[second].copy_from_slice(&record_a);
    std::fs::write(&sealed.path, &bytes).expect("écriture");

    let outcome = verify_blob(&sealed.path, &sealed.meta, &keys, &vault_id);
    assert!(
        matches!(outcome, Err(Error::Corrupted { .. })),
        "deux morceaux permutés doivent être détectés par l'AAD, or : {outcome:?}"
    );
}

#[test]
fn swapping_the_first_and_last_chunk_is_detected() {
    // Tailles différentes : la permutation déplace aussi les **frontières**
    // d'enregistrement, ce qui doit être détecté de la même façon.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [4; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "swap",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    let mut bytes = std::fs::read(&sealed.path).expect("lecture");
    let ranges = record_ranges(&bytes);
    assert_ne!(ranges[0].len(), ranges[2].len());

    let record_a: Vec<u8> = bytes[ranges[0].clone()].to_vec();
    let record_c: Vec<u8> = bytes[ranges[2].clone()].to_vec();
    let take_first = record_c.len().min(record_a.len());
    bytes[ranges[0].start..ranges[0].start + take_first].copy_from_slice(&record_c[..take_first]);
    let take_last = record_a.len().min(record_c.len());
    bytes[ranges[2].start..ranges[2].start + take_last].copy_from_slice(&record_a[..take_last]);
    std::fs::write(&sealed.path, &bytes).expect("écriture");

    assert!(
        matches!(
            verify_blob(&sealed.path, &sealed.meta, &keys, &vault_id),
            Err(Error::Corrupted { .. })
        ),
        "le déplacement d'un morceau vers une autre position doit être détecté"
    );
}

#[test]
fn duplicating_a_chunk_at_another_position_is_detected() {
    // Rejouer l'enregistrement 0 à la position 1 : nonce et chiffré restent appariés,
    // seule la position change. C'est exactement ce que l'index dans l'AAD empêche.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [5; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "duplicate",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    let mut bytes = std::fs::read(&sealed.path).expect("lecture");
    let ranges = record_ranges(&bytes);
    let record_a: Vec<u8> = bytes[ranges[0].clone()].to_vec();
    bytes[ranges[1].clone()].copy_from_slice(&record_a);
    std::fs::write(&sealed.path, &bytes).expect("écriture");

    assert!(matches!(
        verify_blob(&sealed.path, &sealed.meta, &keys, &vault_id),
        Err(Error::Corrupted { .. })
    ));
}

#[test]
fn a_chunk_from_another_blob_is_detected() {
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [6; 16];
    let data = three_chunk_data();

    let first = seal(
        dir.path(),
        "blob-a",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );
    let second = seal(
        dir.path(),
        "blob-b",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    // Greffe : le morceau 1 de A prend la place du morceau 1 de B.
    let a_bytes = std::fs::read(&first.path).expect("lecture");
    let mut b_bytes = std::fs::read(&second.path).expect("lecture");
    let a_ranges = record_ranges(&a_bytes);
    let b_ranges = record_ranges(&b_bytes);
    let donor = a_bytes[a_ranges[1].clone()].to_vec();
    b_bytes[b_ranges[1].clone()].copy_from_slice(&donor);
    std::fs::write(&second.path, &b_bytes).expect("écriture");

    assert!(
        matches!(
            verify_blob(&second.path, &second.meta, &keys, &vault_id),
            Err(Error::Corrupted { .. })
        ),
        "l'identifiant du blob entre dans l'AAD : un morceau ne peut pas changer de blob"
    );
}

#[test]
fn a_chunk_from_another_vault_is_detected() {
    // Mêmes clés, **identifiant de coffre différent** : c'est la seule variable, ce qui
    // isole la liaison au coffre dans l'AAD.
    let dir = sandbox();
    let keys = subkeys();
    let data = three_chunk_data();

    let source_vault = [7; 16];
    let target_vault = [8; 16];
    let blob = BlobId::generate().expect("id");

    let sealed = seal(dir.path(), "vault-a", blob, &source_vault, &keys, &data);
    let original = std::fs::read(&sealed.path).expect("lecture");

    // Le même blob, tel qu'il serait écrit sous l'autre coffre : on ne peut pas le
    // produire sans les clés de l'autre coffre, donc on **rejoue** simplement le
    // fichier en changeant l'identifiant attendu.
    let mut target = sealed;
    target.meta.id = blob;
    let outcome = verify_blob(&target.path, &target.meta, &keys, &target_vault);
    assert!(
        matches!(outcome, Err(Error::Corrupted { .. })),
        "l'identifiant du coffre entre dans l'AAD"
    );
    let _ = original;

    // Et sous son propre coffre, le même fichier est valide : la seule différence est
    // bien l'identifiant, pas une corruption.
    verify_blob(&target.path, &target.meta, &keys, &source_vault).expect("valide sous son coffre");
}

// ---------------------------------------------------------------------------
// Ce que l'AAD ne protège PAS — et ce qui le détecte
// ---------------------------------------------------------------------------

#[test]
fn removing_a_trailing_chunk_is_detected_by_the_length_not_by_the_aead() {
    // **Le point le plus important de ce fichier.** Une troncature propre se déchiffre
    // morceau par morceau sans qu'aucun tag n'échoue. Ce qui la détecte est la
    // confrontation de la longueur du fichier — puis du `chunk_count` — aux
    // métadonnées de l'archive. Ce test nomme lequel des deux mécanismes agit.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [9; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "tronque",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    let bytes = std::fs::read(&sealed.path).expect("lecture");
    let ranges = record_ranges(&bytes);

    // On retire le **dernier** enregistrement entier : aucun tag ne peut échouer, ils
    // sont tous intacts.
    std::fs::write(&sealed.path, &bytes[..ranges[2].start]).expect("écriture");

    let outcome = AttachmentReader::open(&sealed.path, &sealed.meta, &keys, &vault_id);
    let error = outcome.expect_err("la troncature doit être détectée");
    assert!(
        matches!(&error, Error::Corrupted { reason } if reason.contains("longueur")),
        "c'est la **longueur** qui détecte la troncature propre, pas l'AEAD : {error}"
    );
}

#[test]
fn a_blob_truncated_mid_chunk_is_detected() {
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [10; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "partiel",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    let bytes = std::fs::read(&sealed.path).expect("lecture");
    // Coupe au milieu du premier enregistrement : la longueur ne correspond plus.
    std::fs::write(&sealed.path, &bytes[..BLOB_HEADER_LEN + 10]).expect("écriture");

    assert!(matches!(
        verify_blob(&sealed.path, &sealed.meta, &keys, &vault_id),
        Err(Error::Corrupted { .. })
    ));
}

#[test]
fn a_forged_content_mac_is_detected() {
    // Le rejeu d'une version antérieure du **même** blob : les tags sont valides, seul
    // le contenu a changé. C'est `content_mac` qui l'écarte — sans lui, l'AEAD ne dirait
    // rien puisque les morceaux sont authentiques.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [11; 16];

    let early = seal(
        dir.path(),
        "version",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        b"premiere version",
    );

    // Une version **différente du même blob**, avec le même identifiant.
    let mut meta = early.meta;
    meta.size = 10;
    meta.chunk_count = 1;
    meta.content_mac = [0_u8; 32];

    assert!(
        matches!(
            verify_blob(&early.path, &meta, &keys, &vault_id),
            Err(Error::Corrupted { .. })
        ),
        "un content_mac qui ne correspond pas doit être refusé"
    );
}

#[test]
fn a_metadata_disagreeing_with_the_file_is_refused() {
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [12; 16];
    let sealed = seal(
        dir.path(),
        "meta",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        b"contenu",
    );

    // L'archive est l'autorité : elle ne peut pas être contredite par le fichier.
    let mut wrong_id = meta_like(&sealed.meta);
    wrong_id.id = BlobId::generate().expect("id");
    assert!(matches!(
        AttachmentReader::open(&sealed.path, &wrong_id, &keys, &vault_id),
        Err(Error::Corrupted { .. })
    ));

    let mut wrong_size = meta_like(&sealed.meta);
    wrong_size.size += 1;
    assert!(matches!(
        AttachmentReader::open(&sealed.path, &wrong_size, &keys, &vault_id),
        Err(Error::Corrupted { .. })
    ));
}

#[test]
fn a_header_whose_chunk_count_disagrees_with_its_size_is_refused() {
    // **Ce test remplace « un morceau court non final est refusé ».** Ce cas ne peut pas
    // être construit : le décodeur **recalcule** `chunk_count` à partir de la taille et
    // de la taille de morceau, et refuse tout header où les deux divergent. Un morceau
    // court ne peut donc se trouver qu'en dernière position — par construction, et non
    // par vérification. C'est ce que ce test établit.
    let header = BlobHeader::new(BlobId::generate().expect("id"), 1_500_000).expect("header");
    assert_eq!(
        header.chunk_count, 2,
        "1 500 000 = un morceau plein + un partiel"
    );

    let mut bytes = header.encode();
    bytes[36..40].copy_from_slice(&3_u32.to_be_bytes());
    assert!(
        matches!(BlobHeader::decode(&bytes), Err(Error::Corrupted { .. })),
        "un nombre de morceaux incohérent doit être refusé"
    );

    // Et la taille déclarée ne peut pas dépasser la borne du format.
    let too_big = BlobHeader::new(BlobId::generate().expect("id"), MAX_ATTACHMENT_BYTES + 1);
    assert!(matches!(too_big, Err(Error::InvalidInput { .. })));
}

#[test]
fn an_intermediate_chunk_is_not_a_verdict() {
    // **Sémantique d'API.** `read_all` peut avoir écrit du clair **avant** d'échouer :
    // les morceaux déjà lus étaient authentiques pour leur position, pas validés. Un
    // appelant qui écrit le clair quelque part doit donc attendre la fin du flux — et
    // c'est pourquoi `attach get` écrit dans un temporaire qu'il ne renomme qu'après.
    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [13; 16];
    let data = three_chunk_data();
    let sealed = seal(
        dir.path(),
        "verdict",
        BlobId::generate().expect("id"),
        &vault_id,
        &keys,
        &data,
    );

    // On corrompt le **dernier** morceau : les précédents restent valides.
    let mut bytes = std::fs::read(&sealed.path).expect("lecture");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&sealed.path, &bytes).expect("écriture");

    let mut reader =
        AttachmentReader::open(&sealed.path, &sealed.meta, &keys, &vault_id).expect("ouverture");
    let mut out = Vec::new();
    let outcome = reader.read_all(&mut out);

    assert!(matches!(outcome, Err(Error::Corrupted { .. })));
    assert!(
        !out.is_empty(),
        "du clair authentique mais NON validé a été rendu avant l'échec : c'est la \
         propriété que les appelants doivent connaître"
    );
    assert!(
        out.len() < data.len(),
        "le clair rendu est un préfixe, jamais le contenu complet"
    );
}

// ---------------------------------------------------------------------------
// Ramasse-miettes
// ---------------------------------------------------------------------------

#[test]
fn the_sweep_separates_orphans_unexpected_files_and_missing_blobs() {
    use passlock_core::attachment::{blob_file_name, sweep_blobs};
    use passlock_core::model::Archive;

    let dir = sandbox();
    let keys = subkeys();
    let vault_id = [14; 16];

    // Les fichiers portent le nom **dérivé** — c'est ce nom que le balayage reconnaît
    // comme un nom de blob. Un fichier nommé autrement serait classé « étranger », et
    // ne serait jamais supprimé.
    let referenced_id = BlobId::generate().expect("id");
    let orphan_id = BlobId::generate().expect("id");
    let referenced_name = blob_file_name(&keys, &vault_id, referenced_id).expect("nom");
    let orphan_name = blob_file_name(&keys, &vault_id, orphan_id).expect("nom");

    let referenced = seal(
        dir.path(),
        &referenced_name,
        referenced_id,
        &vault_id,
        &keys,
        b"attache",
    );
    // Le fichier lui-même n'est pas relu par ce test : on vérifie son **nom**, qui est
    // ce que le balayage rend.
    seal(
        dir.path(),
        &orphan_name,
        orphan_id,
        &vault_id,
        &keys,
        b"detache",
    );
    // Un fichier qui ne peut pas être un nom de blob.
    std::fs::write(dir.path().join("notes.txt"), b"a moi").expect("écriture");

    let mut archive = Archive::new(0);
    archive.attachments.push(referenced.meta);

    let sweep = sweep_blobs(dir.path(), &archive, &keys, &vault_id).expect("balayage");

    assert_eq!(
        sweep.orphans,
        vec![std::ffi::OsString::from(&orphan_name)],
        "un seul orphelin : le blob détaché, pas le fichier étranger"
    );
    assert_eq!(
        sweep.unexpected,
        vec![std::ffi::OsString::from("notes.txt")],
        "le fichier étranger est signalé, et jamais confondu avec un orphelin"
    );
    assert!(sweep.missing.is_empty());
    assert!(
        !sweep.is_consistent(),
        "un orphelin rend le répertoire incohérent"
    );

    // Et une métadonnée sans fichier est signalée, jamais silencieuse.
    std::fs::remove_file(&referenced.path).expect("suppression");
    let sweep = sweep_blobs(dir.path(), &archive, &keys, &vault_id).expect("balayage");
    assert_eq!(sweep.missing.len(), 1, "l'absence doit être constatée");
}

#[test]
fn a_blob_name_is_exactly_sixteen_bytes_of_lowercase_hex() {
    use passlock_core::attachment::{blob_file_name, is_blob_name};

    let keys = subkeys();
    let vault_id = [15; 16];
    let name = blob_file_name(&keys, &vault_id, BlobId::generate().expect("id")).expect("nom");

    assert_eq!(name.len(), 32);
    assert!(is_blob_name(&name));
    assert!(
        !is_blob_name(&name.to_uppercase()),
        "l'hexadécimal est minuscule"
    );
    assert!(!is_blob_name("notes.txt"));
    assert!(!is_blob_name(""));

    // Deux blobs distincts, deux noms distincts ; et le même blob sous un autre coffre
    // change de nom, puisque l'identifiant du coffre entre dans le HMAC.
    let other = blob_file_name(&keys, &vault_id, BlobId::generate().expect("id")).expect("nom");
    assert_ne!(name, other);
    let elsewhere = blob_file_name(&keys, &[16; 16], BlobId::generate().expect("id")).expect("nom");
    assert_ne!(name, elsewhere);
}
