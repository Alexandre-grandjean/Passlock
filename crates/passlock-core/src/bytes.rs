//! Lecture bornée de champs binaires.
//!
//! # Pourquoi ce module existe
//!
//! Le conteneur et le header sont décodés depuis des octets **non fiables**, avant
//! toute authentification. Chaque accès y est une occasion d'écrire
//! `offset + longueur`, expression qui **déborde** si `offset` est proche de
//! `usize::MAX` : en mode release, le dépassement est silencieusement ramené modulo
//! la taille du type, ce qui produit une plage d'indices incohérente — et une
//! vérification de borne écrite naïvement peut alors laisser passer un accès hors
//! limites au lieu de le refuser.
//!
//! L'audit adversarial de la phase 1 a relevé que ce risque était **latent** : tous
//! les appels utilisaient des offsets constants ou déjà bornés, donc il n'était pas
//! atteignable. Le corriger maintenant, avant que la phase 2 n'introduise de
//! nouveaux champs de longueur, coûte quelques dizaines de lignes ; le corriger
//! après coup coûterait une relecture complète du format.
//!
//! # Invariant
//!
//! **Toute** lecture de champ du format passe par ce module. Pour chaque accès, il
//! garantit dans cet ordre :
//!
//! 1. `offset + longueur` **ne déborde pas** (`checked_add`) ;
//! 2. la plage obtenue est **entièrement** contenue dans le buffer (`get`) ;
//! 3. aucune allocation n'est effectuée avant que ces deux conditions soient
//!    vérifiées.
//!
//! Aucune fonction de ce module n'alloue : elles retournent toutes une tranche
//! empruntée ou une copie de taille fixe connue à la compilation.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne valide **pas** la sémantique : un `u32` lu correctement peut rester une
//! valeur aberrante. Les bornes de domaine (`m_cost`, `t_cost`, `slot_count`…) sont
//! vérifiées par les modules qui connaissent leur signification.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Retourne la tranche `[offset, offset + len)` en refusant tout débordement.
///
/// C'est la primitive unique sur laquelle reposent toutes les autres fonctions de
/// ce module : toutes les lectures typées y aboutissent, et aucun code du projet
/// ne découpe un buffer non fiable autrement.
///
/// # Erreurs
/// [`Error::MalformedLength`] si l'addition déborde ou si la plage sort du buffer.
pub(crate) fn slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8]> {
    // Étape 1 : l'invariant arithmétique. `checked_add` est la seule protection
    // contre un `offset` hostile proche de `usize::MAX`.
    let end = offset.checked_add(len).ok_or(Error::MalformedLength {
        reason: "dépassement d'entier en calculant la fin d'un champ",
    })?;

    // Étape 2 : l'invariant de borne. `get` retourne `None` au lieu de paniquer,
    // ce qui permet de refuser proprement un buffer tronqué.
    bytes
        .get(offset..end)
        .ok_or(Error::MalformedLength { reason: field })
}

/// Lit un octet à `offset`.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la lecture sort du buffer.
pub(crate) fn u8_at(bytes: &[u8], offset: usize, field: &'static str) -> Result<u8> {
    Ok(slice(bytes, offset, 1, field)?[0])
}

/// Lit un `u16` en gros-boutiste à `offset`.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la lecture sort du buffer.
pub(crate) fn u16_be(bytes: &[u8], offset: usize, field: &'static str) -> Result<u16> {
    let raw = array::<2>(bytes, offset, field)?;
    Ok(u16::from_be_bytes(raw))
}

/// Lit un `u32` en gros-boutiste à `offset`.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la lecture sort du buffer.
pub(crate) fn u32_be(bytes: &[u8], offset: usize, field: &'static str) -> Result<u32> {
    let raw = array::<4>(bytes, offset, field)?;
    Ok(u32::from_be_bytes(raw))
}

/// Lit un `u64` en gros-boutiste à `offset`.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la lecture sort du buffer.
pub(crate) fn u64_be(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64> {
    let raw = array::<8>(bytes, offset, field)?;
    Ok(u64::from_be_bytes(raw))
}

/// Lit un tableau de `N` octets à `offset`.
///
/// La conversion en tableau est infaillible : la longueur a déjà été validée par
/// [`checked_slice`], et elle vaut exactement `N`.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la lecture sort du buffer.
pub(crate) fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; N]> {
    let slice = slice(bytes, offset, N, field)?;
    slice.try_into().map_err(|_| Error::Internal {
        invariant: "longueur de tranche incohérente après vérification de borne",
    })
}

/// Vérifie qu'un buffer fait **exactement** la taille attendue.
///
/// Utilisé pour les structures à taille fixe, où accepter un excédent laisserait
/// passer des octets non interprétés — un vecteur de contrebande.
///
/// # Erreurs
/// [`Error::MalformedLength`] si la longueur diffère.
pub(crate) fn expect_len(bytes: &[u8], expected: usize, field: &'static str) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::MalformedLength { reason: field })
    }
}

/// Vérifie qu'un buffer fait **au moins** la taille attendue.
///
/// Ne remplace pas les lectures bornées : c'est une vérification préalable qui
/// rend les invariants locaux plus lisibles, mais chaque accès reste passé par
/// [`checked_slice`].
///
/// # Erreurs
/// [`Error::MalformedLength`] si le buffer est trop court.
pub(crate) fn expect_min_len(bytes: &[u8], minimum: usize, field: &'static str) -> Result<()> {
    if bytes.len() >= minimum {
        Ok(())
    } else {
        Err(Error::MalformedLength { reason: field })
    }
}

/// Curseur de lecture sur un buffer **non fiable**.
///
/// # Pourquoi un curseur plutôt que des offsets
///
/// Les fonctions de ce module prennent un offset explicite, ce qui convient au
/// header de la phase 1 — une trentaine de champs à positions fixes. L'archive de
/// la phase 2 est une structure **séquentielle** de plusieurs milliers de champs :
/// y propager des offsets à la main serait une source constante d'erreurs, et
/// chaque erreur d'arithmétique serait un défaut de sécurité.
///
/// Le curseur avance seul, et **toutes** ses lectures passent par les primitives
/// bornées ci-dessus. Aucun de ses appelants ne manipule d'offset.
///
/// # Invariant
///
/// [`Reader::count`] est le **seul** moyen d'obtenir un compte destiné à
/// dimensionner une allocation. Il vérifie que ce compte est compatible avec les
/// octets restants **avant** de le retourner (voir sa documentation).
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8> {
        let value = u8_at(self.bytes, self.position, field)?;
        self.position += 1;
        Ok(value)
    }

    pub(crate) fn u16_be(&mut self, field: &'static str) -> Result<u16> {
        let value = u16_be(self.bytes, self.position, field)?;
        self.position += 2;
        Ok(value)
    }

    pub(crate) fn u32_be(&mut self, field: &'static str) -> Result<u32> {
        let value = u32_be(self.bytes, self.position, field)?;
        self.position += 4;
        Ok(value)
    }

    pub(crate) fn u64_be(&mut self, field: &'static str) -> Result<u64> {
        let value = u64_be(self.bytes, self.position, field)?;
        self.position += 8;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N]> {
        let value = array::<N>(self.bytes, self.position, field)?;
        self.position += N;
        Ok(value)
    }

    /// Avance de `len` octets et retourne la tranche correspondante.
    pub(crate) fn slice(&mut self, len: usize, field: &'static str) -> Result<&'a [u8]> {
        let value = slice(self.bytes, self.position, len, field)?;
        self.position += len;
        Ok(value)
    }

    /// Lit un texte préfixé par sa longueur.
    ///
    /// # Erreurs
    /// * la longueur dépasse `maximum` ;
    /// * la tranche sort du buffer ;
    /// * les octets ne sont pas de l'UTF-8 valide.
    ///
    /// L'UTF-8 est **validé**, jamais remplacé silencieusement : une chaîne
    /// substituée donnerait un coffre dont le contenu diffère de celui enregistré,
    /// sans que rien ne le signale.
    pub(crate) fn text(&mut self, maximum: usize, field: &'static str) -> Result<String> {
        let len = usize::try_from(self.u32_be(field)?).map_err(|_| Error::MalformedLength {
            reason: "longueur de texte non représentable",
        })?;
        if len > maximum {
            return Err(Error::MalformedLength {
                reason: "texte au-delà de la longueur maximale admise",
            });
        }
        let raw = self.slice(len, field)?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::MalformedLength {
            reason: "texte non conforme à l'UTF-8",
        })?;
        Ok(text.to_owned())
    }

    /// Lit un compte destiné à dimensionner une allocation.
    ///
    /// # L'invariant central de ce module
    ///
    /// Avant d'être retourné, le compte est confronté aux octets restants :
    ///
    /// ```text
    ///   count × taille_minimale_d_un_enregistrement ≤ octets_restants
    /// ```
    ///
    /// Sans cette vérification, un corps déclarant quatre milliards d'entrées dans
    /// cent octets ferait tenter une réservation de plusieurs dizaines de gigaoctets
    /// **avant** que quiconque ne s'aperçoive que les données n'existent pas.
    ///
    /// `min_record_len` est la taille encodée **minimale** d'un enregistrement de la
    /// section concernée. Elle doit être strictement positive dès qu'un
    /// enregistrement occupe au moins un octet — ce qui est le cas de tous ceux de
    /// ce format.
    ///
    /// # Erreurs
    /// * le compte dépasse `maximum` ;
    /// * la multiplication déborde ;
    /// * les octets restants ne suffisent pas à contenir ce nombre d'enregistrements.
    pub(crate) fn count(
        &mut self,
        maximum: usize,
        min_record_len: usize,
        field: &'static str,
    ) -> Result<usize> {
        let raw = self.u32_be(field)?;
        let count = usize::try_from(raw).map_err(|_| Error::MalformedLength {
            reason: "compte non représentable",
        })?;

        if count > maximum {
            return Err(Error::MalformedLength { reason: field });
        }

        // Étape décisive : le compte doit être *physiquement possible* compte tenu
        // des octets qui restent. C'est ce qui empêche toute allocation massive
        // pilotée par une valeur du fichier.
        let needed = count
            .checked_mul(min_record_len)
            .ok_or(Error::MalformedLength {
                reason: "dépassement d'entier en évaluant la taille d'une section",
            })?;
        if needed > self.remaining() {
            return Err(Error::MalformedLength { reason: field });
        }

        Ok(count)
    }

    /// Réserve une sous-tranche et retourne un curseur dessus.
    ///
    /// Utilisé pour les enregistrements préfixés par leur longueur : le curseur
    /// enfant ne peut pas déborder de la sous-tranche, même si son contenu est
    /// incohérent.
    pub(crate) fn sub_reader(&mut self, len: usize, field: &'static str) -> Result<Reader<'a>> {
        let raw = self.slice(len, field)?;
        Ok(Reader::new(raw))
    }

    /// Lit un tableau de 16 octets, forme des identifiants.
    pub(crate) fn id(&mut self, field: &'static str) -> Result<[u8; 16]> {
        self.array::<16>(field)
    }

    /// Vérifie que le buffer a été entièrement parcouru.
    ///
    /// Un reliquat signale soit une corruption, soit une version de format qui
    /// porte des données que ce décodeur ignore — dans les deux cas, l'accepter
    /// silencieusement serait pire que refuser.
    pub(crate) fn expect_consumed(&self, field: &'static str) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::MalformedLength { reason: field })
        }
    }
}

/// Constructeur d'octets **déterministe**.
///
/// # Déterminisme
///
/// Il n'existe aucune structure associative dans ce qui est écrit : les sections
/// suivent l'ordre d'un `Vec`, les champs suivent leur `ordinal`. Deux archives
/// équivalentes produisent donc des octets identiques, ce qui rend le format
/// testable par simple comparaison — même propriété que le header de la phase 1.
///
/// # Effacement
///
/// Le buffer accumulé contient du contenu déchiffré. Il est donc effacé si le
/// constructeur est abandonné sans [`Writer::finish`], et transféré dans un
/// [`Zeroizing`] lorsqu'il est terminé. Un appelant ne peut donc pas obtenir un
/// `Vec<u8>` nu contenant des secrets par inadvertance.
pub(crate) struct Writer {
    out: Vec<u8>,
    finished: bool,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            finished: false,
        }
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            finished: false,
        }
    }

    /// Longueur courante du buffer.
    ///
    /// N'est utilisé que par les tests, qui confrontent les constantes
    /// `MIN_ENCODED_*` à la taille réellement produite par l'encodeur.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.out.len()
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    pub(crate) fn u16_be(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u32_be(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64_be(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    /// Écrit un texte préfixé par sa longueur.
    ///
    /// # Erreurs
    /// [`Error::MalformedLength`] si le texte dépasse `maximum`. Le refus est
    /// explicite plutôt que silencieux : accepter un texte hors bornes produirait
    /// une archive que notre propre décodeur refuserait.
    pub(crate) fn text(&mut self, value: &str, maximum: usize, field: &'static str) -> Result<()> {
        if value.len() > maximum {
            return Err(Error::MalformedLength { reason: field });
        }
        let len = u32::try_from(value.len()).map_err(|_| Error::MalformedLength {
            reason: "texte trop long pour le format",
        })?;
        self.u32_be(len);
        self.bytes(value.as_bytes());
        Ok(())
    }

    /// Écrit un compte, en refusant de dépasser `maximum`.
    ///
    /// # Erreurs
    /// [`Error::MalformedLength`] si le compte dépasse la borne ou ne tient pas sur
    /// 32 bits.
    pub(crate) fn count(
        &mut self,
        value: usize,
        maximum: usize,
        field: &'static str,
    ) -> Result<()> {
        if value > maximum {
            return Err(Error::MalformedLength { reason: field });
        }
        let raw = u32::try_from(value).map_err(|_| Error::MalformedLength {
            reason: "compte trop grand pour le format",
        })?;
        self.u32_be(raw);
        Ok(())
    }

    pub(crate) fn id(&mut self, value: &[u8; 16]) {
        self.bytes(value);
    }

    /// Termine l'écriture et transfère le buffer.
    pub(crate) fn finish(mut self) -> Zeroizing<Vec<u8>> {
        self.finished = true;
        Zeroizing::new(std::mem::take(&mut self.out))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Un constructeur abandonné en cours de route — sur un `?` par exemple —
        // contient déjà du contenu déchiffré partiel. Il est effacé.
        if !self.finished {
            self.out.as_mut_slice().zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_bounds_succeed() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u8_at(&bytes, 0, "t").expect("lecture"), 0x01);
        assert_eq!(u16_be(&bytes, 0, "t").expect("lecture"), 0x0102);
        assert_eq!(u32_be(&bytes, 0, "t").expect("lecture"), 0x0102_0304);
        assert_eq!(
            u64_be(&bytes, 0, "t").expect("lecture"),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            array::<3>(&bytes, 5, "t").expect("lecture"),
            [0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn every_truncated_read_is_refused() {
        let bytes = [0xAA_u8; 8];
        for len in 0..8 {
            let short = &bytes[..len];
            assert!(
                u8_at(short, len, "t").is_err(),
                "u8 à {len} sur {len} octets"
            );
            assert!(u16_be(short, len, "t").is_err());
            assert!(u32_be(short, len, "t").is_err());
            assert!(u64_be(short, len, "t").is_err());
            assert!(array::<4>(short, len, "t").is_err());
        }
    }

    #[test]
    fn the_last_valid_offset_is_accepted() {
        // Frontière exacte : lire le dernier octet doit réussir, lire après doit
        // échouer. C'est le cas qu'un `offset + len <= bytes.len()` mal écrit
        // laisse passer dans un sens ou dans l'autre.
        let bytes = [0x42_u8; 8];
        assert_eq!(u8_at(&bytes, 7, "t").expect("dernier octet"), 0x42);
        assert!(u8_at(&bytes, 8, "t").is_err());

        assert_eq!(
            array::<8>(&bytes, 0, "t").expect("tout le buffer"),
            [0x42; 8]
        );
        assert!(array::<8>(&bytes, 1, "t").is_err());
    }

    #[test]
    fn an_offset_that_would_overflow_is_refused_not_wrapped() {
        // LE test qui motive ce module. Sans `checked_add`, `usize::MAX + 1`
        // vaudrait `0` en release : la plage `usize::MAX..0` serait vide, `get`
        // retournerait `Some(&[])`, et un appelant qui déstructure ensuite
        // paniquerait sur un index hors limites — ou pire, lirait des données
        // décalées.
        let bytes = [0x11_u8; 16];

        for offset in [usize::MAX, usize::MAX - 1, usize::MAX - 7] {
            let outcome = slice(&bytes, offset, 8, "test");
            assert!(
                matches!(outcome, Err(Error::MalformedLength { .. })),
                "un offset de {offset} a été accepté au lieu d'être refusé"
            );
        }

        assert!(u64_be(&bytes, usize::MAX - 3, "t").is_err());
        assert!(array::<16>(&bytes, usize::MAX - 15, "t").is_err());
    }

    #[test]
    fn an_offset_beyond_the_buffer_is_refused() {
        let bytes = [0_u8; 4];
        assert!(slice(&bytes, 100, 1, "t").is_err());
        assert!(slice(&bytes, 4, 1, "t").is_err());
        assert!(slice(&bytes, 0, 5, "t").is_err());
    }

    #[test]
    fn zero_length_reads_are_valid_boundaries() {
        let bytes = [0_u8; 4];
        assert!(slice(&bytes, 0, 0, "t").is_ok());
        assert!(slice(&bytes, 4, 0, "t").is_ok());
        assert!(slice(&bytes, 5, 0, "t").is_err());
    }

    #[test]
    fn empty_buffer_accepts_nothing_but_zero_length() {
        assert!(slice(&[], 0, 0, "t").is_ok());
        assert!(u8_at(&[], 0, "t").is_err());
        assert!(u64_be(&[], 0, "t").is_err());
    }

    #[test]
    fn exact_length_checks_are_strict() {
        let bytes = [0_u8; 4];
        assert!(expect_len(&bytes, 4, "t").is_ok());
        assert!(expect_len(&bytes, 3, "t").is_err());
        assert!(expect_len(&bytes, 5, "t").is_err());

        assert!(expect_min_len(&bytes, 4, "t").is_ok());
        assert!(expect_min_len(&bytes, 3, "t").is_ok());
        assert!(expect_min_len(&bytes, 5, "t").is_err());
    }
}
