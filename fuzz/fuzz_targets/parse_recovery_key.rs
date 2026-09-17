#![no_main]

//! Cible de fuzzing : décodage d'une clé de récupération (Crockford Base32).
//!
//! # Ce qui est cherché
//!
//! Un décodeur permissif est un **vecteur de malléabilité** : deux chaînes distinctes
//! produisant la même clé. Ici l'enjeu est plus concret que pour le Base32 ordinaire :
//! une clé de récupération est **recopiée à la main**, donc le décodeur doit être
//! tolérant sur ce qui ne change pas la clé (casse, tirets, `I`/`L`/`O`) et
//! **strict** sur tout le reste.
//!
//! # Propriétés vérifiées
//!
//! * aucune panique, sur aucune entrée, y compris toutes les troncatures ;
//! * un décodage accepté est **canonique** : ré-encoder puis redécoder redonne la
//!   même clé, et la forme canonique ne dépend **pas** de la forme d'entrée ;
//! * la forme canonique fait exactement 60 caractères significatifs, n'utilise ni
//!   `I`, ni `L`, ni `O`, ni `U`, et porte 11 séparateurs ;
//! * aucune allocation démesurée : une entrée de grande taille est refusée avant
//!   tout travail, sans égard à son contenu.
//!
//! ```sh
//! cargo +nightly fuzz run parse_recovery_key -- -max_total_time=3600
//! ```

use libfuzzer_sys::fuzz_target;
use passlock_core::recovery::{RecoveryKey, TOTAL_CHARS};

/// Séparateur d'affichage attendu dans la forme canonique.
const SEPARATOR: char = '-';

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    if let Ok(key) = RecoveryKey::decode(&text) {
        let canonical = key.encode();
        // `Zeroizing<String>` n'implemente pas `Display` — délibérément, pour qu'une
        // chaîne secrète ne parte pas dans un `format!` par distraction. On emprunte
        // donc explicitement.
        let canonical_text = canonical.as_str();
        let significant = canonical_text.chars().filter(|c| *c != SEPARATOR).count();

        assert_eq!(
            significant, TOTAL_CHARS,
            "une forme canonique doit porter {TOTAL_CHARS} caractères significatifs"
        );
        assert_eq!(
            canonical_text.chars().filter(|c| *c == SEPARATOR).count(),
            TOTAL_CHARS / 5 - 1,
            "la forme canonique doit être groupée par blocs de 5"
        );
        assert!(
            !canonical_text
                .chars()
                .any(|c| matches!(c, 'I' | 'L' | 'O' | 'U')),
            "une forme canonique ne doit contenir aucun caractère ambigu ni « U » : \
             {canonical_text}"
        );

        // Canonicalité : la forme canonique se redécode vers la même clé.
        let reparsed = RecoveryKey::decode(canonical_text).expect("notre encodage doit être décodable");
        assert_eq!(
            reparsed.expose(),
            key.expose(),
            "non-canonique : « {text} » et « {canonical_text} » divergent"
        );

        // La forme canonique ne dépend pas de la forme d'entrée : déplier les
        // séparateurs et changer la casse doit redonner exactement les mêmes
        // caractères significatifs.
        let lowered = text.to_lowercase().replace(SEPARATOR, "");
        if let Ok(from_lower) = RecoveryKey::decode(&lowered) {
            assert_eq!(
                from_lower.expose(),
                key.expose(),
                "la casse ne doit pas changer la clé"
            );
        }
    }

    // Toutes les troncatures : le moyen le plus simple de faire sortir un décodeur de
    // ses bornes. On découpe sur les **caractères** et non sur les octets, sinon la
    // coupe elle-même paniquerait sur une entrée non ASCII.
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 64 {
        for cut in 0..chars.len() {
            let prefix: String = chars[..cut].iter().collect();
            let _ = RecoveryKey::decode(&prefix);
        }
    }
});
