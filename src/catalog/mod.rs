//! Pattern catalog: dangerous-phrase lists per language.
//!
//! All five lists are enabled by default via [`all_default`].
//! Per-language accessors are exposed for introspection (debugging, audit,
//! callers building custom catalogs).
//!
//! **Pre-release gate:** PL/UA/ZH/RU lists are tentative and MUST receive
//! native-speaker review before v0.1.0 release (false-positive risk on legit
//! content). See spec §7.5.

mod en;
mod pl;
mod ua;
mod zh;
mod ru;

use std::sync::OnceLock;

pub fn default_en() -> &'static [&'static str] { en::PATTERNS }
pub fn default_pl() -> &'static [&'static str] { pl::PATTERNS }
pub fn default_ua() -> &'static [&'static str] { ua::PATTERNS }
pub fn default_zh() -> &'static [&'static str] { zh::PATTERNS }
pub fn default_ru() -> &'static [&'static str] { ru::PATTERNS }

/// Concatenated default catalog (EN + PL + UA + ZH + RU).
/// Built lazily on first call and cached for the process lifetime.
pub fn all_default() -> &'static [&'static str] {
    static ALL: OnceLock<Vec<&'static str>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut v = Vec::with_capacity(
            en::PATTERNS.len() + pl::PATTERNS.len() + ua::PATTERNS.len()
                + zh::PATTERNS.len() + ru::PATTERNS.len()
        );
        v.extend_from_slice(en::PATTERNS);
        v.extend_from_slice(pl::PATTERNS);
        v.extend_from_slice(ua::PATTERNS);
        v.extend_from_slice(zh::PATTERNS);
        v.extend_from_slice(ru::PATTERNS);
        v
    }).as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_language_is_nonempty() {
        assert!(!default_en().is_empty());
        assert!(!default_pl().is_empty());
        assert!(!default_ua().is_empty());
        assert!(!default_zh().is_empty());
        assert!(!default_ru().is_empty());
    }

    #[test]
    fn all_default_concatenates() {
        let expected = default_en().len() + default_pl().len() + default_ua().len()
            + default_zh().len() + default_ru().len();
        assert_eq!(all_default().len(), expected);
    }

    #[test]
    fn all_default_is_cached() {
        let p1 = all_default().as_ptr();
        let p2 = all_default().as_ptr();
        assert_eq!(p1, p2, "OnceLock did not cache");
    }

    #[test]
    fn no_duplicate_within_language() {
        for (name, list) in [
            ("en", default_en()), ("pl", default_pl()), ("ua", default_ua()),
            ("zh", default_zh()), ("ru", default_ru()),
        ] {
            let mut sorted: Vec<&&str> = list.iter().collect();
            sorted.sort();
            for w in sorted.windows(2) {
                assert_ne!(w[0], w[1], "duplicate in {name}: {:?}", w[0]);
            }
        }
    }

    #[test]
    fn patterns_are_lowercase() {
        for &p in all_default() {
            let lower = p.to_lowercase();
            assert_eq!(p, lower, "non-lowercase pattern: {p:?}");
        }
    }
}
