//! Unicode normalization: NFKC + zero-width strip + BiDi strip + homoglyph resolve.

use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;
use crate::finding::{Finding, FindingKind, Severity, UnicodeAnomaly};

const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
];

const BIDI: &[char] = &[
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Minimal homoglyph map: Cyrillic / Greek letters that visually mimic Latin.
/// Not exhaustive; covers the common attack vectors.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic → Latin
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M',
        'Н' => 'H', 'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T',
        'Х' => 'X', 'І' => 'I', 'Ј' => 'J',
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
        'х' => 'x', 'у' => 'y', 'і' => 'i', 'ј' => 'j',
        // Greek → Latin
        'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H',
        'Ι' => 'I', 'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O',
        'Ρ' => 'P', 'Τ' => 'T', 'Υ' => 'Y', 'Χ' => 'X',
        'ο' => 'o',
        _ => return None,
    })
}

pub(crate) fn unicode_normalize(input: &str) -> (Cow<'_, str>, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut out = String::with_capacity(input.len());
    let mut any_zero_width = false;
    let mut any_bidi = false;
    let mut any_homoglyph = false;

    for c in input.chars() {
        if ZERO_WIDTH.contains(&c) { any_zero_width = true; continue; }
        if BIDI.contains(&c)       { any_bidi = true;       continue; }
        if let Some(latin) = homoglyph(c) {
            any_homoglyph = true;
            out.push(latin);
            continue;
        }
        out.push(c);
    }

    let nfkc: String = out.nfkc().collect();
    let any_nfkc_change = nfkc != out;

    if any_zero_width {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::ZeroWidth },
            severity: Severity::Low,
            span: None,
            sanitized: true,
            detail: "zero-width characters stripped".into(),
        });
    }
    if any_bidi {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::BiDi },
            severity: Severity::Medium,
            span: None,
            sanitized: true,
            detail: "BiDi override characters stripped".into(),
        });
    }
    if any_homoglyph {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::Homoglyph },
            severity: Severity::Medium,
            span: None,
            sanitized: true,
            detail: "Cyrillic/Greek homoglyphs resolved to Latin".into(),
        });
    }
    if any_nfkc_change {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::NonNfkc },
            severity: Severity::Low,
            span: None,
            sanitized: true,
            detail: "NFKC normalization applied".into(),
        });
    }

    if findings.is_empty() {
        (Cow::Borrowed(input), findings)
    } else {
        (Cow::Owned(nfkc), findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_ascii_unchanged() {
        let (out, findings) = unicode_normalize("Hello world");
        assert_eq!(out, "Hello world");
        assert!(findings.is_empty());
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn legit_polish_unchanged() {
        let (out, findings) = unicode_normalize("łatwa próba");
        assert_eq!(out, "łatwa próba");
        assert!(findings.is_empty());
    }

    #[test]
    fn legit_cjk_unchanged() {
        let (out, findings) = unicode_normalize("中文测试");
        assert_eq!(out, "中文测试");
        assert!(findings.is_empty());
    }

    #[test]
    fn emoji_unchanged() {
        let (out, findings) = unicode_normalize("rocket 🚀 ship");
        assert_eq!(out, "rocket 🚀 ship");
        assert!(findings.is_empty());
    }

    #[test]
    fn zero_width_stripped() {
        let (out, findings) = unicode_normalize("Ig\u{200B}nore previous");
        assert_eq!(out, "Ignore previous");
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].kind,
            FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::ZeroWidth }));
    }

    #[test]
    fn bom_stripped() {
        let (out, findings) = unicode_normalize("\u{FEFF}hello");
        assert_eq!(out, "hello");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn bidi_override_stripped() {
        let (out, findings) = unicode_normalize("safe\u{202E}txet desrever");
        assert_eq!(out, "safetxet desrever");
        assert!(findings.iter().any(|f| matches!(f.kind,
            FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::BiDi })));
    }

    #[test]
    fn cyrillic_homoglyph_resolved() {
        let (out, findings) = unicode_normalize("Іgnore previous");
        assert_eq!(out, "Ignore previous");
        assert!(findings.iter().any(|f| matches!(f.kind,
            FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::Homoglyph })));
    }

    #[test]
    fn multiple_anomalies_produce_multiple_findings() {
        let (out, findings) = unicode_normalize("\u{FEFF}Іg\u{200B}nore");
        assert_eq!(out, "Ignore");
        assert!(findings.len() >= 2);
    }
}
