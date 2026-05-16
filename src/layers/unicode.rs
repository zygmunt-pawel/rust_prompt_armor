//! Unicode normalization: NFKC + zero-width strip + BiDi strip + homoglyph resolve.

use crate::config::Policy;
use crate::finding::{Finding, FindingKind, Severity, UnicodeAnomaly};
use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;

const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
];

const BIDI: &[char] = &[
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}',
];

/// Minimal homoglyph map: Cyrillic / Greek letters that visually mimic Latin.
/// Not exhaustive; covers the common attack vectors.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic → Latin
        'А' => 'A',
        'В' => 'B',
        'Е' => 'E',
        'К' => 'K',
        'М' => 'M',
        'Н' => 'H',
        'О' => 'O',
        'Р' => 'P',
        'С' => 'C',
        'Т' => 'T',
        'Х' => 'X',
        'І' => 'I',
        'Ј' => 'J',
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'і' => 'i',
        'ј' => 'j',
        // Greek → Latin
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        'ο' => 'o',
        _ => return None,
    })
}

pub(crate) fn unicode_normalize(input: &str, policy: Policy) -> (Cow<'_, str>, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut out = String::with_capacity(input.len());
    let mut any_zero_width = false;
    let mut any_bidi = false;
    let mut any_homoglyph = false;

    for c in input.chars() {
        if ZERO_WIDTH.contains(&c) {
            any_zero_width = true;
            continue;
        }
        if BIDI.contains(&c) {
            any_bidi = true;
            continue;
        }
        if let Some(latin) = homoglyph(c) {
            any_homoglyph = true;
            out.push(latin);
            continue;
        }
        out.push(c);
    }

    let nfkc: String = out.nfkc().collect();
    let any_nfkc_change = nfkc != out;

    // `mutate` controls whether the cleaned string replaces the original. In
    // `WarnOnly` (default) we only report findings; the caller still sees the
    // raw input. In `Sanitize` or `Strict` we apply the cleanup.
    let mutate = matches!(policy, Policy::Sanitize | Policy::Strict);

    if any_zero_width {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::ZeroWidth,
            },
            severity: Severity::Low,
            span: None,
            sanitized: mutate,
            detail: if mutate {
                "zero-width characters stripped".into()
            } else {
                "zero-width characters detected".into()
            },
        });
    }
    if any_bidi {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::BiDi,
            },
            severity: Severity::Medium,
            span: None,
            sanitized: mutate,
            detail: if mutate {
                "BiDi override characters stripped".into()
            } else {
                "BiDi override characters detected".into()
            },
        });
    }
    if any_homoglyph {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::Homoglyph,
            },
            severity: Severity::Medium,
            span: None,
            sanitized: mutate,
            detail: if mutate {
                "Cyrillic/Greek homoglyphs resolved to Latin".into()
            } else {
                "Cyrillic/Greek homoglyphs detected".into()
            },
        });
    }
    if any_nfkc_change {
        findings.push(Finding {
            kind: FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::NonNfkc,
            },
            severity: Severity::Low,
            span: None,
            sanitized: mutate,
            detail: if mutate {
                "NFKC normalization applied".into()
            } else {
                "non-NFKC sequence detected".into()
            },
        });
    }

    if findings.is_empty() || !mutate {
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
        let (out, findings) = unicode_normalize("Hello world", Policy::Sanitize);
        assert_eq!(out, "Hello world");
        assert!(findings.is_empty());
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn legit_polish_unchanged() {
        let (out, findings) = unicode_normalize("łatwa próba", Policy::Sanitize);
        assert_eq!(out, "łatwa próba");
        assert!(findings.is_empty());
    }

    #[test]
    fn legit_cjk_unchanged() {
        let (out, findings) = unicode_normalize("中文测试", Policy::Sanitize);
        assert_eq!(out, "中文测试");
        assert!(findings.is_empty());
    }

    #[test]
    fn emoji_unchanged() {
        let (out, findings) = unicode_normalize("rocket 🚀 ship", Policy::Sanitize);
        assert_eq!(out, "rocket 🚀 ship");
        assert!(findings.is_empty());
    }

    #[test]
    fn zero_width_stripped_under_sanitize() {
        let (out, findings) = unicode_normalize("Ig\u{200B}nore previous", Policy::Sanitize);
        assert_eq!(out, "Ignore previous");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].sanitized);
        assert!(matches!(
            findings[0].kind,
            FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::ZeroWidth
            }
        ));
    }

    #[test]
    fn zero_width_detected_but_not_stripped_under_warnonly() {
        let input = "Ig\u{200B}nore previous";
        let (out, findings) = unicode_normalize(input, Policy::WarnOnly);
        assert_eq!(out, input); // not mutated
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].sanitized);
        assert!(matches!(
            findings[0].kind,
            FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::ZeroWidth
            }
        ));
    }

    #[test]
    fn bom_stripped_under_sanitize() {
        let (out, findings) = unicode_normalize("\u{FEFF}hello", Policy::Sanitize);
        assert_eq!(out, "hello");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].sanitized);
    }

    #[test]
    fn bom_detected_but_not_stripped_under_warnonly() {
        let input = "\u{FEFF}hello";
        let (out, findings) = unicode_normalize(input, Policy::WarnOnly);
        assert_eq!(out, input);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].sanitized);
    }

    #[test]
    fn bidi_override_stripped_under_sanitize() {
        let (out, findings) = unicode_normalize("safe\u{202E}txet desrever", Policy::Sanitize);
        assert_eq!(out, "safetxet desrever");
        assert!(findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::BiDi
            }
        )));
    }

    #[test]
    fn bidi_override_detected_warnonly() {
        let input = "safe\u{202E}txet desrever";
        let (out, findings) = unicode_normalize(input, Policy::WarnOnly);
        assert_eq!(out, input);
        let f = findings
            .iter()
            .find(|f| {
                matches!(
                    f.kind,
                    FindingKind::UnicodeAnomaly {
                        kind: UnicodeAnomaly::BiDi
                    }
                )
            })
            .expect("BiDi finding expected");
        assert!(!f.sanitized);
    }

    #[test]
    fn cyrillic_homoglyph_resolved_under_sanitize() {
        let (out, findings) = unicode_normalize("Іgnore previous", Policy::Sanitize);
        assert_eq!(out, "Ignore previous");
        assert!(findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::UnicodeAnomaly {
                kind: UnicodeAnomaly::Homoglyph
            }
        )));
    }

    #[test]
    fn cyrillic_homoglyph_detected_warnonly() {
        let input = "Іgnore previous";
        let (out, findings) = unicode_normalize(input, Policy::WarnOnly);
        assert_eq!(out, input);
        let f = findings
            .iter()
            .find(|f| {
                matches!(
                    f.kind,
                    FindingKind::UnicodeAnomaly {
                        kind: UnicodeAnomaly::Homoglyph
                    }
                )
            })
            .expect("Homoglyph finding expected");
        assert!(!f.sanitized);
    }

    #[test]
    fn multiple_anomalies_produce_multiple_findings_under_sanitize() {
        let (out, findings) = unicode_normalize("\u{FEFF}Іg\u{200B}nore", Policy::Sanitize);
        assert_eq!(out, "Ignore");
        assert!(findings.len() >= 2);
    }

    #[test]
    fn multiple_anomalies_warnonly_keeps_input_intact() {
        let input = "\u{FEFF}Іg\u{200B}nore";
        let (out, findings) = unicode_normalize(input, Policy::WarnOnly);
        assert_eq!(out, input);
        assert!(findings.len() >= 2);
        assert!(findings.iter().all(|f| !f.sanitized));
    }

    #[test]
    fn strict_policy_still_mutates() {
        // Strict triggers Err in the decider, but the layer itself should
        // produce a normalized string just like Sanitize would.
        let (out, findings) = unicode_normalize("Ig\u{200B}nore", Policy::Strict);
        assert_eq!(out, "Ignore");
        assert!(findings[0].sanitized);
    }
}
