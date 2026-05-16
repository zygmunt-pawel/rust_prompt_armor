//! Findings emitted by each defense layer.

use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Byte range in the ORIGINAL user input (before any sanitization).
    /// `None` when the finding spans the whole input or has no meaningful span.
    pub span: Option<Range<usize>>,
    /// `true` if the layer mutated the text in response to this finding.
    pub sanitized: bool,
    /// Human-readable detail (e.g. which pattern matched, which fence marker).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    UnicodeAnomaly {
        kind: UnicodeAnomaly,
    },
    FenceMarker {
        marker: &'static str,
    },
    DangerousPattern {
        matched: String,
        distance: u8,
    },
    EncodedPayload {
        encoding: Encoding,
        decoded_hit: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeAnomaly {
    ZeroWidth,
    BiDi,
    Homoglyph,
    NonNfkc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Base64,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn finding_equality_by_value() {
        let a = Finding {
            kind: FindingKind::FenceMarker {
                marker: "<|im_end|>",
            },
            severity: Severity::High,
            span: Some(5..15),
            sanitized: true,
            detail: "ChatML end marker".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn finding_kinds_distinct() {
        let unicode = FindingKind::UnicodeAnomaly {
            kind: UnicodeAnomaly::ZeroWidth,
        };
        let fence = FindingKind::FenceMarker {
            marker: "<|im_end|>",
        };
        assert_ne!(unicode, fence);
    }

    #[test]
    fn types_are_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone>() {}
        assert_traits::<Finding>();
        assert_traits::<FindingKind>();
        assert_traits::<UnicodeAnomaly>();
        assert_traits::<Encoding>();
        assert_traits::<Severity>();
    }
}
