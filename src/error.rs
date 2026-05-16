//! `ArmorError` — the single error type returned from the armor pipeline.

use crate::finding::Finding;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ArmorError {
    #[error("input unsalvageable: {} findings, signal lost {:.1}%", findings.len(), signal_lost_pct)]
    Unsalvageable {
        findings: Vec<Finding>,
        signal_lost_pct: f32,
    },

    #[error("user input empty")]
    EmptyInput,

    #[error("input too large: {actual} bytes > limit {limit} bytes (DoS guard)")]
    InputTooLarge { actual: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingKind, Severity};

    #[test]
    fn unsalvageable_display_includes_count_and_pct() {
        let err = ArmorError::Unsalvageable {
            findings: vec![Finding {
                kind: FindingKind::UnicodeAnomaly {
                    kind: crate::finding::UnicodeAnomaly::ZeroWidth,
                },
                severity: Severity::Low,
                span: None,
                sanitized: true,
                detail: "test".into(),
            }],
            signal_lost_pct: 73.5,
        };
        let s = format!("{}", err);
        assert!(s.contains("1 findings"), "got: {s}");
        assert!(s.contains("73.5%"), "got: {s}");
    }

    #[test]
    fn empty_input_display() {
        assert_eq!(format!("{}", ArmorError::EmptyInput), "user input empty");
    }

    #[test]
    fn input_too_large_display() {
        let err = ArmorError::InputTooLarge {
            actual: 2_000_000,
            limit: 1_048_576,
        };
        let s = format!("{}", err);
        assert!(s.contains("2000000"), "got: {s}");
        assert!(s.contains("1048576"), "got: {s}");
    }

    #[test]
    fn error_is_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone>() {}
        assert_traits::<ArmorError>();
    }
}
