//! Final decision: convert (findings, signal_loss, config) → Ok or Err(Unsalvageable).

use crate::config::{ArmorConfig, Policy};
use crate::error::ArmorError;
use crate::finding::{Finding, FindingKind, Severity};

pub(crate) fn decide(
    original_len: usize,
    sanitized_len: usize,
    findings: &[Finding],
    config: &ArmorConfig,
) -> Result<(), ArmorError> {
    // Defense in depth: empty input should have been caught upstream
    // by ArmorError::EmptyInput, but guard explicitly to avoid div-by-zero.
    if original_len == 0 {
        return if findings.is_empty() {
            Ok(())
        } else {
            Err(ArmorError::Unsalvageable {
                findings: findings.to_vec(),
                signal_lost_pct: 0.0,
            })
        };
    }

    let signal_lost = 1.0 - (sanitized_len as f32 / original_len as f32);
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);

    let strict_triggered = findings.iter().any(|f| match f.kind {
        FindingKind::FenceMarker { .. }      => config.fence_policy    == Policy::Strict,
        FindingKind::DangerousPattern { .. } => config.pattern_policy  == Policy::Strict,
        FindingKind::EncodedPayload { .. }   => config.encoding_policy == Policy::Strict,
        FindingKind::UnicodeAnomaly { .. }   => false,
    });

    if has_critical || strict_triggered || signal_lost > config.max_signal_loss {
        return Err(ArmorError::Unsalvageable {
            findings: findings.to_vec(),
            signal_lost_pct: (signal_lost * 100.0).max(0.0),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{UnicodeAnomaly, Encoding};

    fn fnd(kind: FindingKind, severity: Severity) -> Finding {
        Finding { kind, severity, span: None, sanitized: true, detail: "".into() }
    }

    #[test]
    fn ok_when_below_threshold_no_critical() {
        let res = decide(100, 80, &[
            fnd(FindingKind::UnicodeAnomaly { kind: UnicodeAnomaly::ZeroWidth }, Severity::Low),
        ], &ArmorConfig::default());
        assert!(res.is_ok());
    }

    #[test]
    fn err_when_signal_loss_exceeds_threshold() {
        // 50 / 100 = 0.5 sanitized → 0.5 lost; default threshold is 0.5, > means strict greater.
        // Use 30 / 100 = 0.3 sanitized → 0.7 lost.
        let res = decide(100, 30, &[
            fnd(FindingKind::FenceMarker { marker: "<|im_end|>" }, Severity::High),
        ], &ArmorConfig::default());
        assert!(matches!(res, Err(ArmorError::Unsalvageable { .. })));
    }

    #[test]
    fn err_on_critical_regardless_of_signal_loss() {
        let res = decide(100, 99, &[
            fnd(FindingKind::EncodedPayload {
                encoding: Encoding::Base64,
                decoded_hit: Some("ignore previous".into()),
            }, Severity::Critical),
        ], &ArmorConfig::default());
        assert!(matches!(res, Err(ArmorError::Unsalvageable { .. })));
    }

    #[test]
    fn err_on_strict_pattern_policy_any_finding() {
        let mut config = ArmorConfig::default();
        config.pattern_policy = Policy::Strict;
        let res = decide(100, 90, &[
            fnd(FindingKind::DangerousPattern {
                matched: "ignore previous".into(), distance: 0,
            }, Severity::Low),
        ], &config);
        assert!(matches!(res, Err(ArmorError::Unsalvageable { .. })));
    }

    #[test]
    fn ok_on_warnonly_encoding_no_critical_no_strict() {
        let res = decide(100, 100, &[
            fnd(FindingKind::EncodedPayload { encoding: Encoding::Hex, decoded_hit: None }, Severity::Low),
        ], &ArmorConfig::default());
        assert!(res.is_ok());
    }

    #[test]
    fn empty_input_with_no_findings_is_ok() {
        let res = decide(0, 0, &[], &ArmorConfig::default());
        assert!(res.is_ok());
    }

    #[test]
    fn empty_input_with_findings_is_err() {
        let res = decide(0, 0, &[
            fnd(FindingKind::FenceMarker { marker: "<|im_end|>" }, Severity::High),
        ], &ArmorConfig::default());
        assert!(matches!(res, Err(ArmorError::Unsalvageable { .. })));
    }
}
