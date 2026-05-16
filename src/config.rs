//! Per-builder configuration: thresholds, policies, framing.

#[derive(Debug, Clone)]
pub struct ArmorConfig {
    /// Fraction of input that may be removed by sanitization before
    /// `ArmorError::Unsalvageable` triggers. 0.5 = 50%.
    pub max_signal_loss: f32,
    /// Hard cap on user input bytes; above this, `ArmorError::InputTooLarge`
    /// is returned without running the pipeline (DoS guard).
    pub max_input_bytes: usize,
    pub fence_policy: Policy,
    pub pattern_policy: Policy,
    pub encoding_policy: Policy,
    pub framing: Framing,
}

impl Default for ArmorConfig {
    fn default() -> Self {
        Self {
            max_signal_loss: 0.5,
            max_input_bytes: 1_048_576, // 1 MiB
            fence_policy: Policy::Sanitize,
            pattern_policy: Policy::Sanitize,
            encoding_policy: Policy::WarnOnly,
            framing: Framing::Tagged,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Replace the finding with `[REDACTED:...]` and continue.
    Sanitize,
    /// Record the finding but do not mutate the text.
    WarnOnly,
    /// Any finding of this kind → `Err(Unsalvageable)`.
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Wrap system with `<system>...</system>` + data-not-instructions notice,
    /// wrap user with `<user_data>...</user_data>`.
    Tagged,
    /// No wrapping; return sanitized strings verbatim.
    Bare,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_safe_values() {
        let c = ArmorConfig::default();
        assert_eq!(c.max_signal_loss, 0.5);
        assert_eq!(c.max_input_bytes, 1_048_576);
        assert_eq!(c.fence_policy, Policy::Sanitize);
        assert_eq!(c.pattern_policy, Policy::Sanitize);
        assert_eq!(c.encoding_policy, Policy::WarnOnly);
        assert_eq!(c.framing, Framing::Tagged);
    }

    #[test]
    fn config_is_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone>() {}
        assert_traits::<ArmorConfig>();
        assert_traits::<Policy>();
        assert_traits::<Framing>();
    }
}
