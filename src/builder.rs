//! Public builder API: `Armor::builder()` → configure → `build()` (runs
//! pipeline) → `render()` (final framing wrap).

use crate::armored::Armored;
use crate::config::ArmorConfig;
use crate::error::ArmorError;
use crate::finding::Finding;
use crate::layers;

pub struct Armor;

impl Armor {
    pub fn builder() -> ArmorBuilder {
        ArmorBuilder::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArmorBuilder {
    system: String,
    user: String,
    extra_patterns: &'static [&'static str],
    config: ArmorConfig,
}

impl ArmorBuilder {
    pub fn system(mut self, s: impl Into<String>) -> Self {
        self.system = s.into();
        self
    }
    pub fn user(mut self, s: impl Into<String>) -> Self {
        self.user = s.into();
        self
    }
    pub fn extra_patterns(mut self, patterns: &'static [&'static str]) -> Self {
        self.extra_patterns = patterns;
        self
    }
    pub fn config(mut self, c: ArmorConfig) -> Self {
        self.config = c;
        self
    }

    /// Validate input + run pipeline. This is where the work happens.
    pub fn build(self) -> Result<Armored, ArmorError> {
        if self.user.is_empty() {
            return Err(ArmorError::EmptyInput);
        }
        if self.user.len() > self.config.max_input_bytes {
            return Err(ArmorError::InputTooLarge {
                actual: self.user.len(),
                limit: self.config.max_input_bytes,
            });
        }

        let original_user_len = self.user.len();
        let mut findings: Vec<Finding> = Vec::new();

        // ---- System pipeline: only unicode normalize ----
        let (sys_after_unicode, sys_findings) = layers::unicode::unicode_normalize(&self.system);
        findings.extend(sys_findings);
        let system_sanitized = sys_after_unicode.into_owned();

        // ---- User pipeline: full ----
        let (after_unicode, fs) = layers::unicode::unicode_normalize(&self.user);
        findings.extend(fs);

        let (after_fence, fs) = layers::fence::fence_sanitize(&after_unicode);
        findings.extend(fs);

        let (after_patterns, fs) =
            layers::patterns::pattern_detect(&after_fence, self.extra_patterns);
        findings.extend(fs);

        let (after_encoding, fs) =
            layers::encoding::encoding_detect(&after_patterns, self.extra_patterns);
        findings.extend(fs);

        let user_sanitized = after_encoding.into_owned();
        let sanitized_len = user_sanitized.len();

        crate::decider::decide(original_user_len, sanitized_len, &findings, &self.config)?;

        Ok(Armored {
            system_sanitized,
            user_sanitized,
            findings,
            framing: self.config.framing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_path_clean_text() {
        let armored = Armor::builder()
            .system("Classify text.")
            .user("Hello, this is a friendly product description.")
            .build()
            .expect("should succeed");
        assert!(armored.findings().is_empty());
        let p = armored.render();
        assert!(p.system.contains("Classify text."));
        assert!(
            p.user
                .contains("Hello, this is a friendly product description.")
        );
    }

    #[test]
    fn empty_user_errors() {
        let res = Armor::builder().system("x").user("").build();
        assert!(matches!(res, Err(ArmorError::EmptyInput)));
    }

    #[test]
    fn too_large_user_errors() {
        let huge = "a".repeat(2_000_000);
        let res = Armor::builder().system("x").user(huge).build();
        assert!(matches!(res, Err(ArmorError::InputTooLarge { .. })));
    }

    #[test]
    fn too_large_user_passes_with_raised_cap() {
        let huge = "a".repeat(2_000_000);
        let config = ArmorConfig {
            max_input_bytes: 10_000_000,
            ..ArmorConfig::default()
        };
        let res = Armor::builder()
            .system("x")
            .user(huge)
            .config(config)
            .build();
        assert!(res.is_ok());
    }

    #[test]
    fn extra_patterns_trigger_finding() {
        let armored = Armor::builder()
            .system("x")
            .user("This contains the secret phrase here")
            .extra_patterns(&["the secret phrase"])
            .build()
            .expect("should succeed");
        assert!(!armored.findings().is_empty());
    }

    #[test]
    fn render_twice_same_result() {
        let armored = Armor::builder()
            .system("sys")
            .user("hello")
            .build()
            .unwrap();
        let p1 = armored.render();
        let p2 = armored.render();
        assert_eq!(p1.system, p2.system);
        assert_eq!(p1.user, p2.user);
    }
}
