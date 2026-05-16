//! Output types: `Armored` (intermediate, holds sanitized parts + findings)
//! and `ArmoredPrompt` (final, what the caller sends to the LLM).

use crate::config::Framing;
use crate::finding::Finding;
use crate::layers::fence::framing_wrap;

#[derive(Debug, Clone)]
pub struct ArmoredPrompt {
    pub system: String,
    pub user: String,
    pub warnings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct Armored {
    pub(crate) system_sanitized: String,
    pub(crate) user_sanitized: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) framing: Framing,
}

impl Armored {
    /// Render the final prompt pair. Cheap and idempotent — call as many
    /// times as needed (e.g. once per LLM API attempt).
    pub fn render(&self) -> ArmoredPrompt {
        let (system, user) = match self.framing {
            Framing::Tagged => framing_wrap(&self.system_sanitized, &self.user_sanitized),
            Framing::Bare => (self.system_sanitized.clone(), self.user_sanitized.clone()),
        };
        ArmoredPrompt {
            system,
            user,
            warnings: self.findings.clone(),
        }
    }

    pub fn findings(&self) -> &[Finding] { &self.findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(framing: Framing) -> Armored {
        Armored {
            system_sanitized: "sys".into(),
            user_sanitized: "usr".into(),
            findings: vec![],
            framing,
        }
    }

    #[test]
    fn tagged_framing_wraps_both_parts() {
        let a = make(Framing::Tagged);
        let p = a.render();
        assert!(p.system.contains("<system>"));
        assert!(p.system.contains("sys"));
        assert!(p.user.contains("<user_data>"));
        assert!(p.user.contains("usr"));
    }

    #[test]
    fn bare_framing_passes_through() {
        let a = make(Framing::Bare);
        let p = a.render();
        assert_eq!(p.system, "sys");
        assert_eq!(p.user, "usr");
    }

    #[test]
    fn render_is_idempotent() {
        let a = make(Framing::Tagged);
        let p1 = a.render();
        let p2 = a.render();
        assert_eq!(p1.system, p2.system);
        assert_eq!(p1.user, p2.user);
    }

    #[test]
    fn findings_accessor_returns_stored() {
        let a = make(Framing::Bare);
        assert!(a.findings().is_empty());
    }
}
