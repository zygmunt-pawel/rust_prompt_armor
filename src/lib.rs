//! `rust_prompt_armor` — deterministic, cheap defenses against prompt injection.
//!
//! Scope and API are intentionally empty at this point. The crate is reserved
//! for the cluster of work described in the eligibility BC1 discussion
//! (2026-05-15): generalize the `Prompt`/`render`/fence-sanitize pattern,
//! add unicode normalization, dangerous-pattern detection with fuzzy match,
//! and an output-validator hook surface.
//!
//! Not published, not pinned by any consumer yet — safe to redesign freely.
