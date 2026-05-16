//! `rust_prompt_armor` — deterministic, cheap defenses against prompt injection.

pub mod catalog;
pub mod config;
pub mod error;
pub mod finding;
pub(crate) mod layers;
pub(crate) mod util;
