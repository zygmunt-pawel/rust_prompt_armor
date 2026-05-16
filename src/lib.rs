//! `rust_prompt_armor` — deterministic, cheap defenses against prompt injection.
//!
//! See [`builder::Armor`] for the entry point.

pub mod armored;
pub mod builder;
pub mod catalog;
pub mod config;
pub(crate) mod decider;
pub mod error;
pub mod finding;
pub(crate) mod layers;
pub(crate) mod util;

// Compile-time assert that public types are thread-safe.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<builder::Armor>();
    assert_send_sync::<builder::ArmorBuilder>();
    assert_send_sync::<armored::Armored>();
    assert_send_sync::<armored::ArmoredPrompt>();
    assert_send_sync::<finding::Finding>();
    assert_send_sync::<error::ArmorError>();
    assert_send_sync::<config::ArmorConfig>();
};
