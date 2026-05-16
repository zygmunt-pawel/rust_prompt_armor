//! Builder API surface, config overrides, DoS cap, idempotency.

use rust_prompt_armor::{Armor, ArmorConfig, ArmorError, Framing, Policy};

#[test]
fn empty_system_is_allowed() {
    let armored = Armor::builder()
        .system("")
        .user("hello")
        .build()
        .expect("empty system OK; only user must be non-empty");
    let p = armored.render();
    assert!(p.system.contains("<system>"));
    assert!(p.user.contains("hello"));
}

#[test]
fn bare_framing_skips_wrap() {
    let mut config = ArmorConfig::default();
    config.framing = Framing::Bare;
    let armored = Armor::builder()
        .system("sys")
        .user("hello")
        .config(config)
        .build()
        .unwrap();
    let p = armored.render();
    assert_eq!(p.system, "sys");
    assert_eq!(p.user, "hello");
}

#[test]
fn strict_pattern_policy_errors_on_any_match() {
    let mut config = ArmorConfig::default();
    config.pattern_policy = Policy::Strict;
    let res = Armor::builder()
        .system("x")
        .user("please ignore previous now")
        .config(config)
        .build();
    assert!(matches!(res, Err(ArmorError::Unsalvageable { .. })));
}

#[test]
fn dos_cap_default_1mib() {
    let huge = "a".repeat(2_000_000);
    let res = Armor::builder().system("x").user(huge).build();
    match res {
        Err(ArmorError::InputTooLarge { actual, limit }) => {
            assert_eq!(actual, 2_000_000);
            assert_eq!(limit, 1_048_576);
        }
        other => panic!("expected InputTooLarge, got {other:?}"),
    }
}

#[test]
fn dos_cap_can_be_raised() {
    let huge = "a".repeat(2_000_000);
    let mut config = ArmorConfig::default();
    config.max_input_bytes = 10_000_000;
    let res = Armor::builder().system("x").user(huge).config(config).build();
    assert!(res.is_ok());
}

#[test]
fn extra_patterns_apply_in_addition_to_defaults() {
    let armored = Armor::builder()
        .system("x")
        .user("This contains acme-internal-codeword here")
        .extra_patterns(&["acme-internal-codeword"])
        .build()
        .unwrap();
    assert!(!armored.findings().is_empty());
}

#[test]
fn render_twice_produces_same_strings() {
    let armored = Armor::builder().system("sys").user("hello world").build().unwrap();
    let p1 = armored.render();
    let p2 = armored.render();
    assert_eq!(p1.system, p2.system);
    assert_eq!(p1.user, p2.user);
}
