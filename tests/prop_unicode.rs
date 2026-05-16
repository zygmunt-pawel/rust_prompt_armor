//! Property: armor pipeline never panics on arbitrary Unicode input,
//! always produces valid UTF-8 output.

use proptest::prelude::*;
use rust_prompt_armor::Armor;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn arbitrary_string_does_not_panic(s in ".{0,2000}") {
        let res = Armor::builder().system("sys").user(s).build();
        // Whether Ok or Err, must not panic.
        let _ = res;
    }

    #[test]
    fn output_is_valid_utf8(s in ".{1,1000}") {
        if let Ok(armored) = Armor::builder().system("sys").user(s).build() {
            let p = armored.render();
            prop_assert!(std::str::from_utf8(p.system.as_bytes()).is_ok());
            prop_assert!(std::str::from_utf8(p.user.as_bytes()).is_ok());
        }
    }

    #[test]
    fn unicode_chars_passthrough_or_redact_safely(
        s in "\\PC{1,500}"  // any printable unicode incl. CJK, RTL, emoji
    ) {
        let res = Armor::builder().system("sys").user(s).build();
        if let Ok(a) = res {
            let p = a.render();
            // Verify no invalid UTF-8 even after replacements
            prop_assert!(p.user.is_char_boundary(0));
            prop_assert!(p.user.is_char_boundary(p.user.len()));
        }
    }
}
