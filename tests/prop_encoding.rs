//! Property: encoding detection / decode never panics on arbitrary
//! base64/hex-looking input.

use proptest::prelude::*;
use rust_prompt_armor::Armor;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn arbitrary_base64_charset_does_not_panic(
        s in "[A-Za-z0-9+/=]{0,500}"
    ) {
        let input = format!("note: {s}");
        let res = Armor::builder().system("sys").user(input).build();
        let _ = res;
    }

    #[test]
    fn arbitrary_hex_does_not_panic(
        s in "[0-9a-fA-F]{0,200}"
    ) {
        let input = format!("hash: {s}");
        let res = Armor::builder().system("sys").user(input).build();
        let _ = res;
    }

    #[test]
    fn mixed_content_with_random_encoded_blobs(
        prefix in "[a-zA-Z ]{0,100}",
        blob in "[A-Za-z0-9+/=]{20,200}",
        suffix in "[a-zA-Z ]{0,100}"
    ) {
        let input = format!("{prefix} {blob} {suffix}");
        let res = Armor::builder().system("sys").user(input).build();
        let _ = res;
    }
}
