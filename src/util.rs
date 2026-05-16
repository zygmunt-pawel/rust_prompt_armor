//! UTF-8-boundary-safe helpers used by sanitization layers.

/// Replace bytes `range` of `s` with `replacement`, snapping `range`
/// outward to the nearest `char` boundaries if it falls inside a
/// multi-byte sequence. Returns the new string and the actual byte
/// range that was replaced (post-snap).
///
/// This prevents creating invalid UTF-8 when a fence marker or pattern
/// match boundary coincidentally lands inside a multi-byte char.
pub(crate) fn safe_replace_range(
    s: &str,
    range: std::ops::Range<usize>,
    replacement: &str,
) -> (String, std::ops::Range<usize>) {
    let start = snap_left(s, range.start);
    let end = snap_right(s, range.end);
    let mut out = String::with_capacity(s.len() + replacement.len());
    out.push_str(&s[..start]);
    out.push_str(replacement);
    out.push_str(&s[end..]);
    (out, start..end)
}

fn snap_left(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn snap_right(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn ascii_replace_unchanged() {
        let (out, range) = safe_replace_range("hello world", 6..11, "[X]");
        assert_eq!(out, "hello [X]");
        assert_eq!(range, 6..11);
    }

    #[test]
    fn two_byte_char_polish_l() {
        // "łatwy" = ł (2 bytes: 0xC5 0x82) + atwy
        // Asking to replace bytes 1..3 (mid-ł through end-of-'a') snaps start
        // left to 0 (start of ł) and leaves end at 3 (boundary between 'a' and 't').
        // So bytes 0..3 ("ła") are replaced.
        let (out, range) = safe_replace_range("łatwy", 1..3, "[X]");
        assert_eq!(out, "[X]twy");
        assert_eq!(range, 0..3);
    }

    #[test]
    fn three_byte_char_cjk() {
        // "中文" = 中 (3 bytes) + 文 (3 bytes), total 6 bytes
        // Asking to replace bytes 1..4 (mid-中 through mid-文) snaps to 0..6.
        let (out, range) = safe_replace_range("中文", 1..4, "[X]");
        assert_eq!(out, "[X]");
        assert_eq!(range, 0..6);
    }

    #[test]
    fn four_byte_emoji() {
        // "a🚀b" = a (1) + 🚀 (4) + b (1), total 6 bytes
        // Replace bytes 2..4 (mid-emoji) snaps to 1..5 (full emoji).
        let (out, range) = safe_replace_range("a🚀b", 2..4, "[X]");
        assert_eq!(out, "a[X]b");
        assert_eq!(range, 1..5);
    }

    #[test]
    fn range_at_end_of_string() {
        let (out, range) = safe_replace_range("hello", 3..10, "");
        assert_eq!(out, "hel");
        assert_eq!(range, 3..5);
    }

    #[test]
    fn empty_replacement_just_deletes() {
        let (out, range) = safe_replace_range("hello world", 5..6, "");
        assert_eq!(out, "helloworld");
        assert_eq!(range, 5..6);
    }

    #[test]
    fn output_is_always_valid_utf8() {
        // Property-like: never panic, always produces valid String
        let cases = ["łatwy", "中文", "a🚀b", "ёлки", "ігри"];
        for s in cases {
            for start in 0..=s.len() {
                for end in start..=s.len() {
                    let (out, _) = safe_replace_range(s, start..end, "[X]");
                    assert!(
                        std::str::from_utf8(out.as_bytes()).is_ok(),
                        "invalid UTF-8 produced from '{s}' range {start}..{end}"
                    );
                }
            }
        }
    }
}
