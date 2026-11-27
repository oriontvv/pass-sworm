use super::*;

#[test]
fn respects_length() {
    for len in 1..=64 {
        assert_eq!(generate(len, true, false).chars().count(), len);
    }
    assert_eq!(generate(0, true, false).chars().count(), 1);
}

#[test]
fn symbols_can_be_disabled() {
    for _ in 0..50 {
        let pw = generate(40, false, false);
        assert!(
            pw.chars().all(|c| c.is_alphanumeric()),
            "unexpected symbol in {pw}"
        );
    }
}

#[test]
fn ambiguous_characters_are_excluded() {
    for _ in 0..50 {
        let pw = generate(40, true, true);
        assert!(
            !pw.chars().any(|c| AMBIGUOUS.contains(c)),
            "ambiguous character in {pw}"
        );
    }
}

#[test]
fn every_enabled_class_is_represented() {
    for _ in 0..50 {
        let pw = generate(8, true, false);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "{pw}");
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "{pw}");
        assert!(pw.chars().any(|c| c.is_ascii_digit()), "{pw}");
        assert!(pw.chars().any(|c| !c.is_alphanumeric()), "{pw}");
    }
}

#[test]
fn consecutive_passwords_differ() {
    let a = generate(32, true, true);
    let b = generate(32, true, true);
    assert_ne!(a, b);
}

#[test]
fn short_lengths_do_not_panic() {
    // Fewer characters than classes: the guarantee is best effort only.
    assert_eq!(generate(2, true, false).chars().count(), 2);
}
