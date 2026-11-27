use super::*;

#[test]
fn typing_and_editing() {
    let mut i = Input::default();
    for c in "abc".chars() {
        i.insert(c);
    }
    assert_eq!(i.value, "abc");
    i.left();
    i.insert('X');
    assert_eq!(i.value, "abXc");
    i.backspace();
    assert_eq!(
        i.value, "abc",
        "backspace removes the char before the cursor"
    );
    i.home();
    i.delete();
    assert_eq!(i.value, "bc", "delete removes the char under the cursor");
    i.end();
    i.backspace();
    assert_eq!(i.value, "b");
}

#[test]
fn multibyte_safe() {
    let mut i = Input::default();
    i.insert('ш');
    i.insert('ї');
    i.backspace();
    assert_eq!(i.value, "ш");
    i.left();
    i.insert('ё');
    assert_eq!(i.value, "ёш");
}

#[test]
fn ctrl_keys_are_not_consumed_as_text() {
    let mut i = Input::default();
    let k = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);
    assert!(!i.handle_key(k));
    assert!(i.value.is_empty());
}

#[test]
fn masked_line_hides_secret() {
    let i = Input::new("secret");
    let line = i.line(true, false);
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    assert_eq!(text, "••••••");
}
