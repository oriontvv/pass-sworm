use super::*;
use pass_sworm::crypto::KdfParams;
use pass_sworm::model::Hlc;
use pass_sworm::store::VaultStore;

fn temp_store(tag: &str) -> (VaultStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("psw-app-{tag}-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = VaultStore::open(dir.join("vault.psw")).unwrap();
    (store, dir)
}

fn fast_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.crypto.argon2_m_cost_kib = 8 * 1024;
    cfg.crypto.argon2_t_cost = 1;
    cfg.crypto.argon2_p_cost = 1;
    cfg
}

fn test_device() -> DeviceIdentity {
    DeviceIdentity {
        replica: Uuid::from_u128(0xD),
        name: "test".into(),
        secret: String::new(),
    }
}

fn unlocked_app() -> (App, std::path::PathBuf) {
    let (store, dir) = temp_store("app");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let mut app = App::new(fast_cfg(), store, test_device(), tx);
    let (bytes, opened) = format::create(
        Vault::new(),
        "master pw",
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    app.store.write(&bytes, 5).unwrap();
    app.unlocked = Some(Unlocked {
        vault: opened.vault,
        dek: opened.dek,
        header: opened.header,
    });
    app.screen = Screen::Vault;
    (app, dir)
}

fn type_str(app: &mut App, s: &str) {
    for c in s.chars() {
        app.update(Msg::Key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::NONE,
        )));
    }
}

#[test]
fn add_edit_clone_delete_flow() {
    let (mut app, dir) = unlocked_app();

    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('a'),
        KeyModifiers::NONE,
    )));
    type_str(&mut app, "github");
    app.update(Msg::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
    type_str(&mut app, "alice");
    app.update(Msg::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
    type_str(&mut app, "s3cret");
    app.update(Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));

    assert!(app.overlay.is_none());
    let vault = &app.unlocked.as_ref().unwrap().vault;
    assert_eq!(vault.visible().count(), 1);
    let entry = vault.visible().next().unwrap();
    assert_eq!(entry.name.value, "github");
    assert_eq!(entry.password.value, "s3cret");
    let id = entry.id;

    // The vault was persisted: a fresh unlock sees the entry.
    let reopened = format::unlock(&app.store.read().unwrap(), "master pw").unwrap();
    assert_eq!(reopened.vault.visible().count(), 1);

    // clone
    app.selected = Some(id);
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::NONE,
    )));
    let vault = &app.unlocked.as_ref().unwrap().vault;
    assert_eq!(vault.visible().count(), 2);

    // delete with confirmation
    app.selected = Some(id);
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('d'),
        KeyModifiers::NONE,
    )));
    assert!(matches!(app.overlay, Some(Overlay::ConfirmDelete { .. })));
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('y'),
        KeyModifiers::NONE,
    )));
    let vault = &app.unlocked.as_ref().unwrap().vault;
    assert_eq!(vault.visible().count(), 1);
    assert!(vault.get(id).unwrap().is_deleted());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_name_is_rejected() {
    let (mut app, dir) = unlocked_app();
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('a'),
        KeyModifiers::NONE,
    )));
    app.update(Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    match &app.overlay {
        Some(Overlay::Editor(editor)) => {
            assert!(editor.error.is_some());
        }
        _ => panic!("editor should stay open on a validation error"),
    }
    assert_eq!(app.unlocked.as_ref().unwrap().vault.visible().count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn filter_selects_matching_entries() {
    let (mut app, dir) = unlocked_app();
    let hlc = Hlc {
        wall_ms: 1,
        counter: 0,
    };
    let replica = app.replica;
    let vault = &mut app.unlocked.as_mut().unwrap().vault;
    vault.add(
        &Draft {
            name: "github".into(),
            ..Default::default()
        },
        hlc,
        replica,
    );
    vault.add(
        &Draft {
            name: "gitlab".into(),
            ..Default::default()
        },
        hlc,
        replica,
    );
    vault.add(
        &Draft {
            name: "aws".into(),
            ..Default::default()
        },
        hlc,
        replica,
    );

    app.filter.value = "git".into();
    assert_eq!(app.rows().len(), 2);
    app.filter.value = "zzz".into();
    assert!(app.rows().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ctrl_g_fills_the_password_field() {
    let (mut app, dir) = unlocked_app();
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('a'),
        KeyModifiers::NONE,
    )));
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('g'),
        KeyModifiers::CONTROL,
    )));

    match &app.overlay {
        Some(Overlay::Editor(editor)) => {
            assert_eq!(editor.focus, PASSWORD_FIELD);
            assert_eq!(
                editor.fields[PASSWORD_FIELD].input.value.chars().count(),
                app.cfg.generator.length,
                "generated password must use the configured length"
            );
            assert!(editor.reveal, "a generated password should be visible");
        }
        _ => panic!("editor should be open"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_restore_brings_back_the_previous_version() {
    let (mut app, dir) = unlocked_app();
    let hlc = app.clock.tick();
    let replica = app.replica;
    let id = app.unlocked.as_mut().unwrap().vault.add(
        &Draft {
            name: "acc".into(),
            username: "user".into(),
            password: "old".into(),
            ..Default::default()
        },
        hlc,
        replica,
    );

    let mut edit = Draft::from_entry(app.unlocked.as_ref().unwrap().vault.get(id).unwrap());
    edit.password = "new".into();
    let hlc = app.clock.tick();
    app.unlocked
        .as_mut()
        .unwrap()
        .vault
        .update(id, &edit, hlc, replica);

    app.selected = Some(id);
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('h'),
        KeyModifiers::NONE,
    )));
    assert!(matches!(app.overlay, Some(Overlay::History(_))));

    app.update(Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));

    let entry = app.unlocked.as_ref().unwrap().vault.get(id).unwrap();
    assert_eq!(entry.password.value, "old");
    assert_eq!(entry.history.len(), 2, "restore must be undoable too");

    let reopened = format::unlock(&app.store.read().unwrap(), "master pw").unwrap();
    assert_eq!(reopened.vault.get(id).unwrap().password.value, "old");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_on_a_fresh_entry_is_a_no_op() {
    let (mut app, dir) = unlocked_app();
    let hlc = Hlc {
        wall_ms: 1,
        counter: 0,
    };
    let replica = app.replica;
    let id = app.unlocked.as_mut().unwrap().vault.add(
        &Draft {
            name: "x".into(),
            ..Default::default()
        },
        hlc,
        replica,
    );
    app.selected = Some(id);
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('h'),
        KeyModifiers::NONE,
    )));
    assert!(app.overlay.is_none());
    assert!(app.status.contains("no previous versions"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn every_screen_renders_without_panicking() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let (mut terminal, _) = (Terminal::new(TestBackend::new(80, 24)).unwrap(), ());

    // Unlock screen for a vault that does not exist yet (create mode).
    let (store, unlock_dir) = temp_store("render-unlock");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let mut fresh = App::new(fast_cfg(), store, test_device(), tx);
    terminal.draw(|f| fresh.draw(f)).unwrap();

    // Vault screen and every overlay.
    let (mut app, vault_dir) = unlocked_app();
    terminal.draw(|f| app.draw(f)).unwrap();

    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('a'),
        KeyModifiers::NONE,
    )));
    terminal.draw(|f| app.draw(f)).unwrap();
    app.update(Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));

    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('?'),
        KeyModifiers::NONE,
    )));
    terminal.draw(|f| app.draw(f)).unwrap();
    app.update(Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));

    let replica = app.replica;
    let id = app.unlocked.as_mut().unwrap().vault.add(
        &Draft {
            name: "x".into(),
            password: "p".into(),
            ..Default::default()
        },
        Hlc {
            wall_ms: 1,
            counter: 0,
        },
        replica,
    );
    app.selected = Some(id);

    // History overlay needs at least one previous version.
    let mut edit = Draft::from_entry(app.unlocked.as_ref().unwrap().vault.get(id).unwrap());
    edit.password = "p2".into();
    app.unlocked.as_mut().unwrap().vault.update(
        id,
        &edit,
        Hlc {
            wall_ms: 2,
            counter: 0,
        },
        replica,
    );
    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('h'),
        KeyModifiers::NONE,
    )));
    terminal.draw(|f| app.draw(f)).unwrap();
    app.update(Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));

    app.update(Msg::Key(KeyEvent::new(
        KeyCode::Char('d'),
        KeyModifiers::NONE,
    )));
    terminal.draw(|f| app.draw(f)).unwrap();

    // A tiny terminal must not panic either.
    let mut small = Terminal::new(TestBackend::new(20, 8)).unwrap();
    small.draw(|f| app.draw(f)).unwrap();

    std::fs::remove_dir_all(&unlock_dir).ok();
    std::fs::remove_dir_all(&vault_dir).ok();
}
