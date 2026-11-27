//! Application state machine and key handling.
//!
//! Everything that changes state arrives as a [`Msg`]: key events, background
//! results (unlock, clipboard expiry) and timer ticks. That keeps the update
//! logic testable without a terminal.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use ratatui::Frame;
use ratatui::widgets::TableState;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use pass_sworm::config::Config;
use pass_sworm::crypto::Key;
use pass_sworm::device::DeviceIdentity;
use pass_sworm::format::{self, Header, Opened};
use pass_sworm::model::{Draft, Entry, HlcClock, Vault};
use pass_sworm::store::VaultStore;

use crate::tui::input::Input;
use crate::tui::view;

pub enum Msg {
    Tick,
    Key(KeyEvent),
    Unlocked(Result<Box<Opened>, String>),
    ClipboardExpired,
}

/// State that exists only while the vault is decrypted.
pub struct Unlocked {
    pub vault: Vault,
    pub dek: Key,
    pub header: Header,
}

pub(crate) enum Screen {
    Unlock(UnlockScreen),
    Vault,
}

pub(crate) struct UnlockScreen {
    pub password: Input,
    pub confirm: Input,
    pub focus_confirm: bool,
    pub create: bool,
    pub busy: bool,
    pub error: Option<String>,
}

impl UnlockScreen {
    fn new(create: bool) -> Self {
        Self {
            password: Input::default(),
            confirm: Input::default(),
            focus_confirm: false,
            create,
            busy: false,
            error: None,
        }
    }
}

pub struct Editor {
    pub id: Option<Uuid>,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub reveal: bool,
    pub error: Option<String>,
}

/// Index of the password field in [`Editor::fields`].
const PASSWORD_FIELD: usize = 2;

pub struct Field {
    pub label: &'static str,
    pub input: Input,
    pub secret: bool,
}

impl Editor {
    fn new(id: Option<Uuid>, draft: Draft) -> Self {
        let fields = vec![
            Field {
                label: "Name",
                input: Input::new(draft.name),
                secret: false,
            },
            Field {
                label: "Username",
                input: Input::new(draft.username),
                secret: false,
            },
            Field {
                label: "Password",
                input: Input::new(draft.password),
                secret: true,
            },
            Field {
                label: "URL",
                input: Input::new(draft.url),
                secret: false,
            },
            Field {
                label: "Tags",
                input: Input::new(draft.tags),
                secret: false,
            },
            Field {
                label: "Notes",
                input: Input::new(draft.notes),
                secret: true,
            },
        ];
        Self {
            id,
            fields,
            focus: 0,
            reveal: false,
            error: None,
        }
    }

    fn to_draft(&self) -> Draft {
        let get = |i: usize| self.fields[i].input.value.clone();
        Draft {
            name: get(0),
            username: get(1),
            password: get(2),
            url: get(3),
            tags: get(4),
            notes: get(5),
        }
    }

    fn wipe(&mut self) {
        for f in &mut self.fields {
            if f.secret {
                f.input.clear();
            }
        }
    }
}

pub enum Overlay {
    Editor(Editor),
    ConfirmDelete { id: Uuid, name: String },
    History(HistoryOverlay),
    Help,
}

pub struct HistoryOverlay {
    pub id: Uuid,
    pub index: usize,
}

pub struct App {
    pub(crate) cfg: Config,
    pub(crate) store: VaultStore,
    /// Local replica id; every op produced here is stamped with it.
    pub(crate) replica: Uuid,
    tx: UnboundedSender<Msg>,
    clock: HlcClock,

    pub(crate) screen: Screen,
    pub(crate) unlocked: Option<Unlocked>,
    pub(crate) overlay: Option<Overlay>,

    pub(crate) filter: Input,
    pub(crate) filter_editing: bool,
    pub(crate) selected: Option<Uuid>,
    pub(crate) table_state: TableState,

    pub(crate) status: String,
    should_quit: bool,
    last_activity: Instant,

    clipboard: Option<arboard::Clipboard>,
    clipboard_hash: Option<[u8; 32]>,
    clipboard_deadline: Option<Instant>,
}

impl App {
    pub fn new(
        cfg: Config,
        store: VaultStore,
        device: DeviceIdentity,
        tx: UnboundedSender<Msg>,
    ) -> Self {
        let create = !store.exists();
        Self {
            cfg,
            store,
            replica: device.replica,
            tx,
            clock: HlcClock::default(),
            screen: Screen::Unlock(UnlockScreen::new(create)),
            unlocked: None,
            overlay: None,
            filter: Input::default(),
            filter_editing: false,
            selected: None,
            table_state: TableState::default(),
            status: String::new(),
            should_quit: false,
            last_activity: Instant::now(),
            clipboard: None,
            clipboard_hash: None,
            clipboard_deadline: None,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        view::draw(self, frame);
    }

    pub fn update(&mut self, msg: Msg) {
        match msg {
            Msg::Tick => self.on_tick(),
            Msg::Key(key) => self.on_key(key),
            Msg::Unlocked(result) => self.on_unlocked(result),
            Msg::ClipboardExpired => self.on_clipboard_expired(),
        }
    }

    // ----- unlock screen -------------------------------------------------

    fn on_key(&mut self, key: KeyEvent) {
        self.last_activity = Instant::now();
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if matches!(self.screen, Screen::Unlock(_)) {
            self.unlock_key(key);
            return;
        }
        if self.overlay.is_some() {
            self.overlay_key(key);
            return;
        }
        self.vault_key(key);
    }

    fn unlock_key(&mut self, key: KeyEvent) {
        let mut submit = false;
        {
            let Screen::Unlock(u) = &mut self.screen else {
                return;
            };
            if u.busy {
                return;
            }
            match key.code {
                KeyCode::Enter => submit = true,
                KeyCode::Esc => self.should_quit = true,
                KeyCode::Tab => {
                    if u.create {
                        u.focus_confirm = !u.focus_confirm;
                    }
                }
                _ => {
                    let input = if u.create && u.focus_confirm {
                        &mut u.confirm
                    } else {
                        &mut u.password
                    };
                    input.handle_key(key);
                }
            }
        }
        if submit {
            self.try_unlock();
        }
    }

    fn try_unlock(&mut self) {
        let create;
        let password;
        let kdf = self.cfg.crypto.kdf_params();
        {
            let Screen::Unlock(u) = &mut self.screen else {
                return;
            };
            if u.create {
                if u.password.value.chars().count() < 8 {
                    u.error = Some("master password must be at least 8 characters".into());
                    return;
                }
                if u.password.value != u.confirm.value {
                    u.error = Some("passwords do not match".into());
                    return;
                }
            }
            if u.password.is_empty() {
                u.error = Some("enter the master password".into());
                return;
            }
            u.busy = true;
            u.error = None;
            create = u.create;
            password = u.password.value.clone();
        }

        let path = self.store.path().to_path_buf();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || -> Result<Opened, String> {
                if create {
                    // A create is cheap to fail: the file is written by the UI
                    // thread through the store right after unlocking.
                    format::create(Vault::new(), &password, kdf)
                        .map(|(_, opened)| opened)
                        .map_err(|e| e.to_string())
                } else {
                    let bytes =
                        std::fs::read(&path).map_err(|e| format!("cannot read vault: {e}"))?;
                    format::unlock(&bytes, &password).map_err(|e| e.to_string())
                }
            })
            .await;
            let result = match result {
                Ok(r) => r,
                Err(e) => Err(format!("unlock task failed: {e}")),
            };
            let _ = tx.send(Msg::Unlocked(result.map(Box::new)));
        });
    }

    fn on_unlocked(&mut self, result: Result<Box<Opened>, String>) {
        if let Screen::Unlock(u) = &mut self.screen {
            u.busy = false;
        }
        match result {
            Ok(opened) => {
                let opened = *opened;
                let is_new = !self.store.exists();
                self.unlocked = Some(Unlocked {
                    vault: opened.vault,
                    dek: opened.dek,
                    header: opened.header,
                });
                self.screen = Screen::Vault;
                self.selected = self.first_id();
                if is_new {
                    self.persist("vault created");
                } else {
                    self.status = "unlocked".into();
                }
            }
            Err(message) => {
                if let Screen::Unlock(u) = &mut self.screen {
                    u.error = Some(message);
                }
            }
        }
    }

    // ----- vault screen --------------------------------------------------

    pub(crate) fn rows(&self) -> Vec<(Uuid, String, String)> {
        let Some(u) = &self.unlocked else {
            return Vec::new();
        };
        let pattern = self.filter.value.trim();
        let mut items: Vec<&Entry> = u.vault.visible().collect();

        if pattern.is_empty() {
            items.sort_by_key(|e| e.name.value.to_lowercase());
        } else {
            let matcher = SkimMatcherV2::default();
            let mut scored: Vec<(i64, &Entry)> = items
                .iter()
                .filter_map(|e| {
                    let haystack = format!(
                        "{} {} {} {}",
                        e.name.value,
                        e.username.value,
                        e.url.value.as_deref().unwrap_or(""),
                        e.tags.value.join(" ")
                    );
                    matcher
                        .fuzzy_match(&haystack, pattern)
                        .map(|score| (score, *e))
                })
                .collect();
            scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
            items = scored.into_iter().map(|(_, e)| e).collect();
        }

        items
            .into_iter()
            .map(|e| (e.id, e.name.value.clone(), e.username.value.clone()))
            .collect()
    }

    pub(crate) fn selected_index(&self, rows: &[(Uuid, String, String)]) -> Option<usize> {
        let id = self.selected?;
        rows.iter().position(|(rid, _, _)| *rid == id)
    }

    fn first_id(&self) -> Option<Uuid> {
        self.rows().first().map(|(id, _, _)| *id)
    }

    fn move_selection(&mut self, delta: isize) {
        let rows = self.rows();
        if rows.is_empty() {
            self.selected = None;
            return;
        }
        let current = self.selected_index(&rows).unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, rows.len() as isize - 1);
        self.selected = Some(rows[next as usize].0);
    }

    fn vault_key(&mut self, key: KeyEvent) {
        if self.filter_editing {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.filter_editing = false,
                _ => {
                    self.filter.handle_key(key);
                    self.selected = self.first_id();
                }
            }
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.overlay = Some(Overlay::Help),
            KeyCode::Char('/') => self.filter_editing = true,
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') => self.selected = self.first_id(),
            KeyCode::Char('G') => {
                let rows = self.rows();
                self.selected = rows.last().map(|(id, _, _)| *id);
            }
            KeyCode::Char('a') => self.open_editor(None),
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(id) = self.selected {
                    self.open_editor(Some(id));
                }
            }
            KeyCode::Char('d') => self.request_delete(),
            KeyCode::Char('c') => self.clone_selected(),
            KeyCode::Char('y') => self.copy_password(),
            KeyCode::Char('h') => self.open_history(),
            KeyCode::Char('l') if ctrl => self.lock(),
            KeyCode::Esc => {
                self.filter.clear();
                self.selected = self.first_id();
            }
            _ => {}
        }
    }

    fn open_editor(&mut self, id: Option<Uuid>) {
        let draft = id
            .and_then(|id| self.unlocked.as_ref()?.vault.get(id))
            .map(Draft::from_entry)
            .unwrap_or_default();
        self.overlay = Some(Overlay::Editor(Editor::new(id, draft)));
    }

    fn request_delete(&mut self) {
        let Some(id) = self.selected else { return };
        let Some(u) = &self.unlocked else { return };
        let Some(entry) = u.vault.get(id) else { return };
        self.overlay = Some(Overlay::ConfirmDelete {
            id,
            name: entry.name.value.clone(),
        });
    }

    fn clone_selected(&mut self) {
        let Some(id) = self.selected else { return };
        let hlc = self.clock.tick();
        if let Some(u) = self.unlocked.as_mut()
            && let Some(new_id) = u.vault.clone_entry(id, hlc, self.replica)
        {
            self.selected = Some(new_id);
            self.persist("entry cloned");
        }
    }

    // ----- history --------------------------------------------------------

    fn open_history(&mut self) {
        let Some(id) = self.selected else { return };
        let Some(u) = &self.unlocked else { return };
        let Some(entry) = u.vault.get(id) else { return };
        if entry.history.is_empty() {
            self.status = "no previous versions for this entry".into();
            return;
        }
        self.overlay = Some(Overlay::History(HistoryOverlay { id, index: 0 }));
    }

    fn history_key(&mut self, history: &mut HistoryOverlay, key: KeyEvent) -> bool {
        let len = self
            .unlocked
            .as_ref()
            .and_then(|u| u.vault.get(history.id))
            .map(|e| e.history.len())
            .unwrap_or(0);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => false,
            KeyCode::Char('j') | KeyCode::Down => {
                if len > 0 {
                    history.index = (history.index + 1).min(len - 1);
                }
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                history.index = history.index.saturating_sub(1);
                true
            }
            KeyCode::Enter => {
                self.restore_snapshot(history.id, history.index);
                false
            }
            _ => true,
        }
    }

    /// Restore an old version of an entry as a normal edit. The state that is
    /// current at that moment goes into history itself, so a restore can be
    /// undone the same way.
    fn restore_snapshot(&mut self, id: Uuid, index: usize) {
        let Some(u) = self.unlocked.as_ref() else {
            return;
        };
        let Some(snapshot) = u
            .vault
            .get(id)
            .and_then(|entry| entry.history.get(index))
            .cloned()
        else {
            return;
        };

        let mut draft = Draft {
            name: snapshot.name,
            username: snapshot.username,
            password: snapshot.password,
            url: snapshot.url.unwrap_or_default(),
            notes: snapshot.notes.unwrap_or_default(),
            tags: snapshot.tags.join(", "),
        };
        let hlc = self.clock.tick();
        if let Some(u) = self.unlocked.as_mut() {
            u.vault.update(id, &draft, hlc, self.replica);
        }
        draft.wipe();
        self.persist("entry restored from history");
    }

    // ----- overlays -------------------------------------------------------

    fn overlay_key(&mut self, key: KeyEvent) {
        let Some(mut overlay) = self.overlay.take() else {
            return;
        };
        let keep = match &mut overlay {
            Overlay::Editor(editor) => self.editor_key(editor, key),
            Overlay::ConfirmDelete { id, .. } => self.confirm_key(*id, key),
            Overlay::History(history) => self.history_key(history, key),
            Overlay::Help => !matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')
            ),
        };
        if keep {
            self.overlay = Some(overlay);
        }
    }

    fn editor_key(&mut self, editor: &mut Editor, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => {
                editor.wipe();
                return false;
            }
            KeyCode::Enter => return self.editor_commit(editor),
            KeyCode::Tab | KeyCode::Down => {
                editor.focus = (editor.focus + 1) % editor.fields.len();
                return true;
            }
            KeyCode::BackTab | KeyCode::Up => {
                editor.focus = (editor.focus + editor.fields.len() - 1) % editor.fields.len();
                return true;
            }
            KeyCode::Char('r') if ctrl => {
                editor.reveal = !editor.reveal;
                return true;
            }
            KeyCode::Char('g') if ctrl => {
                let generator = &self.cfg.generator;
                let password = pass_sworm::generator::generate(
                    generator.length,
                    generator.symbols,
                    generator.avoid_ambiguous,
                );
                editor.fields[PASSWORD_FIELD].input = Input::new(password);
                editor.focus = PASSWORD_FIELD;
                editor.reveal = true;
                return true;
            }
            _ => {}
        }
        editor.fields[editor.focus].input.handle_key(key);
        true
    }

    fn editor_commit(&mut self, editor: &mut Editor) -> bool {
        let mut draft = editor.to_draft();
        if draft.name.trim().is_empty() {
            editor.error = Some("name must not be empty".into());
            draft.wipe();
            return true;
        }
        let hlc = self.clock.tick();
        let id = editor.id;
        let Some(u) = self.unlocked.as_mut() else {
            draft.wipe();
            return false;
        };
        match id {
            Some(id) => {
                u.vault.update(id, &draft, hlc, self.replica);
                self.selected = Some(id);
            }
            None => {
                let new_id = u.vault.add(&draft, hlc, self.replica);
                self.selected = Some(new_id);
            }
        }
        draft.wipe();
        editor.wipe();
        self.persist(if id.is_some() {
            "entry updated"
        } else {
            "entry added"
        });
        false
    }

    fn confirm_key(&mut self, id: Uuid, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                let hlc = self.clock.tick();
                if let Some(u) = self.unlocked.as_mut() {
                    u.vault.delete(id, hlc, self.replica);
                }
                self.selected = self.first_id();
                self.persist("entry deleted");
                false
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => false,
            _ => true,
        }
    }

    // ----- clipboard ------------------------------------------------------

    fn copy_password(&mut self) {
        let Some(id) = self.selected else { return };
        let Some(u) = &self.unlocked else { return };
        let Some(entry) = u.vault.get(id) else { return };
        let secret = entry.password.value.clone();
        if secret.is_empty() {
            self.status = "entry has no password".into();
            return;
        }

        if self.clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(cb) => self.clipboard = Some(cb),
                Err(e) => {
                    self.status = format!("clipboard unavailable: {e}");
                    return;
                }
            }
        }
        let Some(cb) = self.clipboard.as_mut() else {
            return;
        };
        if let Err(e) = cb.set_text(secret.clone()) {
            self.status = format!("clipboard error: {e}");
            return;
        }

        let hash = *blake3::hash(secret.as_bytes()).as_bytes();
        let seconds = self.cfg.clipboard.clear_after_seconds;
        if seconds == 0 {
            self.clipboard_hash = None;
            self.clipboard_deadline = None;
            self.status = "password copied to clipboard".into();
            return;
        }

        self.clipboard_hash = Some(hash);
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(seconds));
        self.status = format!("password copied; wiping in {seconds}s");

        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            let _ = tx.send(Msg::ClipboardExpired);
        });
    }

    fn on_clipboard_expired(&mut self) {
        let Some(expected) = self.clipboard_hash.take() else {
            return;
        };
        self.clipboard_deadline = None;
        if let Some(cb) = self.clipboard.as_mut() {
            // Only wipe if the clipboard still holds our secret: the user may
            // have copied something else in the meantime.
            if let Ok(current) = cb.get_text()
                && *blake3::hash(current.as_bytes()).as_bytes() == expected
            {
                let _ = cb.set_text(String::new());
                self.status = "clipboard wiped".into();
            }
        }
    }

    pub(crate) fn clipboard_seconds_left(&self) -> Option<u64> {
        let deadline = self.clipboard_deadline?;
        let now = Instant::now();
        if deadline <= now {
            return Some(0);
        }
        Some(deadline.duration_since(now).as_secs() + 1)
    }

    // ----- lifecycle ------------------------------------------------------

    fn on_tick(&mut self) {
        let minutes = self.cfg.general.auto_lock_minutes;
        if minutes > 0
            && self.unlocked.is_some()
            && self.last_activity.elapsed() >= Duration::from_secs(minutes * 60)
        {
            self.lock();
            self.status = "vault locked after inactivity".into();
        }
    }

    fn lock(&mut self) {
        self.unlocked = None;
        self.overlay = None;
        self.selected = None;
        self.filter.clear();
        self.filter_editing = false;
        self.screen = Screen::Unlock(UnlockScreen::new(false));
    }

    /// Re-encrypt and write the vault. Cheap: only the AEAD runs, never Argon2.
    fn persist(&mut self, status: &str) {
        let Some(u) = self.unlocked.as_ref() else {
            return;
        };
        let sealed = match format::reseal(&u.vault, &u.dek, &u.header) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.status = format!("encrypt failed: {e}");
                return;
            }
        };
        match self.store.write(&sealed, self.cfg.general.backups) {
            Ok(()) => self.status = status.to_string(),
            Err(e) => self.status = format!("save failed: {e}"),
        }
    }
}

#[cfg(test)]
#[path = "../tests/tui/app.rs"]
mod tests;
