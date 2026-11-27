//! Vault data model and merge rules.
//!
//! Every mutation is expressed as an [`Op`] and applied through [`Vault::apply`].
//! Local edits build an op and apply it immediately; ops received from a peer go
//! through the same function. One code path for both sides means the merge
//! rules are what actually runs locally, not a parallel implementation.
//!
//! Each field carries its own HLC timestamp and replica id, so edits to
//! different fields on different devices never conflict. Concurrent edits to
//! the same field are resolved by `(hlc, replica_id)`, which is a total order:
//! the merge is commutative, associative and idempotent.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroize;

/// Maximum number of previous versions kept per entry.
pub const HISTORY_DEPTH: usize = 10;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Hybrid logical clock: monotonic timestamps that survive wall-clock skew.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
}

impl Hlc {
    pub const ZERO: Hlc = Hlc {
        wall_ms: 0,
        counter: 0,
    };
}

/// Clock of a single replica.
#[derive(Debug, Clone, Default)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    pub fn tick(&mut self) -> Hlc {
        self.tick_at(now_ms())
    }

    pub fn tick_at(&mut self, wall_ms: u64) -> Hlc {
        if wall_ms > self.last.wall_ms {
            self.last = Hlc {
                wall_ms,
                counter: 0,
            };
        } else {
            self.last.counter = self.last.counter.saturating_add(1);
        }
        self.last
    }

    /// Adopt a timestamp coming from another replica.
    pub fn observe(&mut self, other: Hlc) {
        if other > self.last {
            self.last = other;
        }
    }
}

/// A field value together with its version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldVersion<T> {
    pub value: T,
    pub hlc: Hlc,
    pub replica: Uuid,
}

impl<T> FieldVersion<T> {
    pub fn new(value: T, hlc: Hlc, replica: Uuid) -> Self {
        Self {
            value,
            hlc,
            replica,
        }
    }

    pub fn version(&self) -> (Hlc, Uuid) {
        (self.hlc, self.replica)
    }
}

/// A previous entry state kept for undo/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub at: Hlc,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub name: FieldVersion<String>,
    pub username: FieldVersion<String>,
    pub password: FieldVersion<String>,
    pub url: FieldVersion<Option<String>>,
    pub notes: FieldVersion<Option<String>>,
    pub tags: FieldVersion<Vec<String>>,
    pub tombstone: FieldVersion<bool>,
    #[serde(default)]
    pub history: Vec<Snapshot>,
}

impl Entry {
    pub fn is_deleted(&self) -> bool {
        self.tombstone.value
    }

    pub fn snapshot(&self, at: Hlc) -> Snapshot {
        Snapshot {
            at,
            name: self.name.value.clone(),
            username: self.username.value.clone(),
            password: self.password.value.clone(),
            url: self.url.value.clone(),
            notes: self.notes.value.clone(),
            tags: self.tags.value.clone(),
        }
    }
}

/// Secrets must not stay in freed heap memory after an entry is dropped.
impl Drop for Entry {
    fn drop(&mut self) {
        self.password.value.zeroize();
        if let Some(notes) = self.notes.value.as_mut() {
            notes.zeroize();
        }
        for snap in &mut self.history {
            snap.password.zeroize();
        }
    }
}

/// Editable view of an entry (what the TUI works with).
#[derive(Debug, Clone, Default)]
pub struct Draft {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Comma-separated tags.
    pub tags: String,
}

impl Draft {
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            name: entry.name.value.clone(),
            username: entry.username.value.clone(),
            password: entry.password.value.clone(),
            url: entry.url.value.clone().unwrap_or_default(),
            notes: entry.notes.value.clone().unwrap_or_default(),
            tags: entry.tags.value.join(", "),
        }
    }

    pub fn tag_list(&self) -> Vec<String> {
        self.tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Explicitly wipe secrets. Drafts are short-lived UI state and carry no
    /// `Drop` impl, because that would forbid struct-update syntax and partial
    /// moves in callers.
    pub fn wipe(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
    }
}

/// A device allowed to sync this vault (populated from M3 onward).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub name: String,
    pub replica_id: Uuid,
    pub added_at_ms: u64,
}

/// The subset of an entry's fields that an op actually changes.
///
/// `Option<T>` means "not touched by this op"; for fields whose value is itself
/// optional (`url`, `notes`), the outer `Option` is "touched" and the inner one
/// is the new value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EntryPatch {
    pub name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

impl EntryPatch {
    pub fn from_draft(draft: &Draft) -> Self {
        Self {
            name: Some(draft.name.clone()),
            username: Some(draft.username.clone()),
            password: Some(draft.password.clone()),
            url: Some(non_empty(&draft.url)),
            notes: Some(non_empty(&draft.notes)),
            tags: Some(draft.tag_list()),
        }
    }

    /// Only the fields whose value differs from the current entry.
    pub fn diff(entry: &Entry, draft: &Draft) -> Self {
        let mut patch = Self::default();
        if entry.name.value != draft.name {
            patch.name = Some(draft.name.clone());
        }
        if entry.username.value != draft.username {
            patch.username = Some(draft.username.clone());
        }
        if entry.password.value != draft.password {
            patch.password = Some(draft.password.clone());
        }
        let url = non_empty(&draft.url);
        if entry.url.value != url {
            patch.url = Some(url);
        }
        let notes = non_empty(&draft.notes);
        if entry.notes.value != notes {
            patch.notes = Some(notes);
        }
        let tags = draft.tag_list();
        if entry.tags.value != tags {
            patch.tags = Some(tags);
        }
        patch
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.url.is_none()
            && self.notes.is_none()
            && self.tags.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OpAction {
    Upsert { entry_id: Uuid, patch: EntryPatch },
    Delete { entry_id: Uuid },
}

/// A single mutation. Ops are immutable, idempotent when replayed and totally
/// ordered by `(hlc, replica, seq)` for diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Op {
    pub id: Uuid,
    pub replica: Uuid,
    pub seq: u64,
    pub hlc: Hlc,
    pub action: OpAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub schema: u16,
    /// Devices known to this vault. Populated by pairing; not used for
    /// authorization yet (any holder of the DEK can sync).
    #[serde(default)]
    pub devices: Vec<DeviceRecord>,
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub oplog: Vec<Op>,
}

pub const SCHEMA_VERSION: u16 = 1;

impl Vault {
    pub fn new() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            devices: Vec::new(),
            entries: Vec::new(),
            oplog: Vec::new(),
        }
    }

    pub fn visible(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| !e.is_deleted())
    }

    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    fn next_seq(&self, replica: Uuid) -> u64 {
        self.oplog
            .iter()
            .filter(|op| op.replica == replica)
            .map(|op| op.seq)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// Record a locally produced op in the log and apply it.
    pub fn record(&mut self, action: OpAction, hlc: Hlc, replica: Uuid) -> Op {
        let op = Op {
            id: Uuid::now_v7(),
            replica,
            seq: self.next_seq(replica),
            hlc,
            action,
        };
        self.apply(&op);
        op
    }

    /// Apply an op from any source. Idempotent: an op id already in the log is
    /// ignored, so replaying a whole log is harmless.
    pub fn apply(&mut self, op: &Op) -> bool {
        if self.oplog.iter().any(|existing| existing.id == op.id) {
            return false;
        }
        let changed = match &op.action {
            OpAction::Upsert { entry_id, patch } => self.apply_upsert(*entry_id, patch, op),
            OpAction::Delete { entry_id } => self.apply_delete(*entry_id, op),
        };
        self.oplog.push(op.clone());
        changed
    }

    fn apply_upsert(&mut self, id: Uuid, patch: &EntryPatch, op: &Op) -> bool {
        if self.get(id).is_none() {
            self.entries.push(new_entry(id, patch, op));
            return true;
        }

        let Some(entry) = self.get_mut(id) else {
            return false;
        };
        let incoming = (op.hlc, op.replica);
        let before = entry.snapshot(op.hlc);
        let mut changed = false;

        macro_rules! merge {
            ($field:ident, $value:expr) => {
                if let Some(value) = $value {
                    if incoming > entry.$field.version() {
                        entry.$field.value = value;
                        entry.$field.hlc = op.hlc;
                        entry.$field.replica = op.replica;
                        changed = true;
                    }
                }
            };
        }
        merge!(name, patch.name.clone());
        merge!(username, patch.username.clone());
        merge!(password, patch.password.clone());
        merge!(url, patch.url.clone());
        merge!(notes, patch.notes.clone());
        merge!(tags, patch.tags.clone());

        if changed {
            entry.history.insert(0, before);
            entry.history.truncate(HISTORY_DEPTH);
        }
        changed
    }

    fn apply_delete(&mut self, id: Uuid, op: &Op) -> bool {
        let Some(entry) = self.get_mut(id) else {
            return false;
        };
        if entry.tombstone.value || (op.hlc, op.replica) <= entry.tombstone.version() {
            return false;
        }
        entry.tombstone = FieldVersion::new(true, op.hlc, op.replica);
        true
    }

    /// Create an entry from a draft.
    pub fn add(&mut self, draft: &Draft, hlc: Hlc, replica: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        let patch = EntryPatch::from_draft(draft);
        self.record(
            OpAction::Upsert {
                entry_id: id,
                patch,
            },
            hlc,
            replica,
        );
        id
    }

    /// Update an entry. Only changed fields are touched. Returns true if
    /// anything changed.
    pub fn update(&mut self, id: Uuid, draft: &Draft, hlc: Hlc, replica: Uuid) -> bool {
        let Some(entry) = self.get(id) else {
            return false;
        };
        let patch = EntryPatch::diff(entry, draft);
        if patch.is_empty() {
            return false;
        }
        self.record(
            OpAction::Upsert {
                entry_id: id,
                patch,
            },
            hlc,
            replica,
        );
        true
    }

    /// Mark an entry deleted (tombstone, not a physical removal).
    pub fn delete(&mut self, id: Uuid, hlc: Hlc, replica: Uuid) -> bool {
        let Some(entry) = self.get(id) else {
            return false;
        };
        if entry.tombstone.value {
            return false;
        }
        self.record(OpAction::Delete { entry_id: id }, hlc, replica);
        true
    }

    /// Clone an entry under a new id. A clone is an ordinary insert, so it
    /// needs no special support in the merge.
    pub fn clone_entry(&mut self, id: Uuid, hlc: Hlc, replica: Uuid) -> Option<Uuid> {
        let src = self.get(id)?.clone();
        let new_id = Uuid::now_v7();
        let mut draft = Draft::from_entry(&src);
        draft.name = format!("{} (copy)", src.name.value);
        let patch = EntryPatch::from_draft(&draft);
        draft.wipe();
        self.record(
            OpAction::Upsert {
                entry_id: new_id,
                patch,
            },
            hlc,
            replica,
        );
        Some(new_id)
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a brand-new entry from the first op that mentions it. Fields the op
/// does not touch start at [`Hlc::ZERO`], so any later op wins over them.
fn new_entry(id: Uuid, patch: &EntryPatch, op: &Op) -> Entry {
    fn field<T>(value: T, present: bool, op: &Op) -> FieldVersion<T> {
        FieldVersion {
            value,
            hlc: if present { op.hlc } else { Hlc::ZERO },
            replica: op.replica,
        }
    }
    Entry {
        id,
        name: field(
            patch.name.clone().unwrap_or_default(),
            patch.name.is_some(),
            op,
        ),
        username: field(
            patch.username.clone().unwrap_or_default(),
            patch.username.is_some(),
            op,
        ),
        password: field(
            patch.password.clone().unwrap_or_default(),
            patch.password.is_some(),
            op,
        ),
        url: field(patch.url.clone().flatten(), patch.url.is_some(), op),
        notes: field(patch.notes.clone().flatten(), patch.notes.is_some(), op),
        tags: field(
            patch.tags.clone().unwrap_or_default(),
            patch.tags.is_some(),
            op,
        ),
        tombstone: FieldVersion::new(false, Hlc::ZERO, op.replica),
        history: Vec::new(),
    }
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
#[path = "tests/model.rs"]
mod tests;
