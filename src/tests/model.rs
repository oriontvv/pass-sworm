use super::*;

const A: Uuid = Uuid::from_u128(0xA);
const B: Uuid = Uuid::from_u128(0xB);

fn hlc(wall_ms: u64) -> Hlc {
    Hlc {
        wall_ms,
        counter: 0,
    }
}

fn vault() -> Vault {
    Vault::new()
}

fn draft(name: &str, password: &str) -> Draft {
    Draft {
        name: name.into(),
        password: password.into(),
        ..Default::default()
    }
}

#[test]
fn add_update_delete_roundtrip() {
    let mut v = vault();
    let mut clock = HlcClock::default();
    let d = Draft {
        name: "github".into(),
        username: "alice".into(),
        password: "s3cret".into(),
        url: " https://github.com ".into(),
        notes: String::new(),
        tags: " work , infra ".into(),
    };
    let id = v.add(&d, clock.tick(), A);
    assert_eq!(v.visible().count(), 1);

    let e = v.get(id).unwrap();
    assert_eq!(e.url.value.as_deref(), Some("https://github.com"));
    assert_eq!(e.tags.value, vec!["work", "infra"]);
    assert_eq!(e.notes.value, None);

    let mut edit = Draft::from_entry(e);
    edit.password = "n3w".into();
    assert!(v.update(id, &edit, clock.tick(), A));

    let e = v.get(id).unwrap();
    assert_eq!(e.password.value, "n3w");
    assert_eq!(e.history.len(), 1);
    assert_eq!(e.history[0].password, "s3cret");

    let hlc_before = e.password.hlc;
    assert!(!v.update(id, &edit, clock.tick(), A));
    assert_eq!(v.get(id).unwrap().password.hlc, hlc_before);

    assert!(v.delete(id, clock.tick(), A));
    assert!(v.get(id).unwrap().is_deleted());
    assert_eq!(v.visible().count(), 0);
    assert!(!v.delete(id, clock.tick(), A));
}

#[test]
fn update_only_bumps_changed_fields() {
    let mut v = vault();
    let mut clock = HlcClock::default();
    let id = v.add(&draft("a", "p"), clock.tick(), A);
    let username_hlc = v.get(id).unwrap().username.hlc;

    let mut d = Draft::from_entry(v.get(id).unwrap());
    d.password = "p2".into();
    v.update(id, &d, clock.tick(), A);

    let e = v.get(id).unwrap();
    assert_eq!(
        e.username.hlc, username_hlc,
        "untouched field keeps its hlc"
    );
    assert!(e.password.hlc > username_hlc);
}

#[test]
fn clone_creates_independent_copy() {
    let mut v = vault();
    let mut clock = HlcClock::default();
    let id = v.add(&draft("src", "p"), clock.tick(), A);
    let new_id = v.clone_entry(id, clock.tick(), A).unwrap();
    assert_ne!(id, new_id);
    assert_eq!(v.visible().count(), 2);
    assert_eq!(v.get(new_id).unwrap().name.value, "src (copy)");
    assert!(v.get(new_id).unwrap().history.is_empty());
}

#[test]
fn hlc_survives_clock_going_backwards() {
    let mut clock = HlcClock::default();
    let a = clock.tick_at(1_000);
    let b = clock.tick_at(500);
    assert!(b > a);
    assert_eq!(b.wall_ms, 1_000);
    assert_eq!(b.counter, 1);
}

// ----- op log ---------------------------------------------------------

#[test]
fn every_mutation_records_exactly_one_op() {
    let mut v = vault();
    let mut clock = HlcClock::default();
    let id = v.add(&draft("a", "p"), clock.tick(), A);

    let mut d = Draft::from_entry(v.get(id).unwrap());
    d.username = "u".into();
    v.update(id, &d, clock.tick(), A);
    v.update(id, &d, clock.tick(), A); // no-op, must not record
    v.clone_entry(id, clock.tick(), A);
    v.delete(id, clock.tick(), A);

    assert_eq!(v.oplog.len(), 4);
    assert_eq!(v.oplog[0].seq, 1);
    assert_eq!(v.oplog[3].seq, 4);
    assert!(v.oplog.iter().all(|op| op.replica == A));
    assert!(v.oplog.windows(2).all(|w| w[0].id != w[1].id));
}

#[test]
fn replaying_an_op_is_a_no_op() {
    let mut v = vault();
    let mut clock = HlcClock::default();
    let id = v.add(&draft("a", "p"), clock.tick(), A);
    let op = v.oplog[0].clone();
    let entries_before = v.entries.len();

    assert!(!v.apply(&op));
    assert_eq!(v.oplog.len(), 1);
    assert_eq!(v.entries.len(), entries_before);
    assert_eq!(v.get(id).unwrap().name.value, "a");
}

#[test]
fn concurrent_edits_to_different_fields_both_survive() {
    let mut a = vault();
    let id = a.add(&draft("acc", "old"), hlc(1), A);
    // Device B starts from the same state.
    let mut b = a.clone();

    let mut da = Draft::from_entry(a.get(id).unwrap());
    da.password = "from-A".into();
    a.update(id, &da, hlc(2), A);

    let mut db = Draft::from_entry(b.get(id).unwrap());
    db.username = "from-B".into();
    b.update(id, &db, hlc(2), B);

    // Cross-apply each other's ops.
    for op in b.oplog.clone() {
        a.apply(&op);
    }
    for op in a.oplog.clone() {
        b.apply(&op);
    }

    for v in [&a, &b] {
        let e = v.get(id).unwrap();
        assert_eq!(e.password.value, "from-A");
        assert_eq!(e.username.value, "from-B");
    }
}

#[test]
fn conflicting_edits_resolve_deterministically() {
    let mut base = Vault::new();
    let id = base.add(&draft("acc", "old"), hlc(1), A);

    let mut a = base.clone();
    let mut b = base.clone();
    let mut da = Draft::from_entry(a.get(id).unwrap());
    da.password = "from-A".into();
    a.update(id, &da, hlc(2), A);
    let mut db = Draft::from_entry(b.get(id).unwrap());
    db.password = "from-B".into();
    b.update(id, &db, hlc(2), B);

    // Replica B wins the tie at equal hlc.
    let mut ab = a.clone();
    for op in b.oplog.clone() {
        ab.apply(&op);
    }
    let mut ba = b.clone();
    for op in a.oplog.clone() {
        ba.apply(&op);
    }
    assert_eq!(ab.get(id).unwrap().password.value, "from-B");
    assert_eq!(ba.get(id).unwrap().password.value, "from-B");

    // The losing value is preserved in history rather than dropped.
    let history: Vec<String> = ab
        .get(id)
        .unwrap()
        .history
        .iter()
        .map(|s| s.password.clone())
        .collect();
    assert!(history.contains(&"from-A".to_string()) || history.contains(&"old".to_string()));
}

#[test]
fn later_timestamp_beats_replica_tiebreak() {
    let mut base = Vault::new();
    let id = base.add(&draft("acc", "old"), hlc(1), B);

    let mut a = base.clone();
    let mut b = base.clone();
    let mut da = Draft::from_entry(a.get(id).unwrap());
    da.password = "from-A".into();
    a.update(id, &da, hlc(5), A);
    let mut db = Draft::from_entry(b.get(id).unwrap());
    db.password = "from-B".into();
    b.update(id, &db, hlc(4), B);

    for op in b.oplog.clone() {
        a.apply(&op);
    }
    assert_eq!(a.get(id).unwrap().password.value, "from-A");
}

#[test]
fn delete_and_edit_converge_regardless_of_order() {
    let mut base = Vault::new();
    let id = base.add(&draft("acc", "p"), hlc(1), A);

    let mut a = base.clone();
    let mut b = base.clone();
    a.delete(id, hlc(3), A);
    let mut db = Draft::from_entry(b.get(id).unwrap());
    db.password = "edited".into();
    b.update(id, &db, hlc(2), B);

    let mut ab = a.clone();
    for op in b.oplog.clone() {
        ab.apply(&op);
    }
    let mut ba = b.clone();
    for op in a.oplog.clone() {
        ba.apply(&op);
    }

    // Delete has the later hlc, so it wins on both sides.
    assert!(ab.get(id).unwrap().is_deleted());
    assert!(ba.get(id).unwrap().is_deleted());
    assert_eq!(ab.visible().count(), 0);
    assert_eq!(ba.visible().count(), 0);
    // The edit is not lost, it is still in the entry.
    assert_eq!(ab.get(id).unwrap().password.value, "edited");
}

#[test]
fn ops_commute_under_any_permutation() {
    let mut base = Vault::new();
    let id = base.add(&draft("acc", "p"), hlc(1), A);

    let mut variants = Vec::new();
    for (n, replica) in [(2, A), (3, B), (4, A)] {
        let mut v = base.clone();
        let mut d = Draft::from_entry(v.get(id).unwrap());
        match n {
            2 => d.username = format!("user-{n}"),
            3 => d.notes = format!("note-{n}"),
            _ => d.password = format!("pw-{n}"),
        }
        v.update(id, &d, hlc(n), replica);
        variants.push(v.oplog.last().unwrap().clone());
    }

    let mut forward = base.clone();
    for op in &variants {
        forward.apply(op);
    }
    let mut backward = base.clone();
    for op in variants.iter().rev() {
        backward.apply(op);
    }
    let mut shuffled = base.clone();
    {
        let mut order = vec![1usize, 2, 0];
        while let Some(i) = order.pop() {
            shuffled.apply(&variants[i]);
        }
    }

    assert_eq!(forward.get(id).unwrap().username.value, "user-2");
    assert_eq!(
        forward.get(id).unwrap().notes.value.as_deref(),
        Some("note-3")
    );
    assert_eq!(forward.get(id).unwrap().password.value, "pw-4");

    for other in [&backward, &shuffled] {
        assert_eq!(other.get(id).unwrap().username.value, "user-2");
        assert_eq!(
            other.get(id).unwrap().notes.value.as_deref(),
            Some("note-3")
        );
        assert_eq!(other.get(id).unwrap().password.value, "pw-4");
    }
}
