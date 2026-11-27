use super::*;
use crate::model::{Draft, HlcClock};
use uuid::Uuid;

const A: Uuid = Uuid::from_u128(0xA);
const B: Uuid = Uuid::from_u128(0xB);

#[test]
fn one_round_converges_both_logs() {
    let dek = Key::random();
    let mut a = Vault::new();
    let mut b = Vault::new();
    let mut ca = HlcClock::default();
    let mut cb = HlcClock::default();
    a.add(
        &Draft {
            name: "github".into(),
            ..Default::default()
        },
        ca.tick(),
        A,
    );
    b.add(
        &Draft {
            name: "aws".into(),
            ..Default::default()
        },
        cb.tick(),
        B,
    );
    b.add(
        &Draft {
            name: "gitlab".into(),
            ..Default::default()
        },
        cb.tick(),
        B,
    );

    let request = build_request(&a, &dek).unwrap();
    assert_eq!(request.ops.len(), 1);
    let (reply, report) = handle_request(&mut b, &dek, &request).unwrap();
    assert_eq!(report.applied, 1, "server absorbs the client op");

    let back = absorb(&mut a, &dek, &reply.ops);
    assert_eq!(back.applied, 2, "client absorbs the two server ops");

    assert_eq!(a.visible().count(), 3);
    assert_eq!(b.visible().count(), 3);
    assert_eq!(a.oplog.len(), 3);
    assert_eq!(b.oplog.len(), 3);
}

#[test]
fn a_second_round_is_a_no_op() {
    let dek = Key::random();
    let mut a = Vault::new();
    let mut b = Vault::new();
    let mut clock = HlcClock::default();
    a.add(
        &Draft {
            name: "x".into(),
            ..Default::default()
        },
        clock.tick(),
        A,
    );

    let request = build_request(&a, &dek).unwrap();
    let (reply, _) = handle_request(&mut b, &dek, &request).unwrap();
    absorb(&mut a, &dek, &reply.ops);

    let request = build_request(&a, &dek).unwrap();
    let (reply, report) = handle_request(&mut b, &dek, &request).unwrap();
    assert_eq!(report.applied, 0);
    assert!(reply.ops.is_empty(), "nothing new to send back");
}

#[test]
fn envelopes_from_a_foreign_vault_are_rejected() {
    let dek = Key::random();
    let other = Key::random();
    let mut a = Vault::new();
    let mut clock = HlcClock::default();
    a.add(
        &Draft {
            name: "x".into(),
            ..Default::default()
        },
        clock.tick(),
        A,
    );
    let request = build_request(&a, &dek).unwrap();

    let mut b = Vault::new();
    let (reply, report) = handle_request(&mut b, &other, &request).unwrap();
    assert_eq!(report.applied, 0);
    assert_eq!(report.rejected, 1);
    assert!(b.oplog.is_empty());
    assert!(reply.ops.is_empty());
}
