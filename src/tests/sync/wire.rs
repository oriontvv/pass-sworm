use super::*;
use crate::model::{Hlc, OpAction};

fn op() -> Op {
    Op {
        id: Uuid::from_u128(7),
        replica: Uuid::from_u128(1),
        seq: 1,
        hlc: Hlc {
            wall_ms: 42,
            counter: 0,
        },
        action: OpAction::Delete {
            entry_id: Uuid::from_u128(9),
        },
    }
}

#[test]
fn roundtrip() {
    let dek = Key::random();
    let wire = seal_op(&dek, &op()).unwrap();
    assert_eq!(open_op(&dek, &wire).unwrap(), op());
}

#[test]
fn wrong_key_is_rejected() {
    let dek = Key::random();
    let wire = seal_op(&dek, &op()).unwrap();
    assert!(open_op(&Key::random(), &wire).is_err());
}

#[test]
fn envelope_cannot_be_relabelled() {
    let dek = Key::random();
    let mut wire = seal_op(&dek, &op()).unwrap();
    wire.id = Uuid::from_u128(8);
    assert!(open_op(&dek, &wire).is_err());
}

#[test]
fn ciphertext_does_not_leak_the_payload() {
    let dek = Key::random();
    let mut op = op();
    op.action = OpAction::Delete {
        entry_id: Uuid::from_u128(0xDEAD_BEEF),
    };
    let wire = seal_op(&dek, &op).unwrap();
    let haystack = wire.ciphertext.clone();
    assert!(
        !haystack
            .windows(4)
            .any(|w| w == 0xDEAD_BEEFu32.to_be_bytes())
    );
}
