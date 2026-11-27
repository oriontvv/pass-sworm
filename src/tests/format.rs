use super::*;
use crate::model::Draft;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn sample_vault() -> Vault {
    let mut v = Vault::new();
    v.add(
        &Draft {
            name: "github".into(),
            username: "alice".into(),
            password: "s3cret".into(),
            ..Default::default()
        },
        crate::model::Hlc {
            wall_ms: 1,
            counter: 0,
        },
        uuid::Uuid::from_u128(1),
    );
    v
}

#[test]
fn roundtrip_preserves_entries() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    let opened = unlock(&bytes, "pw").unwrap();
    assert_eq!(opened.vault.visible().count(), 1);
    let e = opened.vault.visible().next().unwrap();
    assert_eq!(e.name.value, "github");
    assert_eq!(e.password.value, "s3cret");
}

#[test]
fn wrong_password_is_rejected() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    assert!(unlock(&bytes, "pw2").is_err());
}

#[test]
fn every_header_region_is_authenticated() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    // Flip one bit in each byte of the header and make sure nothing opens.
    for i in 0..HEADER_LEN {
        let mut tampered = bytes.clone();
        tampered[i] ^= 0x01;
        assert!(
            unlock(&tampered, "pw").is_err(),
            "tampering with byte {i} of the header went unnoticed"
        );
    }
}

#[test]
fn body_tampering_is_rejected() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(unlock(&tampered, "pw").is_err());
}

#[test]
fn downgrading_kdf_parameters_is_rejected() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    let mut tampered = bytes.clone();
    // m_cost = 8 KiB instead of 8192 KiB would make brute force cheap.
    tampered[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&8u32.to_le_bytes());
    assert!(unlock(&tampered, "pw").is_err());
}

#[test]
fn reseal_keeps_dek_and_rotates_body_nonce() {
    let (bytes, opened) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    let again = reseal(&opened.vault, &opened.dek, &opened.header).unwrap();
    let head_a = Header::from_bytes(&bytes[..HEADER_LEN]).unwrap();
    let head_b = Header::from_bytes(&again[..HEADER_LEN]).unwrap();
    assert_ne!(head_a.body_nonce, head_b.body_nonce);
    assert_eq!(head_a.wrapped_dek, head_b.wrapped_dek);
    assert_eq!(head_a.salt, head_b.salt);
    // The re-sealed file still opens with the same password.
    assert!(unlock(&again, "pw").is_ok());
}

#[test]
fn truncated_file_is_rejected() {
    let (bytes, _) = create(sample_vault(), "pw", fast_kdf()).unwrap();
    assert!(unlock(&bytes[..10], "pw").is_err());
    assert!(unlock(&bytes[..HEADER_LEN], "pw").is_err());
}
