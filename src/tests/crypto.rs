use super::*;

fn fast_params() -> KdfParams {
    // 8 MiB / 1 pass: fast enough for tests, still valid.
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn kek_is_deterministic_for_same_inputs() {
    let salt = [7u8; SALT_LEN];
    let a = derive_kek("correct horse", &salt, fast_params()).unwrap();
    let b = derive_kek("correct horse", &salt, fast_params()).unwrap();
    assert_eq!(a.bytes(), b.bytes());
}

#[test]
fn kek_differs_on_salt_and_password() {
    let a = derive_kek("pw", &[1u8; SALT_LEN], fast_params()).unwrap();
    let b = derive_kek("pw", &[2u8; SALT_LEN], fast_params()).unwrap();
    let c = derive_kek("pw2", &[1u8; SALT_LEN], fast_params()).unwrap();
    assert_ne!(a.bytes(), b.bytes());
    assert_ne!(a.bytes(), c.bytes());
}

#[test]
fn seal_open_roundtrip_and_aad_binding() {
    let key = Key::random();
    let nonce = random_bytes::<NONCE_LEN>();
    let ct = seal(&key, &nonce, b"header", b"secret").unwrap();
    assert_eq!(open(&key, &nonce, b"header", &ct).unwrap(), b"secret");
    assert!(open(&key, &nonce, b"other-aad", &ct).is_err());
}

#[test]
fn rejects_weak_or_absurd_kdf_params() {
    assert!(
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 4
        }
        .validate()
        .is_err()
    );
    assert!(
        KdfParams {
            m_cost_kib: 8192,
            t_cost: 0,
            p_cost: 1
        }
        .validate()
        .is_err()
    );
    assert!(
        KdfParams {
            m_cost_kib: 8192,
            t_cost: 1,
            p_cost: 65
        }
        .validate()
        .is_err()
    );
    assert!(
        KdfParams {
            m_cost_kib: 4 * 1024 * 1024,
            t_cost: 1,
            p_cost: 1
        }
        .validate()
        .is_err()
    );
    assert!(fast_params().validate().is_ok());
}

#[test]
fn subkeys_are_domain_separated() {
    let dek = Key::random();
    let a = dek.derive(CTX_ENTRIES);
    let b = dek.derive(CTX_OPS);
    assert_ne!(a.bytes(), b.bytes());
    assert_ne!(a.bytes(), dek.bytes());
}

#[test]
fn session_keys_depend_on_both_nonces_and_the_dek() {
    let dek = Key::random();
    let c = [1u8; 32];
    let s = [2u8; 32];
    let a = derive_session_key(&dek, "ctx", &[&c, &s]);
    let b = derive_session_key(&dek, "ctx", &[&c, &s]);
    let other_nonce = derive_session_key(&dek, "ctx", &[&s, &c]);
    let other_dek = derive_session_key(&Key::random(), "ctx", &[&c, &s]);
    assert_eq!(a.bytes(), b.bytes());
    assert_ne!(a.bytes(), other_nonce.bytes());
    assert_ne!(a.bytes(), other_dek.bytes());
}

#[test]
fn keyed_mac_binds_every_part() {
    let key = Key::random();
    let mac = keyed_mac(&key, &[b"client", b"nonce"]);
    assert_eq!(mac, keyed_mac(&key, &[b"client", b"nonce"]));
    assert_ne!(mac, keyed_mac(&key, &[b"server", b"nonce"]));
    assert_ne!(mac, keyed_mac(&key, &[b"client", b"other"]));
}
