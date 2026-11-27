use super::*;
use crate::model::{Draft, HlcClock};
use tokio::io::{ReadHalf, WriteHalf, duplex, split};
use uuid::Uuid;

fn vault_with(name: &str, replica: u128) -> Vault {
    let mut vault = Vault::new();
    let mut clock = HlcClock::default();
    vault.add(
        &Draft {
            name: name.into(),
            password: format!("{name}-secret"),
            ..Default::default()
        },
        clock.tick(),
        Uuid::from_u128(replica),
    );
    vault
}

type Half = (
    ReadHalf<tokio::io::DuplexStream>,
    WriteHalf<tokio::io::DuplexStream>,
);

fn pipe() -> (Half, Half) {
    let (a, b) = duplex(64 * 1024);
    (split(a), split(b))
}

#[tokio::test]
async fn two_vaults_converge() {
    let dek = Key::random();
    let mut client = vault_with("github", 1);
    let mut server = vault_with("aws", 2);
    let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();

    let server_dek = dek.clone();
    let server_task = tokio::spawn(async move {
        let outcome = run_server(&mut sr, &mut sw, &mut server, &server_dek).await;
        (server, outcome)
    });
    let client_outcome = run_client(&mut cr, &mut cw, &mut client, &dek)
        .await
        .unwrap();
    let (server, server_outcome) = server_task.await.unwrap();
    let server_outcome = server_outcome.unwrap();

    assert_eq!(client_outcome.applied, 1);
    assert_eq!(server_outcome.applied, 1);
    assert_eq!(client.visible().count(), 2);
    assert_eq!(server.visible().count(), 2);
    assert_eq!(client.oplog.len(), 2);
    assert_eq!(server.oplog.len(), 2);
}

#[tokio::test]
async fn a_peer_with_a_different_dek_is_rejected_and_learns_nothing() {
    let mut client = vault_with("github", 1);
    let mut server = vault_with("aws", 2);
    let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();

    let server_dek = Key::random();
    let server_task = tokio::spawn(async move {
        let outcome = run_server(&mut sr, &mut sw, &mut server, &server_dek).await;
        (server, outcome)
    });
    let result = run_client(&mut cr, &mut cw, &mut client, &Key::random()).await;
    let message = format!("{:#}", result.unwrap_err());
    assert!(
        message.contains("authentication"),
        "unexpected error: {message}"
    );

    // A real client closes the stream after a failed handshake. Without this
    // the server would wait for the proof forever and the test would hang.
    drop(cw);
    drop(cr);

    let (server, outcome) = server_task.await.unwrap();
    assert!(outcome.is_err());
    assert_eq!(server.visible().count(), 1, "server absorbed nothing");
    assert_eq!(client.visible().count(), 1, "client absorbed nothing");
}

#[tokio::test]
async fn a_second_session_moves_nothing() {
    let dek = Key::random();
    let mut client = vault_with("github", 1);
    let mut server = vault_with("aws", 2);

    for round in 0..2 {
        let ((mut cr, mut cw), (mut sr, mut sw)) = pipe();
        let server_dek = dek.clone();
        let task = tokio::spawn(async move {
            let outcome = run_server(&mut sr, &mut sw, &mut server, &server_dek).await;
            (server, outcome)
        });
        let outcome = run_client(&mut cr, &mut cw, &mut client, &dek)
            .await
            .unwrap();
        let (back, server_outcome) = task.await.unwrap();
        server = back;
        let server_outcome = server_outcome.unwrap();
        if round == 1 {
            assert_eq!(outcome.applied, 0);
            assert_eq!(server_outcome.applied, 0);
            assert_eq!(outcome.received, 0, "nothing new to send back");
        }
    }
}

#[tokio::test]
async fn garbage_from_a_stranger_is_an_error_not_a_panic() {
    let dek = Key::random();
    let mut server = vault_with("aws", 2);
    let ((_cr, mut cw), (mut sr, mut sw)) = pipe();

    // A frame that claims to be 1 GiB, then silence.
    cw.write_all(&(1u32 << 30).to_be_bytes()).await.unwrap();
    let result = run_server(&mut sr, &mut sw, &mut server, &dek).await;
    assert!(result.is_err());
    assert_eq!(server.visible().count(), 1);
}

#[tokio::test]
async fn a_tampered_session_frame_is_rejected() {
    let dek = Key::random();
    let session = session_key(&dek, &[1u8; 32], &[2u8; 32]);
    let mut frame = seal(&session, b"payload").unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 1;
    assert!(open(&session, &frame).is_err());
}
