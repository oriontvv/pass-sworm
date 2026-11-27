use super::*;
use crate::model::{Draft, HlcClock};
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

async fn node() -> SyncNode {
    SyncNode::start(SecretKey::generate(), &NetConfig::isolated())
        .await
        .expect("cannot start a test node")
}

#[tokio::test]
async fn peers_find_each_other_by_endpoint_id_alone() {
    let dek = Key::random();
    let server = node().await;
    let client = node().await;
    // Out-of-band addressing stands in for DNS/mDNS; the sync call below
    // takes nothing but the endpoint id.
    client.remember(server.addr());

    let mut server_vault = vault_with("aws", 2);
    let mut client_vault = vault_with("github", 1);
    let server_id = server.id();

    let server_dek = dek.clone();
    let serving = tokio::spawn(async move {
        let outcome = server
            .serve(
                &mut server_vault,
                &server_dek,
                Duration::from_secs(20),
                |_| {},
            )
            .await;
        (server, server_vault, outcome)
    });

    let outcome = client
        .sync_with(server_id, &mut client_vault, &dek, Duration::from_secs(20))
        .await
        .expect("client sync");
    let (server, server_vault, served) = serving.await.unwrap();
    let served = served.expect("server sync");

    assert_eq!(outcome.applied, 1);
    assert_eq!(served.applied, 1);
    assert_eq!(client_vault.visible().count(), 2);
    assert_eq!(server_vault.visible().count(), 2);

    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn a_stranger_does_not_end_the_wait_and_learns_nothing() {
    let dek = Key::random();
    let server = node().await;
    let stranger = node().await;
    let friend = node().await;
    stranger.remember(server.addr());
    friend.remember(server.addr());

    let mut server_vault = vault_with("aws", 2);
    let server_id = server.id();
    let server_dek = dek.clone();
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = events.clone();
    let serving = tokio::spawn(async move {
        let outcome = server
            .serve(
                &mut server_vault,
                &server_dek,
                Duration::from_secs(30),
                move |e| seen.lock().unwrap().push(e.to_string()),
            )
            .await;
        (server, server_vault, outcome)
    });

    // Someone who knows the endpoint id but not the vault key is turned away.
    let mut stranger_vault = vault_with("evil", 9);
    let rejected = stranger
        .sync_with(
            server_id,
            &mut stranger_vault,
            &Key::random(),
            Duration::from_secs(10),
        )
        .await;
    assert!(rejected.is_err());
    assert_eq!(
        stranger_vault.visible().count(),
        1,
        "stranger received nothing"
    );

    // The listener is still waiting, and a real peer then succeeds.
    let mut friend_vault = vault_with("github", 1);
    let outcome = friend
        .sync_with(server_id, &mut friend_vault, &dek, Duration::from_secs(10))
        .await
        .expect("friend sync");
    let (server, server_vault, served) = serving.await.unwrap();
    served.expect("server sync");

    assert_eq!(outcome.applied, 1);
    assert_eq!(server_vault.visible().count(), 2);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.contains("session failed")),
        "the failed attempt must be reported"
    );

    stranger.close().await;
    friend.close().await;
    server.close().await;
}

#[tokio::test]
async fn an_unknown_endpoint_id_fails_cleanly() {
    let client = node().await;
    let mut vault = vault_with("x", 1);
    let nobody = SecretKey::generate().public();
    let result = client
        .sync_with(nobody, &mut vault, &Key::random(), Duration::from_secs(3))
        .await;
    assert!(result.is_err());
    client.close().await;
}
