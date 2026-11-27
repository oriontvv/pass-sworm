use super::*;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("psw-dev-{tag}-{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn identity_is_stable_across_loads() {
    let dir = temp_dir("stable");
    let vault = dir.join("vault.psw");
    let first = DeviceIdentity::load_or_create(&vault).unwrap();
    let second = DeviceIdentity::load_or_create(&vault).unwrap();
    assert_eq!(first.replica, second.replica);
    assert!(!second.name.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn separate_installs_get_separate_replicas() {
    let dir = temp_dir("separate");
    let a = DeviceIdentity::load_or_create(&dir.join("a.psw")).unwrap();
    let b = DeviceIdentity::load_or_create(&dir.join("b.psw")).unwrap();
    assert_ne!(a.replica, b.replica);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn device_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("perms");
    let vault = dir.join("vault.psw");
    DeviceIdentity::load_or_create(&vault).unwrap();
    let mode = fs::metadata(sidecar_path(&vault))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "device file must not be group/world readable"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn endpoint_id_is_stable_and_unique_per_install() {
    let dir = temp_dir("endpoint");
    let a1 = DeviceIdentity::load_or_create(&dir.join("a.psw")).unwrap();
    let a2 = DeviceIdentity::load_or_create(&dir.join("a.psw")).unwrap();
    let b = DeviceIdentity::load_or_create(&dir.join("b.psw")).unwrap();
    assert_eq!(a1.endpoint_id().unwrap(), a2.endpoint_id().unwrap());
    assert_ne!(a1.endpoint_id().unwrap(), b.endpoint_id().unwrap());
    // The id has to survive being copied by hand and parsed back.
    let text = a1.endpoint_id().unwrap().to_string();
    assert_eq!(
        text.parse::<iroh::EndpointId>().unwrap(),
        a1.endpoint_id().unwrap()
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_device_file_without_a_key_is_upgraded_in_place() {
    let dir = temp_dir("upgrade");
    let vault = dir.join("vault.psw");
    let replica = Uuid::from_u128(0xABCD);
    // What an installation from before sync support looks like.
    fs::write(
        sidecar_path(&vault),
        format!("replica = \"{replica}\"\nname = \"old-laptop\"\n"),
    )
    .unwrap();

    let upgraded = DeviceIdentity::load_or_create(&vault).unwrap();
    assert_eq!(upgraded.replica, replica, "replica id must not change");
    assert_eq!(upgraded.name, "old-laptop");
    assert!(!upgraded.secret.is_empty());

    let again = DeviceIdentity::load_or_create(&vault).unwrap();
    assert_eq!(
        again.endpoint_id().unwrap(),
        upgraded.endpoint_id().unwrap()
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn debug_output_never_contains_the_secret() {
    let dir = temp_dir("redact");
    let device = DeviceIdentity::load_or_create(&dir.join("vault.psw")).unwrap();
    let printed = format!("{device:?}");
    assert!(!printed.contains(&device.secret));
    assert!(printed.contains("redacted"));
    fs::remove_dir_all(&dir).ok();
}
