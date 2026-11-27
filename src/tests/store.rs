use super::*;
use std::io::ErrorKind;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pass-sworm-test-{tag}-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn write_read_and_backup_rotation() {
    let dir = temp_dir("store");
    let path = dir.join("vault.psw");
    let store = VaultStore::open(&path).unwrap();

    store.write(b"one", 3).unwrap();
    assert_eq!(store.read().unwrap(), b"one");
    store.write(b"two", 3).unwrap();
    store.write(b"three", 3).unwrap();

    assert_eq!(store.read().unwrap(), b"three");
    assert_eq!(fs::read(with_suffix(&path, ".bak.1")).unwrap(), b"two");
    assert_eq!(fs::read(with_suffix(&path, ".bak.2")).unwrap(), b"one");
    assert!(!with_suffix(&path, ".bak.3").exists());

    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn second_instance_cannot_open_the_same_vault() {
    let dir = temp_dir("lock");
    let path = dir.join("vault.psw");
    let first = VaultStore::open(&path).unwrap();
    let second = VaultStore::open(&path);
    assert!(second.is_err(), "exclusive lock was not enforced");
    drop(first);
    assert!(VaultStore::open(&path).is_ok());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_file_is_an_error_not_a_panic() {
    let dir = temp_dir("missing");
    let store = VaultStore::open(dir.join("vault.psw")).unwrap();
    let err = store.read().unwrap_err();
    let io = err.downcast_ref::<std::io::Error>();
    assert!(matches!(io.map(|e| e.kind()), Some(ErrorKind::NotFound)));
    fs::remove_dir_all(&dir).ok();
}
