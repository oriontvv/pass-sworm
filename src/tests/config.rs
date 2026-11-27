use super::*;

#[test]
fn defaults_match_the_design() {
    let c = Config::default();
    assert_eq!(c.clipboard.clear_after_seconds, 30);
    assert_eq!(c.general.auto_lock_minutes, 10);
    assert_eq!(c.general.backups, 5);
    assert_eq!(c.generator.length, 20);
    assert_eq!(c.crypto.kdf_params(), KdfParams::default());
}

#[test]
fn partial_toml_keeps_defaults_for_missing_keys() {
    let c: Config = toml::from_str("[clipboard]\nclear_after_seconds = 5\n").unwrap();
    assert_eq!(c.clipboard.clear_after_seconds, 5);
    assert_eq!(c.general.auto_lock_minutes, 10);
    assert_eq!(c.crypto.kdf_params(), KdfParams::default());
}

#[test]
fn missing_file_falls_back_to_defaults() {
    let dir = std::env::temp_dir().join(format!("psw-cfg-{}", uuid::Uuid::now_v7()));
    let c = Config::load(Some(&dir.join("nope.toml"))).unwrap();
    assert_eq!(c.clipboard.clear_after_seconds, 30);
}

#[test]
fn explicit_vault_path_is_honoured() {
    let mut c = Config::default();
    c.general.vault = "/tmp/somewhere/vault.psw".into();
    assert_eq!(
        c.vault_path().unwrap(),
        PathBuf::from("/tmp/somewhere/vault.psw")
    );
}
