# pass-sworm

A terminal password manager written in Rust. The vault is a single encrypted file, and your devices sync with each other directly over [iroh](https://github.com/n0-computer/iroh). Peers are addressed by endpoint id only: you never type or share an IP address.

## Features

- List, fuzzy-filter, add, edit, delete and clone entries in a ratatui TUI
- Copy a password to the clipboard; it is wiped after N seconds (default 30, configurable) unless you copied something else meanwhile
- Built-in password generator
- Per-entry version history with restore
- Vault encrypted with your master password (Argon2id + XChaCha20-Poly1305)
- Auto-lock after inactivity
- Peer-to-peer sync with per-field conflict resolution

## Build

```console
$ cargo build --release
$ ./target/release/pass-sworm --help
```

## Quick start

```console
$ pass-sworm                          # open the default vault (created on first run)
$ pass-sworm --vault ~/secrets/work.psw   # use a specific vault file
$ pass-sworm --config ./my-config.toml    # use a specific config file
```

On first run you are asked to choose a master password (at least 8 characters). There is no recovery if you forget it.

## Keys

| Key | Action |
|---|---|
| `j` / `k`, arrows | move selection |
| `g` / `G` | first / last entry |
| `/` | fuzzy filter (name, username, URL, tags) |
| `a` | add entry |
| `e`, `Enter` | edit entry |
| `c` | clone entry |
| `d` | delete entry (asks for confirmation) |
| `y` | copy password to the clipboard |
| `h` | view and restore previous versions |
| `Ctrl-G` | generate a password (in the editor) |
| `Ctrl-R` | show or hide secrets (in the editor) |
| `Ctrl-L` | lock the vault |
| `?` | help |
| `q`, `Ctrl-C` | quit |

## Configuration

The config file is optional. Every key has a default, and missing keys fall back to it.

```toml
[general]
vault = "~/.local/share/pass-sworm/vault.psw"   # empty = platform data directory
auto_lock_minutes = 10                          # 0 disables auto-lock
backups = 5                                     # rotated copies next to the vault

[clipboard]
clear_after_seconds = 30                        # 0 disables the wipe

[crypto]                                        # defaults for NEW vaults only
argon2_m_cost_kib = 65536
argon2_t_cost = 3
argon2_p_cost = 4

[generator]
length = 20
symbols = true
avoid_ambiguous = true                          # no Il1O0o
```

Existing vaults keep the KDF parameters stored in their header.

## Syncing devices

Each installation has its own identity (a replica id and an iroh keypair) in `<vault>.device`. The public half of the keypair is the endpoint id, the only thing you copy between devices.

**1. Pair.** Copy the encrypted vault file to the second device. It is useless without the master password. Each device creates its own identity on first use.

**2. Find the endpoint id.**

```console
$ pass-sworm devices
vault:       /home/me/.local/share/pass-sworm/vault.psw
device:      laptop
replica:     0198c1a2-...
endpoint id: 7f3a...9c21
```

**3. Sync.** Close the TUI first (sync takes the vault lock). On one device:

```console
$ pass-sworm sync --listen
endpoint id: 7f3a...9c21
on the other device run: pass-sworm sync --peer 7f3a...9c21
```

On the other:

```console
$ pass-sworm sync --peer 7f3a...9c21
Master password:
sync complete: 3 sent, 5 received, 5 applied, 0 rejected
```

Options:

- `--timeout <seconds>`: how long to wait (default 300)
- `--dht`: also publish to and resolve from the mainline DHT
- `--no-mdns`: disable local-network discovery
- `--password-stdin`: read the master password from stdin (scripts)

iroh finds the peer through DNS/pkarr, mDNS on the local network, optionally the DHT, then hole-punches, falling back to a relay. Only the relay URL is published, never your IP addresses.

### How conflicts are resolved

Every field of an entry carries its own timestamp. Edits to different fields on different devices both survive. Concurrent edits to the same field are resolved deterministically, and the losing value goes to the entry's history so you can restore it with `h`. Deleting and editing converge to the same result on every device.

## Security model

- The master password only feeds Argon2id. The derived key unwraps a random data key, so changing the password never invalidates synced data.
- The whole file header is authenticated, so KDF parameters cannot be downgraded.
- Sync peers must prove possession of the data key; a stranger who learns your endpoint id gets nothing.
- Not protected against malware running as your user while the vault is unlocked.
- The clipboard is a system resource: clipboard managers and cross-device clipboards may keep a copy.
- There is no per-device revocation yet.

## Development

```console
$ cargo test
$ cargo clippy --all-targets
```

Unit tests live in a `tests.rs` file next to the module they test (for `src/crypto.rs`, in `src/crypto/tests.rs`). End-to-end tests are in `tests/`. Tests that bind an iroh endpoint need real network access; they skip themselves when it is blocked.
