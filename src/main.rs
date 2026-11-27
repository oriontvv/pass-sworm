#![forbid(unsafe_code)]

mod tui;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};

use pass_sworm::config::Config;
use pass_sworm::device::DeviceIdentity;
use pass_sworm::format;
use pass_sworm::store::VaultStore;
use pass_sworm::sync::{NetConfig, SyncNode};

/// A TUI password manager with an encrypted vault.
#[derive(Debug, Parser)]
#[command(name = "pass-sworm", version, about)]
struct Cli {
    /// Path to the config file (default: platform config directory).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Path to the vault file (overrides the config).
    #[arg(long)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the interactive UI (the default).
    Tui,
    /// Sync with another device through iroh. Peers are addressed by endpoint id only.
    Sync(SyncArgs),
    /// Show this device's endpoint id and replica id.
    Devices,
}

#[derive(Debug, Args)]
struct SyncArgs {
    /// Endpoint id of the peer to sync with (see `pass-sworm devices` on that device).
    #[arg(long, conflicts_with = "listen")]
    peer: Option<String>,

    /// Wait for a peer to connect to this device.
    #[arg(long, conflicts_with = "peer")]
    listen: bool,

    /// How long to wait, in seconds.
    #[arg(long, default_value_t = 300)]
    timeout: u64,

    /// Also publish to and resolve from the mainline DHT.
    #[arg(long)]
    dht: bool,

    /// Disable mDNS discovery on the local network.
    #[arg(long)]
    no_mdns: bool,

    /// Read the master password from the first line of stdin instead of
    /// prompting on the terminal. Intended for scripts and tests.
    #[arg(long)]
    password_stdin: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;
    let vault_path = match cli.vault {
        Some(path) => path,
        None => cfg.vault_path()?,
    };

    match cli.command.unwrap_or(Command::Tui) {
        Command::Tui => {
            let store = VaultStore::open(vault_path.clone())?;
            let device = DeviceIdentity::load_or_create(&vault_path)?;
            tui::run(cfg, store, device)
        }
        Command::Devices => {
            let device = DeviceIdentity::load_or_create(&vault_path)?;
            println!("vault:       {}", vault_path.display());
            println!("device:      {}", device.name);
            println!("replica:     {}", device.replica);
            println!("endpoint id: {}", device.endpoint_id()?);
            Ok(())
        }
        Command::Sync(args) => cmd_sync(&cfg, &vault_path, args),
    }
}

fn cmd_sync(cfg: &Config, vault_path: &Path, args: SyncArgs) -> Result<()> {
    let timeout = Duration::from_secs(args.timeout.max(1));
    let peer = match (&args.peer, args.listen) {
        (Some(raw), false) => Some(
            raw.trim()
                .parse::<iroh::EndpointId>()
                .map_err(|e| anyhow!("invalid endpoint id: {e}"))?,
        ),
        (None, true) => None,
        _ => bail!("specify exactly one of --peer <endpoint-id> or --listen"),
    };

    // The store takes an exclusive lock, so sync cannot race a running TUI.
    let store = VaultStore::open(vault_path)?;
    if !store.exists() {
        bail!(
            "no vault at {}; run `pass-sworm` once to create it",
            vault_path.display()
        );
    }
    let device = DeviceIdentity::load_or_create(vault_path)?;

    let password = if args.password_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("cannot read the password from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password("Master password: ")?
    };
    let opened = format::unlock(&store.read()?, &password)?;
    let mut vault = opened.vault;

    let net = NetConfig {
        relay: true,
        mdns: !args.no_mdns,
        dht: args.dht,
        loopback_only: false,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(async {
        let node = SyncNode::start(device.secret_key()?, &net).await?;
        if !node.wait_online().await {
            eprintln!(
                "warning: relay is not reachable; only local-network peers can find this device"
            );
        }
        let result = match peer {
            Some(peer) => node.sync_with(peer, &mut vault, &opened.dek, timeout).await,
            None => {
                println!("endpoint id: {}", node.id());
                println!(
                    "on the other device run: pass-sworm sync --peer {}",
                    node.id()
                );
                node.serve(&mut vault, &opened.dek, timeout, |event| {
                    eprintln!("{event}")
                })
                .await
            }
        };
        node.close().await;
        result
    })?;

    let sealed = format::reseal(&vault, &opened.dek, &opened.header)?;
    store.write(&sealed, cfg.general.backups)?;
    println!("sync complete: {}", outcome.describe());
    Ok(())
}
