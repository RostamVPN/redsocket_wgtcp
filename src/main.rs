// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! redsocket-wgtcp — userspace WireGuard-over-TCP SOCKS5 client.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use rand::Rng;
use std::path::PathBuf;

use redsocket_wgtcp::config::Config;
use redsocket_wgtcp::wg::{self, WgPeer};

#[derive(Parser)]
#[command(
    name = "redsocket-wgtcp",
    about = "Userspace WireGuard-over-TCP client with a local SOCKS5 front-end",
    long_about = "Speaks the WGTCP carrier protocol entirely in userspace: no kernel \
                  module, no TUN device, no root. WireGuard crypto runs via boringtun \
                  and the tunnel's TCP/IP stack via smoltcp."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the client.
    Run {
        /// Path to the TOML configuration file.
        #[arg(short, long)]
        config: PathBuf,

        /// Override the SOCKS5 listen address.
        #[arg(long)]
        socks: Option<String>,
    },
    /// Generate a WireGuard keypair (base64, same format as `wg genkey`).
    Genkey,
    /// Print the public key for a private key read from stdin.
    Pubkey,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    match cli.command {
        Command::Genkey => genkey(),
        Command::Pubkey => pubkey(),
        Command::Run { config, socks } => run(config, socks).await,
    }
}

fn genkey() -> Result<()> {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;

    let public = WgPeer::public_key(&key);
    println!("private: {}", wg::key_to_base64(&key));
    println!("public:  {}", wg::key_to_base64(&public));
    Ok(())
}

fn pubkey() -> Result<()> {
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
        .context("read private key from stdin")?;
    let key = wg::parse_key(&input)?;
    println!("{}", wg::key_to_base64(&WgPeer::public_key(&key)));
    Ok(())
}

async fn run(config_path: PathBuf, socks_override: Option<String>) -> Result<()> {
    let mut cfg = Config::load(&config_path)?;
    if let Some(s) = socks_override {
        cfg.socks_listen = s;
    }

    let private_key = cfg.private_key_bytes()?;
    log::info!(
        "our key {} to peer {}",
        wg::key_label(&WgPeer::public_key(&private_key)),
        wg::key_label(&cfg.peer_public_key_bytes()?)
    );

    let (_tx, rx) = tokio::sync::watch::channel(false);
    redsocket_wgtcp::run_tunnel(cfg, rx).await
}
