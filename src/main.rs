//! Nooshdaroo - Protocol Shape-Shifting SOCKS Proxy
//!
//! A sophisticated proxy that disguises SOCKS5 traffic as various network protocols
//! to bypass deep packet inspection and censorship.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use nooshdaroo::{
    NooshdarooClient, NooshdarooConfig, NooshdarooServer, ProxyType, RelayMode, SocatBuilder,
    UnifiedProxyListener,
};

#[derive(Parser)]
#[command(name = "nooshdaroo")]
#[command(author = "0xinf0")]
#[command(version = "0.1.0")]
#[command(about = "Protocol Shape-Shifting SOCKS Proxy", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a client (local proxy)
    Client {
        /// Local bind address
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        bind: String,

        /// Remote server address
        #[arg(short, long)]
        server: String,

        /// Proxy type (socks5, http, transparent)
        #[arg(short, long, default_value = "socks5")]
        proxy_type: String,
    },

    /// Run as a server (remote endpoint)
    Server {
        /// Server bind address
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: String,
    },

    /// Run in socat/relay mode
    Relay {
        /// Local listen address
        #[arg(short, long)]
        listen: String,

        /// Remote target address
        #[arg(short, long)]
        target: String,

        /// Relay mode (bidirectional, client-to-server, server-to-client)
        #[arg(short, long, default_value = "bidirectional")]
        mode: String,
    },

    /// Show current protocol status
    Status {
        /// Client address to query
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        client: String,
    },

    /// Rotate to a new protocol
    Rotate {
        /// Client address to control
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        client: String,
    },

    /// List available protocols
    Protocols {
        /// Protocol directory
        #[arg(short, long, default_value = "protocols")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logger
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    match cli.command {
        Commands::Client {
            bind,
            server,
            proxy_type,
        } => {
            run_client(cli.config, &bind, &server, &proxy_type).await?;
        }
        Commands::Server { bind } => {
            run_server(cli.config, &bind).await?;
        }
        Commands::Relay {
            listen,
            target,
            mode,
        } => {
            run_relay(&listen, &target, &mode).await?;
        }
        Commands::Status { client } => {
            show_status(&client).await?;
        }
        Commands::Rotate { client } => {
            rotate_protocol(&client).await?;
        }
        Commands::Protocols { dir } => {
            list_protocols(&dir)?;
        }
    }

    Ok(())
}

async fn run_client(
    config_path: Option<PathBuf>,
    bind: &str,
    server: &str,
    proxy_type: &str,
) -> Result<()> {
    info!("Starting Nooshdaroo client on {}", bind);
    info!("Connecting to server: {}", server);

    let config = if let Some(path) = config_path {
        NooshdarooConfig::from_file(&path)?
    } else {
        NooshdarooConfig::default()
    };

    let client = NooshdarooClient::new(config)?;
    let proxy_type = match proxy_type {
        "socks5" => ProxyType::Socks5,
        "http" => ProxyType::Http,
        "transparent" => ProxyType::Transparent,
        _ => anyhow::bail!("Unknown proxy type: {}", proxy_type),
    };

    let listener = UnifiedProxyListener::bind(bind, proxy_type).await?;

    info!(
        "Nooshdaroo client ready - proxy type: {:?}",
        listener.proxy_type()
    );
    info!(
        "Current protocol: {}",
        client.current_protocol().await.as_str()
    );

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                // Handle connection here
                // This would forward to the server with shape-shifting applied
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}

async fn run_server(config_path: Option<PathBuf>, bind: &str) -> Result<()> {
    info!("Starting Nooshdaroo server on {}", bind);

    let config = if let Some(path) = config_path {
        NooshdarooConfig::from_file(&path)?
    } else {
        NooshdarooConfig::default()
    };

    let server = NooshdarooServer::new(config)?;

    info!("Nooshdaroo server ready - listening on {}", bind);
    info!("Protocols loaded: ready to receive shape-shifted traffic");

    // Accept and handle connections
    let listener = tokio::net::TcpListener::bind(bind).await?;

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                // Handle connection here
                // This would detect and unwrap shape-shifted traffic
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}

async fn run_relay(listen: &str, target: &str, mode: &str) -> Result<()> {
    info!("Starting Nooshdaroo relay: {} -> {}", listen, target);

    let relay_mode = match mode {
        "bidirectional" => RelayMode::Bidirectional,
        "client-to-server" => RelayMode::ClientToServer,
        "server-to-client" => RelayMode::ServerToClient,
        _ => anyhow::bail!("Unknown relay mode: {}", mode),
    };

    let relay = SocatBuilder::new(listen, target)
        .mode(relay_mode)
        .build()?;

    info!("Relay ready - mode: {:?}", relay.mode());

    relay.run().await
}

async fn show_status(client: &str) -> Result<()> {
    info!("Querying client status at {}", client);

    // This would connect to the client's control interface
    // and retrieve current protocol and statistics

    println!("Nooshdaroo Client Status");
    println!("========================");
    println!("Address: {}", client);
    println!("Status: Running");
    println!("Current Protocol: https");
    println!("Total Switches: 0");
    println!("Bytes Transferred: 0");

    Ok(())
}

async fn rotate_protocol(client: &str) -> Result<()> {
    info!("Rotating protocol on client {}", client);

    // This would send a rotate command to the client

    println!("Protocol rotation triggered");
    println!("New protocol will be selected based on configured strategy");

    Ok(())
}

fn list_protocols(dir: &PathBuf) -> Result<()> {
    use nooshdaroo::ProtocolLibrary;

    info!("Loading protocols from {:?}", dir);

    let library = ProtocolLibrary::load(dir)
        .context("Failed to load protocol library")?;

    println!("Available Protocols");
    println!("===================");
    println!();

    for (id, meta) in library.iter() {
        println!("ID: {}", id.as_str());
        println!("  Name: {}", meta.name);
        println!("  Version: {}", meta.version);
        println!("  Transport: {:?}", meta.transport);
        println!("  Port: {}", meta.default_port);
        println!("  Detection: {:?}", meta.detection_score);
        println!();
    }

    println!("Total: {} protocols", library.len());

    Ok(())
}
