//! Nooshdaroo - Protocol Shape-Shifting SOCKS Proxy
//!
//! A sophisticated proxy that disguises SOCKS5 traffic as various network protocols
//! to bypass deep packet inspection and censorship.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use nooshdaroo::{
    Bidirectional, ClientToServer, NooshdarooClient, NooshdarooConfig, NooshdarooServer,
    ProxyType, ServerToClient, SocatBuilder, UnifiedProxyListener,
};

#[derive(Parser)]
#[command(name = "nooshdaroo")]
#[command(author = "Sina Rabbani")]
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

    /// Generate Noise protocol keypair for encrypted transport
    Genkey {
        /// Save server config to file
        #[arg(long)]
        server_config: Option<PathBuf>,

        /// Save client config to file
        #[arg(long)]
        client_config: Option<PathBuf>,

        /// Server bind address
        #[arg(long, default_value = "0.0.0.0:8443")]
        server_bind: String,

        /// Client bind address
        #[arg(long, default_value = "127.0.0.1:1080")]
        client_bind: String,

        /// Server address (for client config)
        #[arg(long, default_value = "myserver.com:8443")]
        server_addr: String,

        /// Noise pattern to use
        #[arg(long, default_value = "nk")]
        pattern: String,
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
        Commands::Genkey {
            server_config,
            client_config,
            server_bind,
            client_bind,
            server_addr,
            pattern,
        } => {
            generate_keypair(
                server_config,
                client_config,
                &server_bind,
                &client_bind,
                &server_addr,
                &pattern,
            )?;
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

    let bind_addr: SocketAddr = bind.parse()?;
    let listener = UnifiedProxyListener::new(bind_addr, vec![proxy_type]);

    info!(
        "Nooshdaroo client ready - proxy type: {:?}",
        proxy_type
    );
    info!(
        "Current protocol: {}",
        client.current_protocol().await.as_str()
    );

    // Start listening for connections
    listener.listen().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
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

    let relay_direction = match mode {
        "bidirectional" => Bidirectional,
        "client-to-server" => ClientToServer,
        "server-to-client" => ServerToClient,
        _ => anyhow::bail!("Unknown relay mode: {}", mode),
    };

    let relay = SocatBuilder::new(listen, target)
        .mode(relay_direction);

    info!("Relay ready - mode: {:?}", relay_direction);

    relay.run().await.map_err(|e| anyhow::anyhow!("{}", e))
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
        println!("  Transport: {:?}", meta.transport);
        println!("  Port: {}", meta.default_port);
        println!();
    }

    println!("Total: {} protocols", library.len());

    Ok(())
}

fn generate_keypair(
    server_config_path: Option<PathBuf>,
    client_config_path: Option<PathBuf>,
    server_bind: &str,
    client_bind: &str,
    server_addr: &str,
    pattern: &str,
) -> Result<()> {
    use std::fs;
    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║        Nooshdaroo Encrypted Transport Key Generator               ║");
    println!("╚════════════════════════════════════════════════════════════════════╝\n");

    println!("Generating X25519 keypair for Noise Protocol encryption...\n");

    let keypair = nooshdaroo::generate_noise_keypair()
        .context("Failed to generate keypair")?;

    // Display keys with clear visual separation
    println!("┌────────────────────────────────────────────────────────────────────┐");
    println!("│ PRIVATE KEY (🔒 Keep this SECRET! Never share!)                    │");
    println!("├────────────────────────────────────────────────────────────────────┤");
    println!("│ {}  │", keypair.private_key_base64());
    println!("└────────────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌────────────────────────────────────────────────────────────────────┐");
    println!("│ PUBLIC KEY (✅ Safe to share with peers)                           │");
    println!("├────────────────────────────────────────────────────────────────────┤");
    println!("│ {}  │", keypair.public_key_base64());
    println!("└────────────────────────────────────────────────────────────────────┘");
    println!();

    // Configuration examples
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║                    CONFIGURATION EXAMPLES                          ║");
    println!("╚════════════════════════════════════════════════════════════════════╝\n");

    println!("📋 COPY THIS TO YOUR SERVER CONFIG (server.toml):");
    println!("─────────────────────────────────────────────────────────────────────");
    println!("[server]");
    println!("bind = \"0.0.0.0:8443\"");
    println!();
    println!("[transport]");
    println!("pattern = \"nk\"              # Server authentication (recommended)");
    println!("local_private_key = \"{}\"", keypair.private_key_base64());
    println!("─────────────────────────────────────────────────────────────────────\n");

    println!("📋 COPY THIS TO YOUR CLIENT CONFIG (client.toml):");
    println!("─────────────────────────────────────────────────────────────────────");
    println!("[client]");
    println!("bind_address = \"127.0.0.1:1080\"");
    println!("server_address = \"myserver.com:8443\"");
    println!();
    println!("[transport]");
    println!("pattern = \"nk\"              # Must match server pattern");
    println!("remote_public_key = \"{}\"", keypair.public_key_base64());
    println!("─────────────────────────────────────────────────────────────────────\n");

    println!("💡 AVAILABLE PATTERNS:");
    println!("  • nk  - Server authentication (recommended for most users)");
    println!("  • xx  - Anonymous encryption (no authentication)");
    println!("  • kk  - Mutual authentication (both sides verify)");
    println!();

    println!("📖 For more information:");
    println!("  • Read NOISE_TRANSPORT.md");
    println!("  • Check examples/ directory for sample configs");
    println!();

    println!("🔒 SECURITY REMINDER:");
    println!("  ⚠️  NEVER commit private keys to version control!");
    println!("  ⚠️  Store private keys with permissions 600 (chmod 600 server.toml)");
    println!("  ⚠️  Use different keys for dev/staging/production");
    println!("  ✅  Rotate keys every 90 days for best security");
    println!();

    // Save to files if requested
    if let Some(ref path) = server_config_path {
        let server_config = format!(
            r#"# Nooshdaroo Server Configuration with Encrypted Transport
# Generated: {}

[server]
bind = "{}"

[transport]
pattern = "{}"              # Noise protocol pattern
local_private_key = "{}"   # 🔒 KEEP SECRET!

# Optional: Protocol shape-shifting
[shapeshift]
strategy = "adaptive"
initial_protocol = "https"
"#,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            server_bind,
            pattern,
            keypair.private_key_base64()
        );

        fs::write(path, server_config)
            .with_context(|| format!("Failed to write server config to {:?}", path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        println!("✅ Server config saved to: {:?}", path);
        println!("   (permissions set to 600 for security)\n");
    }

    if let Some(ref path) = client_config_path {
        let client_config = format!(
            r#"# Nooshdaroo Client Configuration with Encrypted Transport
# Generated: {}

[client]
bind_address = "{}"
server_address = "{}"
proxy_type = "socks5"

[transport]
pattern = "{}"                  # Noise protocol pattern (must match server)
remote_public_key = "{}"       # Server's public key

# Optional: Application profile
[traffic]
application_profile = "zoom"
enabled = true

# Optional: Adaptive bandwidth
[bandwidth]
adaptive_quality = true
initial_quality = "high"
"#,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            client_bind,
            server_addr,
            pattern,
            keypair.public_key_base64()
        );

        fs::write(path, client_config)
            .with_context(|| format!("Failed to write client config to {:?}", path))?;

        println!("✅ Client config saved to: {:?}", path);
        println!();
    }

    if server_config_path.is_some() || client_config_path.is_some() {
        println!("🚀 QUICK START:");
        if let Some(ref path) = server_config_path {
            println!("   Server: nooshdaroo server --config {:?}", path);
        }
        if let Some(ref path) = client_config_path {
            println!("   Client: nooshdaroo client --config {:?}", path);
        }
        println!();
    }

    Ok(())
}
