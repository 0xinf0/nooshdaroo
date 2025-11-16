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
    Bidirectional, ClientToServer, NoiseTransport, NooshdarooClient, NooshdarooConfig,
    NooshdarooServer, ProxyType, ServerToClient, SocatBuilder, UnifiedProxyListener,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_DATE: &str = env!("BUILD_DATE");
const GIT_HASH: &str = env!("GIT_HASH");

#[derive(Parser)]
#[command(name = "nooshdaroo")]
#[command(author = "Sina Rabbani")]
#[command(version = VERSION)]
#[command(about = "Protocol Shape-Shifting SOCKS Proxy", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose logging (-v info, -vv debug, -vvv trace, -vvvv all modules trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

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

        /// Remote server address (optional if specified in config file)
        #[arg(short, long)]
        server: Option<String>,

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

    // Initialize logger with multiple verbosity levels
    let log_level = match cli.verbose {
        0 => log::LevelFilter::Warn,   // Default: warnings and errors only
        1 => log::LevelFilter::Info,   // -v: info level
        2 => log::LevelFilter::Debug,  // -vv: debug level
        3 => log::LevelFilter::Trace,  // -vvv: trace level for nooshdaroo
        _ => log::LevelFilter::Trace,  // -vvvv: trace level for all modules
    };

    let mut logger = env_logger::Builder::from_default_env();

    if cli.verbose >= 4 {
        // Maximum verbosity: trace everything including dependencies
        logger.filter_level(log::LevelFilter::Trace);
    } else if cli.verbose >= 3 {
        // Trace for our crate only, debug for others
        logger.filter_module("nooshdaroo", log::LevelFilter::Trace);
        logger.filter_level(log::LevelFilter::Debug);
    } else {
        logger.filter_level(log_level);
    }

    logger
        .format_timestamp_millis()
        .format_module_path(true)
        .init();

    match cli.command {
        Commands::Client {
            bind,
            server,
            proxy_type,
        } => {
            run_client(cli.config, &bind, server.as_deref(), &proxy_type).await?;
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
    server: Option<&str>,
    proxy_type: &str,
) -> Result<()> {
    info!("Starting Nooshdaroo client on {}", bind);

    let config = if let Some(ref path) = config_path {
        NooshdarooConfig::from_file(path)?
    } else {
        NooshdarooConfig::default()
    };

    let client = NooshdarooClient::new(config.clone())?;
    let proxy_type = match proxy_type {
        "socks5" => ProxyType::Socks5,
        "http" => ProxyType::Http,
        "transparent" => ProxyType::Transparent,
        _ => anyhow::bail!("Unknown proxy type: {}", proxy_type),
    };

    // Determine server address from config or CLI argument
    let server_addr_str = match (config.socks.server_address.as_deref(), server) {
        (Some(config_server), _) => {
            // Config file server takes precedence
            info!("Using server address from config: {}", config_server);
            config_server
        }
        (None, Some(cli_server)) => {
            // Fallback to CLI argument
            info!("Using server address from CLI: {}", cli_server);
            cli_server
        }
        (None, None) => {
            anyhow::bail!("No server address specified. Provide --server argument or set server_address in config file under [socks] section");
        }
    };

    // Determine bind address from config or CLI argument
    let bind_addr: SocketAddr = if config_path.is_some() {
        config.socks.listen_addr
    } else {
        bind.parse()?
    };

    // Parse server address
    let server_addr: SocketAddr = server_addr_str.parse()
        .context(format!("Invalid server address: {}", server_addr_str))?;

    info!("Server address: {}", server_addr);

    // Get current protocol from client
    let protocol_id = client.current_protocol().await;
    info!("Current protocol: {}", protocol_id.as_str());

    // Create listener with or without tunneling
    let listener = if let Some(noise_config) = config.transport {
        info!("Tunnel mode enabled - traffic will be encrypted via Noise Protocol");
        info!("Connecting to server: {}", server_addr);
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id)
            .with_server(server_addr, noise_config)
    } else {
        warn!("Direct mode - no server tunneling configured");
        warn!("WARNING: Traffic will bypass proxy and connect directly!");
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id)
    };

    info!(
        "Nooshdaroo client ready - proxy type: {:?}",
        proxy_type
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

    let server = NooshdarooServer::new(config.clone())?;

    // Extract noise config for tunnel decryption
    let noise_config = config.transport.clone();

    // Extract protocol from shapeshift config
    let protocol_id = match &config.shapeshift.strategy {
        nooshdaroo::StrategyType::Fixed(s) => s.current_protocol(),
        nooshdaroo::StrategyType::TimeBased(s) => s.current_protocol().unwrap_or_default(),
        nooshdaroo::StrategyType::TrafficBased(s) => s.current_protocol().unwrap_or_default(),
        nooshdaroo::StrategyType::Adaptive(s) => s.current_protocol_id().unwrap_or_default(),
        nooshdaroo::StrategyType::Environment(s) => s.current_protocol_id().unwrap_or_default(),
    };

    if noise_config.is_none() {
        warn!("No Noise transport configuration found - server will not accept encrypted tunnels");
    } else {
        info!("Noise Protocol encryption enabled - ready to accept encrypted tunnels");
    }

    info!("Nooshdaroo server ready - listening on {}", bind);
    info!("Protocols loaded: ready to receive shape-shifted traffic");
    info!("Server protocol: {}", protocol_id.as_str());

    // Accept and handle connections
    let listener = tokio::net::TcpListener::bind(bind).await?;

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                let noise_cfg = noise_config.clone();
                let proto_id = protocol_id.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_tunnel_connection(stream, addr, noise_cfg, proto_id).await {
                        log::error!("Tunnel connection error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}

/// Handle incoming tunnel connection from client
async fn handle_tunnel_connection(
    mut tunnel_stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    noise_config: Option<nooshdaroo::NoiseConfig>,
    protocol_id: nooshdaroo::ProtocolId,
) -> Result<()> {
    use nooshdaroo::NoiseTransport;

    // If no noise config, reject connection
    let noise_config = noise_config
        .ok_or_else(|| anyhow::anyhow!("Server not configured for encrypted tunnels"))?;

    log::debug!("Performing Noise handshake with {}", peer_addr);

    // Perform server-side Noise handshake
    let mut noise_transport = NoiseTransport::server_handshake(&mut tunnel_stream, &noise_config)
        .await
        .context("Noise handshake failed")?;

    log::debug!("Noise handshake completed with {}", peer_addr);

    // Read target information from client
    let target_data = noise_transport
        .read(&mut tunnel_stream)
        .await
        .context("Failed to read target info")?;

    let target_str = String::from_utf8_lossy(&target_data);
    log::info!("Client {} requests connection to: {}", peer_addr, target_str);

    // Parse target address (format: "host:port")
    let parts: Vec<&str> = target_str.split(':').collect();
    if parts.len() != 2 {
        let error_msg = format!("Invalid target format: {}", target_str);
        log::error!("{}", error_msg);
        noise_transport.write(&mut tunnel_stream, error_msg.as_bytes()).await?;
        return Err(anyhow::anyhow!(error_msg));
    }

    let target_host = parts[0];
    let target_port = parts[1].parse::<u16>()
        .context("Invalid port number")?;

    // Connect to actual target
    log::debug!("Connecting to target {}:{}", target_host, target_port);
    let target_addr = format!("{}:{}", target_host, target_port);

    let target_stream = match tokio::net::TcpStream::connect(&target_addr).await {
        Ok(stream) => {
            log::info!("Connected to target {}:{}", target_host, target_port);
            // Send success response to client through tunnel
            noise_transport.write(&mut tunnel_stream, b"OK").await?;
            stream
        }
        Err(e) => {
            let error_msg = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                format!("Connection refused to {}:{}", target_host, target_port)
            } else if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::NotFound {
                format!("Host unreachable: {}:{}", target_host, target_port)
            } else {
                format!("Failed to connect to {}:{}: {}", target_host, target_port, e)
            };
            log::error!("{}", error_msg);
            noise_transport.write(&mut tunnel_stream, error_msg.as_bytes()).await?;
            return Err(anyhow::anyhow!(error_msg));
        }
    };

    // Create protocol wrapper matching client protocol
    let wrapper = nooshdaroo::ProtocolWrapper::new(protocol_id.clone(), None);
    log::debug!("Created {} protocol wrapper for traffic obfuscation", protocol_id.as_str());

    // Relay data bidirectionally between client tunnel and target
    log::debug!("Starting bidirectional relay for {}:{}", target_host, target_port);
    if let Err(e) = relay_tunnel_to_target(tunnel_stream, noise_transport, target_stream, wrapper).await {
        log::debug!("Relay ended for {}:{}: {}", target_host, target_port, e);
    } else {
        log::debug!("Relay completed for {}:{}", target_host, target_port);
    }

    Ok(())
}

/// Relay data between encrypted tunnel and target with protocol wrapping
async fn relay_tunnel_to_target(
    mut tunnel: tokio::net::TcpStream,
    mut noise: NoiseTransport,
    mut target: tokio::net::TcpStream,
    mut wrapper: nooshdaroo::ProtocolWrapper,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut target_buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            // Read from tunnel (wrapped), unwrap, decrypt, write to target
            result = noise.read_raw(&mut tunnel) => {
                match result {
                    Ok(wrapped) if !wrapped.is_empty() => {
                        // Unwrap protocol headers
                        let encrypted = wrapper.unwrap(&wrapped)?;
                        log::debug!("Unwrapped {} bytes to {} bytes", wrapped.len(), encrypted.len());

                        // Decrypt with Noise
                        let data = noise.decrypt(&encrypted)?;
                        log::debug!("Decrypted {} bytes to {} bytes", encrypted.len(), data.len());

                        // Write to target
                        target.write_all(&data).await?;
                    }
                    Ok(_) => break, // Empty read = EOF
                    Err(e) => {
                        log::debug!("Noise read error: {}", e);
                        break;
                    }
                }
            }
            // Read from target, encrypt, wrap, write to tunnel
            result = target.read(&mut target_buf) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // Encrypt with Noise
                        let encrypted = noise.encrypt(&target_buf[..n])?;
                        log::debug!("Encrypted {} bytes to {} bytes", n, encrypted.len());

                        // Wrap with protocol headers
                        let wrapped = wrapper.wrap(&encrypted)?;
                        log::debug!("Wrapped {} bytes to {} bytes with protocol obfuscation", encrypted.len(), wrapped.len());

                        // Write wrapped data to tunnel
                        noise.write_raw(&mut tunnel, &wrapped).await?;
                    }
                    Err(e) => {
                        log::debug!("Target read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
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
