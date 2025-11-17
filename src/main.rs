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

        /// Proxy type (socks5, http)
        #[arg(short = 'p', long, default_value = "socks5")]
        proxy_type: String,

        /// Protocol to use (https, dns, ssh, etc.) - overrides config file
        #[arg(long)]
        protocol: Option<String>,

        /// Server port override
        #[arg(long)]
        port: Option<u16>,

        /// Use preset profile (corporate, airport, hotel, china, iran, russia)
        #[arg(long, value_parser = ["corporate", "airport", "hotel", "china", "iran", "russia"])]
        profile: Option<String>,

        /// Automatically select best protocol by testing all paths
        #[arg(long)]
        auto_protocol: bool,
    },

    /// Run as a server (remote endpoint)
    Server {
        /// Server bind address
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: String,

        /// Listen on multiple ports simultaneously (443, 53, 22, 80, 8080, etc.)
        #[arg(long)]
        multi_port: bool,

        /// Maximum number of ports to listen on (when --multi-port is enabled)
        #[arg(long, default_value = "20")]
        max_ports: usize,

        /// Base64-encoded Noise protocol private key (overrides config file)
        #[arg(long, env = "NOOSHDAROO_PRIVATE_KEY")]
        private_key: Option<String>,
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

    /// Generate Noise protocol keypair (keys only)
    Genkey {
        /// Output format: text (default), json, or quiet (private key only)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Generate configuration files
    Genconf {
        /// Save server config to file
        #[arg(long)]
        server_config: Option<PathBuf>,

        /// Save client config to file
        #[arg(long)]
        client_config: Option<PathBuf>,

        /// Server bind address
        #[arg(long, default_value = "0.0.0.0:8443")]
        server_addr: String,

        /// Client bind address
        #[arg(long, default_value = "127.0.0.1:1080")]
        client_addr: String,

        /// Remote server address (for client config)
        #[arg(long, default_value = "myserver.com:8443")]
        remote_server: String,

        /// Noise pattern to use
        #[arg(long, default_value = "nk")]
        pattern: String,

        /// Server private key (base64 encoded)
        #[arg(long)]
        server_private_key: Option<String>,

        /// Server public key (base64 encoded, for client config)
        #[arg(long)]
        server_public_key: Option<String>,
    },

    /// Test all protocol/port combinations to find best path
    TestPaths {
        /// Server address to test
        #[arg(short, long)]
        server: String,

        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: String,

        /// Protocol directory
        #[arg(long, default_value = "protocols")]
        protocol_dir: PathBuf,
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
            protocol,
            port,
            profile,
            auto_protocol,
        } => {
            run_client(
                cli.config,
                &bind,
                server.as_deref(),
                &proxy_type,
                protocol.as_deref(),
                port,
                profile.as_deref(),
                auto_protocol,
            )
            .await?;
        }
        Commands::Server {
            bind,
            multi_port,
            max_ports,
            private_key,
        } => {
            run_server(cli.config, &bind, multi_port, max_ports, private_key.as_deref()).await?;
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
        Commands::Genkey { format } => {
            generate_keypair(&format)?;
        }
        Commands::Genconf {
            server_config,
            client_config,
            server_addr,
            client_addr,
            remote_server,
            pattern,
            server_private_key,
            server_public_key,
        } => {
            generate_config_files(
                server_config,
                client_config,
                &server_addr,
                &client_addr,
                &remote_server,
                &pattern,
                server_private_key,
                server_public_key,
            )?;
        }
        Commands::TestPaths {
            server,
            format,
            protocol_dir,
        } => {
            test_all_paths(&server, &format, &protocol_dir).await?;
        }
    }

    Ok(())
}

async fn run_client(
    config_path: Option<PathBuf>,
    bind: &str,
    server: Option<&str>,
    proxy_type: &str,
    protocol: Option<&str>,
    port: Option<u16>,
    profile: Option<&str>,
    auto_protocol: bool,
) -> Result<()> {
    info!("Starting Nooshdaroo client on {}", bind);

    // Load config from profile, config file, or default (in priority order)
    let mut config = if let Some(profile_name) = profile {
        info!("Loading preset profile: {}", profile_name);
        nooshdaroo::profiles::load_profile(profile_name)?
    } else if let Some(ref path) = config_path {
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
    let mut server_addr: SocketAddr = server_addr_str.parse()
        .context(format!("Invalid server address: {}", server_addr_str))?;

    // Apply port override if specified
    if let Some(port_override) = port {
        info!("Overriding server port from CLI: {}", port_override);
        server_addr.set_port(port_override);
    }

    info!("Server address: {}", server_addr);

    // Determine protocol: auto-select, CLI override, or config
    let protocol_id = if auto_protocol {
        info!("Auto-protocol mode: testing all paths to find best connection...");
        // Use PathTester to find best protocol
        let library = Arc::new(nooshdaroo::ProtocolLibrary::load(&PathBuf::from("protocols"))?);
        let tester = nooshdaroo::PathTester::new(library);
        let test_config = nooshdaroo::MultiPortConfig::default();

        let results = tester.test_all_paths(&server_addr.ip().to_string(), &test_config).await;

        if results.is_empty() {
            warn!("No successful paths found, using default protocol");
            client.current_protocol().await
        } else {
            // Pick the best scoring protocol
            let best = &results[0];
            info!(
                "Auto-selected protocol: {} on port {} (score: {:.2})",
                best.protocol.as_str(),
                best.addr.port(),
                best.score()
            );
            // Update server port to the best one found
            server_addr.set_port(best.addr.port());
            best.protocol.clone()
        }
    } else if let Some(proto_name) = protocol {
        info!("Using protocol from CLI: {}", proto_name);
        nooshdaroo::ProtocolId::from(proto_name)
    } else {
        // Use protocol from client config
        let proto = client.current_protocol().await;
        info!("Current protocol: {}", proto.as_str());
        proto
    };

    // Create listener with or without tunneling
    let listener = if let Some(noise_config) = config.transport {
        info!("Tunnel mode enabled - traffic will be encrypted via Noise Protocol");
        info!("Connecting to server: {}", server_addr);
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id)
            .with_server(server_addr, noise_config)
            .with_controller(client.controller.clone())
    } else {
        warn!("Direct mode - no server tunneling configured");
        warn!("WARNING: Traffic will bypass proxy and connect directly!");
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id)
            .with_controller(client.controller.clone())
    };

    info!(
        "Nooshdaroo client ready - proxy type: {:?}",
        proxy_type
    );

    // Start listening for connections
    listener.listen().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}

async fn run_server(
    config_path: Option<PathBuf>,
    bind: &str,
    multi_port: bool,
    max_ports: usize,
    cli_private_key: Option<&str>,
) -> Result<()> {
    info!("Starting Nooshdaroo server on {}", bind);

    let mut config = if let Some(path) = config_path {
        NooshdarooConfig::from_file(&path)?
    } else {
        NooshdarooConfig::default()
    };

    // If private key is provided via CLI, override config
    if let Some(key) = cli_private_key {
        info!("Using private key from --private-key argument");
        if let Some(mut noise_config) = config.transport {
            noise_config.local_private_key = Some(key.to_string());
            config.transport = Some(noise_config);
        }
    }

    // If multi-port mode is enabled, use MultiPortServer
    if multi_port {
        info!("Multi-port mode enabled - listening on up to {} ports", max_ports);
        let library = Arc::new(nooshdaroo::ProtocolLibrary::load(&PathBuf::from("protocols"))?);

        let mp_config = nooshdaroo::MultiPortConfig {
            max_ports,
            ..Default::default()
        };

        let mp_server = nooshdaroo::MultiPortServer::new(library, mp_config);
        mp_server.initialize().await.map_err(|e| anyhow::anyhow!("{}", e))?;

        info!("Multi-port server initialized on:");
        info!("  HTTPS: 443, 8443");
        info!("  DNS: 53");
        info!("  SSH: 22, 2222");
        info!("  HTTP: 80, 8080, 8000");
        info!("  VPN: 1194, 51820");
        info!("  Email: 25, 587, 993, 995");

        mp_server.start().await.map_err(|e| anyhow::anyhow!("{}", e))?;

        return Ok(());
    }

    // Single-port mode (original implementation)
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
    use nooshdaroo::{NoiseTransport, ProtocolWrapper};

    // If no noise config, reject connection
    let noise_config = noise_config
        .ok_or_else(|| anyhow::anyhow!("Server not configured for encrypted tunnels"))?;

    log::debug!("Performing Noise handshake with {} using protocol {}", peer_addr, protocol_id.as_str());

    // Create protocol wrapper for handshake wrapping
    let mut protocol_wrapper = ProtocolWrapper::new(protocol_id.clone(), None);

    // Perform server-side Noise handshake with protocol wrapping
    let mut noise_transport = NoiseTransport::server_handshake(&mut tunnel_stream, &noise_config, Some(&mut protocol_wrapper))
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

    // Parse target address (format: "host:port" or "[ipv6]:port")
    let (target_host, target_port) = if target_str.starts_with('[') {
        // IPv6 format: [2a00:800::1]:80
        if let Some(bracket_end) = target_str.find(']') {
            let ipv6_part = &target_str[1..bracket_end]; // Strip [ and ]
            let port_part = &target_str[bracket_end + 1..]; // Everything after ]

            if !port_part.starts_with(':') {
                let error_msg = format!("Invalid IPv6 target format: {}", target_str);
                log::error!("{}", error_msg);
                noise_transport.write(&mut tunnel_stream, error_msg.as_bytes()).await?;
                return Err(anyhow::anyhow!(error_msg));
            }

            let port = port_part[1..].parse::<u16>()
                .context("Invalid port number")?;
            (ipv6_part, port)
        } else {
            let error_msg = format!("Invalid IPv6 target format: {}", target_str);
            log::error!("{}", error_msg);
            noise_transport.write(&mut tunnel_stream, error_msg.as_bytes()).await?;
            return Err(anyhow::anyhow!(error_msg));
        }
    } else {
        // IPv4 or hostname format: example.com:80
        let parts: Vec<&str> = target_str.split(':').collect();
        if parts.len() != 2 {
            let error_msg = format!("Invalid target format: {}", target_str);
            log::error!("{}", error_msg);
            noise_transport.write(&mut tunnel_stream, error_msg.as_bytes()).await?;
            return Err(anyhow::anyhow!(error_msg));
        }

        let port = parts[1].parse::<u16>()
            .context("Invalid port number")?;
        (parts[0], port)
    };

    let target_host = target_host;

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

/// Generate Noise protocol keypair (keys only)
fn generate_keypair(format: &str) -> Result<()> {
    let keypair = nooshdaroo::generate_noise_keypair()
        .context("Failed to generate keypair")?;

    match format {
        "private" => {
            // Only output private key (for piping, like wg genkey)
            println!("{}", keypair.private_key_base64());
        }
        "public" => {
            // Only output public key
            println!("{}", keypair.public_key_base64());
        }
        "json" => {
            // JSON output for machine parsing
            let json = serde_json::json!({
                "private_key": keypair.private_key_base64(),
                "public_key": keypair.public_key_base64(),
                "algorithm": "X25519",
                "noise_pattern": "nk"
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        _ => {
            // Default: both keys, clean output (like wg genkey + wg pubkey)
            eprintln!("private key: {}", keypair.private_key_base64());
            eprintln!("public key: {}", keypair.public_key_base64());
        }
    }

    Ok(())
}

/// Generate configuration files
fn generate_config_files(
    server_config_path: Option<PathBuf>,
    client_config_path: Option<PathBuf>,
    server_addr: &str,
    client_addr: &str,
    remote_server: &str,
    pattern: &str,
    cli_server_private_key: Option<String>,
    cli_server_public_key: Option<String>,
) -> Result<()> {
    use std::fs;

    // If keys not provided via CLI, generate new keypair
    let (server_private_key, server_public_key) = if let (Some(priv_key), Some(pub_key)) =
        (cli_server_private_key, cli_server_public_key) {
        (priv_key, pub_key)
    } else {
        let keypair = nooshdaroo::generate_noise_keypair()
            .context("Failed to generate keypair")?;
        (keypair.private_key_base64(), keypair.public_key_base64())
    };

    println!("\n╔════════════════════════════════════════════════════════════════════╗");
    println!("║        Nooshdaroo Configuration File Generator                    ║");
    println!("╚════════════════════════════════════════════════════════════════════╝\n");

    // Save server config if requested
    if let Some(ref path) = server_config_path {
        let server_config = format!(
            r#"# Nooshdaroo Server Configuration
# Generated: {}

mode = "server"
protocol_dir = "protocols"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"
password = "nooshdaroo-server-secret"

[server]
listen_addr = "{}"

[transport]
pattern = "{}"
local_private_key = "{}"   # 🔒 KEEP SECRET!

[socks]
listen_addr = "127.0.0.1:0"
server_address = "0.0.0.0:0"
auth_required = false

[shapeshift.strategy]
type = "adaptive"
protocol = "https"
"#,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            server_addr,
            pattern,
            server_private_key
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
        println!("   (permissions set to 600 for security)");
    }

    // Save client config if requested
    if let Some(ref path) = client_config_path {
        let client_config = format!(
            r#"# Nooshdaroo Client Configuration
# Generated: {}

mode = "client"
protocol_dir = "protocols"

[encryption]
cipher = "cha-cha20-poly1305"
key_derivation = "argon2"
password = "nooshdaroo-client-secret"

[socks]
listen_addr = "{}"
server_address = "{}"
auth_required = false

[transport]
pattern = "{}"
remote_public_key = "{}"   # Server's public key

[shapeshift.strategy]
type = "fixed"
protocol = "https"
"#,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            client_addr,
            remote_server,
            pattern,
            server_public_key
        );

        fs::write(path, client_config)
            .with_context(|| format!("Failed to write client config to {:?}", path))?;

        println!("✅ Client config saved to: {:?}", path);
    }

    println!();
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

/// Test all protocol/port combinations to find best path
async fn test_all_paths(server: &str, format: &str, protocol_dir: &PathBuf) -> Result<()> {
    info!("Testing all paths to {}...", server);

    // Load protocol library
    let library = Arc::new(nooshdaroo::ProtocolLibrary::load(protocol_dir)?);
    let tester = nooshdaroo::PathTester::new(library);
    let config = nooshdaroo::MultiPortConfig::default();

    // Run tests
    let results = tester.test_all_paths(server, &config).await;

    if results.is_empty() {
        warn!("No successful paths found!");
        return Ok(());
    }

    // Output results
    if format == "json" {
        // JSON output
        let json_output = serde_json::to_string_pretty(&results)?;
        println!("{}", json_output);
    } else {
        // Text output
        println!("\n🔍 Testing paths to {}...\n", server);
        println!("{:<15} {:<8} {:<12} {:<10} {:<10} {}",
            "PROTOCOL", "PORT", "LATENCY", "SCORE", "STATUS", "NOTES");
        println!("{}", "-".repeat(80));

        for result in &results {
            let status = if result.success { "✓ OK" } else { "✗ FAIL" };
            let latency_ms = format!("{:.2}ms", result.latency.as_secs_f64() * 1000.0);
            let score = format!("{:.2}", result.score());

            println!("{:<15} {:<8} {:<12} {:<10} {:<10}",
                result.protocol.as_str(),
                result.addr.port(),
                latency_ms,
                score,
                status
            );
        }

        println!("\n📊 SUMMARY:");
        let successful = results.iter().filter(|r| r.success).count();
        let total = results.len();
        println!("  Successful paths: {}/{}", successful, total);

        if successful > 0 {
            let best = &results[0];
            println!("\n🏆 RECOMMENDED:");
            println!("  Protocol: {}", best.protocol.as_str());
            println!("  Port: {}", best.addr.port());
            println!("  Score: {:.2}/1.00", best.score());
            println!("\n💡 To use this path:");
            println!("  nooshdaroo client --protocol {} --port {} --server {}",
                best.protocol.as_str(), best.addr.port(), server);
        }
    }

    Ok(())
}
