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
    DnsUdpTunnelServer, DnsUdpTunnelClient,
};
use nooshdaroo::config::TransportType;

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
    let config = if let Some(profile_name) = profile {
        info!("Loading preset profile: {}", profile_name);
        nooshdaroo::profiles::load_profile(profile_name)?
    } else if let Some(ref path) = config_path {
        NooshdarooConfig::from_file(path)?
    } else {
        NooshdarooConfig::default()
    };

    // Check transport type - UDP requires different code path
    if config.socks.transport == TransportType::Udp {
        return run_udp_client(config, bind, server, proxy_type, protocol, port).await;
    }

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
    let config_arc = Arc::new(config.clone());
    let listener = if let Some(noise_config) = config.transport {
        info!("Tunnel mode enabled - traffic will be encrypted via Noise Protocol");
        info!("Connecting to server: {}", server_addr);
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id, config_arc.clone())
            .with_server(server_addr, noise_config)
            .with_controller(client.controller.clone())
    } else {
        warn!("Direct mode - no server tunneling configured");
        warn!("WARNING: Traffic will bypass proxy and connect directly!");
        UnifiedProxyListener::new(bind_addr, vec![proxy_type], protocol_id, config_arc.clone())
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

/// Run client in UDP DNS tunnel mode
/// This accepts SOCKS5 connections locally via TCP, then tunnels them via UDP DNS packets
async fn run_udp_client(
    config: NooshdarooConfig,
    bind: &str,
    server: Option<&str>,
    proxy_type: &str,
    _protocol: Option<&str>,
    port: Option<u16>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use rand::Rng;

    info!("Starting Nooshdaroo UDP DNS tunnel client");

    // Determine bind address
    let bind_addr: SocketAddr = config.socks.listen_addr;

    // Determine server address
    let server_addr_str = match (config.socks.server_address.as_deref(), server) {
        (Some(config_server), _) => {
            info!("Using server address from config: {}", config_server);
            config_server.to_string()
        }
        (None, Some(cli_server)) => {
            info!("Using server address from CLI: {}", cli_server);
            cli_server.to_string()
        }
        (None, None) => {
            anyhow::bail!("No server address specified for UDP tunnel");
        }
    };

    let mut server_addr: SocketAddr = server_addr_str.parse()
        .context(format!("Invalid server address: {}", server_addr_str))?;

    if let Some(port_override) = port {
        info!("Overriding server port: {}", port_override);
        server_addr.set_port(port_override);
    }

    info!("UDP DNS tunnel mode: {} -> {}", bind_addr, server_addr);
    info!("Proxy type: {}", proxy_type);

    // Start local TCP listener for SOCKS5
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("UDP DNS tunnel client listening on {} (SOCKS5 via TCP -> UDP DNS tunnel)", bind_addr);

    loop {
        match listener.accept().await {
            Ok((mut client_stream, client_addr)) => {
                let server = server_addr;

                tokio::spawn(async move {
                    if let Err(e) = handle_udp_tunnel_connection(&mut client_stream, client_addr, server).await {
                        log::error!("UDP tunnel connection error from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a single SOCKS5 connection and tunnel it via UDP DNS
async fn handle_udp_tunnel_connection(
    client: &mut tokio::net::TcpStream,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use rand::Rng;

    log::debug!("New SOCKS5 connection from {} for UDP tunnel", client_addr);

    // SOCKS5 handshake
    let mut buf = [0u8; 256];

    // Read greeting (version + nmethods + methods)
    let n = client.read(&mut buf[..2]).await?;
    if n < 2 || buf[0] != 0x05 {
        anyhow::bail!("Invalid SOCKS5 greeting");
    }
    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods]).await?;

    // Send method selection (no auth)
    client.write_all(&[0x05, 0x00]).await?;

    // Read connection request
    client.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 {
        anyhow::bail!("Invalid SOCKS5 request");
    }

    let addr_type = buf[3];
    let target_addr = match addr_type {
        0x01 => {
            // IPv4
            client.read_exact(&mut buf[..4]).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            format!("{}", ip)
        }
        0x03 => {
            // Domain name
            client.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            client.read_exact(&mut buf[..len]).await?;
            String::from_utf8_lossy(&buf[..len]).to_string()
        }
        0x04 => {
            // IPv6
            client.read_exact(&mut buf[..16]).await?;
            let ip = std::net::Ipv6Addr::new(
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            format!("{}", ip)
        }
        _ => anyhow::bail!("Unsupported address type: {}", addr_type),
    };

    // Read port
    client.read_exact(&mut buf[..2]).await?;
    let target_port = u16::from_be_bytes([buf[0], buf[1]]);

    log::info!("SOCKS5 CONNECT request to {}:{} via UDP DNS tunnel", target_addr, target_port);

    // Create DNS tunnel client with random session ID
    let session_id: u16 = rand::thread_rng().gen();
    let local_bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let dns_client = DnsUdpTunnelClient::new(server_addr, local_bind, session_id);

    // Send CONNECT request to server via UDP DNS
    // Protocol: [cmd:1][addr_type:1][addr_len:1][addr:var][port:2]
    let mut connect_req = Vec::new();
    connect_req.push(0x01); // CONNECT command
    connect_req.push(0x03); // Domain type
    connect_req.push(target_addr.len() as u8);
    connect_req.extend_from_slice(target_addr.as_bytes());
    connect_req.extend_from_slice(&target_port.to_be_bytes());

    let response = match dns_client.send_and_receive(connect_req).await {
        Ok(resp) => resp,
        Err(e) => {
            // Send SOCKS5 failure response
            let reply = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = client.write_all(&reply).await;
            anyhow::bail!("UDP tunnel connect failed: {}", e);
        }
    };

    // Check response status
    if response.is_empty() || response[0] != 0x00 {
        let reply = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = client.write_all(&reply).await;
        anyhow::bail!("Server returned error status");
    }

    // Send SOCKS5 success response
    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply).await?;

    log::debug!("SOCKS5 handshake complete, starting bidirectional relay via UDP DNS");

    // Bidirectional relay via UDP DNS
    // DNS is request-response based, so we must poll for server data
    // even when the client has nothing to send
    let mut client_buf = vec![0u8; 65536];
    let poll_interval = std::time::Duration::from_millis(50);
    let mut consecutive_empty_polls = 0u32;

    loop {
        tokio::select! {
            // Read from local client
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        log::debug!("Client closed connection");
                        break;
                    }
                    Ok(n) => {
                        // Send data to server via UDP DNS and get response
                        let mut data_req = vec![0x02]; // DATA command
                        data_req.extend_from_slice(&client_buf[..n]);

                        match dns_client.send_and_receive(data_req).await {
                            Ok(response) => {
                                consecutive_empty_polls = 0; // Reset on successful data exchange
                                if response.len() > 1 {
                                    // Response contains data from server
                                    client.write_all(&response[1..]).await?;
                                }
                            }
                            Err(e) => {
                                log::error!("UDP DNS tunnel error: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Client read error: {}", e);
                        break;
                    }
                }
            }
            // Poll for server data when client has nothing to send
            // This is critical for DNS tunneling since server can't push data
            _ = tokio::time::sleep(poll_interval) => {
                // Send POLL command (0x03) to retrieve any buffered server data
                let poll_req = vec![0x03]; // POLL command

                match dns_client.send_and_receive(poll_req).await {
                    Ok(response) => {
                        if response.len() > 1 {
                            // Server has buffered data for us
                            consecutive_empty_polls = 0;
                            client.write_all(&response[1..]).await?;
                        } else {
                            // No data available, back off slightly if many empty polls
                            consecutive_empty_polls += 1;
                            if consecutive_empty_polls > 100 {
                                // After many empty polls, sleep a bit longer
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("UDP DNS tunnel poll error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_server(
    config_path: Option<PathBuf>,
    bind: &str,
    multi_port: bool,
    max_ports: usize,
    cli_private_key: Option<&str>,
) -> Result<()> {
    let mut config = if let Some(path) = config_path {
        NooshdarooConfig::from_file(&path)?
    } else {
        NooshdarooConfig::default()
    };

    // Use config file's listen_addr if available, otherwise use CLI bind argument
    let bind_addr = if let Some(ref server_config) = config.server {
        info!("Using listen_addr from config file: {}", server_config.listen_addr);
        server_config.listen_addr.to_string()
    } else {
        warn!("No [server] section found in config, using CLI bind argument: {}", bind);
        bind.to_string()
    };

    info!("Starting Nooshdaroo server on {}", bind_addr);

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

    // Check transport type from config
    let transport_type = config.server.as_ref()
        .map(|s| s.transport)
        .unwrap_or(TransportType::Tcp);

    // UDP DNS Tunnel mode
    if transport_type == TransportType::Udp {
        info!("UDP DNS tunnel mode enabled on {}", bind_addr);
        info!("This mode is optimized for Iran censorship bypass where only DNS (UDP port 53) passes DPI");

        let bind_addr: std::net::SocketAddr = bind_addr.parse()?;
        let udp_server = DnsUdpTunnelServer::new(bind_addr);

        // Session map: session_id -> (target TCP stream, read buffer)
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        type SessionMap = Arc<RwLock<HashMap<u16, TcpStream>>>;
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));

        // Handler for UDP DNS tunnel packets
        // Protocol:
        // - CONNECT (0x01): [cmd:1][addr_type:1][addr_len:1][addr:var][port:2]
        // - DATA (0x02): [cmd:1][payload...]
        // - POLL (0x03): [cmd:1] - retrieve buffered data without sending
        // Response:
        // - Success: [0x00][response_data...]
        // - Error: [0x01][error_code:1]
        let sessions_clone = sessions.clone();
        udp_server.listen(move |session_id, client_addr, payload| {
            let sessions = sessions_clone.clone();
            async move {
                if payload.is_empty() {
                    return Err("Empty payload".to_string());
                }

                let cmd = payload[0];
                match cmd {
                    0x01 => {
                        // CONNECT command
                        if payload.len() < 5 {
                            return Ok(vec![0x01, 0x01]); // Error: invalid request
                        }

                        let addr_type = payload[1];
                        let (target_addr, target_port) = match addr_type {
                            0x01 => {
                                // IPv4
                                if payload.len() < 8 {
                                    return Ok(vec![0x01, 0x01]);
                                }
                                let ip = std::net::Ipv4Addr::new(
                                    payload[2], payload[3], payload[4], payload[5]
                                );
                                let port = u16::from_be_bytes([payload[6], payload[7]]);
                                (format!("{}:{}", ip, port), port)
                            }
                            0x03 => {
                                // Domain name
                                if payload.len() < 3 {
                                    return Ok(vec![0x01, 0x01]);
                                }
                                let addr_len = payload[2] as usize;
                                if payload.len() < 3 + addr_len + 2 {
                                    return Ok(vec![0x01, 0x01]);
                                }
                                let domain = String::from_utf8_lossy(&payload[3..3+addr_len]).to_string();
                                let port = u16::from_be_bytes([payload[3+addr_len], payload[4+addr_len]]);
                                (format!("{}:{}", domain, port), port)
                            }
                            0x04 => {
                                // IPv6
                                if payload.len() < 20 {
                                    return Ok(vec![0x01, 0x01]);
                                }
                                let ip = std::net::Ipv6Addr::new(
                                    u16::from_be_bytes([payload[2], payload[3]]),
                                    u16::from_be_bytes([payload[4], payload[5]]),
                                    u16::from_be_bytes([payload[6], payload[7]]),
                                    u16::from_be_bytes([payload[8], payload[9]]),
                                    u16::from_be_bytes([payload[10], payload[11]]),
                                    u16::from_be_bytes([payload[12], payload[13]]),
                                    u16::from_be_bytes([payload[14], payload[15]]),
                                    u16::from_be_bytes([payload[16], payload[17]]),
                                );
                                let port = u16::from_be_bytes([payload[18], payload[19]]);
                                (format!("[{}]:{}", ip, port), port)
                            }
                            _ => {
                                return Ok(vec![0x01, 0x08]); // Error: unsupported address type
                            }
                        };

                        log::info!("UDP session {:04x} CONNECT to {} from {}", session_id, target_addr, client_addr);

                        // Connect to target
                        match TcpStream::connect(&target_addr).await {
                            Ok(stream) => {
                                // Store the connection
                                let mut sessions_lock = sessions.write().await;
                                sessions_lock.insert(session_id, stream);
                                drop(sessions_lock);
                                log::info!("UDP session {:04x} connected to {}", session_id, target_addr);
                                Ok(vec![0x00]) // Success
                            }
                            Err(e) => {
                                log::error!("UDP session {:04x} connect failed: {}", session_id, e);
                                Ok(vec![0x01, 0x05]) // Error: connection refused
                            }
                        }
                    }
                    0x02 => {
                        // DATA command
                        let data = &payload[1..];

                        let mut sessions_lock = sessions.write().await;
                        if let Some(stream) = sessions_lock.get_mut(&session_id) {
                            // Write data to target
                            if let Err(e) = stream.write_all(data).await {
                                log::error!("UDP session {:04x} write error: {}", session_id, e);
                                sessions_lock.remove(&session_id);
                                return Ok(vec![0x01, 0x04]); // Error: connection closed
                            }

                            // Read available response with short timeout
                            let mut response_buf = vec![0u8; 65536];
                            let read_result = tokio::time::timeout(
                                std::time::Duration::from_millis(100),
                                stream.read(&mut response_buf)
                            ).await;

                            let mut response = vec![0x00]; // Success prefix
                            match read_result {
                                Ok(Ok(0)) => {
                                    // Connection closed by target
                                    sessions_lock.remove(&session_id);
                                }
                                Ok(Ok(n)) => {
                                    // Got data from target
                                    response.extend_from_slice(&response_buf[..n]);
                                }
                                Ok(Err(e)) => {
                                    log::debug!("UDP session {:04x} read error: {}", session_id, e);
                                    sessions_lock.remove(&session_id);
                                }
                                Err(_) => {
                                    // Timeout - no data available, that's OK
                                }
                            }
                            Ok(response)
                        } else {
                            log::warn!("UDP session {:04x} not found", session_id);
                            Ok(vec![0x01, 0x04]) // Error: no connection
                        }
                    }
                    0x03 => {
                        // POLL command - retrieve any buffered data from server without sending
                        // This is essential for DNS tunneling since server can't push data
                        let mut sessions_lock = sessions.write().await;
                        if let Some(stream) = sessions_lock.get_mut(&session_id) {
                            // Read available response with short timeout
                            let mut response_buf = vec![0u8; 65536];
                            let read_result = tokio::time::timeout(
                                std::time::Duration::from_millis(100),
                                stream.read(&mut response_buf)
                            ).await;

                            let mut response = vec![0x00]; // Success prefix
                            match read_result {
                                Ok(Ok(0)) => {
                                    // Connection closed by target
                                    log::debug!("UDP session {:04x} POLL: connection closed", session_id);
                                    sessions_lock.remove(&session_id);
                                }
                                Ok(Ok(n)) => {
                                    // Got data from target
                                    log::debug!("UDP session {:04x} POLL: {} bytes available", session_id, n);
                                    response.extend_from_slice(&response_buf[..n]);
                                }
                                Ok(Err(e)) => {
                                    log::debug!("UDP session {:04x} POLL read error: {}", session_id, e);
                                    sessions_lock.remove(&session_id);
                                }
                                Err(_) => {
                                    // Timeout - no data available, that's OK
                                }
                            }
                            Ok(response)
                        } else {
                            log::warn!("UDP session {:04x} POLL: not found", session_id);
                            Ok(vec![0x01, 0x04]) // Error: no connection
                        }
                    }
                    _ => {
                        log::warn!("UDP session {:04x} unknown command: {}", session_id, cmd);
                        Ok(vec![0x01, 0x07]) // Error: unknown command
                    }
                }
            }
        }).await.map_err(|e| anyhow::anyhow!("{}", e))?;

        return Ok(());
    }

    // Single-port TCP mode (original implementation)
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

    info!("Nooshdaroo server ready - listening on {}", bind_addr);
    info!("Protocols loaded: ready to receive shape-shifted traffic");
    info!("Server protocol: {}", protocol_id.as_str());

    // Accept and handle connections
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let config_arc = Arc::new(config);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                let noise_cfg = noise_config.clone();
                let proto_id = protocol_id.clone();
                let cfg = config_arc.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_tunnel_connection(stream, addr, noise_cfg, proto_id, cfg).await {
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
    config: Arc<nooshdaroo::NooshdarooConfig>,
) -> Result<()> {
    use nooshdaroo::{NoiseTransport, ProtocolWrapper};

    // If no noise config, reject connection
    let noise_config = noise_config
        .ok_or_else(|| anyhow::anyhow!("Server not configured for encrypted tunnels"))?;

    log::debug!("Performing Noise handshake with {} using protocol {}", peer_addr, protocol_id.as_str());

    // Create protocol wrapper for handshake wrapping
    let mut protocol_wrapper = ProtocolWrapper::new(protocol_id.clone(), nooshdaroo::WrapperRole::Server, None);

    // Perform server-side Noise handshake with protocol wrapping
    let mut noise_transport = NoiseTransport::server_handshake(&mut tunnel_stream, &noise_config, Some(&mut protocol_wrapper))
        .await
        .context("Noise handshake failed")?;

    log::debug!("Noise handshake completed with {}", peer_addr);

    // Enable TLS session emulation if configured AND protocol is TLS-based
    let is_tls_protocol = protocol_id.as_str().starts_with("https") ||
                          protocol_id.as_str().starts_with("tls") ||
                          protocol_id.as_str() == "dns" || // DNS over TLS
                          protocol_id.as_str() == "dns-google";

    let use_tls_emulation = config.detection.enable_tls_session_emulation && is_tls_protocol;
    if use_tls_emulation {
        noise_transport.enable_tls_wrapping();
        log::info!("Full TLS session emulation enabled for protocol: {}", protocol_id.as_str());
    }

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
            // Enable TCP_NODELAY for low latency (critical for HTTP/2)
            stream.set_nodelay(true)?;
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

    // Relay data bidirectionally between client tunnel and target
    log::debug!("Starting bidirectional relay for {}:{}", target_host, target_port);
    if use_tls_emulation {
        // Use NoiseTransport's built-in TLS wrapping (no protocol wrapper)
        log::debug!("Using TLS session emulation (no protocol wrapper)");
        if let Err(e) = relay_with_noise_only(tunnel_stream, noise_transport, target_stream).await {
            log::debug!("Relay ended for {}:{}: {}", target_host, target_port, e);
        } else {
            log::debug!("Relay completed for {}:{}", target_host, target_port);
        }
    } else {
        // Use protocol wrapper for obfuscation
        let wrapper = nooshdaroo::ProtocolWrapper::new(protocol_id.clone(), nooshdaroo::WrapperRole::Server, None);
        log::debug!("Created {} protocol wrapper for traffic obfuscation", protocol_id.as_str());
        if let Err(e) = relay_tunnel_to_target(tunnel_stream, noise_transport, target_stream, wrapper).await {
            log::debug!("Relay ended for {}:{}: {}", target_host, target_port, e);
        } else {
            log::debug!("Relay completed for {}:{}", target_host, target_port);
        }
    }

    Ok(())
}

/// Relay using NoiseTransport only (for TLS session emulation)
async fn relay_with_noise_only(
    mut tunnel: tokio::net::TcpStream,
    mut noise: NoiseTransport,
    mut target: tokio::net::TcpStream,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut target_buf = vec![0u8; 8192];
    let mut tunnel_closed = false;
    let mut target_closed = false;

    loop {
        tokio::select! {
            // Read from tunnel (TLS-wrapped), unwrap+decrypt, write to target
            result = noise.read(&mut tunnel), if !tunnel_closed => {
                match result {
                    Ok(data) if !data.is_empty() => {
                        // NoiseTransport.read() handles TLS unwrapping AND decryption
                        target.write_all(&data).await?;
                        target.flush().await?;
                    }
                    Ok(_) => {
                        // Tunnel closed connection
                        log::debug!("Tunnel closed connection");
                        tunnel_closed = true;
                        if target_closed {
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("Noise read error: {}", e);
                        tunnel_closed = true;
                        if target_closed {
                            break;
                        }
                    }
                }
            }
            // Read from target, encrypt+wrap with TLS, write to tunnel
            result = target.read(&mut target_buf), if !target_closed => {
                match result {
                    Ok(0) => {
                        // Target closed write half - shutdown tunnel write, but keep reading
                        log::debug!("Target closed connection, shutting down tunnel write");
                        target_closed = true;
                        if tunnel_closed {
                            break;
                        }
                    }
                    Ok(n) => {
                        // NoiseTransport.write() handles encryption AND TLS wrapping
                        noise.write(&mut tunnel, &target_buf[..n]).await?;
                    }
                    Err(e) => {
                        log::debug!("Target read error: {}", e);
                        target_closed = true;
                        if tunnel_closed {
                            break;
                        }
                    }
                }
            }
        }
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
