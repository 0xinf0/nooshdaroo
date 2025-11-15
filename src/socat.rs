//! Socat-like bidirectional relay functionality

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Relay modes (like socat)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RelayMode {
    /// TCP to TCP relay
    TcpToTcp {
        listen: String,
        connect: String,
    },
    /// TCP to STDIO relay
    TcpToStdio {
        address: String,
    },
    /// File to network relay
    FileToTcp {
        file_path: String,
        address: String,
    },
    /// Encrypted relay through Nooshdaroo
    EncryptedRelay {
        listen: String,
        connect: String,
        protocol: String,
    },
}

/// Socat-like bidirectional relay
#[allow(dead_code)]
pub struct SocatRelay {
    mode: RelayMode,
}

impl SocatRelay {
    /// Create new relay
    pub fn new(mode: RelayMode) -> Self {
        Self { mode }
    }

    /// Start relay
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.mode {
            RelayMode::TcpToTcp { listen, connect } => {
                Self::tcp_to_tcp(listen, connect).await
            }
            RelayMode::TcpToStdio { address } => Self::tcp_to_stdio(address).await,
            RelayMode::FileToTcp { file_path, address } => {
                Self::file_to_tcp(file_path, address).await
            }
            RelayMode::EncryptedRelay {
                listen,
                connect,
                protocol,
            } => Self::encrypted_relay(listen, connect, protocol).await,
        }
    }

    /// TCP to TCP relay (basic socat functionality)
    async fn tcp_to_tcp(
        listen: String,
        connect: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        log::info!("Socat relay: {} -> {}", listen, connect);

        loop {
            let (inbound, _) = listener.accept().await?;
            let connect_addr = connect.clone();

            tokio::spawn(async move {
                if let Err(e) = relay_connection(inbound, connect_addr).await {
                    log::error!("Relay error: {}", e);
                }
            });
        }
    }

    /// TCP to STDIO relay
    #[cfg(feature = "stdio")]
    async fn tcp_to_stdio(address: String) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(&address).await?;
        log::info!("Socat stdio relay to {}", address);

        // For now, just connect and log (requires tokio stdio features)
        drop(stream);
        Err("STDIO relay requires tokio stdio features".into())
    }

    #[cfg(not(feature = "stdio"))]
    async fn tcp_to_stdio(_address: String) -> Result<(), Box<dyn std::error::Error>> {
        Err("STDIO relay not supported (compile with stdio feature)".into())
    }

    /// File to TCP relay
    #[cfg(feature = "fs")]
    async fn file_to_tcp(
        file_path: String,
        address: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use tokio::fs::File;
        use tokio::io::AsyncReadExt;

        let mut file = File::open(&file_path).await?;
        let mut stream = TcpStream::connect(&address).await?;

        log::info!("Socat file relay: {} -> {}", file_path, address);

        let mut buf = vec![0u8; 8192];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await?;
        }

        Ok(())
    }

    #[cfg(not(feature = "fs"))]
    async fn file_to_tcp(
        _file_path: String,
        _address: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err("File relay not supported (compile with fs feature)".into())
    }

    /// Encrypted relay through Nooshdaroo protocol emulation
    async fn encrypted_relay(
        listen: String,
        connect: String,
        protocol: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        log::info!("Encrypted relay: {} -> {} (protocol: {})", listen, connect, protocol);

        loop {
            let (inbound, _) = listener.accept().await?;
            let connect_addr = connect.clone();
            let proto = protocol.clone();

            tokio::spawn(async move {
                if let Err(e) = encrypted_relay_connection(inbound, connect_addr, proto).await {
                    log::error!("Encrypted relay error: {}", e);
                }
            });
        }
    }
}

/// Relay single connection
async fn relay_connection(
    mut inbound: TcpStream,
    connect_to: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut outbound = TcpStream::connect(&connect_to).await?;

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        Ok::<_, std::io::Error>(())
    };

    let server_to_client = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        Ok::<_, std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

/// Relay with encryption/obfuscation
async fn encrypted_relay_connection(
    mut inbound: TcpStream,
    connect_to: String,
    protocol: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut outbound = TcpStream::connect(&connect_to).await?;

    log::debug!("Encrypted relay using protocol: {}", protocol);

    // TODO: Apply Nooshdaroo protocol emulation
    // For now, just relay plaintext
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        Ok::<_, std::io::Error>(())
    };

    let server_to_client = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        Ok::<_, std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

/// Builder for socat-like command line interface
#[allow(dead_code)]
pub struct SocatBuilder {
    mode: Option<RelayMode>,
}

impl SocatBuilder {
    pub fn new() -> Self {
        Self { mode: None }
    }

    /// Parse socat-like arguments
    /// Examples:
    ///   TCP-LISTEN:8080,fork TCP:example.com:80
    ///   TCP:example.com:443 STDIO
    ///   FILE:/path/to/file TCP:example.com:80
    pub fn parse_args(mut self, args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err("Need at least 2 arguments".to_string());
        }

        let left = &args[0];
        let right = &args[1];

        // Parse left side
        let (left_type, left_addr) = parse_address_spec(left)?;
        let (right_type, right_addr) = parse_address_spec(right)?;

        self.mode = Some(match (left_type.as_str(), right_type.as_str()) {
            ("TCP-LISTEN", "TCP") | ("TCP4-LISTEN", "TCP") => RelayMode::TcpToTcp {
                listen: left_addr,
                connect: right_addr,
            },
            ("TCP", "STDIO") => RelayMode::TcpToStdio { address: left_addr },
            ("FILE", "TCP") => RelayMode::FileToTcp {
                file_path: left_addr,
                address: right_addr,
            },
            ("NOOSHDAROO-LISTEN", "TCP") => RelayMode::EncryptedRelay {
                listen: left_addr.clone(),
                connect: right_addr,
                protocol: args.get(2).cloned().unwrap_or_else(|| "https".to_string()),
            },
            _ => return Err(format!("Unsupported combination: {} -> {}", left_type, right_type)),
        });

        Ok(self)
    }

    pub fn build(self) -> Result<SocatRelay, String> {
        Ok(SocatRelay {
            mode: self.mode.ok_or("No mode specified")?,
        })
    }
}

impl Default for SocatBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse socat address specification
fn parse_address_spec(spec: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid address spec: {}", spec));
    }

    let addr_type = parts[0].to_uppercase();
    let addr = parts[1].to_string();

    Ok((addr_type, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_listen() {
        let result = parse_address_spec("TCP-LISTEN:8080");
        assert!(result.is_ok());
        let (addr_type, addr) = result.unwrap();
        assert_eq!(addr_type, "TCP-LISTEN");
        assert_eq!(addr, "8080");
    }

    #[test]
    fn test_parse_tcp() {
        let result = parse_address_spec("TCP:example.com:443");
        assert!(result.is_ok());
        let (addr_type, addr) = result.unwrap();
        assert_eq!(addr_type, "TCP");
        assert_eq!(addr, "example.com:443");
    }

    #[test]
    fn test_socat_builder() {
        let args = vec![
            "TCP-LISTEN:8080".to_string(),
            "TCP:example.com:80".to_string(),
        ];
        let builder = SocatBuilder::new().parse_args(&args);
        assert!(builder.is_ok());
    }
}
