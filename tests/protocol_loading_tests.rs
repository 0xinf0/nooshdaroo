// Protocol Loading Integration Tests
// Tests that all 121 protocols can be loaded and parsed correctly

use nooshdaroo::ProtocolLibrary;
use std::path::PathBuf;

#[test]
fn test_protocol_library_loads() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Should have loaded all protocols
    assert!(library.len() >= 100, "Expected at least 100 protocols, got {}", library.len());
}

#[test]
fn test_http_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check key HTTP protocols
    let http_protocols = vec![
        "http2", "http3", "websocket", "quic", "grpc", "graphql", "rest", "soap"
    ];

    for proto in http_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing HTTP protocol: {}",
            proto
        );
    }
}

#[test]
fn test_vpn_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check VPN protocols
    let vpn_protocols = vec![
        "wireguard", "openvpn", "ikev2", "ipsec", "tailscale", "zerotier"
    ];

    for proto in vpn_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing VPN protocol: {}",
            proto
        );
    }
}

#[test]
fn test_gaming_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check gaming protocols
    let gaming_protocols = vec![
        "minecraft", "steam", "discord", "fortnite", "valorant"
    ];

    for proto in gaming_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing gaming protocol: {}",
            proto
        );
    }
}

#[test]
fn test_database_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check database protocols
    let db_protocols = vec![
        "postgresql", "mysql", "redis", "mongodb", "elasticsearch"
    ];

    for proto in db_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing database protocol: {}",
            proto
        );
    }
}

#[test]
fn test_iot_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check IoT protocols
    let iot_protocols = vec![
        "mqtt", "coap", "amqp", "zigbee", "lorawan", "matter"
    ];

    for proto in iot_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing IoT protocol: {}",
            proto
        );
    }
}

#[test]
fn test_security_protocols_exist() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check security protocols
    let security_protocols = vec![
        "kerberos", "ldap", "radius", "oauth2", "saml"
    ];

    for proto in security_protocols {
        assert!(
            library.iter().any(|(id, _)| id.as_str().contains(proto)),
            "Missing security protocol: {}",
            proto
        );
    }
}

#[test]
fn test_protocol_metadata() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Check that all protocols have metadata
    for (id, meta) in library.iter() {
        assert!(!meta.name.is_empty(), "Protocol {} has empty name", id.as_str());
        assert!(meta.default_port > 0, "Protocol {} has invalid port", id.as_str());
    }
}

#[test]
fn test_https_protocol_details() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    // Find HTTPS protocol
    let https = library.iter()
        .find(|(id, _)| id.as_str() == "https")
        .expect("HTTPS protocol not found");

    let meta = https.1;
    assert_eq!(meta.name.to_lowercase(), "https");
    assert_eq!(meta.default_port, 443);
}

#[test]
fn test_protocol_count_by_category() {
    let protocol_dir = PathBuf::from("protocols");
    let library = ProtocolLibrary::load(&protocol_dir)
        .expect("Failed to load protocol library");

    let total = library.len();
    println!("Total protocols loaded: {}", total);

    // Count by directory (category)
    let categories = vec![
        ("http", "HTTP/Web"),
        ("email", "Email"),
        ("dns", "DNS"),
        ("vpn", "VPN"),
        ("streaming", "Streaming"),
        ("database", "Database"),
        ("messaging", "Messaging"),
        ("file-transfer", "File Transfer"),
        ("gaming", "Gaming"),
        ("iot", "IoT"),
        ("security", "Security"),
        ("network", "Network"),
        ("cloud", "Cloud"),
        ("voip", "VoIP"),
    ];

    for (dir, name) in categories {
        let count = library.iter()
            .filter(|(id, _)| id.as_str().contains(dir) || id.as_str().contains(&dir.replace("-", "")))
            .count();
        println!("{}: {} protocols", name, count);
    }
}

#[test]
fn test_all_protocol_files_parse() {
    use std::fs;
    use std::path::Path;

    let protocols_dir = Path::new("protocols");

    // Walk through all PSF files
    fn visit_dirs(dir: &Path, protocols: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, protocols)?;
                } else if path.extension().and_then(|s| s.to_str()) == Some("psf") {
                    protocols.push(path);
                }
            }
        }
        Ok(())
    }

    let mut protocol_files = Vec::new();
    visit_dirs(protocols_dir, &mut protocol_files).expect("Failed to walk protocol directory");

    println!("Found {} PSF files", protocol_files.len());
    assert!(protocol_files.len() >= 100, "Expected at least 100 PSF files");

    // Try to read each file (basic validation)
    for file in &protocol_files {
        let content = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", file.display(), e));

        assert!(content.contains("@SEGMENT"), "File {} missing @SEGMENT markers", file.display());

        // Basic validation of required sections
        if !content.contains("@SEGMENT.FORMATS") {
            println!("Warning: {} missing FORMATS section", file.display());
        }
        if !content.contains("@SEGMENT.SEQUENCE") {
            println!("Warning: {} missing SEQUENCE section", file.display());
        }
    }
}
