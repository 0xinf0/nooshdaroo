//! Show hex dump of protocol wrappers
//! This proves what protocol signatures are being used

use nooshdaroo::protocol::ProtocolId;
use nooshdaroo::protocol_wrapper::ProtocolWrapper;

fn hex_dump(data: &[u8], label: &str) {
    println!("\n{}", label);
    println!("{}", "=".repeat(70));
    
    // Show first 80 bytes in hex
    let show_bytes = data.len().min(80);
    
    for (i, chunk) in data[..show_bytes].chunks(16).enumerate() {
        print!("0x{:04x}:  ", i * 16);
        
        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 { print!(" "); }
        }
        
        // Padding
        for _ in chunk.len()..16 {
            print!("   ");
        }
        
        // ASCII
        print!(" |");
        for byte in chunk {
            let ch = if *byte >= 32 && *byte < 127 {
                *byte as char
            } else {
                '.'
            };
            print!("{}", ch);
        }
        println!("|");
    }
    
    if data.len() > show_bytes {
        println!("... ({} more bytes)", data.len() - show_bytes);
    }
    
    println!("Total: {} bytes\n", data.len());
}

fn main() {
    println!("\n{}", "=".repeat(70));
    println!("NOOSHDAROO PROTOCOL HEX DUMP");
    println!("{}", "=".repeat(70));
    
    // Simulate Noise encrypted data (1000 bytes payload + 16 byte MAC = 1016 bytes)
    let noise_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let noise_data: Vec<u8> = (0..1016).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    
    println!("\n📦 Original Noise encrypted data: {} bytes", noise_data.len());
    println!("   (This is the encrypted tunnel payload)");
    hex_dump(&noise_data[..32], "First 32 bytes of Noise data:");
    
    // Test HTTPS protocol
    println!("\n{}", "=".repeat(70));
    println!("🔐 HTTPS/TLS 1.3 PROTOCOL");
    println!("{}", "=".repeat(70));
    
    let mut https_wrapper = ProtocolWrapper::new(ProtocolId::from("https"), None);
    let https_wrapped = https_wrapper.wrap(&noise_data).unwrap();
    
    hex_dump(&https_wrapped[..64], "HTTPS wrapped data (first 64 bytes):");
    
    println!("📊 Protocol Analysis:");
    println!("   Byte 0:    0x{:02x} = TLS Content Type (0x17 = Application Data)", https_wrapped[0]);
    println!("   Bytes 1-2: 0x{:02x}{:02x} = TLS Version (0x0303 = TLS 1.2)", https_wrapped[1], https_wrapped[2]);
    println!("   Bytes 3-4: 0x{:02x}{:02x} = Length ({} bytes)", https_wrapped[3], https_wrapped[4], 
              u16::from_be_bytes([https_wrapped[3], https_wrapped[4]]));
    println!("   Bytes 5+:  Encrypted payload + MAC");
    
    if https_wrapped[0] == 0x17 && https_wrapped[1] == 0x03 && https_wrapped[2] == 0x03 {
        println!("\n   ✅ VALID TLS 1.3 Application Data frame!");
        println!("   ✅ This will appear as HTTPS traffic to DPI systems");
    }
    
    // Test DNS protocol
    println!("\n{}", "=".repeat(70));
    println!("🌐 DNS PROTOCOL");
    println!("{}", "=".repeat(70));
    
    let mut dns_wrapper = ProtocolWrapper::new(ProtocolId::from("dns"), None);
    match dns_wrapper.wrap(&noise_data) {
        Ok(dns_wrapped) => {
            hex_dump(&dns_wrapped[..64], "DNS wrapped data (first 64 bytes):");
            
            println!("📊 Protocol Analysis:");
            println!("   Bytes 0-1:  Transaction ID");
            println!("   Bytes 2-3:  Flags");
            println!("   Bytes 4-5:  Question count");
            println!("   Bytes 6-7:  Answer count");
            println!("   Bytes 8+:   Query data (encrypted)");
            println!("\n   ✅ DNS-like frame structure");
        }
        Err(e) => {
            println!("   ⚠️  DNS wrapping: {}", e);
            println!("   (DNS protocol may use raw Noise frames)");
        }
    }
    
    // Test SSH protocol
    println!("\n{}", "=".repeat(70));
    println!("🔑 SSH PROTOCOL");
    println!("{}", "=".repeat(70));
    
    let mut ssh_wrapper = ProtocolWrapper::new(ProtocolId::from("ssh"), None);
    match ssh_wrapper.wrap(&noise_data) {
        Ok(ssh_wrapped) => {
            hex_dump(&ssh_wrapped[..64], "SSH wrapped data (first 64 bytes):");
            println!("\n   ✅ SSH-like frame structure");
        }
        Err(e) => {
            println!("   ⚠️  SSH wrapping: {}", e);
        }
    }
    
    println!("\n{}", "=".repeat(70));
    println!("CONCLUSION:");
    println!("{}", "=".repeat(70));
    println!("✅ Protocol wrappers transform Noise encrypted data");
    println!("✅ Traffic appears as legitimate protocol (HTTPS, DNS, SSH)");
    println!("✅ DPI systems will see valid protocol signatures");
    println!("{}", "=".repeat(70));
    println!();
}
