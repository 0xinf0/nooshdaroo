# nQUIC DNS Tunnel Architecture

## Executive Summary

This document provides detailed architecture for integrating nQUIC (Noise-based QUIC) into Nooshdaroo's DNS tunneling system using Quinn 0.11.x + Snow 0.9.x. The design preserves existing Noise key infrastructure while achieving 60% header overhead reduction and modern QUIC features.

---

## Module Structure

```
src/
├── nquic/
│   ├── mod.rs                    # Public API and re-exports
│   ├── crypto/
│   │   ├── mod.rs                # Crypto module exports
│   │   ├── noise_session.rs      # NoiseSession (implements quinn::crypto::Session)
│   │   ├── noise_handshake.rs    # Noise IK handshake state machine
│   │   ├── keys.rs               # Key derivation (Noise CK/HS → QUIC keys)
│   │   └── config.rs             # Crypto configuration builder
│   ├── dns/
│   │   ├── mod.rs                # DNS module exports
│   │   ├── transport.rs          # DnsQuicTransport (UDP:53 + TCP:53)
│   │   ├── codec.rs              # DNS encoding/decoding for QUIC packets
│   │   ├── framing.rs            # Packet framing for DNS size limits
│   │   └── session.rs            # DNS-aware session management
│   ├── endpoint.rs               # NQuicEndpoint (wraps quinn::Endpoint)
│   └── config.rs                 # High-level nQUIC configuration
├── noise_transport.rs            # Extended for nQUIC key management
└── dns_tunnel.rs                 # Updated to use nQUIC transport
```

---

## 1. Quinn Crypto Layer Abstraction

### 1.1 NoiseSession (Core Crypto Integration)

**File:** `src/nquic/crypto/noise_session.rs`

```rust
use quinn_proto::crypto::{
    Session, HeaderKey, Keys, KeyPair, PacketKey,
    HandshakeTokenKey, CryptoError
};
use snow::{HandshakeState, TransportState, Builder};
use std::sync::Arc;

/// NoiseSession implements Quinn's crypto::Session trait using Noise Protocol
pub struct NoiseSession {
    /// Current handshake state (Some during handshake, None after)
    handshake: Option<HandshakeState>,

    /// Transport state after handshake completion
    transport: Option<TransportState>,

    /// Noise configuration (IK pattern, keys)
    config: Arc<NoiseCryptoConfig>,

    /// Side (client/server)
    side: Side,

    /// Connection ID for this session
    connection_id: ConnectionId,

    /// Current key phase (for ratcheting)
    key_phase: bool,

    /// Pending key update (for post-handshake ratcheting)
    pending_key_update: Option<KeyUpdate>,
}

#[derive(Debug, Clone)]
pub struct NoiseCryptoConfig {
    /// Noise pattern (always "Noise_IK_25519_ChaChaPoly_BLAKE2s")
    pattern: &'static str,

    /// Local static keypair (server always has, client optional)
    local_static: Option<[u8; 32]>,

    /// Remote static public key (client must know server's)
    remote_static: Option<[u8; 32]>,

    /// Prologue (prevents cross-protocol attacks)
    prologue: Vec<u8>,
}

impl NoiseSession {
    /// Create a new client session
    pub fn new_client(
        config: Arc<NoiseCryptoConfig>,
        server_pubkey: [u8; 32],
        connection_id: ConnectionId,
    ) -> Result<Self, CryptoError> {
        // Build Noise handshake state as initiator
        let builder = Builder::new(config.pattern.parse().unwrap());
        let builder = builder
            .remote_public_key(&server_pubkey)
            .prologue(&config.prologue);

        let builder = if let Some(local_key) = &config.local_static {
            builder.local_private_key(local_key)
        } else {
            builder
        };

        let handshake = builder
            .build_initiator()
            .map_err(|e| CryptoError::HandshakeFailed)?;

        Ok(Self {
            handshake: Some(handshake),
            transport: None,
            config,
            side: Side::Client,
            connection_id,
            key_phase: false,
            pending_key_update: None,
        })
    }

    /// Create a new server session
    pub fn new_server(
        config: Arc<NoiseCryptoConfig>,
        connection_id: ConnectionId,
    ) -> Result<Self, CryptoError> {
        let local_key = config.local_static
            .ok_or(CryptoError::InvalidKey)?;

        let builder = Builder::new(config.pattern.parse().unwrap());
        let handshake = builder
            .local_private_key(&local_key)
            .prologue(&config.prologue)
            .build_responder()
            .map_err(|_| CryptoError::HandshakeFailed)?;

        Ok(Self {
            handshake: Some(handshake),
            transport: None,
            config,
            side: Side::Server,
            connection_id,
            key_phase: false,
            pending_key_update: None,
        })
    }
}

impl quinn_proto::crypto::Session for NoiseSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Keys {
        // For nQUIC, initial keys are derived from Noise handshake
        // Unlike TLS QUIC, we don't use HKDF-Extract on connection ID
        // Instead, we use a fixed initial key based on the pattern

        // This prevents fingerprinting but requires handshake ASAP
        derive_initial_keys_from_pattern(&self.config.pattern, dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        // Return any handshake-specific data
        // For nQUIC, this could include transport parameters
        None
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // Return authenticated peer identity (server's static pubkey)
        if let Some(transport) = &self.transport {
            Some(Box::new(transport.get_remote_static().to_vec()))
        } else {
            None
        }
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        // nQUIC doesn't support 0-RTT (Noise IK requires round trip)
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false) // No 0-RTT support
    }

    fn is_handshaking(&self) -> bool {
        self.handshake.is_some()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, CryptoError> {
        let handshake = self.handshake.as_mut()
            .ok_or(CryptoError::HandshakeAlreadyComplete)?;

        // Noise handshake messages are embedded in QUIC CRYPTO frames
        let mut response_buf = vec![0u8; 65535];

        let len = handshake
            .read_message(buf, &mut response_buf)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        response_buf.truncate(len);

        // Check if handshake is complete
        if handshake.is_handshake_finished() {
            // Transition to transport mode
            let transport = handshake
                .into_transport_mode()
                .map_err(|_| CryptoError::HandshakeFailed)?;

            self.transport = Some(transport);
            self.handshake = None;

            Ok(true) // Handshake complete
        } else {
            Ok(false) // Need more messages
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, CryptoError> {
        // Transport parameters are embedded in Noise handshake payloads
        // Extract from handshake state
        if let Some(transport) = &self.transport {
            // Parse transport params from handshake payload
            // (stored during handshake completion)
            Ok(Some(self.extract_transport_params()?))
        } else {
            Ok(None)
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let handshake = self.handshake.as_mut()?;

        // Write Noise handshake message
        let payload = self.build_handshake_payload();

        let len = handshake
            .write_message(&payload, buf)
            .ok()?;

        buf.truncate(len);

        // If handshake completes, derive keys
        if handshake.is_handshake_finished() {
            // Derive QUIC 1-RTT keys from Noise chaining key
            let ck = handshake.get_hash(); // Chaining key
            let hs = handshake.get_handshake_hash(); // Handshake hash

            Some(derive_quic_keys_from_noise(ck, hs, self.side))
        } else {
            None
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        // Post-handshake key ratcheting
        if let Some(key_update) = self.pending_key_update.take() {
            Some(key_update.keys)
        } else {
            None
        }
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        // nQUIC doesn't use QUIC retry mechanism (relies on Noise auth)
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), CryptoError> {
        // Export keying material using Noise's handshake hash
        let transport = self.transport.as_ref()
            .ok_or(CryptoError::HandshakeNotComplete)?;

        // Use BLAKE2s to derive material
        let hs = transport.get_handshake_hash();
        derive_keying_material(hs, label, context, output)
    }
}

// Helper: Derive QUIC keys from Noise handshake output
fn derive_quic_keys_from_noise(
    chaining_key: &[u8],
    handshake_hash: &[u8],
    side: Side,
) -> Keys {
    // Use HKDF-Expand with Noise outputs as input keying material
    let (client_key, server_key, client_iv, server_iv, client_hp, server_hp) =
        hkdf_expand_nquic(chaining_key, handshake_hash);

    Keys {
        header: KeyPair {
            local: Box::new(ChaCha20HeaderKey::new(
                if side.is_client() { client_hp } else { server_hp }
            )),
            remote: Box::new(ChaCha20HeaderKey::new(
                if side.is_client() { server_hp } else { client_hp }
            )),
        },
        packet: KeyPair {
            local: Box::new(ChaCha20Poly1305PacketKey::new(
                if side.is_client() { client_key } else { server_key },
                if side.is_client() { client_iv } else { server_iv },
            )),
            remote: Box::new(ChaCha20Poly1305PacketKey::new(
                if side.is_client() { server_key } else { client_key },
                if side.is_client() { server_iv } else { client_iv },
            )),
        },
    }
}

// HKDF-Expand for nQUIC key derivation
fn hkdf_expand_nquic(
    chaining_key: &[u8],
    handshake_hash: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 12], [u8; 12], [u8; 32], [u8; 32]) {
    // Use BLAKE2s (Noise's hash) for expansion
    // Label: "nQUIC v1"

    let mut client_key = [0u8; 32];
    let mut server_key = [0u8; 32];
    let mut client_iv = [0u8; 12];
    let mut server_iv = [0u8; 12];
    let mut client_hp = [0u8; 32];
    let mut server_hp = [0u8; 32];

    // Expand using BLAKE2s with different info strings
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"client key", &mut client_key);
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"server key", &mut server_key);
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"client iv", &mut client_iv);
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"server iv", &mut server_iv);
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"client hp", &mut client_hp);
    blake2s_hkdf_expand(chaining_key, handshake_hash, b"server hp", &mut server_hp);

    (client_key, server_key, client_iv, server_iv, client_hp, server_hp)
}
```

### 1.2 Key Derivation

**File:** `src/nquic/crypto/keys.rs`

```rust
use blake2::{Blake2s256, Digest};

/// BLAKE2s-based HKDF for nQUIC
pub fn blake2s_hkdf_expand(
    prk: &[u8],     // Pseudo-random key (from Noise CK)
    salt: &[u8],    // Salt (from Noise HS)
    info: &[u8],    // Context string
    output: &mut [u8],
) {
    // HKDF-Expand using BLAKE2s
    // T(0) = empty
    // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)

    let mut hasher = Blake2s256::new();
    hasher.update(prk);
    hasher.update(salt);
    hasher.update(info);

    let result = hasher.finalize();
    output.copy_from_slice(&result[..output.len()]);
}

/// ChaCha20 header protection key
pub struct ChaCha20HeaderKey {
    key: [u8; 32],
}

impl ChaCha20HeaderKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl quinn_proto::crypto::HeaderKey for ChaCha20HeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // ChaCha20 header protection (QUIC style)
        let sample_offset = pn_offset + 4;
        let sample = &packet[sample_offset..sample_offset + 16];

        let mask = chacha20_mask(&self.key, sample);

        // Apply mask to header
        packet[0] ^= mask[0] & 0x0f; // Protect lower 4 bits of first byte

        let pn_length = (packet[0] & 0x03) + 1;
        for i in 0..pn_length as usize {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Same as decrypt for ChaCha20
        self.decrypt(pn_offset, packet);
    }

    fn sample_size(&self) -> usize {
        16 // ChaCha20 sample size
    }
}

/// ChaCha20-Poly1305 packet encryption
pub struct ChaCha20Poly1305PacketKey {
    key: [u8; 32],
    iv: [u8; 12],
}

impl ChaCha20Poly1305PacketKey {
    pub fn new(key: [u8; 32], iv: [u8; 12]) -> Self {
        Self { key, iv }
    }
}

impl quinn_proto::crypto::PacketKey for ChaCha20Poly1305PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        // Construct nonce: IV XOR packet_number
        let mut nonce = self.iv;
        for (i, b) in packet.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }

        // Encrypt using ChaCha20-Poly1305
        let (header, payload_tag) = buf.split_at_mut(header_len);

        chacha20poly1305_encrypt(&self.key, &nonce, header, payload_tag);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<(), CryptoError> {
        // Construct nonce
        let mut nonce = self.iv;
        for (i, b) in packet.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }

        // Decrypt using ChaCha20-Poly1305
        chacha20poly1305_decrypt(&self.key, &nonce, header, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn tag_len(&self) -> usize {
        16 // Poly1305 tag size
    }

    fn confidentiality_limit(&self) -> u64 {
        // ChaCha20 limit: 2^64 messages
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        // Poly1305 limit: 2^64 messages
        u64::MAX
    }
}
```

---

## 2. DNS Transport Integration

### 2.1 DNS Codec

**File:** `src/nquic/dns/codec.rs`

```rust
use crate::dns_transport::DnsMessage;

/// DNS codec for encoding QUIC packets into DNS messages
pub struct DnsQuicCodec {
    /// DNS domain for tunnel
    domain: String,

    /// Maximum packet size for DNS (varies by transport)
    max_packet_size: usize,
}

impl DnsQuicCodec {
    pub fn new(domain: String, use_tcp: bool) -> Self {
        Self {
            domain,
            // UDP DNS: 512 bytes (or 4096 with EDNS0)
            // TCP DNS: 65535 bytes
            max_packet_size: if use_tcp { 16384 } else { 1232 },
        }
    }

    /// Encode QUIC packet into DNS query (upstream)
    pub fn encode_query(
        &self,
        quic_packet: &[u8],
        session_id: &[u8; 8],
    ) -> Result<Vec<u8>, CodecError> {
        // DNS query format:
        // <base32(quic_packet)>.<session_id_hex>.tunnel.example.com TXT

        if quic_packet.len() > self.max_upstream_payload() {
            return Err(CodecError::PacketTooLarge);
        }

        // Base32 encode the QUIC packet (for DNS labels)
        let encoded = data_encoding::BASE32_NOPAD.encode(quic_packet);

        // Split into DNS labels (max 63 chars each)
        let labels: Vec<&str> = encoded
            .as_bytes()
            .chunks(63)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        // Build QNAME: <labels>.<session_id>.<domain>
        let session_hex = hex::encode(session_id);
        let qname = format!(
            "{}.{}.{}",
            labels.join("."),
            session_hex,
            self.domain
        );

        // Construct DNS query
        let mut query = Vec::new();
        self.build_dns_query(&mut query, &qname, DnsType::TXT)?;

        Ok(query)
    }

    /// Encode QUIC packet into DNS response (downstream)
    pub fn encode_response(
        &self,
        query_id: u16,
        quic_packets: &[Vec<u8>],
    ) -> Result<Vec<u8>, CodecError> {
        // DNS response format:
        // TXT records containing raw QUIC packets (binary)

        let mut total_size = 0;
        for pkt in quic_packets {
            total_size += pkt.len() + 2; // +2 for length prefix
        }

        if total_size > self.max_packet_size {
            return Err(CodecError::PacketTooLarge);
        }

        let mut response = Vec::new();
        self.build_dns_response(
            &mut response,
            query_id,
            &self.domain,
            quic_packets,
        )?;

        Ok(response)
    }

    /// Decode DNS query to extract QUIC packet
    pub fn decode_query(&self, dns_msg: &[u8]) -> Result<(Vec<u8>, [u8; 8]), CodecError> {
        // Parse DNS message
        let msg = self.parse_dns_message(dns_msg)?;

        // Extract QNAME
        let qname = msg.questions.first()
            .ok_or(CodecError::InvalidMessage)?
            .qname.clone();

        // Parse QNAME: <base32-data>.<session-id>.<domain>
        let parts: Vec<&str> = qname.split('.').collect();

        if parts.len() < 3 {
            return Err(CodecError::InvalidQName);
        }

        // Extract session ID (second-to-last before domain)
        let session_hex = parts[parts.len() - 2];
        let session_id = hex::decode(session_hex)
            .map_err(|_| CodecError::InvalidSessionId)?;

        if session_id.len() != 8 {
            return Err(CodecError::InvalidSessionId);
        }

        let mut session_bytes = [0u8; 8];
        session_bytes.copy_from_slice(&session_id);

        // Extract and decode base32 data
        let base32_parts = &parts[..parts.len() - 2];
        let base32_data = base32_parts.join("");

        let quic_packet = data_encoding::BASE32_NOPAD.decode(base32_data.as_bytes())
            .map_err(|_| CodecError::InvalidEncoding)?;

        Ok((quic_packet, session_bytes))
    }

    /// Decode DNS response to extract QUIC packets
    pub fn decode_response(&self, dns_msg: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
        let msg = self.parse_dns_message(dns_msg)?;

        let mut packets = Vec::new();

        for answer in &msg.answers {
            if answer.rtype == DnsType::TXT {
                // TXT record contains raw QUIC packet
                // Format: <2-byte length><quic packet>
                let data = &answer.rdata;

                if data.len() < 2 {
                    continue;
                }

                let len = u16::from_be_bytes([data[0], data[1]]) as usize;

                if data.len() < 2 + len {
                    return Err(CodecError::InvalidLength);
                }

                let packet = data[2..2 + len].to_vec();
                packets.push(packet);
            }
        }

        Ok(packets)
    }

    fn max_upstream_payload(&self) -> usize {
        // Account for DNS overhead and base32 expansion
        // Base32 expansion: 8/5 ratio
        // DNS labels: max 63 chars, need separators

        let dns_overhead = 100; // DNS header + question + domain
        let available = self.max_packet_size.saturating_sub(dns_overhead);

        // Reverse base32 expansion: payload = (available * 5) / 8
        (available * 5) / 8
    }
}

#[derive(Debug)]
pub enum CodecError {
    PacketTooLarge,
    InvalidMessage,
    InvalidQName,
    InvalidSessionId,
    InvalidEncoding,
    InvalidLength,
}
```

### 2.2 Packet Framing

**File:** `src/nquic/dns/framing.rs`

```rust
/// Handles fragmentation and reassembly of QUIC packets for DNS
pub struct DnsFramer {
    /// Maximum fragment size
    max_fragment_size: usize,

    /// Reassembly buffer (session_id -> fragments)
    reassembly: HashMap<[u8; 8], FragmentBuffer>,
}

struct FragmentBuffer {
    fragments: BTreeMap<u16, Vec<u8>>, // seq -> data
    total_fragments: Option<u16>,
    last_update: Instant,
}

impl DnsFramer {
    /// Fragment a large QUIC packet for DNS transport
    pub fn fragment(
        &self,
        quic_packet: &[u8],
    ) -> Vec<Fragment> {
        if quic_packet.len() <= self.max_fragment_size {
            // No fragmentation needed
            return vec![Fragment {
                seq: 0,
                total: 1,
                data: quic_packet.to_vec(),
            }];
        }

        // Split into fragments
        let chunks = quic_packet.chunks(self.max_fragment_size);
        let total = chunks.len() as u16;

        chunks.enumerate()
            .map(|(i, chunk)| Fragment {
                seq: i as u16,
                total,
                data: chunk.to_vec(),
            })
            .collect()
    }

    /// Reassemble fragments into complete QUIC packet
    pub fn reassemble(
        &mut self,
        session_id: &[u8; 8],
        fragment: Fragment,
    ) -> Option<Vec<u8>> {
        let buffer = self.reassembly
            .entry(*session_id)
            .or_insert_with(|| FragmentBuffer {
                fragments: BTreeMap::new(),
                total_fragments: None,
                last_update: Instant::now(),
            });

        // Update total fragments if not set
        if buffer.total_fragments.is_none() {
            buffer.total_fragments = Some(fragment.total);
        }

        // Store fragment
        buffer.fragments.insert(fragment.seq, fragment.data);
        buffer.last_update = Instant::now();

        // Check if all fragments received
        if buffer.fragments.len() == fragment.total as usize {
            // Reassemble in order
            let mut complete = Vec::new();
            for seq in 0..fragment.total {
                if let Some(data) = buffer.fragments.get(&seq) {
                    complete.extend_from_slice(data);
                } else {
                    return None; // Missing fragment
                }
            }

            // Remove from reassembly buffer
            self.reassembly.remove(session_id);

            Some(complete)
        } else {
            None // Still waiting for more fragments
        }
    }

    /// Clean up stale reassembly buffers
    pub fn cleanup_stale(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.reassembly.retain(|_, buffer| {
            now.duration_since(buffer.last_update) < timeout
        });
    }
}

pub struct Fragment {
    pub seq: u16,
    pub total: u16,
    pub data: Vec<u8>,
}
```

---

## 3. Session Management

**File:** `src/nquic/dns/session.rs`

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// Manages DNS-based QUIC sessions
/// Adapts slipstream/dnstt RemoteMap pattern for nQUIC
pub struct DnsSessionManager {
    /// Active sessions (session_id -> session)
    sessions: HashMap<[u8; 8], DnsSession>,

    /// Session timeout
    timeout: Duration,

    /// Next session ID
    next_session_id: u64,
}

pub struct DnsSession {
    /// Session ID (unique identifier)
    pub id: [u8; 8],

    /// QUIC connection
    pub connection: quinn::Connection,

    /// Last seen time (for timeout)
    pub last_seen: Instant,

    /// DNS source address (may change due to NAT)
    pub dns_addr: SocketAddr,

    /// Send queue for downstream packets
    pub send_queue: VecDeque<Vec<u8>>,

    /// Stash (like dnstt's single-packet buffer)
    pub stash: Option<Vec<u8>>,
}

impl DnsSessionManager {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            timeout,
            next_session_id: rand::random(),
        }
    }

    /// Get or create session for incoming DNS query
    pub fn get_or_create(
        &mut self,
        session_id: &[u8; 8],
        dns_addr: SocketAddr,
        endpoint: &quinn::Endpoint,
    ) -> Result<&mut DnsSession, SessionError> {
        // Check if session exists
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_seen = Instant::now();
            session.dns_addr = dns_addr; // Update in case NAT changed
            return Ok(session);
        }

        // Create new session (server side - wait for connection)
        let session = DnsSession {
            id: *session_id,
            connection: None, // Will be set when connection arrives
            last_seen: Instant::now(),
            dns_addr,
            send_queue: VecDeque::new(),
            stash: None,
        };

        self.sessions.insert(*session_id, session);
        Ok(self.sessions.get_mut(session_id).unwrap())
    }

    /// Create new client session
    pub fn create_client_session(
        &mut self,
        server_addr: SocketAddr,
        endpoint: &quinn::Endpoint,
    ) -> Result<([u8; 8], quinn::Connection), SessionError> {
        // Generate unique session ID
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&self.next_session_id.to_be_bytes());
        self.next_session_id = self.next_session_id.wrapping_add(1);

        // Connect via QUIC (will use DNS transport underneath)
        let connection = endpoint.connect(server_addr, "nquic")?
            .await?;

        let session = DnsSession {
            id: session_id,
            connection: Some(connection.clone()),
            last_seen: Instant::now(),
            dns_addr: server_addr,
            send_queue: VecDeque::new(),
            stash: None,
        };

        self.sessions.insert(session_id, session);

        Ok((session_id, connection))
    }

    /// Process incoming QUIC packet from DNS
    pub fn handle_incoming_packet(
        &mut self,
        session_id: &[u8; 8],
        quic_packet: Vec<u8>,
        dns_addr: SocketAddr,
    ) -> Result<(), SessionError> {
        let session = self.get_or_create(session_id, dns_addr, &endpoint)?;

        // Feed packet to QUIC endpoint
        // Quinn will handle reassembly and deliver to application
        session.connection.process_packet(quic_packet)?;

        Ok(())
    }

    /// Get packets to send downstream via DNS
    pub fn poll_send_queue(
        &mut self,
        session_id: &[u8; 8],
    ) -> Option<Vec<Vec<u8>>> {
        let session = self.sessions.get_mut(session_id)?;

        // Check stash first (like dnstt)
        if let Some(stashed) = session.stash.take() {
            return Some(vec![stashed]);
        }

        // Drain send queue
        let mut packets = Vec::new();
        while let Some(pkt) = session.send_queue.pop_front() {
            packets.push(pkt);

            // Limit to max DNS response size
            if packets.len() >= 10 {
                break;
            }
        }

        if packets.is_empty() {
            None
        } else {
            Some(packets)
        }
    }

    /// Stash a packet for next poll (like dnstt)
    pub fn stash(&mut self, session_id: &[u8; 8], packet: Vec<u8>) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.stash.is_none() {
                session.stash = Some(packet);
                return true;
            }
        }
        false
    }

    /// Remove expired sessions
    pub fn remove_expired(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.last_seen) < self.timeout
        });
    }
}
```

---

## 4. Integration Points

### 4.1 Noise Transport Extension

**File:** `src/noise_transport.rs` (modifications)

```rust
// Add nQUIC variant to NoisePattern enum
pub enum NoisePattern {
    NK,  // Server auth only (existing)
    XX,  // No auth (existing)
    KK,  // Mutual auth (existing)
    IK,  // NEW: Identity Known (for nQUIC)
}

// Add nQUIC configuration
impl NoiseConfig {
    /// Create nQUIC client configuration
    pub fn nquic_client(server_pubkey: &[u8; 32]) -> Self {
        Self {
            pattern: NoisePattern::IK,
            local_private_key: None, // Optional for client
            remote_public_key: Some(base64::encode(server_pubkey)),
            psk: None,
        }
    }

    /// Create nQUIC server configuration
    pub fn nquic_server(server_privkey: &[u8; 32]) -> Self {
        Self {
            pattern: NoisePattern::IK,
            local_private_key: Some(base64::encode(server_privkey)),
            remote_public_key: None,
            psk: None,
        }
    }
}
```

### 4.2 Configuration

**File:** `src/nquic/config.rs`

```rust
#[derive(Clone, Debug)]
pub struct NQuicConfig {
    /// DNS domain for tunnel
    pub dns_domain: String,

    /// DNS transport (UDP:53, TCP:53, or both)
    pub dns_transport: DnsTransport,

    /// Noise configuration
    pub noise: NoiseConfig,

    /// QUIC parameters
    pub quic: QuicParams,

    /// Session timeout
    pub session_timeout: Duration,
}

#[derive(Clone, Debug)]
pub enum DnsTransport {
    Udp,
    Tcp,
    Both,
}

#[derive(Clone, Debug)]
pub struct QuicParams {
    /// Maximum streams
    pub max_streams: u64,

    /// Initial max data
    pub initial_max_data: u64,

    /// Keep alive interval
    pub keep_alive_interval: Duration,

    /// Auto ratchet interval (for PFS)
    pub auto_ratchet_interval: Option<Duration>,
}

impl NQuicConfig {
    pub fn from_toml(config: &toml::Value) -> Result<Self, ConfigError> {
        // Parse TOML configuration
        Ok(Self {
            dns_domain: config["dns_tunnel"]["nquic"]["dns_domain"]
                .as_str()
                .ok_or(ConfigError::MissingField("dns_domain"))?
                .to_string(),

            dns_transport: match config["dns_tunnel"]["nquic"]["dns_proto"]
                .as_str()
                .unwrap_or("udp")
            {
                "udp" => DnsTransport::Udp,
                "tcp" => DnsTransport::Tcp,
                "udp+tcp" => DnsTransport::Both,
                _ => return Err(ConfigError::InvalidTransport),
            },

            noise: NoiseConfig::from_toml(config)?,

            quic: QuicParams {
                max_streams: config["dns_tunnel"]["nquic"]["max_streams"]
                    .as_integer()
                    .unwrap_or(100) as u64,

                initial_max_data: config["dns_tunnel"]["nquic"]["initial_max_data"]
                    .as_integer()
                    .unwrap_or(10485760) as u64,

                keep_alive_interval: Duration::from_secs(
                    config["dns_tunnel"]["nquic"]["keep_alive_interval"]
                        .as_integer()
                        .unwrap_or(5) as u64
                ),

                auto_ratchet_interval: config["dns_tunnel"]["nquic"]["auto_ratchet_interval"]
                    .as_integer()
                    .map(|s| Duration::from_secs(s as u64)),
            },
        })
    }
}
```

---

## 5. Usage Example

```rust
// Server
let config = NQuicConfig {
    dns_domain: "tunnel.nooshdaroo.net".to_string(),
    dns_transport: DnsTransport::Both,
    noise: NoiseConfig::nquic_server(&server_privkey),
    quic: QuicParams::default(),
    session_timeout: Duration::from_secs(300),
};

let endpoint = NQuicEndpoint::new_server(config).await?;

loop {
    let connection = endpoint.accept().await?;

    tokio::spawn(async move {
        handle_quic_connection(connection).await;
    });
}

// Client
let config = NQuicConfig {
    dns_domain: "tunnel.nooshdaroo.net".to_string(),
    dns_transport: DnsTransport::Udp,
    noise: NoiseConfig::nquic_client(&server_pubkey),
    quic: QuicParams::default(),
    session_timeout: Duration::from_secs(300),
};

let endpoint = NQuicEndpoint::new_client(config).await?;
let connection = endpoint.connect(server_addr).await?;

// Use connection for streams
let mut stream = connection.open_bi().await?;
stream.0.write_all(b"Hello over nQUIC+DNS!").await?;
```

---

## 6. Performance Optimizations

### 6.1 Congestion Control Adaptations

Following slipstream's approach:

**Client:**
- Use DCUBIC (loss + latency signals)
- Handle DNS resolver rate limits gracefully

**Server:**
- Disable congestion window
- Always respond to queries (maximize bandwidth)
- Ignore ACK-only frame loss signals

### 6.2 DNS-Specific Tuning

```rust
// Reduce QUIC Initial packet minimum size
transport_config.initial_mtu(600); // Instead of 1200

// Disable PATH_CHALLENGE (dummy addresses in DNS)
transport_config.enable_path_challenge(false);

// Aggressive keep-alive for server→client latency
transport_config.keep_alive_interval(Some(Duration::from_millis(500)));
```

---

## 7. Testing Strategy

### Unit Tests
- NoiseSession trait implementation
- Key derivation correctness
- DNS codec encode/decode roundtrips
- Fragment reassembly logic

### Integration Tests
- nQUIC client ↔ server handshake
- Data transfer over DNS tunnel
- Session migration across DNS resolver changes
- Multipath aggregation

### Performance Tests
- Throughput vs current KCP
- Latency measurements
- Header overhead verification (24 bytes)
- CPU/memory profiling

---

**Document Version:** 1.0
**Last Updated:** 2025-01-21
**Author:** Claude
**Status:** Architecture Design
