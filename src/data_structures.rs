use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::binary_protocol_utils::{hex_encode, hex_decode};
use sha2::{Sha256, Digest};

// Debug levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum DebugLevel {
    Clean = 0,    // Default - minimal output
    Basic = 1,    // Connection info, key exchanges
    Full = 2,     // All debug output
}

// Global debug level
pub static mut DEBUG_LEVEL: DebugLevel = DebugLevel::Clean;

// Debug macro for basic debug (level 1+)
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::data_structures::DEBUG_LEVEL as u8 >= crate::data_structures::DebugLevel::Basic as u8 {
                println!($($arg)*);
            }
        }
    };
}

// Debug macro for full debug (level 2)
#[macro_export]
macro_rules! debug_full_println {
    ($($arg:tt)*) => {
        unsafe {
            if crate::data_structures::DEBUG_LEVEL as u8 >= crate::data_structures::DebugLevel::Full as u8 {
                println!($($arg)*);
            }
        }
    };
}

// --- pub constants ---

#[allow(dead_code)]
pub const VERSION: &str = "v1.0.0";

pub const BITCHAT_SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);

pub const BITCHAT_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

// Cover traffic prefix used by iOS for dummy messages
pub const COVER_TRAFFIC_PREFIX: &str = "☂DUMMY☂";

// Packet header flags
pub const FLAG_HAS_RECIPIENT: u8 = 0x01;
pub const FLAG_HAS_SIGNATURE: u8 = 0x02;
pub const FLAG_IS_COMPRESSED: u8 = 0x04;

// Message payload flags (matching Swift's toBinaryPayload)
#[allow(dead_code)]
pub const MSG_FLAG_IS_RELAY: u8 = 0x01;
pub const MSG_FLAG_IS_PRIVATE: u8 = 0x02;
pub const MSG_FLAG_HAS_ORIGINAL_SENDER: u8 = 0x04;
pub const MSG_FLAG_HAS_RECIPIENT_NICKNAME: u8 = 0x08;
pub const MSG_FLAG_HAS_SENDER_PEER_ID: u8 = 0x10;
pub const MSG_FLAG_HAS_MENTIONS: u8 = 0x20;
pub const MSG_FLAG_HAS_CHANNEL: u8 = 0x40;
pub const MSG_FLAG_IS_ENCRYPTED: u8 = 0x80;

#[allow(dead_code)]
pub const SIGNATURE_SIZE: usize = 64;  // Ed25519 signature size

// Swift's SpecialRecipients.broadcast = Data(repeating: 0xFF, count: 8)
pub const BROADCAST_RECIPIENT: [u8; 8] = [0xFF; 8];

// --- Protocol pub structs and Enums ---

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionStatus {
    None,               // Failed or incompatible
    NoHandshake,        // No handshake attempted yet
    NoiseHandshaking,   // Currently establishing
    NoiseSecured,       // Established but not verified
    NoiseVerified,      // Established and verified
}

impl EncryptionStatus {
    pub fn icon(&self) -> Option<&'static str> {
        match self {
            EncryptionStatus::None => Some("🔒❌"),           // Failed handshake
            EncryptionStatus::NoHandshake => None,            // No icon when no handshake attempted
            EncryptionStatus::NoiseHandshaking => Some("🔄"), // Establishing
            EncryptionStatus::NoiseSecured => Some("🔒"),     // Encrypted
            EncryptionStatus::NoiseVerified => Some("🔒✅"),  // Encrypted & Verified
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            EncryptionStatus::None => "Encryption failed",
            EncryptionStatus::NoHandshake => "Not encrypted",
            EncryptionStatus::NoiseHandshaking => "Establishing encryption...",
            EncryptionStatus::NoiseSecured => "Encrypted",
            EncryptionStatus::NoiseVerified => "Encrypted & Verified",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType { 
    Announce = 0x01, 
    KeyExchange = 0x02, 
    Leave = 0x03,
    Message = 0x04,
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    ChannelAnnounce = 0x08,      // Channel status announcement (matches Swift v2 code)
    ChannelRetention = 0x09,     // Channel retention policy (matches Swift v2 code)
    DeliveryAck = 0x0A,          // Acknowledge message received
    DeliveryStatusRequest = 0x0B,  // Request delivery status
    ReadReceipt = 0x0C,          // Message has been read
    
    // Noise Protocol messages
    NoiseHandshakeInit = 0x10,   // Noise handshake initiation
    NoiseHandshakeResp = 0x11,   // Noise handshake response
    NoiseEncrypted = 0x12,       // Noise encrypted transport message
    NoiseIdentityAnnounce = 0x13, // Announce static public key for discovery
    
    // Protocol version negotiation
    VersionHello = 0x20,         // Initial version announcement
    VersionAck = 0x21,           // Version acknowledgment
    
    // Protocol-level acknowledgments
    ProtocolAck = 0x22,          // Generic protocol acknowledgment
    ProtocolNack = 0x23,         // Negative acknowledgment (failure)
    SystemValidation = 0x24,     // Session validation ping
    HandshakeRequest = 0x25,     // Request handshake for pending messages
}

// Peer information
#[derive(Debug, Clone)]
pub struct Peer { 
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,  // SHA256 hash of Noise static public key
    pub last_seen: Option<SystemTime>,
    pub connection_state: PeerConnectionState,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            nickname: None,
            fingerprint: None,
            last_seen: None,
            connection_state: PeerConnectionState::Disconnected,
        }
    }
}

// Peer connection states (matching Swift implementation)
#[derive(Debug, Clone, PartialEq)]
pub enum PeerConnectionState {
    Disconnected,
    Connected,
    Authenticating,
    Authenticated,
}

// Fingerprint calculation utility
pub fn calculate_fingerprint(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

// Packet structure - matches Swift BitchatPacket exactly
#[derive(Debug)]
pub struct BitchatPacket { 
    pub version: u8,                    // Protocol version (1)
    pub msg_type: MessageType,          // Message type
    pub sender_id: Vec<u8>,            // Sender ID as binary data (8 bytes)
    pub sender_id_str: String,          // Sender ID as hex string
    pub recipient_id: Option<Vec<u8>>,  // Recipient ID as binary data (8 bytes) - optional
    pub recipient_id_str: Option<String>, // Recipient ID as hex string - optional
    pub timestamp: u64,                 // Timestamp in milliseconds
    pub payload: Vec<u8>,              // Message payload
    pub signature: Option<Vec<u8>>,    // Optional signature (64 bytes)
    pub ttl: u8,                       // Time to live
}

#[derive(Debug)]
pub struct BitchatMessage { 
    pub id: String, 
    pub sender: String,  // Add sender field
    pub content: String, 
    pub channel: Option<String>,
    pub is_encrypted: bool,
    pub encrypted_content: Option<Vec<u8>>,  // Store raw encrypted bytes
}

// Delivery confirmation pub structures matching iOS
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeliveryAck {
    #[serde(rename = "originalMessageID")]
    pub original_message_id: String,
    #[serde(rename = "ackID")]
    pub ack_id: String,
    #[serde(rename = "recipientID")]
    pub recipient_id: String,
    #[serde(rename = "recipientNickname")]
    pub recipient_nickname: String,
    pub timestamp: u64,
    #[serde(rename = "hopCount")]
    pub hop_count: u8,
}

// Read receipt structure matching Swift
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadReceipt {
    #[serde(rename = "originalMessageID")]
    pub original_message_id: String,
    #[serde(rename = "receiptID")]
    pub receipt_id: String,
    #[serde(rename = "readerID")]
    pub reader_id: String,
    #[serde(rename = "readerNickname")]
    pub reader_nickname: String,
    pub timestamp: u64,
}

// Handshake request for pending messages
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeRequest {
    #[serde(rename = "requestID")]
    pub request_id: String,
    #[serde(rename = "requesterID")]
    pub requester_id: String,
    #[serde(rename = "requesterNickname")]
    pub requester_nickname: String,
    #[serde(rename = "targetID")]
    pub target_id: String,
    #[serde(rename = "pendingMessageCount")]
    pub pending_message_count: u8,
    pub timestamp: u64,
}

impl HandshakeRequest {
    /// Create a new HandshakeRequest with auto-generated UUID and current timestamp
    pub fn new(requester_id: String, requester_nickname: String, target_id: String, pending_message_count: u8) -> Self {
        use uuid::Uuid;
        use std::time::{SystemTime, UNIX_EPOCH};
        
        Self {
            request_id: Uuid::new_v4().to_string(),
            requester_id,
            requester_nickname,
            target_id,
            pending_message_count,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }
    
    /// Private constructor for binary decoding (matches Swift implementation)
    pub(crate) fn from_parts(
        request_id: String,
        requester_id: String,
        requester_nickname: String,
        target_id: String,
        pending_message_count: u8,
        timestamp: u64,
    ) -> Self {
        Self {
            request_id,
            requester_id,
            requester_nickname,
            target_id,
            pending_message_count,
            timestamp,
        }
    }
}

// Protocol-level acknowledgment
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolAck {
    #[serde(rename = "originalPacketID")]
    pub original_packet_id: String,
    #[serde(rename = "ackID")]
    pub ack_id: String,
    #[serde(rename = "senderID")]
    pub sender_id: String,
    #[serde(rename = "receiverID")]
    pub receiver_id: String,
    #[serde(rename = "packetType")]
    pub packet_type: u8,
    pub timestamp: u64,
    #[serde(rename = "hopCount")]
    pub hop_count: u8,
}

// Protocol-level negative acknowledgment
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolNack {
    #[serde(rename = "originalPacketID")]
    pub original_packet_id: String,
    #[serde(rename = "nackID")]
    pub nack_id: String,
    #[serde(rename = "senderID")]
    pub sender_id: String,
    #[serde(rename = "receiverID")]
    pub receiver_id: String,
    #[serde(rename = "packetType")]
    pub packet_type: u8,
    pub timestamp: u64,
    pub reason: String,
    #[serde(rename = "errorCode")]
    pub error_code: u8,
}

// Version negotiation hello message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionHello {
    #[serde(rename = "supportedVersions")]
    pub supported_versions: Vec<u8>,
    #[serde(rename = "preferredVersion")]
    pub preferred_version: u8,
    #[serde(rename = "clientVersion")]
    pub client_version: String,
    pub platform: String,
    pub capabilities: Option<Vec<String>>,
}

// Version negotiation acknowledgment
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionAck {
    #[serde(rename = "agreedVersion")]
    pub agreed_version: u8,
    #[serde(rename = "serverVersion")]
    pub server_version: String,
    pub platform: String,
    pub capabilities: Option<Vec<String>>,
    pub rejected: bool,
    pub reason: Option<String>,
}

// Noise identity announcement
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoiseIdentityAnnouncement {
    #[serde(rename = "peerID")]
    pub peer_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: Vec<u8>,
    #[serde(rename = "signingPublicKey")]
    pub signing_public_key: Vec<u8>,
    pub nickname: String,
    pub timestamp: u64,
    #[serde(rename = "previousPeerID")]
    pub previous_peer_id: Option<String>,
    pub signature: Vec<u8>,
}

// Track sent messages awaiting delivery confirmation
pub struct DeliveryTracker {
    pub pending_messages: HashMap<String, (String, SystemTime, bool)>, // message_id -> (content, sent_time, is_private)
    pub sent_acks: HashSet<String>, // Track ACK IDs we've already sent to prevent duplicates
}

impl DeliveryTracker {
    pub fn new() -> Self {
        Self {
            pending_messages: HashMap::new(),
            sent_acks: HashSet::new(),
        }
    }
    
    pub fn track_message(&mut self, message_id: String, content: String, is_private: bool) {
        self.pending_messages.insert(message_id, (content, SystemTime::now(), is_private));
    }
    
    pub fn mark_delivered(&mut self, message_id: &str) -> bool {
        self.pending_messages.remove(message_id).is_some()
    }
    
    pub fn should_send_ack(&mut self, ack_id: &str) -> bool {
        self.sent_acks.insert(ack_id.to_string())
    }
}

// Fragment reassembly tracking - using hex strings as keys (matching Swift)
pub struct FragmentCollector {
    pub fragments: HashMap<String, HashMap<u16, Vec<u8>>>,  // fragment_id_hex -> (index -> data)
    pub metadata: HashMap<String, (u16, u8, String)>,  // fragment_id_hex -> (total, original_type, sender_id)
}

impl FragmentCollector {
    pub fn new() -> Self {
        FragmentCollector {
            fragments: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn add_fragment(&mut self, fragment_id: [u8; 8], index: u16, total: u16, original_type: u8, data: Vec<u8>, sender_id: String) -> Option<(Vec<u8>, String)> {
        // Convert fragment ID to hex string (matching Swift's hexEncodedString)
        let fragment_id_hex = fragment_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        debug_full_println!("[COLLECTOR] Adding fragment {} (index {}/{}) for ID {}", 
                index + 1, index + 1, total, &fragment_id_hex[..8]);
        
        // Initialize if first fragment
        if !self.fragments.contains_key(&fragment_id_hex) {
            debug_full_println!("[COLLECTOR] Creating new fragment collection for ID {}", &fragment_id_hex[..8]);
            self.fragments.insert(fragment_id_hex.clone(), HashMap::new());
            self.metadata.insert(fragment_id_hex.clone(), (total, original_type, sender_id.clone()));
        }
        
        // Add fragment data at index
        if let Some(fragment_map) = self.fragments.get_mut(&fragment_id_hex) {
            fragment_map.insert(index, data);
            debug_full_println!("[COLLECTOR] Fragment {} stored. Have {}/{} fragments", 
                    index + 1, fragment_map.len(), total);
            
            // Check if we have all fragments
            if fragment_map.len() == total as usize {
                debug_full_println!("[COLLECTOR] ✓ All fragments received! Reassembling...");
                
                // Reassemble in order
                let mut complete_data = Vec::new();
                for i in 0..total {
                    if let Some(fragment_data) = fragment_map.get(&i) {
                        debug_full_println!("[COLLECTOR] Appending fragment {} ({} bytes)", i + 1, fragment_data.len());
                        complete_data.extend_from_slice(fragment_data);
                    } else {
                        debug_full_println!("[COLLECTOR] ✗ Missing fragment {}", i + 1);
                        return None;
                    }
                }
                
                debug_full_println!("[COLLECTOR] ✓ Reassembly complete: {} bytes total", complete_data.len());
                
                // Get sender from metadata
                let sender = self.metadata.get(&fragment_id_hex)
                    .map(|(_, _, s)| s.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                // Clean up
                self.fragments.remove(&fragment_id_hex);
                self.metadata.remove(&fragment_id_hex);
                
                return Some((complete_data, sender));
            } else {
                debug_full_println!("[COLLECTOR] Waiting for more fragments ({}/{} received)", 
                        fragment_map.len(), total);
            }
        }
        
        None
    }
}

// Protocol version constants
pub struct ProtocolVersion;

impl ProtocolVersion {
    pub const CURRENT: u8 = 1;
    pub const MINIMUM: u8 = 1;
    pub const MAXIMUM: u8 = 1;
    
    pub fn is_supported(version: u8) -> bool {
        version == 1
    }
    
    pub fn negotiate_version(client_versions: &[u8], server_versions: &[u8]) -> Option<u8> {
        let client_set: std::collections::HashSet<u8> = client_versions.iter().cloned().collect();
        let server_set: std::collections::HashSet<u8> = server_versions.iter().cloned().collect();
        let common: std::collections::HashSet<u8> = client_set.intersection(&server_set).cloned().collect();
        
        common.into_iter().max()
    }
}

// MARK: - BinaryEncodable Implementation for BitchatPacket

impl crate::binary_protocol_utils::BinaryEncodable for BitchatPacket {
    fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Header: version (1 byte)
        data.push(self.version);
        
        // Type (1 byte)
        data.push(self.msg_type as u8);
        
        // TTL (1 byte)
        data.push(self.ttl);
        
        // Timestamp (8 bytes, big-endian)
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // Flags (1 byte)
        let mut flags: u8 = 0;
        if self.recipient_id.is_some() {
            flags |= FLAG_HAS_RECIPIENT;
        }
        if self.signature.is_some() {
            flags |= FLAG_HAS_SIGNATURE;
        }
        data.push(flags);
        
        // Payload length (2 bytes, big-endian)
        let payload_len = self.payload.len() as u16;
        data.extend_from_slice(&payload_len.to_be_bytes());
        
        // SenderID (8 bytes)
        data.extend_from_slice(&self.sender_id);
        
        // RecipientID (8 bytes) - if present
        if let Some(recipient_id) = &self.recipient_id {
            data.extend_from_slice(recipient_id);
        } else {
            // Use broadcast recipient
            data.extend_from_slice(&BROADCAST_RECIPIENT);
        }
        
        // Payload
        data.extend_from_slice(&self.payload);
        
        // Signature (64 bytes) - if present
        if let Some(signature) = &self.signature {
            data.extend_from_slice(signature);
        }
        
        data
    }
    
    fn from_binary_data(data: &[u8]) -> Option<Self> {
        if data.len() < 22 { // Minimum size: version(1) + type(1) + ttl(1) + timestamp(8) + flags(1) + payload_len(2) + sender(8)
            return None;
        }
        
        let mut offset = 0;
        
        // Version
        let version = data.get(offset)?;
        if *version != 1 {
            return None; // Only support version 1
        }
        offset += 1;
        
        // Message type
        let msg_type_byte = data.get(offset)?;
        let msg_type = match msg_type_byte {
            0x01 => MessageType::Announce,
            0x02 => MessageType::KeyExchange,
            0x03 => MessageType::Leave,
            0x04 => MessageType::Message,
            0x05 => MessageType::FragmentStart,
            0x06 => MessageType::FragmentContinue,
            0x07 => MessageType::FragmentEnd,
            0x08 => MessageType::ChannelAnnounce,
            0x09 => MessageType::ChannelRetention,
            0x0A => MessageType::DeliveryAck,
            0x0B => MessageType::DeliveryStatusRequest,
            0x0C => MessageType::ReadReceipt,
            0x10 => MessageType::NoiseHandshakeInit,
            0x11 => MessageType::NoiseHandshakeResp,
            0x12 => MessageType::NoiseEncrypted,
            0x13 => MessageType::NoiseIdentityAnnounce,
            0x20 => MessageType::VersionHello,
            0x21 => MessageType::VersionAck,
            0x22 => MessageType::ProtocolAck,
            0x23 => MessageType::ProtocolNack,
            0x24 => MessageType::SystemValidation,
            0x25 => MessageType::HandshakeRequest,
            _ => return None,
        };
        offset += 1;
        
        // TTL
        let ttl = *data.get(offset)?;
        offset += 1;
        
        // Timestamp (8 bytes, big-endian)
        if data.len() < offset + 8 {
            return None;
        }
        let timestamp_bytes = &data[offset..offset + 8];
        let timestamp = u64::from_be_bytes([
            timestamp_bytes[0], timestamp_bytes[1], timestamp_bytes[2], timestamp_bytes[3],
            timestamp_bytes[4], timestamp_bytes[5], timestamp_bytes[6], timestamp_bytes[7]
        ]);
        offset += 8;
        
        // Flags
        let flags = *data.get(offset)?;
        let has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0;
        let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;
        let is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;
        offset += 1;
        
        // Payload length (2 bytes, big-endian)
        if data.len() < offset + 2 {
            return None;
        }
        let payload_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        // SenderID (8 bytes)
        if data.len() < offset + 8 {
            return None;
        }
        let sender_id = data.get(offset..offset + 8)?.to_vec();
        let sender_id_str = hex_encode(&sender_id);
        offset += 8;
        
        // RecipientID (8 bytes) - if present
        let recipient_id = if has_recipient {
            if data.len() < offset + 8 {
                return None;
            }
            let recipient_bytes = data.get(offset..offset + 8)?.to_vec();
            offset += 8;
            Some(recipient_bytes)
        } else {
            None
        };
        
        let recipient_id_str = recipient_id.as_ref().map(|id| hex_encode(id));
        
        // Payload
        if data.len() < offset + payload_len {
            return None;
        }
        let payload = data.get(offset..offset + payload_len)?.to_vec();
        offset += payload_len;
        
        // Signature (64 bytes) - if present
        let signature = if has_signature {
            if data.len() < offset + SIGNATURE_SIZE {
                return None;
            }
            let signature_data = data.get(offset..offset + SIGNATURE_SIZE)?.to_vec();
            offset += SIGNATURE_SIZE;
            Some(signature_data)
        } else {
            None
        };
        
        Some(BitchatPacket {
            version: *version,
            msg_type,
            sender_id,
            sender_id_str,
            recipient_id,
            recipient_id_str,
            timestamp,
            payload,
            signature,
            ttl,
        })
    }
}

