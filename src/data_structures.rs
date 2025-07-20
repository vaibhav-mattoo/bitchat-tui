use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

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
}

#[derive(Debug, Default, Clone)]
pub struct Peer { pub nickname: Option<String> }

#[derive(Debug)]
pub struct BitchatPacket { 
    pub msg_type: MessageType, 
    pub _sender_id: Vec<u8>,  // Kept for protocol compatibility 
    pub sender_id_str: String,  // Add string version for easy comparison
    pub recipient_id: Option<Vec<u8>>,  // Add recipient ID
    pub recipient_id_str: Option<String>,  // Add string version of recipient
    pub payload: Vec<u8>,
    pub ttl: u8,  // Add TTL field
}

#[derive(Debug)]
pub struct BitchatMessage { 
    pub id: String, 
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

