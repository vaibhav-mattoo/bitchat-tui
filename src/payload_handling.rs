use std::time::SystemTime;
use uuid::Uuid;
use crate::data_structures::{
    BitchatMessage, MSG_FLAG_HAS_CHANNEL, MSG_FLAG_IS_PRIVATE, MSG_FLAG_IS_ENCRYPTED,
    MSG_FLAG_HAS_ORIGINAL_SENDER, MSG_FLAG_HAS_RECIPIENT_NICKNAME, MSG_FLAG_HAS_SENDER_PEER_ID,
    MSG_FLAG_HAS_MENTIONS, DebugLevel, DEBUG_LEVEL
};
use crate::debug_full_println;
use crate::encryption::EncryptionService;

// Remove PKCS#7 padding from data
pub fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    
    // Last byte tells us how much padding to remove
    let padding_length = data[data.len() - 1] as usize;
    
    debug_full_println!("[PADDING] Data size: {}, padding length indicated: {}", data.len(), padding_length);
    
    // Validate padding
    if padding_length == 0 || padding_length > data.len() || padding_length > 255 {
        debug_full_println!("[PADDING] Invalid padding length, returning data as-is");
        return data.to_vec();
    }
    
    // Remove padding
    let unpadded_len = data.len() - padding_length;
    debug_full_println!("[PADDING] Removing {} bytes of padding, resulting size: {}", padding_length, unpadded_len);
    
    data[..unpadded_len].to_vec()
}

pub fn parse_bitchat_message_payload(data: &[u8]) -> Result<BitchatMessage, &'static str> {
    debug_full_println!("[PARSE] Parsing message payload, size: {} bytes", data.len());
    debug_full_println!("[PARSE] First 32 bytes hex: {}", hex::encode(&data[..std::cmp::min(32, data.len())]));

    let mut offset = 0;

    if data.len() < 1 { return Err("Payload too short for flags"); }

    let flags = data[offset];
    debug_full_println!("[PARSE] Flags: 0x{:02X} (has_channel={}, is_private={}, is_encrypted={}, has_recipient_nickname={}, has_sender_peer_id={})", 
             flags, 
             (flags & MSG_FLAG_HAS_CHANNEL) != 0, 
             (flags & MSG_FLAG_IS_PRIVATE) != 0, 
             (flags & MSG_FLAG_IS_ENCRYPTED) != 0,
             (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0,
             (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0);

    offset += 1;

    let has_channel = (flags & MSG_FLAG_HAS_CHANNEL) != 0;
    let is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0;
    let _is_private = (flags & MSG_FLAG_IS_PRIVATE) != 0;
    let has_original_sender = (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0;
    let has_recipient_nickname = (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0;
    let has_sender_peer_id = (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0;
    let has_mentions = (flags & MSG_FLAG_HAS_MENTIONS) != 0;

    if data.len() < offset + 8 { return Err("Payload too short for timestamp"); }

    offset += 8;

    if data.len() < offset + 1 { return Err("Payload too short for ID length"); }

    let id_len = data[offset] as usize;

    offset += 1;

    if data.len() < offset + id_len { return Err("Payload too short for ID"); }

    let id = String::from_utf8_lossy(&data[offset..offset + id_len]).to_string();

    offset += id_len;

    if data.len() < offset + 1 { return Err("Payload too short for sender length"); }

    let sender_len = data[offset] as usize;

    offset += 1;

    if data.len() < offset + sender_len { return Err("Payload too short for sender"); }

    offset += sender_len;

    if data.len() < offset + 2 { return Err("Payload too short for content length"); }

    let content_len_bytes: [u8; 2] = data[offset..offset+2].try_into().unwrap();

    let content_len = u16::from_be_bytes(content_len_bytes) as usize;

    offset += 2;

    if data.len() < offset + content_len { return Err("Payload too short for content"); }

    let (content, encrypted_content) = if is_encrypted {
        // For encrypted messages, store raw bytes and empty string
        ("".to_string(), Some(data[offset..offset + content_len].to_vec()))
    } else {
        // For normal messages, parse as UTF-8 string
        (String::from_utf8_lossy(&data[offset..offset + content_len]).to_string(), None)
    };

    offset += content_len;

    // Handle optional fields based on flags
    if has_original_sender {
        if data.len() < offset + 1 { return Err("Payload too short for original sender length"); }
        let orig_sender_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + orig_sender_len { return Err("Payload too short for original sender"); }
        offset += orig_sender_len;
    }

    if has_recipient_nickname {
        if data.len() < offset + 1 { return Err("Payload too short for recipient nickname length"); }
        let recipient_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + recipient_len { return Err("Payload too short for recipient nickname"); }
        offset += recipient_len;
    }

    if has_sender_peer_id {
        if data.len() < offset + 1 { return Err("Payload too short for sender peer ID length"); }
        let peer_id_len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + peer_id_len { return Err("Payload too short for sender peer ID"); }
        offset += peer_id_len;
    }

    // Parse mentions array (iOS compatibility - must be in correct order)
    if has_mentions {
        if data.len() < offset + 2 { return Err("Payload too short for mentions count"); }
        let mentions_count_bytes: [u8; 2] = data[offset..offset+2].try_into().unwrap();
        let mentions_count = u16::from_be_bytes(mentions_count_bytes) as usize;
        offset += 2;
        
        // Skip each mention
        for _ in 0..mentions_count {
            if data.len() < offset + 1 { return Err("Payload too short for mention length"); }
            let mention_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + mention_len { return Err("Payload too short for mention"); }
            offset += mention_len;
        }
    }

    let mut channel: Option<String> = None;

    if has_channel {

        if data.len() < offset + 1 { return Err("Payload too short for channel length"); }

        let channel_len = data[offset] as usize;

        offset += 1;

        if data.len() < offset + channel_len { return Err("Payload too short for channel"); }

        channel = Some(String::from_utf8_lossy(&data[offset..offset + channel_len]).to_string());
        let _ = channel_len;  // Channel length consumed

    }

    Ok(BitchatMessage { id, content, channel, is_encrypted, encrypted_content })

}

pub fn create_bitchat_message_payload(sender: &str, content: &str, channel: Option<&str>) -> Vec<u8> {
    // Use the complex format that iOS expects (when iOS was working)
    let (payload, _) = create_bitchat_message_payload_full(sender, content, channel, false, "f453f3e0");
    payload
}

#[allow(dead_code)]
pub fn create_bitchat_message_payload_with_flags(sender: &str, content: &str, channel: Option<&str>, is_private: bool) -> Vec<u8> {
    // For backward compatibility, use a default peer ID
    let (payload, _) = create_bitchat_message_payload_full(sender, content, channel, is_private, "00000000");
    payload
}

pub fn create_bitchat_message_payload_full(sender: &str, content: &str, channel: Option<&str>, is_private: bool, sender_peer_id: &str) -> (Vec<u8>, String) {
    // Match Swift's toBinaryPayload format exactly
    let mut data = Vec::new();
    let mut flags: u8 = 0;
    
    // Always set hasSenderPeerID flag since we always include it
    flags |= MSG_FLAG_HAS_SENDER_PEER_ID;
    
    if channel.is_some() {
        flags |= MSG_FLAG_HAS_CHANNEL;
    }
    
    if is_private {
        flags |= MSG_FLAG_IS_PRIVATE;  // Add private flag
        // Private messages in Swift don't set recipient nickname in the payload
        // The recipient is handled at the packet level
    }
    
    data.push(flags);
    
    let timestamp_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    let id = Uuid::new_v4().to_string();
    data.push(id.len() as u8);
    data.extend_from_slice(id.as_bytes());
    
    data.push(sender.len() as u8);
    data.extend_from_slice(sender.as_bytes());
    
    let content_len = content.len() as u16;
    data.extend_from_slice(&content_len.to_be_bytes());
    data.extend_from_slice(content.as_bytes());
    
    // Since we always set MSG_FLAG_HAS_SENDER_PEER_ID, we need to include it
    data.push(sender_peer_id.len() as u8);
    data.extend_from_slice(sender_peer_id.as_bytes());
    
    if let Some(channel_name) = channel {
        data.push(channel_name.len() as u8);
        data.extend_from_slice(channel_name.as_bytes());
    }
    
    (data, id)
}

pub fn create_encrypted_channel_message_payload(
    sender: &str, 
    content: &str, 
    channel: &str, 
    channel_key: &[u8; 32],
    encryption_service: &EncryptionService,
    sender_peer_id: &str
) -> (Vec<u8>, String) {
    // Create message with encrypted content (matching Swift implementation)
    let mut data = Vec::new();
    let flags: u8 = MSG_FLAG_HAS_CHANNEL | MSG_FLAG_IS_ENCRYPTED | MSG_FLAG_HAS_SENDER_PEER_ID;
    
    data.push(flags);
    
    let timestamp_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    let id = Uuid::new_v4().to_string();
    data.push(id.len() as u8);
    data.extend_from_slice(id.as_bytes());
    
    data.push(sender.len() as u8);
    data.extend_from_slice(sender.as_bytes());
    
    // Encrypt the actual content
    let encrypted_content = match encryption_service.encrypt_with_key(content.as_bytes(), channel_key) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            println!("[!] Failed to encrypt message: {:?}", e);
            let (payload, id) = create_bitchat_message_payload_full(sender, content, Some(channel), false, "00000000");
            return (payload, id);
        }
    };
    
    // Content length is for encrypted content
    let content_len = encrypted_content.len() as u16;
    data.extend_from_slice(&content_len.to_be_bytes());
    data.extend_from_slice(&encrypted_content);
    
    // Sender peer ID (since we set MSG_FLAG_HAS_SENDER_PEER_ID)
    data.push(sender_peer_id.len() as u8);
    data.extend_from_slice(sender_peer_id.as_bytes());
    
    // Channel name
    data.push(channel.len() as u8);
    data.extend_from_slice(channel.as_bytes());
    
    (data, id)
}
