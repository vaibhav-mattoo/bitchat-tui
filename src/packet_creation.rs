
use std::time::SystemTime;
use crate::data_structures::{
    MessageType, FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE, BROADCAST_RECIPIENT
};
use crate::debug_full_println;

pub fn create_bitchat_packet(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, None)
}

pub fn create_bitchat_packet_with_signature(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, signature)
}

pub fn create_bitchat_packet_with_recipient_and_signature(sender_id_str: &str, recipient_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, Some(recipient_id_str), msg_type, payload, signature)
}

pub fn create_bitchat_packet_with_recipient(sender_id_str: &str, recipient_id_str: Option<&str>, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    debug_full_println!("[PACKET] ==================== PACKET CREATION START ====================");
    debug_full_println!("[PACKET] Creating packet: type={:?} (0x{:02X}), sender_id={}, payload_len={}", msg_type, msg_type as u8, sender_id_str, payload.len());
    
    // SWIFT BINARYPROTOCOL FORMAT: 
    // Header (Fixed 13 bytes):
    // - Version: 1 byte
    // - Type: 1 byte  
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)
    // Variable sections:
    // - SenderID: 8 bytes (fixed)
    // - RecipientID: 8 bytes (if hasRecipient flag set)
    // - Payload: Variable length
    // - Signature: 64 bytes (if hasSignature flag set)
    
    let mut data = Vec::new();
    
    // 1. Version (1 byte)
    let version = 1u8;
    data.push(version);
    
    // 2. Type (1 byte)
    let msg_type_byte = msg_type as u8;
    data.push(msg_type_byte);
    
    // 3. TTL (1 byte) - MOVED UP to match Swift
    let ttl = 7u8; // whitepaper specifies 7 for maximum reach
    data.push(ttl);
    
    // 4. Timestamp (8 bytes, big-endian)
    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    // 5. Flags (1 byte)
    let mut flags: u8 = 0;
    let has_recipient = match msg_type {
        MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => false,
        _ => true
    };
    if has_recipient {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    // No compression for now
    data.push(flags);
    
    // 6. Payload length (2 bytes, big-endian)
    let payload_length = payload.len() as u16;
    data.extend_from_slice(&payload_length.to_be_bytes());
    
    debug_full_println!("[PACKET] Header: version={}, type=0x{:02X}, ttl={}, flags=0x{:02X}, payload_len={}", 
            version, msg_type_byte, ttl, flags, payload_length);
    
    // 7. Sender ID (8 bytes) - Use ASCII bytes directly, pad with zeros
    let mut sender_id_bytes = sender_id_str.as_bytes().to_vec();
    if sender_id_bytes.len() < 8 {
        sender_id_bytes.resize(8, 0);
    } else if sender_id_bytes.len() > 8 {
        sender_id_bytes.truncate(8);
    }
    data.extend_from_slice(&sender_id_bytes);
    debug_full_println!("[PACKET] Sender ID: {} -> {} bytes: {}", sender_id_str, sender_id_bytes.len(), hex::encode(&sender_id_bytes));
    
    // 8. Recipient ID (8 bytes) - only if hasRecipient flag is set
    if has_recipient {
        if let Some(recipient) = recipient_id_str {
            // Private message - use specific recipient
            let mut recipient_bytes = recipient.as_bytes().to_vec();
            if recipient_bytes.len() < 8 {
                recipient_bytes.resize(8, 0);
            } else if recipient_bytes.len() > 8 {
                recipient_bytes.truncate(8);
            }
            data.extend_from_slice(&recipient_bytes);
            debug_full_println!("[PACKET] Recipient ID (private): {} -> {} bytes: {}", recipient, recipient_bytes.len(), hex::encode(&recipient_bytes));
        } else {
            // Broadcast message
            data.extend_from_slice(&BROADCAST_RECIPIENT);
            debug_full_println!("[PACKET] Recipient ID (broadcast): {} bytes: {}", BROADCAST_RECIPIENT.len(), hex::encode(&BROADCAST_RECIPIENT));
        }
    } else {
        debug_full_println!("[PACKET] No recipient ID (fragment packet)");
    }
    
    // 9. Payload (variable)
    data.extend_from_slice(&payload);
    debug_full_println!("[PACKET] Payload: {} bytes", payload.len());
    
    // 10. Signature (64 bytes if present)
    if let Some(sig) = &signature {
        data.extend_from_slice(sig);
        debug_full_println!("[PACKET] Signature: {} bytes", sig.len());
    }
    
    debug_full_println!("[PACKET] Final packet size: {} bytes", data.len());
    debug_full_println!("[PACKET] Full packet hex: {}", hex::encode(&data));
    
    // Calculate offsets for structure breakdown
    let mut offset = 0;
    debug_full_println!("[PACKET] Packet structure breakdown:");
    debug_full_println!("[PACKET]   - Version (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - Type (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - TTL (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - Timestamp (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    debug_full_println!("[PACKET]   - Flags (1 byte): {}", hex::encode(&data[offset..offset+1])); offset += 1;
    debug_full_println!("[PACKET]   - PayloadLength (2 bytes): {}", hex::encode(&data[offset..offset+2])); offset += 2;
    debug_full_println!("[PACKET]   - Sender ID (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    
    if has_recipient {
        debug_full_println!("[PACKET]   - Recipient ID (8 bytes): {}", hex::encode(&data[offset..offset+8])); offset += 8;
    }
    
    debug_full_println!("[PACKET]   - Payload ({} bytes): {}", payload.len(), hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())]));
    offset += payload.len();
    
    if signature.is_some() {
        debug_full_println!("[PACKET]   - Signature (64 bytes): {}", hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())]));
        // offset += SIGNATURE_SIZE;  // Not needed as we're done parsing
    }
    
    debug_full_println!("[PACKET] ==================== PACKET CREATION END ====================");
    
    data
}
