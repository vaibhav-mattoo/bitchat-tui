use crate::compression::decompress;
use crate::data_structures::{
    BitchatPacket, MessageType, FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE, FLAG_IS_COMPRESSED,
};
use crate::debug_full_println;
use crate::encryption::EncryptionService;
use hex;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Write;

// Debug logging function
fn write_packet_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("packet_debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = file.write_all(log_entry.as_bytes());
    }
}

// Remove PKCS#7 padding from data (matching Swift's MessagePadding.unpad)
fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }

    // Last byte tells us how much padding to remove
    let padding_length = data[data.len() - 1] as usize;

    // Validate padding
    if padding_length == 0 || padding_length > data.len() || padding_length > 255 {
        return data.to_vec();
    }

    // Remove padding
    let unpadded_len = data.len() - padding_length;
    data[..unpadded_len].to_vec()
}

pub fn parse_bitchat_packet(data: &[u8]) -> Result<BitchatPacket, &'static str> {
    write_packet_debug_log(&format!(
        "Starting packet parsing, data length: {}",
        data.len()
    ));

    // Remove padding first (matching Swift's MessagePadding.unpad)
    let unpadded_data = unpad_message(data);
    write_packet_debug_log(&format!(
        "After unpadding, data length: {}",
        unpadded_data.len()
    ));

    // Swift BinaryProtocol format:
    // Header (Fixed 13 bytes):
    // - Version: 1 byte
    // - Type: 1 byte
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)

    const HEADER_SIZE: usize = 13;
    const SENDER_ID_SIZE: usize = 8;
    const RECIPIENT_ID_SIZE: usize = 8;
    const SIGNATURE_SIZE: usize = 64;

    if unpadded_data.len() < HEADER_SIZE + SENDER_ID_SIZE {
        write_packet_debug_log(&format!(
            "Packet too small: {} bytes, need at least {}",
            unpadded_data.len(),
            HEADER_SIZE + SENDER_ID_SIZE
        ));
        return Err("Packet too small.");
    }

    let mut offset = 0;

    // 1. Version (1 byte)
    let version = unpadded_data[offset];
    offset += 1;
    if !crate::data_structures::ProtocolVersion::is_supported(version) {
        return Err("Unsupported version.");
    }

    // 2. Type (1 byte)
    let msg_type_raw = unpadded_data[offset];
    offset += 1;
    let msg_type = match msg_type_raw {
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

        // Noise Protocol messages
        0x10 => MessageType::NoiseHandshakeInit,
        0x11 => MessageType::NoiseHandshakeResp,
        0x12 => MessageType::NoiseEncrypted,
        0x13 => MessageType::NoiseIdentityAnnounce,

        // Protocol version negotiation
        0x20 => MessageType::VersionHello,
        0x21 => MessageType::VersionAck,

        // Protocol-level acknowledgments
        0x22 => MessageType::ProtocolAck,
        0x23 => MessageType::ProtocolNack,
        0x24 => MessageType::SystemValidation,
        0x25 => MessageType::HandshakeRequest,

        _ => return Err("Unknown message type."),
    };

    // 3. TTL (1 byte)
    let ttl = unpadded_data[offset];
    offset += 1;

    // 4. Timestamp (8 bytes) - read it properly
    let timestamp_bytes: [u8; 8] = unpadded_data[offset..offset + 8].try_into().unwrap();
    let timestamp = u64::from_be_bytes(timestamp_bytes);
    offset += 8;

    // 5. Flags (1 byte)
    let flags = unpadded_data[offset];
    offset += 1;
    let has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0;
    let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;
    let is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;

    // 6. Payload length (2 bytes, big-endian)
    if unpadded_data.len() < offset + 2 {
        return Err("Packet too small for payload length.");
    }
    let payload_len_bytes: [u8; 2] = unpadded_data[offset..offset + 2].try_into().unwrap();
    let payload_len = u16::from_be_bytes(payload_len_bytes) as usize;
    offset += 2;

    // Calculate expected total size
    let mut expected_size = HEADER_SIZE + SENDER_ID_SIZE + payload_len;
    if has_recipient {
        expected_size += RECIPIENT_ID_SIZE;
    }
    if has_signature {
        expected_size += SIGNATURE_SIZE;
    }

    if unpadded_data.len() < expected_size {
        return Err("Packet data shorter than expected.");
    }

    // 7. Sender ID (8 bytes)
    let sender_id = unpadded_data[offset..offset + SENDER_ID_SIZE].to_vec();
    // Convert 8-byte binary data to hex string (matching Swift's hexEncodedString())
    let sender_id_str = hex::encode(&sender_id);

    // Debug logging for sender ID parsing
    write_packet_debug_log(&format!("Raw sender ID bytes: {:?}", sender_id));
    write_packet_debug_log(&format!("Sender ID as hex: '{}'", sender_id_str));

    offset += SENDER_ID_SIZE;

    // 8. Recipient ID (8 bytes if hasRecipient flag set)
    let (recipient_id, recipient_id_str) = if has_recipient {
        let recipient_id = unpadded_data[offset..offset + RECIPIENT_ID_SIZE].to_vec();
        // Convert 8-byte binary data to hex string (matching Swift's hexEncodedString())
        let recipient_id_str = hex::encode(&recipient_id);
        debug_full_println!("[PACKET] Recipient ID raw bytes: {:?}", recipient_id);
        debug_full_println!("[PACKET] Recipient ID as string: '{}'", recipient_id_str);
        offset += RECIPIENT_ID_SIZE;
        (Some(recipient_id), Some(recipient_id_str))
    } else {
        (None, None)
    };

    // 9. Payload
    let mut payload = unpadded_data[offset..offset + payload_len].to_vec();
    offset += payload_len;

    // 10. Signature (64 bytes if hasSignature flag set)
    let signature = if has_signature {
        if unpadded_data.len() < offset + SIGNATURE_SIZE {
            return Err("Packet too small for signature.");
        }
        let signature_data = unpadded_data[offset..offset + SIGNATURE_SIZE].to_vec();
        offset += SIGNATURE_SIZE;
        Some(signature_data)
    } else {
        None
    };

    // Decompress if needed
    if is_compressed {
        match decompress(&payload) {
            Ok(decompressed) => payload = decompressed,
            Err(_) => return Err("Failed to decompress payload"),
        }
    }

    Ok(BitchatPacket {
        version,
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

pub fn generate_keys_and_payload(encryption_service: &EncryptionService) -> (Vec<u8>, String) {
    // Use the encryption service to get the combined public key data
    let payload = encryption_service.get_combined_public_key_data();

    // Generate fingerprint from identity key (last 32 bytes of the 96-byte payload)
    let identity_key_bytes = &payload[64..96];
    let mut hasher = Sha256::new();
    hasher.update(identity_key_bytes);
    let hash_result = hasher.finalize();
    let fingerprint = hex::encode(&hash_result[..8]);

    (payload, fingerprint)
}
