
use std::time::SystemTime;
use uuid::Uuid;
use btleplug::api::Characteristic;
use btleplug::platform::Peripheral;
use crate::data_structures::{DeliveryAck, MessageType};
use crate::packet_creation::create_bitchat_packet;
use crate::fragmentation::send_packet_with_fragmentation;
use crate::debug_println;

// Create delivery ACK matching iOS format
pub fn create_delivery_ack(
    original_message_id: &str, 
    recipient_id: &str,
    recipient_nickname: &str,
    hop_count: u8
) -> Vec<u8> {
    let ack = DeliveryAck {
        original_message_id: original_message_id.to_string(),
        ack_id: Uuid::new_v4().to_string(),
        recipient_id: recipient_id.to_string(),
        recipient_nickname: recipient_nickname.to_string(),
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        hop_count,
    };
    
    serde_json::to_vec(&ack).unwrap_or_default()
}

// Check if we should send an ACK for this message (matching iOS logic)
pub fn should_send_ack(is_private: bool, channel: Option<&str>, mentions: Option<&Vec<String>>, my_nickname: &str, active_peer_count: usize) -> bool {
    if is_private {
        // Always ACK private messages
        true
    } else if let Some(_) = channel {
        // For room messages, ACK if:
        // 1. Less than 10 active peers, OR
        // 2. We're mentioned
        if active_peer_count < 10 {
            true
        } else if let Some(mentions_list) = mentions {
            mentions_list.iter().any(|m| m == my_nickname)
        } else {
            false
        }
    } else {
        // Public broadcast messages - no ACK
        false
    }
}


pub async fn send_channel_announce(
    peripheral: &Peripheral,
    cmd_char: &Characteristic,
    my_peer_id: &str,
    channel: &str,
    is_protected: bool,
    key_commitment: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Format: "channel|isProtected|creatorID|keyCommitment"
    let protected_str = if is_protected { "1" } else { "0" };
    let payload = format!(
        "{}|{}|{}|{}",
        channel,
        protected_str,
        my_peer_id,
        key_commitment.unwrap_or("")
    );
    
    let packet = create_bitchat_packet(
        my_peer_id,
        MessageType::ChannelAnnounce,
        payload.into_bytes()
    );
    
    // Set TTL to 5 for wider propagation
    let mut packet_with_ttl = packet;
    packet_with_ttl[2] = 5; // TTL is at offset 2
    
    debug_println!("[CHANNEL] Sending channel announce for {}", channel);
    send_packet_with_fragmentation(&peripheral, cmd_char, packet_with_ttl, my_peer_id).await
}
