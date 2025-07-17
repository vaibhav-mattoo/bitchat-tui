
use std::collections::{HashMap, HashSet};
use std::io::Write;
use btleplug::api::{Characteristic, WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use uuid::Uuid;
use chrono;
use crate::data_structures::{DeliveryTracker, MessageType};
use crate::terminal_ux::{ChatContext, format_message_display};
use crate::encryption::EncryptionService;
use crate::packet_creation::{create_bitchat_packet_with_recipient_and_signature, create_bitchat_packet_with_signature};
use crate::payload_handling::{create_bitchat_message_payload_full, create_bitchat_message_payload, create_encrypted_channel_message_payload};
use crate::fragmentation::{send_packet_with_fragmentation, should_fragment};
use crate::debug_println;

// Handler for private DM messages
pub async fn handle_private_dm_message(
    line: &str,
    nickname: &str,
    my_peer_id: &str,
    target_nickname: &str,
    target_peer_id: &str,
    delivery_tracker: &mut DeliveryTracker,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    chat_context: &ChatContext,
) {
    // Only show echo in debug mode
    debug_println!("{} > {}", chat_context.format_prompt(), line);
    debug_println!("[PRIVATE] Sending DM to {} (peer_id: {})", target_nickname, target_peer_id);
    
    // Create message payload with private flag
    let (message_payload, message_id) = create_bitchat_message_payload_full(nickname, line, None, true, my_peer_id);
    
    // Track private message for delivery confirmation
    delivery_tracker.track_message(message_id.clone(), line.to_string(), true);
    
    // Pad the message for privacy using PKCS#7
    let block_sizes = [256, 512, 1024, 2048];
    let payload_size = message_payload.len();
    let target_size = block_sizes.iter()
        .find(|&&size| payload_size + 16 <= size)
        .copied()
        .unwrap_or(payload_size);
    
    let padding_needed = target_size - message_payload.len();
    let mut padded_payload = message_payload.clone();
    
    if padding_needed > 0 && padding_needed <= 255 {
        // PKCS#7 padding: all padding bytes have the same value (the padding length)
        for _ in 0..padding_needed {
            padded_payload.push(padding_needed as u8);
        }
        debug_println!("[PRIVATE] Added {} bytes of PKCS#7 padding", padding_needed);
    } else if padding_needed == 0 {
        // If already at block size, don't add more padding
        debug_println!("[PRIVATE] Message already at block size, no padding needed");
    }
    
    // Encrypt the padded payload for the recipient
    match encryption_service.encrypt(&padded_payload, target_peer_id) {
        Ok(encrypted) => {
            debug_println!("[PRIVATE] Encrypted payload: {} bytes", encrypted.len());
            
            // Sign the encrypted payload
            let signature = encryption_service.sign(&encrypted);
            
            // Create packet with recipient ID for private routing
            let packet = create_bitchat_packet_with_recipient_and_signature(
                my_peer_id,
                target_peer_id,  // Specify the recipient
                MessageType::Message,
                encrypted,
                Some(signature)
            );
            
            // Send the private message
            if let Err(_e) = send_packet_with_fragmentation(peripheral, cmd_char, packet, my_peer_id).await {
                println!("\n\x1b[91m❌ Failed to send private message\x1b[0m");
                println!("\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m");
            } else {
                // Show the message was sent in a cleaner format
                let timestamp = chrono::Local::now();
                let display = format_message_display(
                    timestamp,
                    nickname,  // sender
                    line,
                    true, // is_private
                    false, // is_channel
                    None, // channel_name
                    Some(target_nickname), // recipient
                    nickname, // my_nickname
                );
                // Move cursor up to overwrite the input line, clear it, print message
                print!("\x1b[1A\r\x1b[K{}\n", display);
                std::io::stdout().flush().unwrap();
            }
        },
        Err(e) => {
            println!("[!] Failed to encrypt private message: {:?}", e);
            println!("[!] Make sure you have received key exchange from {}", target_nickname);
        }
    }
}

// Handler for regular public/channel messages
pub async fn handle_regular_message(
    line: &str,
    nickname: &str,
    my_peer_id: &str,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    encryption_service: &EncryptionService,
    delivery_tracker: &mut DeliveryTracker,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
) {
    // Only show echo in debug mode
    debug_println!("{} > {}", chat_context.format_prompt(), line);
    
    let current_channel = chat_context.current_mode.get_channel().map(|s| s.to_string());
    
    // Check if trying to send to password-protected channel without key
    if let Some(ref channel) = current_channel {
        if password_protected_channels.contains(channel) && !channel_keys.contains_key(channel) {
            println!("❌ Cannot send to password-protected channel {}. Join with password first.", channel);
            return;
        }
    }
    
    let (message_payload, message_id) = if let Some(ref channel) = current_channel {
        if let Some(channel_key) = channel_keys.get(channel) {
            // Encrypt the message content for the channel
            debug_println!("[ENCRYPT] Encrypting message for channel {} 🔒", channel);
            create_encrypted_channel_message_payload(nickname, line, channel, channel_key, encryption_service, my_peer_id)
        } else {
            let payload = create_bitchat_message_payload(nickname, line, current_channel.as_deref());
            (payload, Uuid::new_v4().to_string()) // Generate ID for old style messages
        }
    } else {
        let payload = create_bitchat_message_payload(nickname, line, current_channel.as_deref());
        (payload, Uuid::new_v4().to_string()) // Generate ID for old style messages
    };
    
    // Track the message for delivery confirmation (not for channel messages with 10+ peers)
    let is_private = false;
    delivery_tracker.track_message(message_id.clone(), line.to_string(), is_private);
    
    debug_println!("[MESSAGE] ==================== SENDING USER MESSAGE ====================");
    debug_println!("[MESSAGE] Message content: '{}'", line);
    debug_println!("[MESSAGE] Message payload size: {} bytes", message_payload.len());
    
    // Sign the message payload
    let signature = encryption_service.sign(&message_payload);
    
    // Create the complete message packet with signature
    let message_packet = create_bitchat_packet_with_signature(my_peer_id, MessageType::Message, message_payload.clone(), Some(signature));
    
    // Check if we need to fragment the COMPLETE PACKET (matching Swift behavior)
    if should_fragment(&message_packet) {
        debug_println!("[MESSAGE] Complete packet ({} bytes) requires fragmentation", message_packet.len());
        
        // Use Swift-compatible fragmentation for complete packet
        if let Err(_e) = send_packet_with_fragmentation(peripheral, cmd_char, message_packet, my_peer_id).await {
            println!("\n\x1b[91m❌ Message delivery failed\x1b[0m");
            println!("\x1b[90mConnection lost. Please restart BitChat to reconnect.\x1b[0m");
            return;
        }
    } else {
        // Send as single packet without fragmentation
        debug_println!("[MESSAGE] Sending message as single packet ({} bytes)", message_packet.len());
        
        // Use WithResponse for larger packets (matching Swift's 512 byte threshold)
        let write_type = if message_packet.len() > 512 {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        
        if peripheral.write(cmd_char, &message_packet, write_type).await.is_err() {
            println!("[!] Failed to send message. Connection likely lost.");
            return;
        }
        
        debug_println!("[MESSAGE] ✓ Successfully sent message packet");
    }
    debug_println!("[MESSAGE] ==================== MESSAGE SEND COMPLETE ====================");
    
    // Display the sent message in a clean format
    let timestamp = chrono::Local::now();
    let display = format_message_display(
        timestamp,
        nickname,
        line,
        false, // is_private
        current_channel.is_some(), // is_channel
        current_channel.as_deref(), // channel_name
        None, // recipient
        nickname // my_nickname
    );
    // Move cursor up to overwrite the input line, clear it, print message
    print!("\x1b[1A\r\x1b[K{}\n", display);
    std::io::stdout().flush().unwrap();
}
