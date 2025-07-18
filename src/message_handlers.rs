use std::collections::{HashMap, HashSet};
use btleplug::api::{WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono;
use crate::data_structures::{DeliveryTracker, MessageType, DebugLevel, DEBUG_LEVEL};
use crate::terminal_ux::{ChatContext, format_message_display};
use crate::encryption::EncryptionService;
use crate::packet_creation::{create_bitchat_packet_with_recipient_and_signature, create_bitchat_packet_with_signature};
use crate::payload_handling::{create_bitchat_message_payload_full, create_bitchat_message_payload, create_encrypted_channel_message_payload};
use crate::fragmentation::{send_packet_with_fragmentation, should_fragment};
use std::error::Error;


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
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("{} > {}\n", chat_context.format_prompt(), line)).await;
        let _ = ui_tx.send(format!("[PRIVATE] Sending DM to {} (peer_id: {})\n", target_nickname, target_peer_id)).await;
    }
    
    let (message_payload, message_id) = create_bitchat_message_payload_full(nickname, line, None, true, my_peer_id);
    delivery_tracker.track_message(message_id.clone(), line.to_string(), true);
    
    let block_sizes = [256, 512, 1024, 2048];
    let payload_size = message_payload.len();
    let target_size = block_sizes.iter().find(|&&size| payload_size + 16 <= size).copied().unwrap_or(payload_size);
    let padding_needed = target_size - message_payload.len();
    let mut padded_payload = message_payload;
    
    if padding_needed > 0 && padding_needed <= 255 {
        for _ in 0..padding_needed {
            padded_payload.push(padding_needed as u8);
        }
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[PRIVATE] Added {} bytes of PKCS#7 padding\n", padding_needed)).await;
        }
    } else if padding_needed == 0 && unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send("[PRIVATE] Message already at block size, no padding needed\n".to_string()).await;
    }
    
    match encryption_service.encrypt(&padded_payload, target_peer_id) {
        Ok(encrypted) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[PRIVATE] Encrypted payload: {} bytes\n", encrypted.len())).await;
            }
            
            let signature = encryption_service.sign(&encrypted);
            let packet = create_bitchat_packet_with_recipient_and_signature(my_peer_id, target_peer_id, MessageType::Message, encrypted, Some(signature));
            
            if send_packet_with_fragmentation(peripheral, cmd_char, packet, my_peer_id).await.is_err() {
                let _ = ui_tx.send("\n\x1b[91m❌ Failed to send private message\x1b[0m\n\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m\n".to_string()).await;
            } else {
                let timestamp = chrono::Local::now();
                let display = format_message_display(timestamp, nickname, line, true, false, None, Some(target_nickname), nickname);
                let _ = ui_tx.send(format!("\x1b[1A\r\x1b[K{}\n", display)).await;
            }
        },
        Err(e) => {
            let _ = ui_tx.send(format!("[!] Failed to encrypt private message: {:?}\n", e)).await;
            let _ = ui_tx.send(format!("[!] Make sure you have received key exchange from {}\n", target_nickname)).await;
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
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("{} > {}\n", chat_context.format_prompt(), line)).await;
    }

    let current_channel = chat_context.current_mode.get_channel().map(|s| s.to_string());
    
    if let Some(ref channel) = current_channel {
        if password_protected_channels.contains(channel) && !channel_keys.contains_key(channel) {
            let _ = ui_tx.send(format!("❌ Cannot send to password-protected channel {}. Join with password first.\n", channel)).await;
            return;
        }
    }
    
    let (message_payload, message_id) = if let Some(ref channel) = current_channel {
        if let Some(channel_key) = channel_keys.get(channel) {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[ENCRYPT] Encrypting message for channel {} 🔒\n", channel)).await;
            }
            create_encrypted_channel_message_payload(nickname, line, channel, channel_key, encryption_service, my_peer_id)
        } else {
            (create_bitchat_message_payload(nickname, line, current_channel.as_deref()), Uuid::new_v4().to_string())
        }
    } else {
        (create_bitchat_message_payload(nickname, line, current_channel.as_deref()), Uuid::new_v4().to_string())
    };
    
    delivery_tracker.track_message(message_id.clone(), line.to_string(), false);
    
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send("[MESSAGE] ==================== SENDING USER MESSAGE ====================\n".to_string()).await;
        let _ = ui_tx.send(format!("[MESSAGE] Message content: '{}'\n", line)).await;
        let _ = ui_tx.send(format!("[MESSAGE] Message payload size: {} bytes\n", message_payload.len())).await;
    }
    
    let signature = encryption_service.sign(&message_payload);
    let message_packet = create_bitchat_packet_with_signature(my_peer_id, MessageType::Message, message_payload.clone(), Some(signature));
    
    // THIS BLOCK IS NOW CORRECT
    let send_result: Result<(), Box<dyn Error>> = if should_fragment(&message_packet) {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[MESSAGE] Complete packet ({} bytes) requires fragmentation\n", message_packet.len())).await;
        }
        send_packet_with_fragmentation(peripheral, cmd_char, message_packet, my_peer_id).await
    } else {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[MESSAGE] Sending message as single packet ({} bytes)\n", message_packet.len())).await;
        }
        let write_type = if message_packet.len() > 512 { WriteType::WithResponse } else { WriteType::WithoutResponse };
        // Map the concrete btleplug::Error to a boxed trait object
        peripheral.write(cmd_char, &message_packet, write_type).await.map_err(Into::into)
    };

    if let Err(_) = send_result {
        let _ = ui_tx.send("\n\x1b[91m❌ Message delivery failed\x1b[0m\n\x1b[90mConnection lost. Please restart BitChat to reconnect.\x1b[0m\n".to_string()).await;
        return;
    }
    
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send("[MESSAGE] ✓ Successfully sent message packet\n".to_string()).await;
        let _ = ui_tx.send("[MESSAGE] ==================== MESSAGE SEND COMPLETE ====================\n".to_string()).await;
    }
    
    let timestamp = chrono::Local::now();
    let display = format_message_display(timestamp, nickname, line, false, current_channel.is_some(), current_channel.as_deref(), None, nickname);
    let _ = ui_tx.send(format!("\x1b[1A\r\x1b[K{}\n", display)).await;
}
