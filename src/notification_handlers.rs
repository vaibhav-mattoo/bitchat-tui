use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use rand::Rng;
use btleplug::api::{WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use chrono;
use hex;
use bloomfilter::Bloom;


use crate::data_structures::{
    BitchatPacket, Peer, DeliveryTracker, FragmentCollector, BROADCAST_RECIPIENT,
    COVER_TRAFFIC_PREFIX, MessageType, DeliveryAck, DebugLevel, DEBUG_LEVEL
};
use crate::terminal_ux::{ChatContext, ChatMode};
use crate::encryption::EncryptionService;
use crate::payload_handling::{unpad_message, parse_bitchat_message_payload};
use crate::packet_creation::{
    create_bitchat_packet_with_recipient, create_bitchat_packet
};
use crate::packet_delivery::{create_delivery_ack, should_send_ack};
use crate::packet_parser::{parse_bitchat_packet, generate_keys_and_payload};
use crate::persistence::{AppState, EncryptedPassword, save_state};
use crate::noise_session::NoiseSessionManager;

// Handler for announce messages
pub async fn handle_announce_message(
    packet: &BitchatPacket,
    peers_lock: &mut HashMap<String, Peer>,
    ui_tx: mpsc::Sender<String>,
) {
    let peer_nickname = String::from_utf8_lossy(&packet.payload).trim().to_string();

    let is_new_peer = !peers_lock.contains_key(&packet.sender_id_str);
    let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();

    peer_entry.nickname = Some(peer_nickname.clone());

    if is_new_peer {
        let _ = ui_tx.send(format!("\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ", peer_nickname)).await;
    }
    
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[<-- RECV] Announce: Peer {} is now known as '{}'\n", packet.sender_id_str, peer_nickname)).await;
    }
}

// Handler for message relay
pub async fn handle_message_relay(
    packet: &BitchatPacket,
    notification_value: &[u8],
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
        let _ = ui_tx.send(format!("[DEBUG] Message not for us, checking if we should relay (TTL={})\n", packet.ttl)).await;
    }
    
    if packet.ttl > 1 {
        time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;  // Decrement TTL
        
        if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
            let _ = ui_tx.send("[!] Failed to relay message\n".to_string()).await;
        } else {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
                let _ = ui_tx.send(format!("[DEBUG] Relayed message with TTL={}\n", packet.ttl - 1)).await;
            }
        }
    }
}

// Handler for private message decryption
pub async fn handle_private_message_decryption(
    packet: &BitchatPacket,
    encryption_service: &EncryptionService,
    ui_tx: mpsc::Sender<String>,
) -> Option<Vec<u8>> {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[PRIVATE] This is a private message for us from {}\n", packet.sender_id_str)).await;
        let _ = ui_tx.send(format!("[PRIVATE] Payload size: {} bytes\n", packet.payload.len())).await;
        let _ = ui_tx.send(format!("[PRIVATE] First 32 bytes of encrypted payload: {}\n", hex::encode(&packet.payload[..std::cmp::min(32, packet.payload.len())]))).await;
    }
    
    match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
        Ok(decrypted) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send("[PRIVATE] Successfully decrypted private message!\n".to_string()).await;
                let _ = ui_tx.send(format!("[PRIVATE] Decrypted size: {} bytes\n", decrypted.len())).await;
            }
            Some(decrypted)
        }
        Err(e) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[PRIVATE] Failed to decrypt private message: {:?}\n", e)).await;
                let _ = ui_tx.send(format!("[PRIVATE] Checking if we have shared secret with {}\n", packet.sender_id_str)).await;
            }
            None
        }
    }
}

// Handler for message packets
pub async fn handle_message_packet(
    packet: &BitchatPacket,
    notification_value: &[u8],
    peers_lock: &mut HashMap<String, Peer>,
    bloom: &mut Bloom<String>,
    discovered_channels: &mut HashSet<String>,
    password_protected_channels: &mut HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    chat_context: &mut ChatContext,
    delivery_tracker: &mut DeliveryTracker,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    nickname: &str,
    my_peer_id: &str,
    blocked_peers: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
        let _ = ui_tx.send("[DEBUG] ==================== MESSAGE RECEIVED ====================\n".to_string()).await;
        let _ = ui_tx.send(format!("[DEBUG] Sender: {}\n", packet.sender_id_str)).await;
    }
    
    if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&packet.sender_id_str) {
        if blocked_peers.contains(&fingerprint) {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[BLOCKED] Ignoring message from blocked peer: {}\n", packet.sender_id_str)).await;
            }
            return;
        }
    }
    
    let is_broadcast = packet.recipient_id.as_ref().map(|r| r == &BROADCAST_RECIPIENT).unwrap_or(true);
    let is_for_us = if is_broadcast { true } else { packet.recipient_id_str.as_ref().map(|r| r == my_peer_id).unwrap_or(false) };
    
    if !is_for_us {
        handle_message_relay(packet, notification_value, peripheral, cmd_char, ui_tx.clone()).await;
        return;
    }
    
    let is_private_message = !is_broadcast && is_for_us;
    let mut decrypted_payload = None;
    
    if is_private_message {
        decrypted_payload = handle_private_message_decryption(packet, encryption_service, ui_tx.clone()).await;
        if decrypted_payload.is_none() { return; }
    }
    
    let parse_result = if let Some(ref decrypted) = decrypted_payload {
        parse_bitchat_message_payload(&unpad_message(decrypted))
    } else {
        parse_bitchat_message_payload(&packet.payload)
    };

    if let Ok(message) = parse_result {
        if !bloom.check(&message.id) {
            bloom.set(&message.id);

            // Use the sender from the parsed message instead of the peer nickname
            let sender_nick = &message.sender;
            
            // Add the sender to peers list if they're not already there
            if !peers_lock.contains_key(&packet.sender_id_str) {
                let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();
                peer_entry.nickname = Some(sender_nick.clone());
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send(format!("[PEER] Discovered new peer: {} ({})\n", sender_nick, packet.sender_id_str)).await;
                }
                // Send connected message to TUI so it updates the people list
                let _ = ui_tx.send(format!("{} connected\n", sender_nick)).await;
            }

            if let Some(channel) = &message.channel {
                discovered_channels.insert(channel.clone());
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send(format!("[DISCOVERY] Found channel: {}\n", channel)).await;
                }
                if message.is_encrypted {
                    password_protected_channels.insert(channel.clone());
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                        let _ = ui_tx.send(format!("[SECURITY] Marked {} as password-protected\n", channel)).await;
                    }
                }
            }

            let display_content = if message.is_encrypted {
                if let Some(channel) = &message.channel {
                    channel_keys.get(channel).map_or_else(
                        || "[Encrypted message - join channel with password]".to_string(),
                        |key| message.encrypted_content.as_ref().map_or_else(
                            || "[Encrypted message - no encrypted data]".to_string(),
                            |bytes| encryption_service.decrypt_with_key(bytes, key).map_or_else(
                                |_| "[Encrypted message - decryption failed]".to_string(),
                                |dec| String::from_utf8_lossy(&dec).to_string()
                            )
                        )
                    )
                } else { message.content.clone() }
            } else { message.content.clone() };

            let timestamp = chrono::Local::now();
            
            if is_private_message {
                if display_content.starts_with(COVER_TRAFFIC_PREFIX) {
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                        let _ = ui_tx.send(format!("[COVER] Discarding dummy message from {}\n", sender_nick)).await;
                    }
                    return;
                }
                
                chat_context.last_private_sender = Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                chat_context.add_dm(sender_nick, &packet.sender_id_str);
                
                // Send structured message for TUI to parse
                let structured_msg = format!("__DM__:{}:{}:{}", sender_nick, timestamp.format("%H%M"), display_content);
                let _ = ui_tx.send(structured_msg).await;
                
                if !matches!(&chat_context.current_mode, ChatMode::PrivateDM { .. }) {
                    let _ = ui_tx.send("\x1b[90mÂ» /reply to respond\x1b[0m\n".to_string()).await;
                }
                let _ = ui_tx.send("> ".to_string()).await;
            } else {
                let (_, channel_name) = if let Some(ch) = &message.channel {
                    chat_context.add_channel(ch);
                    (true, Some(ch.as_str()))
                } else {
                    (false, None)
                };
                // Send structured message for TUI to parse
                let channel_key = channel_name.unwrap_or("#public");
                let structured_msg = format!("__CHANNEL__:{}:{}:{}:{}", channel_key, sender_nick, timestamp.format("%H%M"), display_content);
                let _ = ui_tx.send(structured_msg).await;
            }
         
            if should_send_ack(is_private_message, message.channel.as_deref(), None, nickname, peers_lock.len()) {
                let ack_id = format!("{}-{}", message.id, my_peer_id);
                if delivery_tracker.should_send_ack(&ack_id) {
                    let ack_payload = create_delivery_ack(&message.id, my_peer_id, nickname, 1);
                    let final_ack_payload = if is_private_message {
                        encryption_service.encrypt_for_peer(&packet.sender_id_str, &ack_payload).unwrap_or(ack_payload)
                    } else { ack_payload };
                    
                    let mut ack_packet = create_bitchat_packet_with_recipient(my_peer_id, Some(&packet.sender_id_str), MessageType::DeliveryAck, final_ack_payload, None);
                    if ack_packet.len() > 2 { ack_packet[2] = 3; }
                    
                    if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                         if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[ACK] Failed to send delivery ACK: {}\n", e)).await;
                         }
                    }
                }
            }

            if packet.ttl > 1 {
                time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                let mut relay_data = notification_value.to_vec();
                relay_data[2] = packet.ttl - 1;
                if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                    let _ = ui_tx.send("[!] Failed to relay message\n".to_string()).await;
                }
            }
        }
    } else {
        let _ = ui_tx.send("[!] Failed to parse message payload\n".to_string()).await;
    }
}

// Handler for fragment packets
pub async fn handle_fragment_packet(
    packet: &BitchatPacket,
    notification_value: &[u8],
    fragment_collector: &mut FragmentCollector,
    peers_lock: &mut HashMap<String, Peer>,
    bloom: &mut Bloom<String>,
    discovered_channels: &mut HashSet<String>,
    password_protected_channels: &mut HashSet<String>,
    chat_context: &mut ChatContext,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    _nickname: &str,
    my_peer_id: &str,
    blocked_peers: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
) {
    if packet.payload.len() >= 13 {
        let mut fragment_id = [0u8; 8];
        fragment_id.copy_from_slice(&packet.payload[0..8]);
        let index = ((packet.payload[8] as u16) << 8) | (packet.payload[9] as u16);
        let total = ((packet.payload[10] as u16) << 8) | (packet.payload[11] as u16);
        let original_type = packet.payload[12];
        let fragment_data = packet.payload[13..].to_vec();
        
        if let Some((complete_data, _)) = fragment_collector.add_fragment(fragment_id, index, total, original_type, fragment_data, packet.sender_id_str.clone()) {
            if let Ok(reassembled) = parse_bitchat_packet(&complete_data) {
                if reassembled.msg_type == MessageType::Message {
                    if let Some(fp) = encryption_service.get_peer_fingerprint(&reassembled.sender_id_str) {
                        if blocked_peers.contains(&fp) { return; }
                    }
                    
                    let is_broadcast = reassembled.recipient_id.as_ref().map(|r| r == &BROADCAST_RECIPIENT).unwrap_or(true);
                    let is_for_us = if is_broadcast { true } else { reassembled.recipient_id_str.as_ref().map(|r| r == my_peer_id).unwrap_or(false) };
                    let is_private_message = !is_broadcast && is_for_us;
                    
                    let message_result = if is_private_message {
                        encryption_service.decrypt(&reassembled.payload, &reassembled.sender_id_str)
                            .map(|dec| parse_bitchat_message_payload(&unpad_message(&dec)))
                            .unwrap_or(Err("Decryption failed".into()))
                    } else {
                        parse_bitchat_message_payload(&reassembled.payload)
                    };
                    
                    if let Ok(message) = message_result {
                        if !bloom.check(&message.id) {
                            bloom.set(&message.id);
                            
                            // Add the sender to peers list if they're not already there
                            if !peers_lock.contains_key(&reassembled.sender_id_str) {
                                let peer_entry = peers_lock.entry(reassembled.sender_id_str.clone()).or_default();
                                peer_entry.nickname = Some(message.sender.clone());
                                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                                    let _ = ui_tx.send(format!("[PEER] Discovered new peer via fragment: {} ({})\n", message.sender, reassembled.sender_id_str)).await;
                                }
                                // Send connected message to TUI so it updates the people list
                                let _ = ui_tx.send(format!("{} connected\n", message.sender)).await;
                            }
                            
                            let sender_nick = &message.sender;
                            
                            if let Some(ch) = &message.channel {
                                discovered_channels.insert(ch.clone());
                                if message.is_encrypted { password_protected_channels.insert(ch.clone()); }
                            }
                            
                            if is_private_message && message.content.starts_with(COVER_TRAFFIC_PREFIX) { return; }
                            
                            let timestamp = chrono::Local::now();
                            
                            // Send structured message for TUI to parse
                            if is_private_message {
                                let structured_msg = format!("__DM__:{}:{}:{}", sender_nick, timestamp.format("%H%M"), message.content);
                                let _ = ui_tx.send(structured_msg).await;
                            } else {
                                let channel_key = message.channel.as_deref().unwrap_or("#public");
                                let structured_msg = format!("__CHANNEL__:{}:{}:{}:{}", channel_key, sender_nick, timestamp.format("%H%M"), message.content);
                                let _ = ui_tx.send(structured_msg).await;
                            }
                            
                            if is_private_message {
                                chat_context.last_private_sender = Some((reassembled.sender_id_str.clone(), sender_nick.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    
    if packet.ttl > 1 {
        time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;
        if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
            let _ = ui_tx.send("[!] Failed to relay fragment\n".to_string()).await;
        }
    }
}

// Handler for key exchange messages
pub async fn handle_key_exchange_message(
    packet: &BitchatPacket,
    peers_lock: &mut HashMap<String, Peer>,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    let public_key = packet.payload.clone();
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[<-- RECV] Key exchange from {} (key: {} bytes)\n", packet.sender_id_str, public_key.len())).await;
    }
    
    if let Err(e) = encryption_service.add_peer_public_key(&packet.sender_id_str, &public_key) {
        let _ = ui_tx.send(format!("[!] Failed to add peer public key: {:?}\n", e)).await;
    } else {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[+] Successfully added encryption keys for peer {}\n", packet.sender_id_str)).await;
        }
        
        if !peers_lock.contains_key(&packet.sender_id_str) {
            let (key_exchange_payload, _) = generate_keys_and_payload(encryption_service);
            let key_exchange_packet = create_bitchat_packet(my_peer_id, MessageType::KeyExchange, key_exchange_payload);
            if let Err(e) = peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await {
                let _ = ui_tx.send(format!("[!] Failed to send key exchange response: {}\n", e)).await;
            }
        }
    }
}

// Handler for leave messages
pub async fn handle_leave_message(
    packet: &BitchatPacket,
    peers_lock: &mut HashMap<String, Peer>,
    chat_context: &ChatContext,
    ui_tx: mpsc::Sender<String>,
) {
    let payload_str = String::from_utf8_lossy(&packet.payload).trim().to_string();
    
    if payload_str.starts_with('#') {
        let channel = payload_str;
        let sender_nick = peers_lock.get(&packet.sender_id_str).and_then(|p| p.nickname.as_ref()).map_or(&packet.sender_id_str, |n| n);
        
        if let ChatMode::Channel(current_channel) = &chat_context.current_mode {
            if current_channel == &channel {
                let _ = ui_tx.send(format!("\r\x1b[K\x1b[90mÂ« {} left {}\x1b[0m\n> ", sender_nick, channel)).await;
            }
        }
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[<-- RECV] {} left channel {}\n", sender_nick, channel)).await;
        }
    } else {
        peers_lock.remove(&packet.sender_id_str);
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[<-- RECV] Peer {} ({}) has left\n", packet.sender_id_str, payload_str)).await;
        }
    }
}

// Handler for channel announce messages
pub async fn handle_channel_announce_message(
    packet: &BitchatPacket,
    channel_creators: &mut HashMap<String, String>,
    password_protected_channels: &mut HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    channel_key_commitments: &mut HashMap<String, String>,
    chat_context: &mut ChatContext,
    blocked_peers: &HashSet<String>,
    encrypted_channel_passwords: &HashMap<String, EncryptedPassword>,
    nickname: &str,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    ui_tx: mpsc::Sender<String>,
) {
    let payload_str = String::from_utf8_lossy(&packet.payload);
    let parts: Vec<&str> = payload_str.split('|').collect();
    
    if parts.len() >= 3 {
        let channel = parts[0];
        let is_protected = parts[1] == "1";
        let creator_id = parts[2];
        let key_commitment = parts.get(3).unwrap_or(&"");
        
        channel_creators.insert(channel.to_string(), creator_id.to_string());
        
        if is_protected {
            password_protected_channels.insert(channel.to_string());
            if !key_commitment.is_empty() {
                channel_key_commitments.insert(channel.to_string(), key_commitment.to_string());
            }
        } else {
            password_protected_channels.remove(channel);
            channel_keys.remove(channel);
            channel_key_commitments.remove(channel);
        }
        
        chat_context.add_channel(channel);
        
        let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
        let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, encrypted_channel_passwords, nickname);
        if let Err(e) = save_state(&state_to_save) {
            let _ = ui_tx.send(format!("\x1b[93mWarning: Could not save state: {}\x1b[0m\n", e)).await;
        }
    }
}

// Handler for delivery ACK messages
pub async fn handle_delivery_ack_message(
    packet: &BitchatPacket,
    notification_value: &[u8],
    encryption_service: &EncryptionService,
    delivery_tracker: &mut DeliveryTracker,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[<-- RECV] Delivery ACK from {}\n", packet.sender_id_str)).await;
    }
    
    let is_for_us = packet.recipient_id_str.as_ref().map(|r| r == my_peer_id).unwrap_or(false);
    
    if is_for_us {
        let ack_payload = if packet.ttl == 3 && encryption_service.has_peer_key(&packet.sender_id_str) {
            encryption_service.decrypt(&packet.payload, &packet.sender_id_str).unwrap_or_else(|_| packet.payload.clone())
        } else {
            packet.payload.clone()
        };
        
        if let Ok(ack) = serde_json::from_slice::<DeliveryAck>(&ack_payload) {
            if delivery_tracker.mark_delivered(&ack.original_message_id) {
                let _ = ui_tx.send(format!("\r\x1b[K\x1b[90mâœ“ Delivered to {}\x1b[0m\n> ", ack.recipient_nickname)).await;
            }
        }
    } else if packet.ttl > 1 {
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;
        let _ = peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await;
    }
}

// Handler for delivery status request messages
pub async fn handle_delivery_status_request_message(_packet: &BitchatPacket, ui_tx: mpsc::Sender<String>) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send("[<-- RECV] Delivery status request (not implemented)\n".to_string()).await;
    }
}

// Handler for read receipt messages
pub async fn handle_read_receipt_message(_packet: &BitchatPacket, ui_tx: mpsc::Sender<String>) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send("[<-- RECV] Read receipt (not implemented)\n".to_string()).await;
    }
}

// Handler for Noise handshake initiation messages
pub async fn handle_noise_handshake_init(
    packet: &BitchatPacket,
    noise_session_manager: &mut NoiseSessionManager,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[NOISE] Received handshake initiation from {}\n", packet.sender_id_str)).await;
    }
    
    match noise_session_manager.handle_incoming_handshake(&packet.sender_id_str, &packet.payload) {
        Ok(Some(response)) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[NOISE] Generated handshake response ({} bytes)\n", response.len())).await;
            }
            
            // Send handshake response
            let response_packet = create_bitchat_packet_with_recipient(
                my_peer_id,
                Some(&packet.sender_id_str),
                MessageType::NoiseHandshakeResp,
                response,
                None
            );
            
            if peripheral.write(cmd_char, &response_packet, WriteType::WithoutResponse).await.is_err() {
                let _ = ui_tx.send("[!] Failed to send handshake response\n".to_string()).await;
            } else {
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send("[NOISE] Handshake response sent successfully\n".to_string()).await;
                }
            }
        },
        Ok(None) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send("[NOISE] Handshake completed, no response needed\n".to_string()).await;
            }
        },
        Err(e) => {
            let _ = ui_tx.send(format!("[!] Handshake failed: {:?}\n", e)).await;
        }
    }
}

// Handler for Noise handshake response messages
pub async fn handle_noise_handshake_resp(
    packet: &BitchatPacket,
    noise_session_manager: &mut NoiseSessionManager,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[NOISE] Received handshake response from {}\n", packet.sender_id_str)).await;
    }
    
    match noise_session_manager.handle_incoming_handshake(&packet.sender_id_str, &packet.payload) {
        Ok(Some(_)) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send("[NOISE] Handshake response processed, session established\n".to_string()).await;
            }
            
            // Send any pending messages
            send_pending_messages(noise_session_manager, peripheral, cmd_char, my_peer_id, &packet.sender_id_str, ui_tx.clone()).await;
        },
        Ok(None) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send("[NOISE] Handshake completed successfully\n".to_string()).await;
            }
            
            // Send any pending messages
            send_pending_messages(noise_session_manager, peripheral, cmd_char, my_peer_id, &packet.sender_id_str, ui_tx.clone()).await;
        },
        Err(e) => {
            let _ = ui_tx.send(format!("[!] Failed to process handshake response: {:?}\n", e)).await;
        }
    }
}

// Helper function to send pending messages after handshake completion
async fn send_pending_messages(
    noise_session_manager: &mut NoiseSessionManager,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    target_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    let pending_messages = noise_session_manager.get_pending_messages(target_peer_id);
    
    if !pending_messages.is_empty() {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("[NOISE] Sending {} pending messages to {}\n", pending_messages.len(), target_peer_id)).await;
        }
        
        for message_content in pending_messages {
            match noise_session_manager.encrypt(message_content.as_bytes(), target_peer_id) {
                Ok(encrypted) => {
                    // Create Noise encrypted message packet
                    let packet = crate::packet_creation::create_bitchat_packet_with_recipient_and_signature(
                        my_peer_id, 
                        target_peer_id, 
                        crate::data_structures::MessageType::NoiseEncrypted, 
                        encrypted, 
                        None
                    );
                    
                    if crate::fragmentation::send_packet_with_fragmentation(peripheral, cmd_char, packet, my_peer_id).await.is_err() {
                        let _ = ui_tx.send(format!("[!] Failed to send pending message to {}\n", target_peer_id)).await;
                    }
                },
                Err(e) => {
                    let _ = ui_tx.send(format!("[!] Failed to encrypt pending message: {:?}\n", e)).await;
                }
            }
        }
    }
}

// Handler for Noise encrypted messages
pub async fn handle_noise_encrypted_message(
    packet: &BitchatPacket,
    noise_session_manager: &mut NoiseSessionManager,
    peers_lock: &mut HashMap<String, Peer>,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx.send(format!("[NOISE] Received encrypted message from {}\n", packet.sender_id_str)).await;
        let _ = ui_tx.send(format!("[NOISE] Payload size: {} bytes\n", packet.payload.len())).await;
    }
    
    match noise_session_manager.decrypt(&packet.payload, &packet.sender_id_str) {
        Ok(decrypted) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send("[NOISE] Successfully decrypted message!\n".to_string()).await;
                let _ = ui_tx.send(format!("[NOISE] Decrypted size: {} bytes\n", decrypted.len())).await;
            }
            
            // Parse the decrypted message payload
            match crate::payload_handling::parse_bitchat_message_payload(&decrypted) {
                Ok(message) => {
                    // Add the sender to peers list if they're not already there
                    if !peers_lock.contains_key(&packet.sender_id_str) {
                        let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();
                        peer_entry.nickname = Some(message.sender.clone());
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[PEER] Discovered new peer via Noise: {} ({})\n", message.sender, packet.sender_id_str)).await;
                        }
                        // Send connected message to TUI so it updates the people list
                        let _ = ui_tx.send(format!("{} connected\n", message.sender)).await;
                    }
                    
                    // Display the message using the parsed sender
                    let _ = ui_tx.send(format!("\r\x1b[K\x1b[35m[DM from {}]\x1b[0m {}\n> ", message.sender, message.content)).await;
                },
                Err(e) => {
                    let _ = ui_tx.send(format!("[!] Failed to parse decrypted message payload: {}\n", e)).await;
                }
            }
        },
        Err(e) => {
            let _ = ui_tx.send(format!("[!] Failed to decrypt Noise message: {:?}\n", e)).await;
            let _ = ui_tx.send(format!("[!] Make sure you have an established Noise session with {}\n", packet.sender_id_str)).await;
        }
    }
}
