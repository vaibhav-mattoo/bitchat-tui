use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::Duration;
use tokio::time;
use rand::Rng;
use btleplug::api::{WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use chrono;
use hex;
use bloomfilter::Bloom;

use crate::data_structures::{
    BitchatPacket, Peer, DeliveryTracker, FragmentCollector, BROADCAST_RECIPIENT,
    COVER_TRAFFIC_PREFIX, MessageType, DeliveryAck
};
use crate::terminal_ux::{ChatContext, ChatMode, format_message_display};
use crate::encryption::EncryptionService;
use crate::payload_handling::{unpad_message, parse_bitchat_message_payload};
use crate::packet_creation::{
    create_bitchat_packet_with_recipient, create_bitchat_packet
};
use crate::packet_delivery::{create_delivery_ack, should_send_ack};
use crate::packet_parser::{parse_bitchat_packet, generate_keys_and_payload};
use crate::persistence::{AppState, EncryptedPassword, save_state};
use crate::{debug_println, debug_full_println};

// Handler for announce messages
pub fn handle_announce_message(packet: &BitchatPacket, peers_lock: &mut HashMap<String, Peer>) {
    let peer_nickname = String::from_utf8_lossy(&packet.payload).trim().to_string();

    let is_new_peer = !peers_lock.contains_key(&packet.sender_id_str);
    let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();

    peer_entry.nickname = Some(peer_nickname.clone());

    // Show connection notification in clean mode only for new peers
    if is_new_peer {
        // Clear any existing prompt and show connection notification in yellow
        print!("\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ", peer_nickname);
        std::io::stdout().flush().unwrap();
    }
    
    debug_println!("[<-- RECV] Announce: Peer {} is now known as '{}'", packet.sender_id_str, peer_nickname);
}

// Handler for message relay
pub async fn handle_message_relay(
    packet: &BitchatPacket,
    notification_value: &[u8],
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
) {
    debug_full_println!("[DEBUG] Message not for us, checking if we should relay (TTL={})", packet.ttl);
    
    // Relay if TTL > 1
    if packet.ttl > 1 {
        time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;  // Decrement TTL
        
        if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
            println!("[!] Failed to relay message");
        } else {
            debug_full_println!("[DEBUG] Relayed message with TTL={}", packet.ttl - 1);
        }
    }
}

// Handler for private message decryption
pub fn handle_private_message_decryption(
    packet: &BitchatPacket,
    encryption_service: &EncryptionService,
) -> Option<Vec<u8>> {
    debug_println!("[PRIVATE] This is a private message for us from {}", packet.sender_id_str);
    debug_println!("[PRIVATE] Payload size: {} bytes", packet.payload.len());
    debug_println!("[PRIVATE] First 32 bytes of encrypted payload: {}", hex::encode(&packet.payload[..std::cmp::min(32, packet.payload.len())]));
    
    match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
        Ok(decrypted) => {
            debug_println!("[PRIVATE] Successfully decrypted private message!");
            debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
            Some(decrypted)
        }
        Err(e) => {
            debug_println!("[PRIVATE] Failed to decrypt private message: {:?}", e);
            debug_println!("[PRIVATE] Checking if we have shared secret with {}", packet.sender_id_str);
            // Private messages MUST be encrypted, skip if decryption fails
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
) {
    debug_full_println!("[DEBUG] ==================== MESSAGE RECEIVED ====================");
    debug_full_println!("[DEBUG] Sender: {}", packet.sender_id_str);
    
    // Check if sender is blocked
    if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&packet.sender_id_str) {
        if blocked_peers.contains(&fingerprint) {
            debug_println!("[BLOCKED] Ignoring message from blocked peer: {}", packet.sender_id_str);
            return; // Silent drop
        }
    }
    
    // Check if this is a broadcast or targeted message
    let is_broadcast = packet.recipient_id.as_ref()
        .map(|r| r == &BROADCAST_RECIPIENT)
        .unwrap_or(true);
    
    // Check if message is for us
    let is_for_us = if is_broadcast {
        true
    } else {
        packet.recipient_id_str.as_ref()
            .map(|r| {
                let matches = r == my_peer_id;
                debug_full_println!("[DEBUG] Comparing recipient '{}' with my_peer_id '{}': {}", r, my_peer_id, matches);
                matches
            })
            .unwrap_or(false)
    };
    
    if let Some(ref recipient) = packet.recipient_id_str {
        debug_full_println!("[DEBUG] Recipient: {} (broadcast: {})", recipient, is_broadcast);
    } else {
        debug_full_println!("[DEBUG] Recipient: (none/broadcast)");
    }
    
    debug_full_println!("[DEBUG] Payload size: {} bytes", packet.payload.len());
    
    // Handle messages not for us - relay them
    if !is_for_us {
        handle_message_relay(packet, notification_value, peripheral, cmd_char).await;
        return;
    }
    
    // iOS sends private messages with recipient ID set at packet level
    let is_private_message = !is_broadcast && is_for_us;
    let mut decrypted_payload = None;
    
    // If it's a private message for us, we need to decrypt it
    if is_private_message {
        decrypted_payload = handle_private_message_decryption(packet, encryption_service);
        if decrypted_payload.is_none() {
            return; // Skip if decryption failed
        }
    }
    
    // Parse the message payload
    let parse_result = if is_private_message {
        // For private messages, parse the decrypted and unpadded payload
        if let Some(ref decrypted) = decrypted_payload {
            debug_full_println!("[DEBUG] Parsing decrypted private message payload");
            let unpadded = unpad_message(decrypted);
            debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
            parse_bitchat_message_payload(&unpadded)
        } else {
            // If decryption failed but it's a private message, skip it
            debug_full_println!("[DEBUG] Cannot parse private message without decryption");
            return;
        }
    } else {
        // For broadcast messages, parse the payload directly
        debug_full_println!("[DEBUG] Parsing regular message payload");
        parse_bitchat_message_payload(&packet.payload)
    };

    if let Ok(message) = parse_result {
        debug_full_println!("[DEBUG] Message parsed successfully!");
        debug_full_println!("[DEBUG] Message ID: {}", message.id);
        debug_full_println!("[DEBUG] Is encrypted channel: {}", message.is_encrypted);
        debug_full_println!("[DEBUG] Channel: {:?}", message.channel);
        debug_full_println!("[DEBUG] Content length: {} bytes", message.content.len());

        if !bloom.check(&message.id) {
            // Add to bloom filter immediately to prevent duplicate processing
            bloom.set(&message.id);

            let sender_nick = peers_lock.get(&packet.sender_id_str)
                .and_then(|p| p.nickname.as_ref())
                .map_or(&packet.sender_id_str, |n| n);

            // Track discovered channels
            if let Some(channel) = &message.channel {
                discovered_channels.insert(channel.clone());
                debug_println!("[DISCOVERY] Found channel: {}", channel);
                
                // Mark channel as password-protected if we see an encrypted message
                if message.is_encrypted {
                    password_protected_channels.insert(channel.clone());
                    debug_println!("[SECURITY] Marked {} as password-protected", channel);
                }
            }

            {
                // Normal message display with decryption support
                let display_content = if message.is_encrypted {
                    if let Some(channel) = &message.channel {
                        if let Some(channel_key) = channel_keys.get(channel) {
                            // Decrypt the encrypted content
                            if let Some(encrypted_bytes) = &message.encrypted_content {
                                match encryption_service.decrypt_with_key(encrypted_bytes, channel_key) {
                                Ok(decrypted) => String::from_utf8_lossy(&decrypted).to_string(),
                                    Err(_) => "[Encrypted message - decryption failed]".to_string()
                                }
                            } else {
                                "[Encrypted message - no encrypted data]".to_string()
                            }
                        } else {
                            "[Encrypted message - join channel with password]".to_string()
                        }
                    } else {
                        message.content.clone()
                    }
                } else {
                    message.content.clone()
                };

                // Display the message with proper formatting
                let timestamp = chrono::Local::now();
                
                if is_private_message {
                    // Check for iOS cover traffic (dummy messages)
                    if display_content.starts_with(COVER_TRAFFIC_PREFIX) {
                        debug_println!("[COVER] Discarding dummy message from {}", sender_nick);
                        return; // Silently discard cover traffic
                    }
                    
                    // Save the last private sender for replies
                    chat_context.last_private_sender = Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                    chat_context.add_dm(sender_nick, &packet.sender_id_str);
                    
                    let display = format_message_display(
                        timestamp,
                        sender_nick,
                        &display_content,
                        true, // is_private
                        false, // is_channel
                        None, // channel_name
                        Some(nickname), // recipient (me)
                        nickname // my_nickname
                    );
                    // Clear any existing prompt and print the message
                    print!("\r\x1b[K{}\n", display);
                    
                    // Show minimal reply hint
                    if !matches!(&chat_context.current_mode, ChatMode::PrivateDM { .. }) {
                        print!("\x1b[90m» /reply to respond\x1b[0m\n");
                    }
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    
                    // Update last sender for /reply command
                } else if let Some(channel_name) = &message.channel {
                    // Track this channel
                    chat_context.add_channel(channel_name);
                    
                    let display = format_message_display(
                        timestamp,
                        sender_nick,
                        &display_content,
                        false, // is_private
                        true, // is_channel
                        Some(channel_name), // channel_name
                        None, // recipient
                        nickname // my_nickname
                    );
                    // Clear any existing prompt and print the message
                    print!("\r\x1b[K{}\n", display);
                    std::io::stdout().flush().unwrap();
                } else {
                    // Public message
                    let display = format_message_display(
                        timestamp,
                        sender_nick,
                        &display_content,
                        false, // is_private
                        false, // is_channel
                        None, // channel_name
                        None, // recipient
                        nickname // my_nickname
                    );
                    // Clear any existing prompt and print the message
                    print!("\r\x1b[K{}\n> ", display);
                    std::io::stdout().flush().unwrap();
                }
            }
         
            // Send delivery ACK if needed (matching iOS behavior)
            let active_peer_count = peers_lock.len();
            if should_send_ack(is_private_message, message.channel.as_deref(), None, nickname, active_peer_count) {
                // Check if we've already sent an ACK for this message
                let ack_id = format!("{}-{}", message.id, my_peer_id);
                if delivery_tracker.should_send_ack(&ack_id) {
                    debug_println!("[ACK] Sending delivery ACK for message {}", message.id);
                    
                    // Create ACK payload
                    let ack_payload = create_delivery_ack(
                        &message.id,
                        my_peer_id,
                        nickname,
                        1 // hop count
                    );
                    
                    // Encrypt ACK if it's a private message
                    let final_ack_payload = if is_private_message {
                        // Encrypt the ACK for the sender
                        match encryption_service.encrypt_for_peer(&packet.sender_id_str, &ack_payload) {
                            Ok(encrypted) => encrypted,
                            Err(e) => {
                                debug_println!("[ACK] Failed to encrypt ACK: {:?}", e);
                                ack_payload
                            }
                        }
                    } else {
                        ack_payload
                    };
                    
                    // Create and send ACK packet with TTL=3 (limited propagation)
                    let mut ack_packet = create_bitchat_packet_with_recipient(
                        my_peer_id, 
                        Some(&packet.sender_id_str),
                        MessageType::DeliveryAck, 
                        final_ack_payload,
                        None // No signature for ACKs
                    );
                    
                    // Override TTL to 3 for ACKs
                    if ack_packet.len() > 2 {
                        ack_packet[2] = 3; // TTL position
                    }
                    
                    if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                        debug_println!("[ACK] Failed to send delivery ACK: {}", e);
                    }
                }
            }

            // Relay message if TTL > 1 (matching Swift behavior)
            if packet.ttl > 1 {
                // Don't relay immediately - add small random delay
                time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                
                // Create relay packet with decremented TTL
                let mut relay_data = notification_value.to_vec();
                relay_data[2] = packet.ttl - 1;  // Decrement TTL at position 2
                
                if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                    println!("[!] Failed to relay message");
                }
            }
        }
    } else {
        println!("[!] Failed to parse message payload");
        debug_full_println!("[DEBUG] Parse error details:");
        debug_full_println!("[DEBUG] Raw payload hex: {}", hex::encode(&packet.payload));
        if let Some(decrypted) = decrypted_payload {
            debug_full_println!("[DEBUG] Decrypted payload hex: {}", hex::encode(&decrypted));
        }
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
    nickname: &str,
    my_peer_id: &str,
    blocked_peers: &HashSet<String>,
) {
    // Handle fragment (simplified, following working example)
    if packet.payload.len() >= 13 {
        let mut fragment_id = [0u8; 8];
        fragment_id.copy_from_slice(&packet.payload[0..8]);
        
        let index = ((packet.payload[8] as u16) << 8) | (packet.payload[9] as u16);
        let total = ((packet.payload[10] as u16) << 8) | (packet.payload[11] as u16);
        let original_type = packet.payload[12];
        let fragment_data = packet.payload[13..].to_vec();
        
        // Try to reassemble
        if let Some((complete_data, _sender)) = fragment_collector.add_fragment(
            fragment_id, index, total, original_type, fragment_data, packet.sender_id_str.clone()
        ) {
            // Parse and handle the reassembled packet
            if let Ok(reassembled_packet) = parse_bitchat_packet(&complete_data) {
                if reassembled_packet.msg_type == MessageType::Message {
                    // Check if sender is blocked
                    if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&reassembled_packet.sender_id_str) {
                        if blocked_peers.contains(&fingerprint) {
                            debug_println!("[BLOCKED] Ignoring fragmented message from blocked peer: {}", reassembled_packet.sender_id_str);
                            return; // Silent drop
                        }
                    }
                    
                    // Check if this is a private message that needs decryption
                    let is_broadcast = reassembled_packet.recipient_id.as_ref()
                        .map(|r| r == &BROADCAST_RECIPIENT)
                        .unwrap_or(true);
                    
                    let is_for_us = if is_broadcast {
                        true
                    } else {
                        reassembled_packet.recipient_id_str.as_ref()
                            .map(|r| r == my_peer_id)
                            .unwrap_or(false)
                    };
                    
                    let is_private_message = !is_broadcast && is_for_us;
                    
                    // Handle private messages by decrypting first
                    let message_result = if is_private_message {
                        match encryption_service.decrypt(&reassembled_packet.payload, &reassembled_packet.sender_id_str) {
                            Ok(decrypted) => {
                                debug_println!("[PRIVATE] Successfully decrypted fragmented private message!");
                                debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
                                let unpadded = unpad_message(&decrypted);
                                debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
                                parse_bitchat_message_payload(&unpadded)
                            },
                            Err(e) => {
                                debug_println!("[PRIVATE] Failed to decrypt fragmented private message: {:?}", e);
                                return;
                            }
                        }
                    } else {
                        // Regular broadcast message
                        parse_bitchat_message_payload(&reassembled_packet.payload)
                    };
                    
                    if let Ok(message) = message_result {
                        if !bloom.check(&message.id) {
                            let sender_nick = peers_lock.get(&reassembled_packet.sender_id_str)
                                .and_then(|p| p.nickname.as_ref())
                                .map_or(&reassembled_packet.sender_id_str, |n| n);
                            
                            {
                                // Track discovered channels from fragmented messages
                                if let Some(channel) = &message.channel {
                                    discovered_channels.insert(channel.clone());
                                    if message.is_encrypted {
                                        password_protected_channels.insert(channel.clone());
                                    }
                                }
                                
                                // Check for iOS cover traffic in private messages
                                if is_private_message && message.content.starts_with(COVER_TRAFFIC_PREFIX) {
                                    debug_println!("[COVER] Discarding fragmented dummy message from {}", sender_nick);
                                    bloom.set(&message.id); // Mark as seen before continuing
                                    return; // Silently discard
                                }
                                
                                // Regular message - display it
                                let timestamp = chrono::Local::now();
                                let display = format_message_display(
                                    timestamp,
                                    sender_nick,
                                    &message.content,
                                    is_private_message, // Use the actual private message flag
                                    message.channel.is_some(), // is_channel
                                    message.channel.as_deref(),
                                    if is_private_message { Some(nickname) } else { None }, // recipient for private messages
                                    nickname // my_nickname
                                );
                                // Clear any existing prompt and print the message
                                print!("\r\x1b[K{}\n> ", display);
                                std::io::stdout().flush().unwrap();
                                
                                // If it's a private message, update chat context
                                if is_private_message {
                                    chat_context.last_private_sender = Some((reassembled_packet.sender_id_str.clone(), sender_nick.to_string()));
                                }
                            }
                            
                            bloom.set(&message.id);
                        }
                    }
                }
            }
        }
    }
    
    // Relay fragments if TTL > 1
    if packet.ttl > 1 {
        time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;
        
        if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
            println!("[!] Failed to relay fragment");
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
) {
    // Extract public key
    let public_key = packet.payload.clone();
    debug_println!("[<-- RECV] Key exchange from {} (key: {} bytes)", packet.sender_id_str, public_key.len());
    debug_full_println!("[CRYPTO] Key exchange payload first 32 bytes: {}", hex::encode(&public_key[..std::cmp::min(32, public_key.len())]));
    
    // Add peer's public key to encryption service
    if let Err(e) = encryption_service.add_peer_public_key(&packet.sender_id_str, &public_key) {
        println!("[!] Failed to add peer public key: {:?}", e);
    } else {
        debug_println!("[+] Successfully added encryption keys for peer {}", packet.sender_id_str);
        
        // Send our key exchange back if we haven't already
        if !peers_lock.contains_key(&packet.sender_id_str) {
            debug_full_println!("[CRYPTO] Sending key exchange response to {}", packet.sender_id_str);
            let (key_exchange_payload, _) = generate_keys_and_payload(encryption_service);
            let key_exchange_packet = create_bitchat_packet(my_peer_id, MessageType::KeyExchange, key_exchange_payload);
            if let Err(e) = peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await {
                println!("[!] Failed to send key exchange response: {}", e);
            }
        }
    }
}

// Handler for leave messages
pub fn handle_leave_message(
    packet: &BitchatPacket,
    peers_lock: &mut HashMap<String, Peer>,
    chat_context: &ChatContext,
) {
    // Handle leave notification
    let payload_str = String::from_utf8_lossy(&packet.payload).trim().to_string();
    
    if payload_str.starts_with('#') {
        // Channel leave notification
        let channel = payload_str;
        let sender_nick = peers_lock.get(&packet.sender_id_str)
            .and_then(|p| p.nickname.as_ref())
            .map_or(&packet.sender_id_str, |n| n);
        
        // Show leave message only if we're in that channel
        if let ChatMode::Channel(current_channel) = &chat_context.current_mode {
            if current_channel == &channel {
                print!("\r\x1b[K\x1b[90m« {} left {}\x1b[0m\n> ", sender_nick, channel);
                std::io::stdout().flush().unwrap();
            }
        }
        
        debug_println!("[<-- RECV] {} left channel {}", sender_nick, channel);
    } else {
        // Legacy peer disconnect
        peers_lock.remove(&packet.sender_id_str);
        debug_println!("[<-- RECV] Peer {} ({}) has left", packet.sender_id_str, payload_str);
    }
}

// Handler for channel announce messages
pub fn handle_channel_announce_message(
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
) {
    // Parse channel announce: "channel|isProtected|creatorID|keyCommitment"
    let payload_str = String::from_utf8_lossy(&packet.payload);
    let parts: Vec<&str> = payload_str.split('|').collect();
    
    if parts.len() >= 3 {
        let channel = parts[0];
        let is_protected = parts[1] == "1";
        let creator_id = parts[2];
        let _key_commitment = parts.get(3).unwrap_or(&"");
        
        debug_println!("[<-- RECV] Channel announce: {} (protected: {}, owner: {})", 
                     channel, is_protected, creator_id);
        
        // Always update channel creator for any channel announce
        if !creator_id.is_empty() {
            channel_creators.insert(channel.to_string(), creator_id.to_string());
        }
        
        if is_protected {
            password_protected_channels.insert(channel.to_string());
            
            // Store key commitment for verification (matching iOS behavior)
            if !_key_commitment.is_empty() {
                channel_key_commitments.insert(channel.to_string(), _key_commitment.to_string());
                debug_println!("[CHANNEL] Stored key commitment for {}: {}", channel, _key_commitment);
            }
        } else {
            password_protected_channels.remove(channel);
            // If channel is no longer protected, clear keys and commitments
            channel_keys.remove(channel);
            channel_key_commitments.remove(channel);
        }
        
        // Track this channel
        chat_context.add_channel(channel);
        
        // Save state
        let state_to_save = create_app_state(
            blocked_peers,
            channel_creators,
            &chat_context.active_channels,
            password_protected_channels,
            channel_key_commitments,
            encrypted_channel_passwords,
            nickname
        );
        if let Err(e) = save_state(&state_to_save) {
            eprintln!("Warning: Could not save state: {}", e);
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
) {
    debug_println!("[<-- RECV] Delivery ACK from {}", packet.sender_id_str);
    
    // Check if this ACK is for us
    let is_for_us = packet.recipient_id_str.as_ref()
        .map(|r| r == my_peer_id)
        .unwrap_or(false);
    
    if is_for_us {
        // Decrypt the ACK payload if it's encrypted
        let ack_payload = if packet.ttl == 3 && encryption_service.has_peer_key(&packet.sender_id_str) {
            // ACKs might be encrypted for private messages
            match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
                Ok(decrypted) => decrypted,
                Err(_) => packet.payload.clone() // Fall back to unencrypted
            }
        } else {
            packet.payload.clone()
        };
        
        // Parse the ACK JSON
        if let Ok(ack) = serde_json::from_slice::<DeliveryAck>(&ack_payload) {
            debug_println!("[ACK] Received ACK for message: {}", ack.original_message_id);
            debug_println!("[ACK] From: {} ({})", ack.recipient_nickname, ack.recipient_id);
            
            // Mark message as delivered
            if delivery_tracker.mark_delivered(&ack.original_message_id) {
                // Show delivery confirmation
                print!("\r\x1b[K\x1b[90m✓ Delivered to {}\x1b[0m\n> ", ack.recipient_nickname);
                std::io::stdout().flush().unwrap();
            }
        } else {
            debug_println!("[ACK] Failed to parse delivery ACK");
        }
    } else if packet.ttl > 1 {
        // Relay ACK if not for us
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;
        let _ = peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await;
    }
}

// Handler for delivery status request messages
pub fn handle_delivery_status_request_message(_packet: &BitchatPacket) {
    // iOS defines this but doesn't implement it yet
    debug_println!("[<-- RECV] Delivery status request (not implemented)");
}

// Handler for read receipt messages
pub fn handle_read_receipt_message(_packet: &BitchatPacket) {
    // iOS defines this but doesn't implement it yet
    debug_println!("[<-- RECV] Read receipt (not implemented)");
}
