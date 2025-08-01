use bloomfilter::Bloom;
use btleplug::api::{Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use chrono;
use hex;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

use std::fs::OpenOptions;
use std::io::Write;

use crate::data_structures::{
    BitchatMessage, BitchatPacket, DebugLevel, DeliveryAck, DeliveryTracker, FragmentCollector, MessageType, Peer,
    BROADCAST_RECIPIENT, COVER_TRAFFIC_PREFIX, DEBUG_LEVEL,
};
use crate::encryption::EncryptionService;
use crate::noise_protocol::NoiseError;
use crate::noise_session::NoiseSessionManager;
use crate::packet_creation::{create_bitchat_packet, create_bitchat_packet_with_recipient};
use crate::packet_delivery::{create_delivery_ack, should_send_ack};
use crate::packet_parser::{generate_keys_and_payload, parse_bitchat_packet};
use crate::payload_handling::{parse_bitchat_message_payload, unpad_message};
use crate::persistence::{save_state, AppState, EncryptedPassword};
use crate::terminal_ux::{ChatContext, ChatMode};

// MARK: - Debug Logging

pub fn write_noise_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("noise_handler_debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = file.write_all(log_entry.as_bytes());
    }
}

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
        let _ = ui_tx
            .send(format!(
                "\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ",
                peer_nickname
            ))
            .await;
    }

    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send(format!(
                "[<-- RECV] Announce: Peer {} is now known as '{}'\n",
                packet.sender_id_str, peer_nickname
            ))
            .await;
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
        let _ = ui_tx
            .send(format!(
                "[DEBUG] Message not for us, checking if we should relay (TTL={})\n",
                packet.ttl
            ))
            .await;
    }

    if packet.ttl > 1 {
        time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1; // Decrement TTL

        if peripheral
            .write(cmd_char, &relay_data, WriteType::WithoutResponse)
            .await
            .is_err()
        {
            let _ = ui_tx
                .send("[!] Failed to relay message\n".to_string())
                .await;
        } else {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
                let _ = ui_tx
                    .send(format!(
                        "[DEBUG] Relayed message with TTL={}\n",
                        packet.ttl - 1
                    ))
                    .await;
            }
        }
    }
}

// Handler for private message decryption
pub async fn handle_private_message_decryption(
    packet: &BitchatPacket,
    encryption_service: &EncryptionService,
    noise_manager: &mut NoiseSessionManager,
    ui_tx: mpsc::Sender<String>,
) -> Option<Vec<u8>> {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send(format!(
                "[PRIVATE] This is a private message for us from {}\n",
                packet.sender_id_str
            ))
            .await;
        let _ = ui_tx
            .send(format!(
                "[PRIVATE] Payload size: {} bytes\n",
                packet.payload.len()
            ))
            .await;
        let _ = ui_tx
            .send(format!(
                "[PRIVATE] First 32 bytes of encrypted payload: {}\n",
                hex::encode(&packet.payload[..std::cmp::min(32, packet.payload.len())])
            ))
            .await;
    }

    // Try Noise decryption first (preferred for established sessions)
    if noise_manager.is_session_ready(&packet.sender_id_str) {
        match noise_manager.decrypt_message(&packet.sender_id_str, &packet.payload) {
            Ok(decrypted) => {
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx
                        .send(
                            "[PRIVATE] Successfully decrypted with Noise transport cipher!\n"
                                .to_string(),
                        )
                        .await;
                    let _ = ui_tx
                        .send(format!(
                            "[PRIVATE] Decrypted size: {} bytes\n",
                            decrypted.len()
                        ))
                        .await;
                }
                return Some(decrypted);
            }
            Err(e) => {
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx
                        .send(format!(
                            "[PRIVATE] Noise decryption failed: {:?}, trying fallback\n",
                            e
                        ))
                        .await;
                }
            }
        }
    }

    // Fallback to legacy encryption service
    match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
        Ok(decrypted) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send("[PRIVATE] Successfully decrypted with legacy method!\n".to_string())
                    .await;
                let _ = ui_tx
                    .send(format!(
                        "[PRIVATE] Decrypted size: {} bytes\n",
                        decrypted.len()
                    ))
                    .await;
            }
            Some(decrypted)
        }
        Err(e) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[PRIVATE] All decryption methods failed: {:?}\n",
                        e
                    ))
                    .await;
                let _ = ui_tx
                    .send(format!(
                        "[PRIVATE] Checking if we have shared secret with {}\n",
                        packet.sender_id_str
                    ))
                    .await;
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
    noise_manager: &mut NoiseSessionManager,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    nickname: &str,
    my_peer_id: &str,
    blocked_peers: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
        let _ = ui_tx
            .send(
                "[DEBUG] ==================== MESSAGE RECEIVED ====================\n".to_string(),
            )
            .await;
        let _ = ui_tx
            .send(format!("[DEBUG] Sender: {}\n", packet.sender_id_str))
            .await;
    }

    if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&packet.sender_id_str) {
        if blocked_peers.contains(&fingerprint) {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[BLOCKED] Ignoring message from blocked peer: {}\n",
                        packet.sender_id_str
                    ))
                    .await;
            }
            return;
        }
    }

    let is_broadcast = packet
        .recipient_id
        .as_ref()
        .map(|r| r == &BROADCAST_RECIPIENT)
        .unwrap_or(true);
    let is_for_us = if is_broadcast {
        true
    } else {
        packet
            .recipient_id_str
            .as_ref()
            .map(|r| r == my_peer_id)
            .unwrap_or(false)
    };

    if !is_for_us {
        handle_message_relay(
            packet,
            notification_value,
            peripheral,
            cmd_char,
            ui_tx.clone(),
        )
        .await;
        return;
    }

    let is_private_message = !is_broadcast && is_for_us;
    let mut decrypted_payload = None;

    if is_private_message {
        decrypted_payload = handle_private_message_decryption(
            packet,
            encryption_service,
            noise_manager,
            ui_tx.clone(),
        )
        .await;
        if decrypted_payload.is_none() {
            return;
        }
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
                    let _ = ui_tx
                        .send(format!(
                            "[PEER] Discovered new peer: {} ({})\n",
                            sender_nick, packet.sender_id_str
                        ))
                        .await;
                }
                // Send connected message to TUI so it updates the people list
                let _ = ui_tx.send(format!("{} connected\n", sender_nick)).await;
            }

            if let Some(channel) = &message.channel {
                discovered_channels.insert(channel.clone());
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx
                        .send(format!("[DISCOVERY] Found channel: {}\n", channel))
                        .await;
                }
                if message.is_encrypted {
                    password_protected_channels.insert(channel.clone());
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                        let _ = ui_tx
                            .send(format!(
                                "[SECURITY] Marked {} as password-protected\n",
                                channel
                            ))
                            .await;
                    }
                }
            }

            let display_content = if message.is_encrypted {
                if let Some(channel) = &message.channel {
                    channel_keys.get(channel).map_or_else(
                        || "[Encrypted message - join channel with password]".to_string(),
                        |key| {
                            message.encrypted_content.as_ref().map_or_else(
                                || "[Encrypted message - no encrypted data]".to_string(),
                                |bytes| {
                                    encryption_service.decrypt_with_key(bytes, key).map_or_else(
                                        |_| "[Encrypted message - decryption failed]".to_string(),
                                        |dec| String::from_utf8_lossy(&dec).to_string(),
                                    )
                                },
                            )
                        },
                    )
                } else {
                    message.content.clone()
                }
            } else {
                message.content.clone()
            };

            let timestamp = chrono::Local::now();

            if is_private_message {
                if display_content.starts_with(COVER_TRAFFIC_PREFIX) {
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                        let _ = ui_tx
                            .send(format!(
                                "[COVER] Discarding dummy message from {}\n",
                                sender_nick
                            ))
                            .await;
                    }
                    return;
                }

                chat_context.last_private_sender =
                    Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                chat_context.add_dm(sender_nick, &packet.sender_id_str);

                // Send structured message for TUI to parse
                let structured_msg = format!(
                    "__DM__:{}:{}:{}",
                    sender_nick,
                    timestamp.format("%H%M"),
                    display_content
                );
                let _ = ui_tx.send(structured_msg).await;

                if !matches!(&chat_context.current_mode, ChatMode::PrivateDM { .. }) {
                    let _ = ui_tx
                        .send("\x1b[90mÃ‚Â» /reply to respond\x1b[0m\n".to_string())
                        .await;
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
                let structured_msg = format!(
                    "__CHANNEL__:{}:{}:{}:{}",
                    channel_key,
                    sender_nick,
                    timestamp.format("%H%M"),
                    display_content
                );
                let _ = ui_tx.send(structured_msg).await;
            }

            if should_send_ack(
                is_private_message,
                message.channel.as_deref(),
                None,
                nickname,
                peers_lock.len(),
            ) {
                let ack_id = format!("{}-{}", message.id, my_peer_id);
                if delivery_tracker.should_send_ack(&ack_id) {
                    let ack_payload = create_delivery_ack(&message.id, my_peer_id, nickname, 1);
                    let final_ack_payload = if is_private_message {
                        encryption_service
                            .encrypt_for_peer(&packet.sender_id_str, &ack_payload)
                            .unwrap_or(ack_payload)
                    } else {
                        ack_payload
                    };

                    let mut ack_packet = create_bitchat_packet_with_recipient(
                        my_peer_id,
                        Some(&packet.sender_id_str),
                        MessageType::DeliveryAck,
                        final_ack_payload,
                        None,
                    );
                    if ack_packet.len() > 2 {
                        ack_packet[2] = 3;
                    }

                    if let Err(e) = peripheral
                        .write(cmd_char, &ack_packet, WriteType::WithoutResponse)
                        .await
                    {
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx
                                .send(format!("[ACK] Failed to send delivery ACK: {}\n", e))
                                .await;
                        }
                    }
                }
            }

            if packet.ttl > 1 {
                time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                let mut relay_data = notification_value.to_vec();
                relay_data[2] = packet.ttl - 1;
                if peripheral
                    .write(cmd_char, &relay_data, WriteType::WithoutResponse)
                    .await
                    .is_err()
                {
                    let _ = ui_tx
                        .send("[!] Failed to relay message\n".to_string())
                        .await;
                }
            }
        }
    } else {
        let _ = ui_tx
            .send("[!] Failed to parse message payload\n".to_string())
            .await;
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

        if let Some((complete_data, _)) = fragment_collector.add_fragment(
            fragment_id,
            index,
            total,
            original_type,
            fragment_data,
            packet.sender_id_str.clone(),
        ) {
            if let Ok(reassembled) = parse_bitchat_packet(&complete_data) {
                if reassembled.msg_type == MessageType::Message {
                    if let Some(fp) =
                        encryption_service.get_peer_fingerprint(&reassembled.sender_id_str)
                    {
                        if blocked_peers.contains(&fp) {
                            return;
                        }
                    }

                    let is_broadcast = reassembled
                        .recipient_id
                        .as_ref()
                        .map(|r| r == &BROADCAST_RECIPIENT)
                        .unwrap_or(true);
                    let is_for_us = if is_broadcast {
                        true
                    } else {
                        reassembled
                            .recipient_id_str
                            .as_ref()
                            .map(|r| r == my_peer_id)
                            .unwrap_or(false)
                    };
                    let is_private_message = !is_broadcast && is_for_us;

                    let message_result = if is_private_message {
                        encryption_service
                            .decrypt(&reassembled.payload, &reassembled.sender_id_str)
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
                                let peer_entry = peers_lock
                                    .entry(reassembled.sender_id_str.clone())
                                    .or_default();
                                peer_entry.nickname = Some(message.sender.clone());
                                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                                    let _ = ui_tx
                                        .send(format!(
                                            "[PEER] Discovered new peer via fragment: {} ({})\n",
                                            message.sender, reassembled.sender_id_str
                                        ))
                                        .await;
                                }
                                // Send connected message to TUI so it updates the people list
                                let _ = ui_tx.send(format!("{} connected\n", message.sender)).await;
                            }

                            let sender_nick = &message.sender;

                            if let Some(ch) = &message.channel {
                                discovered_channels.insert(ch.clone());
                                if message.is_encrypted {
                                    password_protected_channels.insert(ch.clone());
                                }
                            }

                            if is_private_message
                                && message.content.starts_with(COVER_TRAFFIC_PREFIX)
                            {
                                return;
                            }

                            let timestamp = chrono::Local::now();

                            // Send structured message for TUI to parse
                            if is_private_message {
                                let structured_msg = format!(
                                    "__DM__:{}:{}:{}",
                                    sender_nick,
                                    timestamp.format("%H%M"),
                                    message.content
                                );
                                let _ = ui_tx.send(structured_msg).await;
                            } else {
                                let channel_key = message.channel.as_deref().unwrap_or("#public");
                                let structured_msg = format!(
                                    "__CHANNEL__:{}:{}:{}:{}",
                                    channel_key,
                                    sender_nick,
                                    timestamp.format("%H%M"),
                                    message.content
                                );
                                let _ = ui_tx.send(structured_msg).await;
                            }

                            if is_private_message {
                                chat_context.last_private_sender = Some((
                                    reassembled.sender_id_str.clone(),
                                    sender_nick.to_string(),
                                ));
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
        if peripheral
            .write(cmd_char, &relay_data, WriteType::WithoutResponse)
            .await
            .is_err()
        {
            let _ = ui_tx
                .send("[!] Failed to relay fragment\n".to_string())
                .await;
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
        let _ = ui_tx
            .send(format!(
                "[<-- RECV] Key exchange from {} (key: {} bytes)\n",
                packet.sender_id_str,
                public_key.len()
            ))
            .await;
    }

    if let Err(e) = encryption_service.add_peer_public_key(&packet.sender_id_str, &public_key) {
        let _ = ui_tx
            .send(format!("[!] Failed to add peer public key: {:?}\n", e))
            .await;
    } else {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[+] Successfully added encryption keys for peer {}\n",
                    packet.sender_id_str
                ))
                .await;
        }

        if !peers_lock.contains_key(&packet.sender_id_str) {
            let (key_exchange_payload, _) = generate_keys_and_payload(encryption_service);
            let key_exchange_packet =
                create_bitchat_packet(my_peer_id, MessageType::KeyExchange, key_exchange_payload);
            if let Err(e) = peripheral
                .write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse)
                .await
            {
                let _ = ui_tx
                    .send(format!("[!] Failed to send key exchange response: {}\n", e))
                    .await;
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
        let sender_nick = peers_lock
            .get(&packet.sender_id_str)
            .and_then(|p| p.nickname.as_ref())
            .map_or(&packet.sender_id_str, |n| n);

        if let ChatMode::Channel(current_channel) = &chat_context.current_mode {
            if current_channel == &channel {
                let _ = ui_tx
                    .send(format!(
                        "\r\x1b[K\x1b[90mÃ‚Â« {} left {}\x1b[0m\n> ",
                        sender_nick, channel
                    ))
                    .await;
            }
        }
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[<-- RECV] {} left channel {}\n",
                    sender_nick, channel
                ))
                .await;
        }
    } else {
        peers_lock.remove(&packet.sender_id_str);
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[<-- RECV] Peer {} ({}) has left\n",
                    packet.sender_id_str, payload_str
                ))
                .await;
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
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
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
        let state_to_save = create_app_state(
            blocked_peers,
            channel_creators,
            &channels_vec,
            password_protected_channels,
            channel_key_commitments,
            encrypted_channel_passwords,
            nickname,
        );
        if let Err(e) = save_state(&state_to_save) {
            let _ = ui_tx
                .send(format!(
                    "\x1b[93mWarning: Could not save state: {}\x1b[0m\n",
                    e
                ))
                .await;
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
        let _ = ui_tx
            .send(format!(
                "[<-- RECV] Delivery ACK from {}\n",
                packet.sender_id_str
            ))
            .await;
    }

    let is_for_us = packet
        .recipient_id_str
        .as_ref()
        .map(|r| r == my_peer_id)
        .unwrap_or(false);

    if is_for_us {
        let ack_payload =
            if packet.ttl == 3 && encryption_service.has_peer_key(&packet.sender_id_str) {
                encryption_service
                    .decrypt(&packet.payload, &packet.sender_id_str)
                    .unwrap_or_else(|_| packet.payload.clone())
            } else {
                packet.payload.clone()
            };

        if let Ok(ack) = serde_json::from_slice::<DeliveryAck>(&ack_payload) {
            if delivery_tracker.mark_delivered(&ack.original_message_id) {
                let _ = ui_tx
                    .send(format!(
                        "\r\x1b[K\x1b[90mÃ¢Å“â€œ Delivered to {}\x1b[0m\n> ",
                        ack.recipient_nickname
                    ))
                    .await;
            }
        }
    } else if packet.ttl > 1 {
        let mut relay_data = notification_value.to_vec();
        relay_data[2] = packet.ttl - 1;
        let _ = peripheral
            .write(cmd_char, &relay_data, WriteType::WithoutResponse)
            .await;
    }
}

// Handler for delivery status request messages
pub async fn handle_delivery_status_request_message(
    _packet: &BitchatPacket,
    ui_tx: mpsc::Sender<String>,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send("[<-- RECV] Delivery status request (not implemented)\n".to_string())
            .await;
    }
}

// Handler for read receipt messages
pub async fn handle_read_receipt_message(_packet: &BitchatPacket, ui_tx: mpsc::Sender<String>) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send("[<-- RECV] Read receipt (not implemented)\n".to_string())
            .await;
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
    write_noise_debug_log(&format!(
        "[DEBUG] Starting handle_noise_handshake_init for peer: {}",
        packet.sender_id_str
    ));

    // Check if we already have an established session
    write_noise_debug_log(&format!(
        "[DEBUG] Checking if session exists for peer: {}",
        packet.sender_id_str
    ));
    if noise_session_manager.has_established_session(&packet.sender_id_str) {
        write_noise_debug_log(&format!(
            "[DEBUG] Session already established for peer: {}",
            packet.sender_id_str
        ));
        return;
    }

    // Check if we have a session that's not established yet
    if noise_session_manager.has_session(&packet.sender_id_str) {
        write_noise_debug_log(&format!(
            "[DEBUG] Session exists but not established for peer: {}",
            packet.sender_id_str
        ));

        // Handle the incoming handshake with existing session
        write_noise_debug_log("[DEBUG] About to handle incoming handshake with existing session");
        match noise_session_manager
            .handle_incoming_handshake(&packet.sender_id_str, &packet.payload)
        {
            Ok(response) => {
                write_noise_debug_log(&format!(
                    "[DEBUG] Handshake response generated, response length: {}",
                    response.as_ref().map(|r| r.len()).unwrap_or(0)
                ));

                if let Some(response_data) = response {
                    // NEW â€“ wrap the Noise payload in a BitchatPacket
                    let response_packet = create_bitchat_packet_with_recipient(
                        my_peer_id,
                        Some(&packet.sender_id_str), // send it **only** to the peer that asked
                        MessageType::NoiseHandshakeResp, // msgType  = 0x11
                        response_data,
                        None, // no signature
                    );

                    write_noise_debug_log("[DEBUG] About to send handshake response");
                    match peripheral
                        .write(cmd_char, &response_packet, WriteType::WithoutResponse)
                        .await
                    {
                        Ok(_) => {
                            write_noise_debug_log("[DEBUG] Successfully sent handshake response");
                            let _ = ui_tx
                                .send(format!(
                                    "[DM] Handshake initiated with {}\n> ",
                                    packet.sender_id_str
                                ))
                                .await;
                        }
                        Err(e) => {
                            write_noise_debug_log(&format!(
                                "[DEBUG] Failed to send handshake response: {:?}",
                                e
                            ));
                            let _ = ui_tx
                                .send(format!("[!] Failed to send handshake response: {}\n> ", e))
                                .await;
                        }
                    }
                } else {
                    write_noise_debug_log("[DEBUG] Handshake completed, no response needed");
                    let _ = ui_tx
                        .send(format!(
                            "[DM] Handshake completed with {}\n> ",
                            packet.sender_id_str
                        ))
                        .await;
                }
            }
            Err(e) => {
                write_noise_debug_log(&format!(
                    "[DEBUG] Failed to handle incoming handshake: {:?}",
                    e
                ));
                let _ = ui_tx.send(format!("[!] Handshake failed: {}\n> ", e)).await;
            }
        }
    } else {
        // No session exists, create a new one
        write_noise_debug_log(&format!(
            "[DEBUG] Creating new session for peer: {}",
            packet.sender_id_str
        ));

        // Create a new session as responder
        match noise_session_manager.create_session(
            packet.sender_id_str.clone(),
            crate::noise_protocol::NoiseRole::Responder,
        ) {
            Ok(session) => {
                write_noise_debug_log(&format!(
                    "[DEBUG] Successfully created session for peer: {}",
                    packet.sender_id_str
                ));

                // Handle the incoming handshake
                write_noise_debug_log("[DEBUG] About to handle incoming handshake");
                match noise_session_manager
                    .handle_incoming_handshake(&packet.sender_id_str, &packet.payload)
                {
                    Ok(response) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Handshake response generated, response length: {}",
                            response.as_ref().map(|r| r.len()).unwrap_or(0)
                        ));

                        if let Some(response_data) = response {
                            // NEW â€“ wrap the Noise payload in a BitchatPacket
                            let response_packet = create_bitchat_packet_with_recipient(
                                my_peer_id,
                                Some(&packet.sender_id_str), // send it **only** to the peer that asked
                                MessageType::NoiseHandshakeResp, // msgType  = 0x11
                                response_data,
                                None, // no signature
                            );

                            write_noise_debug_log("[DEBUG] About to send handshake response");
                            match peripheral
                                .write(cmd_char, &response_packet, WriteType::WithoutResponse)
                                .await
                            {
                                Ok(_) => {
                                    write_noise_debug_log(
                                        "[DEBUG] Successfully sent handshake response",
                                    );
                                    let _ = ui_tx
                                        .send(format!(
                                            "[DM] Handshake initiated with {}\n> ",
                                            packet.sender_id_str
                                        ))
                                        .await;
                                }
                                Err(e) => {
                                    write_noise_debug_log(&format!(
                                        "[DEBUG] Failed to send handshake response: {:?}",
                                        e
                                    ));
                                    let _ = ui_tx
                                        .send(format!(
                                            "[!] Failed to send handshake response: {}\n> ",
                                            e
                                        ))
                                        .await;
                                }
                            }
                        } else {
                            write_noise_debug_log(
                                "[DEBUG] Handshake completed, no response needed",
                            );
                            let _ = ui_tx
                                .send(format!(
                                    "[DM] Handshake completed with {}\n> ",
                                    packet.sender_id_str
                                ))
                                .await;
                        }
                    }
                    Err(e) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to handle incoming handshake: {:?}",
                            e
                        ));
                        let _ = ui_tx.send(format!("[!] Handshake failed: {}\n> ", e)).await;
                    }
                }
            }
            Err(e) => {
                write_noise_debug_log(&format!("[DEBUG] Failed to create session: {:?}", e));
                let _ = ui_tx
                    .send(format!("[!] Failed to create session: {}\n> ", e))
                    .await;
            }
        }
    }

    write_noise_debug_log("[DEBUG] Completed handle_noise_handshake_init");
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
    write_noise_debug_log(&format!(
        "[DEBUG] Starting handle_noise_handshake_resp for peer: {}",
        packet.sender_id_str
    ));

    // Check if we have a session for this peer
    write_noise_debug_log(&format!(
        "[DEBUG] Checking if session exists for peer: {}",
        packet.sender_id_str
    ));
    if !noise_session_manager.has_session(&packet.sender_id_str) {
        write_noise_debug_log(&format!(
            "[DEBUG] No session found for peer: {}",
            packet.sender_id_str
        ));
        return;
    }

    // Note: We no longer check for established sessions here
    // The handle_incoming_handshake function will handle this internally

    write_noise_debug_log("[DEBUG] About to handle incoming handshake response");

    // Handle the incoming handshake response
    match noise_session_manager.handle_incoming_handshake(&packet.sender_id_str, &packet.payload) {
        Ok(response) => {
            write_noise_debug_log(&format!(
                "[DEBUG] Handshake response processed, response length: {}",
                response.as_ref().map(|r| r.len()).unwrap_or(0)
            ));

            if let Some(response_data) = response {
                // NEW â€“ wrap the Noise payload in a BitchatPacket
                let response_packet = create_bitchat_packet_with_recipient(
                    my_peer_id,
                    Some(&packet.sender_id_str), // send it **only** to the peer that asked
                    MessageType::NoiseHandshakeResp, // msgType  = 0x11
                    response_data,
                    None, // no signature
                );

                write_noise_debug_log("[DEBUG] About to send handshake response");
                match peripheral
                    .write(cmd_char, &response_packet, WriteType::WithoutResponse)
                    .await
                {
                    Ok(_) => {
                        write_noise_debug_log("[DEBUG] Successfully sent handshake response");
                        let _ = ui_tx
                            .send(format!(
                                "[DM] Handshake response sent to {}\n> ",
                                packet.sender_id_str
                            ))
                            .await;
                    }
                    Err(e) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to send handshake response: {:?}",
                            e
                        ));
                        let _ = ui_tx
                            .send(format!("[!] Failed to send handshake response: {}\n> ", e))
                            .await;
                    }
                }
            } else {
                write_noise_debug_log("[DEBUG] Handshake completed, no response needed");
                let _ = ui_tx
                    .send(format!(
                        "[DM] Handshake completed with {}\n> ",
                        packet.sender_id_str
                    ))
                    .await;

                // Send any pending messages
                write_noise_debug_log("[DEBUG] About to send pending messages");
                send_pending_messages(
                    noise_session_manager,
                    peripheral,
                    cmd_char,
                    my_peer_id,
                    &packet.sender_id_str,
                    ui_tx,
                )
                .await;
            }
        }
        Err(NoiseError::SessionNotFound) => {
            write_noise_debug_log("[DEBUG] Session not found, creating new session as responder");
            // Create a new session as responder (like Swift does)
            match noise_session_manager.create_session(
                packet.sender_id_str.clone(),
                crate::noise_protocol::NoiseRole::Responder,
            ) {
                Ok(_session) => {
                    write_noise_debug_log("[DEBUG] New session created, retrying handshake");
                    // Retry the handshake with the new session
                    match noise_session_manager
                        .handle_incoming_handshake(&packet.sender_id_str, &packet.payload)
                    {
                        Ok(response) => {
                            write_noise_debug_log(&format!(
                                "[DEBUG] Handshake response processed, response length: {}",
                                response.as_ref().map(|r| r.len()).unwrap_or(0)
                            ));

                            if let Some(response_data) = response {
                                // NEW â€“ wrap the Noise payload in a BitchatPacket
                                let response_packet = create_bitchat_packet_with_recipient(
                                    my_peer_id,
                                    Some(&packet.sender_id_str), // send it **only** to the peer that asked
                                    MessageType::NoiseHandshakeResp, // msgType  = 0x11
                                    response_data,
                                    None, // no signature
                                );

                                write_noise_debug_log("[DEBUG] About to send handshake response");
                                match peripheral
                                    .write(cmd_char, &response_packet, WriteType::WithoutResponse)
                                    .await
                                {
                                    Ok(_) => {
                                        write_noise_debug_log(
                                            "[DEBUG] Successfully sent handshake response",
                                        );
                                        let _ = ui_tx
                                            .send(format!(
                                                "[DM] Handshake response sent to {}\n> ",
                                                packet.sender_id_str
                                            ))
                                            .await;
                                    }
                                    Err(e) => {
                                        write_noise_debug_log(&format!(
                                            "[DEBUG] Failed to send handshake response: {:?}",
                                            e
                                        ));
                                        let _ = ui_tx
                                            .send(format!(
                                                "[!] Failed to send handshake response: {}\n> ",
                                                e
                                            ))
                                            .await;
                                    }
                                }
                            } else {
                                write_noise_debug_log(
                                    "[DEBUG] Handshake completed, no response needed",
                                );
                                let _ = ui_tx
                                    .send(format!(
                                        "[DM] Handshake completed with {}\n> ",
                                        packet.sender_id_str
                                    ))
                                    .await;

                                // Send any pending messages
                                write_noise_debug_log("[DEBUG] About to send pending messages");
                                send_pending_messages(
                                    noise_session_manager,
                                    peripheral,
                                    cmd_char,
                                    my_peer_id,
                                    &packet.sender_id_str,
                                    ui_tx,
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            write_noise_debug_log(&format!("[DEBUG] Failed to handle incoming handshake response after session creation: {:?}", e));
                            let _ = ui_tx
                                .send(format!(
                                    "[!] Handshake response failed after session creation: {}\n> ",
                                    e
                                ))
                                .await;
                        }
                    }
                }
                Err(e) => {
                    write_noise_debug_log(&format!(
                        "[DEBUG] Failed to create new session: {:?}",
                        e
                    ));
                    let _ = ui_tx
                        .send(format!("[!] Failed to create new session: {:?}\n> ", e))
                        .await;
                }
            }
        }
        Err(e) => {
            write_noise_debug_log(&format!(
                "[DEBUG] Failed to handle incoming handshake response: {:?}",
                e
            ));
            let _ = ui_tx
                .send(format!("[!] Handshake response failed: {}\n> ", e))
                .await;
        }
    }

    write_noise_debug_log("[DEBUG] Completed handle_noise_handshake_resp");
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
    write_noise_debug_log(&format!(
        "[DEBUG] Starting send_pending_messages for peer: {}",
        target_peer_id
    ));

    let pending_messages = noise_session_manager.get_pending_messages(target_peer_id);
    write_noise_debug_log(&format!(
        "[DEBUG] Found {} pending messages for peer: {}",
        pending_messages.len(),
        target_peer_id
    ));

    if !pending_messages.is_empty() {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[NOISE] Sending {} pending messages to {}\n",
                    pending_messages.len(),
                    target_peer_id
                ))
                .await;
        }

        for (i, message_content) in pending_messages.iter().enumerate() {
            write_noise_debug_log(&format!(
                "[DEBUG] Processing pending message {}: '{}'",
                i, message_content
            ));

            match noise_session_manager.encrypt_message(target_peer_id, message_content.as_bytes())
            {
                Ok(encrypted) => {
                    write_noise_debug_log(&format!(
                        "[DEBUG] Successfully encrypted pending message {}, length: {}",
                        i,
                        encrypted.len()
                    ));

                    // Create Noise encrypted message packet
                    let packet =
                        crate::packet_creation::create_bitchat_packet_with_recipient_and_signature(
                            my_peer_id,
                            target_peer_id,
                            crate::data_structures::MessageType::NoiseEncrypted,
                            encrypted,
                            None,
                        );

                    write_noise_debug_log(&format!(
                        "[DEBUG] Created NoiseEncrypted packet, length: {}",
                        packet.len()
                    ));

                    if crate::fragmentation::send_packet_with_fragmentation(
                        peripheral, cmd_char, packet, my_peer_id,
                    )
                    .await
                    .is_err()
                    {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to send pending message {} via fragmentation",
                            i
                        ));
                        let _ = ui_tx
                            .send(format!(
                                "[!] Failed to send pending message to {}\n",
                                target_peer_id
                            ))
                            .await;
                    } else {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Successfully sent pending message {} via fragmentation",
                            i
                        ));
                    }
                }
                Err(e) => {
                    write_noise_debug_log(&format!(
                        "[DEBUG] Failed to encrypt pending message {}: {:?}",
                        i, e
                    ));
                    let _ = ui_tx
                        .send(format!("[!] Failed to encrypt pending message: {:?}\n", e))
                        .await;
                }
            }
        }
    } else {
        write_noise_debug_log(&format!(
            "[DEBUG] No pending messages for peer: {}",
            target_peer_id
        ));
    }

    write_noise_debug_log(&format!(
        "[DEBUG] Completed send_pending_messages for peer: {}",
        target_peer_id
    ));
}

// Handler for Noise encrypted messages
pub async fn handle_noise_encrypted_message(
    packet: &BitchatPacket,
    noise_manager: &mut NoiseSessionManager,
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
    write_noise_debug_log(&format!("[DEBUG] Starting handle_noise_encrypted_message for peer: {}", packet.sender_id_str));
    write_noise_debug_log(&format!("[DEBUG] Packet payload length: {}", packet.payload.len()));
    write_noise_debug_log(&format!("[DEBUG] Packet first 16 bytes: {:?}", &packet.payload[..std::cmp::min(16, packet.payload.len())]));

    // Check if we have an established session
    if !noise_manager.is_session_ready(&packet.sender_id_str) {
        write_noise_debug_log(&format!("[DEBUG] No established session for peer: {}", packet.sender_id_str));
        return;
    }

    write_noise_debug_log(&format!("[DEBUG] Checking if session is established for peer: {}", packet.sender_id_str));
    write_noise_debug_log(&format!("[DEBUG] Session is established, about to decrypt message, payload length: {}", packet.payload.len()));

    // Decrypt the message using Noise
    match noise_manager.decrypt_message(&packet.sender_id_str, &packet.payload) {
        Ok(decrypted_data) => {
            write_noise_debug_log(&format!("[DEBUG] Successfully decrypted message, length: {}", decrypted_data.len()));
            
            // FIXED: Parse the decrypted data as a BitchatPacket
            write_noise_debug_log("[DEBUG] About to parse decrypted message as BitchatPacket");
            match crate::packet_parser::parse_bitchat_packet(&decrypted_data) {
                Ok(inner_packet) => {
                    write_noise_debug_log(&format!("[DEBUG] Successfully parsed inner packet: {:?}", inner_packet.msg_type));
                    
                    // FIXED: Process the inner packet based on its type
                    match inner_packet.msg_type {
                        crate::data_structures::MessageType::Message => {
                            // FIXED: Parse the inner packet's payload as a BitchatMessage
                            write_noise_debug_log("[DEBUG] About to parse inner message payload");
                            match crate::payload_handling::parse_bitchat_message_payload(&inner_packet.payload) {
                                Ok(message) => {
                                    write_noise_debug_log(&format!("[DEBUG] Successfully parsed inner message: sender={}, content={}", message.sender, message.content));
                                    
                                    // Process the message normally (same logic as regular message handling)
                                    handle_decrypted_message(
                                        &inner_packet,
                                        &message,
                                        peers_lock,
                                        bloom,
                                        discovered_channels,
                                        password_protected_channels,
                                        channel_keys,
                                        chat_context,
                                        delivery_tracker,
                                        encryption_service,
                                        peripheral,
                                        cmd_char,
                                        nickname,
                                        my_peer_id,
                                        blocked_peers,
                                        ui_tx.clone(),
                                    ).await;
                                },
                                Err(e) => {
                                    write_noise_debug_log(&format!("[DEBUG] Failed to parse inner message payload: {:?}", e));
                                }
                            }
                        },
                        _ => {
                            write_noise_debug_log(&format!("[DEBUG] Unexpected inner packet type: {:?}", inner_packet.msg_type));
                        }
                    }
                },
                Err(e) => {
                    write_noise_debug_log(&format!("[DEBUG] Failed to parse decrypted data as BitchatPacket: {:?}", e));
                }
            }
        },
        Err(e) => {
            write_noise_debug_log(&format!("[DEBUG] Failed to decrypt message: {:?}", e));
        }
    }
    
    write_noise_debug_log("[DEBUG] Completed handle_noise_encrypted_message");
}

// FIXED: Add helper function to process decrypted messages
async fn handle_decrypted_message(
    inner_packet: &BitchatPacket,
    message: &BitchatMessage,
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
    if !bloom.check(&message.id) {
        bloom.set(&message.id);

        // Add the sender to peers list if not already there
        if !peers_lock.contains_key(&inner_packet.sender_id_str) {
            let peer_entry = peers_lock.entry(inner_packet.sender_id_str.clone()).or_default();
            peer_entry.nickname = Some(message.sender.clone());
            let _ = ui_tx.send(format!("{} connected\n", message.sender)).await;
        }

        // Handle channel discovery
        if let Some(channel) = &message.channel {
            discovered_channels.insert(channel.clone());
            if message.is_encrypted {
                password_protected_channels.insert(channel.clone());
            }
        }

        // Display the message
        let display_content = if message.is_encrypted {
            if let Some(channel) = &message.channel {
                channel_keys.get(channel).map_or_else(
                    || "[Encrypted message - join channel with password]".to_string(),
                    |key| {
                        message.encrypted_content.as_ref().map_or_else(
                            || "[Encrypted message - no encrypted data]".to_string(),
                            |bytes| {
                                encryption_service.decrypt_with_key(bytes, key).map_or_else(
                                    |_| "[Encrypted message - decryption failed]".to_string(),
                                    |dec| String::from_utf8_lossy(&dec).to_string(),
                                )
                            },
                        )
                    },
                )
            } else {
                message.content.clone()
            }
        } else {
            message.content.clone()
        };

        let timestamp = chrono::Local::now();
        
        // This is a private message since it was Noise-encrypted
        chat_context.last_private_sender = Some((inner_packet.sender_id_str.clone(), message.sender.clone()));
        chat_context.add_dm(&message.sender, &inner_packet.sender_id_str);

        // Send structured message for TUI
        let structured_msg = format!(
            "__DM__:{}:{}:{}",
            message.sender,
            timestamp.format("%H%M"),
            display_content
        );
        let _ = ui_tx.send(structured_msg).await;
    }
}

// FIXED: Add NoiseIdentityAnnounce handler
pub async fn handle_noise_identity_announce(
    packet: &BitchatPacket,
    peers_lock: &mut HashMap<String, Peer>,
    noise_manager: &mut NoiseSessionManager,
    ui_tx: mpsc::Sender<String>,
) {
    write_noise_debug_log(&format!("[DEBUG] Starting handle_noise_identity_announce for peer: {}", packet.sender_id_str));
    
    // Parse the identity announce payload
    if packet.payload.len() >= 72 { // 32 bytes static key + 32 bytes identity hash + 8 bytes nickname length prefix
        let static_key_bytes = &packet.payload[0..32];
        let identity_hash = &packet.payload[32..64];
        let nickname_data = &packet.payload[64..];
        
        if let Ok(nickname) = String::from_utf8(nickname_data.to_vec()) {
            let nickname = nickname.trim_end_matches('\0'); // Remove null padding
            
            write_noise_debug_log(&format!("[DEBUG] Parsed identity announce - nickname: {}, static key: {:?}", nickname, &static_key_bytes[..8]));
            
            // Update peer info
            let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();
            peer_entry.nickname = Some(nickname.to_string());
            
            // Store the static key for potential future handshakes
            if let Err(e) = noise_manager.store_peer_static_key(&packet.sender_id_str, static_key_bytes) {
                write_noise_debug_log(&format!("[DEBUG] Failed to store peer static key: {:?}", e));
            } else {
                write_noise_debug_log(&format!("[DEBUG] Stored static key for peer: {}", packet.sender_id_str));
            }
            
            let _ = ui_tx.send(format!("[IDENTITY] Peer {} announced identity with nickname: {}\n", packet.sender_id_str, nickname)).await;
        } else {
            write_noise_debug_log(&format!("[DEBUG] Failed to parse nickname from identity announce payload"));
        }
    } else {
        write_noise_debug_log(&format!("[DEBUG] Identity announce payload too short: {} bytes", packet.payload.len()));
    }
    
    write_noise_debug_log("[DEBUG] Completed handle_noise_identity_announce");
}

/// Send a handshake request to a target peer (matches Swift sendHandshakeRequest)
pub async fn send_handshake_request(
    target_peer_id: &str,
    pending_count: u8,
    my_peer_id: &str,
    my_nickname: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
) {
    write_noise_debug_log(&format!(
        "[DEBUG] Sending handshake request to {} with {} pending messages",
        target_peer_id, pending_count
    ));

    // Create handshake request (matches Swift HandshakeRequest constructor)
    let request = crate::data_structures::HandshakeRequest::new(
        my_peer_id.to_string(),
        my_nickname.to_string(),
        target_peer_id.to_string(),
        pending_count,
    );

    let request_data = request.to_binary_data();
    write_noise_debug_log(&format!(
        "[DEBUG] Handshake request data length: {}",
        request_data.len()
    ));

    // Create packet for handshake request (matches Swift BitchatPacket constructor)
    let packet_data = create_bitchat_packet_with_recipient(
        my_peer_id,
        Some(target_peer_id),
        MessageType::HandshakeRequest,
        request_data,
        None, // No signature
    );

    // Send the packet
    match peripheral
        .write(cmd_char, &packet_data, WriteType::WithoutResponse)
        .await
    {
        Ok(_) => {
            write_noise_debug_log(&format!(
                "[DEBUG] Handshake request sent successfully to {}",
                target_peer_id
            ));
            let _ = ui_tx
                .send(format!(
                    "[DEBUG] Sent handshake request to {}\n",
                    target_peer_id
                ))
                .await;
        }
        Err(e) => {
            write_noise_debug_log(&format!(
                "[DEBUG] Failed to send handshake request: {:?}",
                e
            ));
            let _ = ui_tx
                .send(format!(
                    "[ERROR] Failed to send handshake request: {:?}\n",
                    e
                ))
                .await;
        }
    }
}

pub async fn handle_handshake_request_message(
    packet: &BitchatPacket,
    noise_session_manager: &mut NoiseSessionManager,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) {
    write_noise_debug_log(&format!(
        "[DEBUG] Starting handle_handshake_request_message from peer: {}",
        packet.sender_id_str
    ));

    // Parse the HandshakeRequest from the payload
    write_noise_debug_log(&format!(
        "[DEBUG] Parsing handshake request payload, length: {}",
        packet.payload.len()
    ));
    match crate::data_structures::HandshakeRequest::from_binary_data(&packet.payload) {
        Some(request) => {
            write_noise_debug_log(&format!("[DEBUG] Parsed handshake request - requester: {}, target: {}, pending messages: {}", 
                request.requester_id, request.target_id, request.pending_message_count));

            // Verify this request is for us (like Swift does)
            // First try exact match
            if request.target_id == my_peer_id {
                write_noise_debug_log(&format!(
                    "[DEBUG] Handshake request target matches exactly: {}",
                    request.target_id
                ));
            } else if request.target_id.len() >= 8
                && my_peer_id.len() >= 8
                && request.target_id[..8] == my_peer_id[..8]
            {
                // Check if first 8 characters match (for padded peer IDs)
                write_noise_debug_log(&format!(
                    "[DEBUG] Handshake request target matches first 8 chars: {} vs {}",
                    &request.target_id[..8],
                    &my_peer_id[..8]
                ));
            } else {
                write_noise_debug_log(&format!(
                    "[DEBUG] Handshake request is not for us (target: {}, we are: {}), ignoring",
                    request.target_id, my_peer_id
                ));
                return;
            }

            write_noise_debug_log(&format!(
                "[DEBUG] Handshake request is for us, processing..."
            ));

            // Check if we have an established session with the requester
            if noise_session_manager.has_established_session(&request.requester_id) {
                write_noise_debug_log(&format!(
                    "[DEBUG] Session already established with requester: {}",
                    request.requester_id
                ));
                return;
            }

            // Check if we have a session in progress
            if noise_session_manager.has_session(&request.requester_id) {
                write_noise_debug_log(&format!(
                    "[DEBUG] Session in progress with requester: {}",
                    request.requester_id
                ));
                return;
            }

            // Apply tie-breaker logic for handshake initiation (like Swift does)
            if my_peer_id < request.requester_id.as_str() {
                // We have lower ID, initiate handshake
                write_noise_debug_log(&format!(
                    "[DEBUG] We have lower ID, initiating handshake with requester: {}",
                    request.requester_id
                ));

                // Create a new session as initiator
                match noise_session_manager.create_session(
                    request.requester_id.clone(),
                    crate::noise_protocol::NoiseRole::Initiator,
                ) {
                    Ok(_session) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Session created successfully for requester: {}",
                            request.requester_id
                        ));

                        // Initiate handshake
                        match noise_session_manager.initiate_handshake(&request.requester_id) {
                            Ok(handshake_data) => {
                                write_noise_debug_log(&format!(
                                    "[DEBUG] Handshake initiated, data length: {}",
                                    handshake_data.len()
                                ));

                                // Create and send handshake init packet
                                let handshake_packet = create_bitchat_packet_with_recipient(
                                    my_peer_id,
                                    Some(&request.requester_id), // <- explicit recipient
                                    MessageType::NoiseHandshakeInit, // msgType 0x10
                                    handshake_data,
                                    None,
                                );
                                match peripheral
                                    .write(cmd_char, &handshake_packet, WriteType::WithoutResponse)
                                    .await
                                {
                                    Ok(_) => {
                                        write_noise_debug_log(
                                            "[DEBUG] Handshake init sent successfully",
                                        );
                                        let _ = ui_tx
                                            .send(format!(
                                                "[DEBUG] Sent handshake init to {}\n",
                                                request.requester_id
                                            ))
                                            .await;
                                    }
                                    Err(e) => {
                                        write_noise_debug_log(&format!(
                                            "[DEBUG] Failed to send handshake init: {:?}",
                                            e
                                        ));
                                        let _ = ui_tx
                                            .send(format!(
                                                "[ERROR] Failed to send handshake init: {:?}\n",
                                                e
                                            ))
                                            .await;
                                    }
                                }
                            }
                            Err(e) => {
                                write_noise_debug_log(&format!(
                                    "[DEBUG] Failed to initiate handshake: {:?}",
                                    e
                                ));
                                let _ = ui_tx
                                    .send(format!(
                                        "[ERROR] Failed to initiate handshake: {:?}\n",
                                        e
                                    ))
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to create session: {:?}",
                            e
                        ));
                        let _ = ui_tx
                            .send(format!("[ERROR] Failed to create session: {:?}\n", e))
                            .await;
                    }
                }
            } else {
                // We have higher ID, send identity announce to prompt them (like Swift does)
                write_noise_debug_log(&format!(
                    "[DEBUG] We have higher ID, sending identity announce to requester: {}",
                    request.requester_id
                ));
                // TODO: Implement sendNoiseIdentityAnnounce equivalent
                let _ = ui_tx
                    .send(format!(
                        "[DEBUG] Would send identity announce to {}\n",
                        request.requester_id
                    ))
                    .await;
            }
        }
        None => {
            write_noise_debug_log("[DEBUG] Failed to parse handshake request payload");
            let _ = ui_tx
                .send("[ERROR] Failed to parse handshake request payload\n".to_string())
                .await;
        }
    }
}

pub fn process_notification(
    packet: &BitchatPacket,
    noise_session_manager: &mut Option<NoiseSessionManager>,
    chat_context: &mut Option<ChatContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    write_noise_debug_log(&format!(
        "[DEBUG] Starting process_notification for packet type: {:?}",
        packet.msg_type
    ));

    let noise_manager = match noise_session_manager {
        Some(manager) => manager,
        None => {
            write_noise_debug_log("[DEBUG] No noise session manager available");
            return Ok(());
        }
    };

    match packet.msg_type {
        MessageType::NoiseHandshakeInit => {
            write_noise_debug_log("[DEBUG] Handling NoiseHandshakeInit");
            // This would need to be handled asynchronously, but for now just log
            write_noise_debug_log("[DEBUG] NoiseHandshakeInit would be handled here");
            Ok(())
        }
        MessageType::NoiseHandshakeResp => {
            write_noise_debug_log("[DEBUG] Handling NoiseHandshakeResp");
            // This would need to be handled asynchronously, but for now just log
            write_noise_debug_log("[DEBUG] NoiseHandshakeResp would be handled here");
            Ok(())
        }
        MessageType::NoiseEncrypted => {
            write_noise_debug_log("[DEBUG] Handling NoiseEncrypted");
            // This would need to be handled asynchronously, but for now just log
            write_noise_debug_log("[DEBUG] NoiseEncrypted would be handled here");
            Ok(())
        }
        MessageType::ProtocolAck => {
            write_noise_debug_log("[DEBUG] Handling ProtocolAck");
            // This would need to be handled asynchronously, but for now just log
            write_noise_debug_log("[DEBUG] ProtocolAck would be handled here");
            Ok(())
        }
        MessageType::ProtocolNack => {
            write_noise_debug_log("[DEBUG] Handling ProtocolNack");
            // This would need to be handled asynchronously, but for now just log
            write_noise_debug_log("[DEBUG] ProtocolNack would be handled here");
            Ok(())
        }
        _ => {
            write_noise_debug_log(&format!(
                "[DEBUG] Ignoring non-Noise packet type: {:?}",
                packet.msg_type
            ));
            Ok(())
        }
    }
}
