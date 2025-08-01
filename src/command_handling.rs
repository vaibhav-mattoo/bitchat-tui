use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use btleplug::api::{WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use tokio::sync::mpsc;
use sha2::{Sha256, Digest};
use chrono;
use crate::data_structures::{MessageType, Peer, DeliveryTracker, DebugLevel, DEBUG_LEVEL};
use crate::terminal_ux::{ChatContext, ChatMode};
use crate::persistence::{AppState, save_state, encrypt_password, EncryptedPassword};
use crate::encryption::EncryptionService;
use crate::packet_creation::{create_bitchat_packet, create_bitchat_packet_with_recipient_and_signature};
use crate::packet_delivery::send_channel_announce;
use crate::payload_handling::create_bitchat_message_payload_full;
use crate::fragmentation::send_packet_with_fragmentation;
use crate::noise_session::NoiseSessionManager;





pub async fn handle_name_command(
    line: &str,
    nickname: &mut String,
    _my_peer_id: &str,
    _peripheral: &Peripheral,
    _cmd_char: &btleplug::api::Characteristic,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line.starts_with("/name ") {
        let new_name = line.trim_start_matches("/name ").trim();
        if new_name.is_empty() {
            let _ = ui_tx.send("\x1b[93m⚠ Usage: /name <new_nickname>\x1b[0m\n\x1b[90mExample: /name Alice\x1b[0m\n".to_string()).await;
        } else if new_name.len() > 20 {
            let _ = ui_tx.send("\x1b[93m⚠ Nickname too long\x1b[0m\n\x1b[90mMaximum 20 characters allowed.\x1b[0m\n".to_string()).await;
        } else if new_name.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
            let _ = ui_tx.send("\x1b[93m⚠ Invalid nickname\x1b[0m\n\x1b[90mNicknames can only contain letters, numbers, hyphens and underscores.\x1b[0m\n".to_string()).await;
        } else if new_name == "system" || new_name == "all" {
            let _ = ui_tx.send("\x1b[93m⚠ Reserved nickname\x1b[0m\n\x1b[90mThis nickname is reserved and cannot be used.\x1b[0m\n".to_string()).await;
        } else {
            *nickname = new_name.to_string();
            // Don't send announcement or message here - let the main loop handle everything via the pending_nickname_update signal
            let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
            let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, nickname);
            if let Err(e) = save_state(&state_to_save) {
                let _ = ui_tx.send(format!("Warning: Could not save nickname: {}\n", e)).await;
            }
        }
        return true;
    }
    false
}




pub async fn handle_join_command(
    line: &str,
    password_protected_channels: &HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    discovered_channels: &mut HashSet<String>,
    chat_context: &mut ChatContext,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &mut AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    _peripheral: &Peripheral,
    _cmd_char: &btleplug::api::Characteristic,
    channel_creators: &HashMap<String, String>,
    blocked_peers: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line.starts_with("/j ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut channel_name = parts.get(1).unwrap_or(&"").to_string();

        if channel_name.is_empty() {
            let _ = ui_tx.send("\x1b[93m⚠ Usage: /j <channel> [password]\x1b[0m\n".to_string()).await;
            return true;
        }
        // If channel name does not start with #, add it automatically
        if !channel_name.starts_with('#') {
            channel_name = format!("#{}", channel_name);
        }
        
        if password_protected_channels.contains(&channel_name) && !channel_keys.contains_key(&channel_name) {
             if let Some(password) = parts.get(2) {
                let key = EncryptionService::derive_channel_key(password, &channel_name);
                if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                    let test_commitment = hex::encode(sha2::Sha256::digest(&key));
                    if &test_commitment != expected_commitment {
                        let _ = ui_tx.send(format!("❌ Wrong password for channel {}.\n", channel_name)).await;
                        return true;
                    }
                }
                channel_keys.insert(channel_name.clone(), key);
                if let Some(identity_key) = &app_state.identity_key {
                    if let Ok(encrypted) = encrypt_password(password, identity_key) {
                        app_state.encrypted_channel_passwords.insert(channel_name.clone(), encrypted);
                        // FIX: Convert HashSet to Vec before saving state
                        let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
                        let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, nickname);
                        if let Err(e) = save_state(&state_to_save) {
                            let _ = ui_tx.send(format!("Warning: Could not save state: {}\n", e)).await;
                        }
                    }
                }
                chat_context.switch_to_channel_silent(&channel_name);
                let _ = ui_tx.send(format!("\x1b[90m» Joined password-protected channel: {} 🔒\n", channel_name)).await;
             } else {
                 let _ = ui_tx.send(format!("❌ Channel {} is password-protected. Use: /j {} <password>\n", channel_name, channel_name)).await;
                 return true;
             }
        } else if password_protected_channels.contains(&channel_name) && channel_keys.contains_key(&channel_name) {
            // User is already in a password-protected channel but we need to verify the password is correct
            if let Some(password) = parts.get(2) {
                let key = EncryptionService::derive_channel_key(password, &channel_name);
                if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                    let test_commitment = hex::encode(sha2::Sha256::digest(&key));
                    if &test_commitment != expected_commitment {
                        // User has wrong password - warn them
                        let warning_msg = format!("⚠️  WARNING: You entered channel {} with the wrong password. Your messages are encrypted and others cannot see them. Leave the channel with /leave and rejoin with the correct password.", channel_name);
                        let _ = ui_tx.send(format!("{}\n", warning_msg)).await;
                        
                        // Add system message to TUI
                        let system_msg = format!("Wrong password detected for channel {}. Messages are encrypted and others cannot see them. Use /leave and rejoin with correct password.", channel_name);
                        app.add_log_message(format!("system: {}", system_msg));
                        
                        return true;
                    }
                }
            }
            chat_context.switch_to_channel(&channel_name);
            let _ = ui_tx.send(format!("\x1b[90m» Switched to channel {}\x1b[0m\n", channel_name)).await;
        } else {
            chat_context.switch_to_channel(&channel_name);
            let _ = ui_tx.send(format!("\x1b[90m» Switched to channel {}\x1b[0m\n", channel_name)).await;
        }
        discovered_channels.insert(channel_name.clone());
        
        return true;
    }
    false
}

pub async fn handle_exit_command(
    line: &str,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line == "/exit" {
        let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
        let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, nickname);
        if let Err(e) = save_state(&state_to_save) {
            let _ = ui_tx.send(format!("Warning: Could not save state: {}\n", e)).await;
        }
        // Set the quit flag to exit the application
        app.should_quit = true;
        return true;
    }
    false
}

pub async fn handle_reply_command(line: &str, chat_context: &mut ChatContext, ui_tx: mpsc::Sender<String>) -> bool {
    if line == "/reply" {
        if let Some((peer_id, nickname)) = chat_context.last_private_sender.clone() {
            chat_context.enter_dm_mode(&nickname, &peer_id);
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("{}\n", chat_context.get_status_line())).await;
            }
        } else {
            let _ = ui_tx.send("» No private messages received yet.\n".to_string()).await;
        }
        return true;
    }
    false
}

pub async fn handle_public_command(line: &str, chat_context: &mut ChatContext, ui_tx: mpsc::Sender<String>) -> bool {
    if line == "/public" {
        chat_context.switch_to_public();
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx.send(format!("{}\n", chat_context.get_status_line())).await;
        }
        return true;
    }
    false
}

pub async fn handle_online_command(line: &str, peers: &Arc<Mutex<HashMap<String, Peer>>>, ui_tx: mpsc::Sender<String>) -> bool {
    if line == "/online" || line == "/w" {
        let peers_lock = peers.lock().await;
        if peers_lock.is_empty() {
            let _ = ui_tx.send("» No one else is online right now.\n".to_string()).await;
        } else {
            let mut online_list: Vec<String> = peers_lock.iter().filter_map(|(_, peer)| peer.nickname.clone()).collect();
            online_list.sort();
            let _ = ui_tx.send(format!("» Online users: {}\n", online_list.join(", "))).await;
        }
        return true;
    }
    false
}

pub async fn handle_channels_command(
    line: &str,
    chat_context: &ChatContext,
    channel_keys: &HashMap<String, [u8; 32]>,
    password_protected_channels: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/channels" {
        let mut all_channels: HashSet<String> = chat_context.active_channels.iter().cloned().collect();
        all_channels.extend(channel_keys.keys().cloned());
        
        if all_channels.is_empty() {
            let _ = ui_tx.send("» No channels discovered yet. Channels appear as people use them.\n".to_string()).await;
        } else {
            let mut channel_list: Vec<String> = all_channels.into_iter().collect();
            channel_list.sort();
            
            let mut output = "» Discovered channels:\n".to_string();
            for channel in channel_list {
                let mut status = String::new();
                if chat_context.active_channels.contains(&channel) { status.push_str(" ✓"); }
                if password_protected_channels.contains(&channel) {
                    status.push_str(" 🔒");
                    if channel_keys.contains_key(&channel) { status.push_str(" 🔑"); }
                }
                output.push_str(&format!("  {}{}\n", channel, status));
            }
            output.push_str("\n✓ = joined, 🔒 = password protected, 🔑 = authenticated\n");
            let _ = ui_tx.send(output).await;
        }
        return true;
    }
    false
}

pub async fn handle_dm_command(
    line: &str,
    chat_context: &mut ChatContext,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    nickname: &str,
    my_peer_id: &str,
    delivery_tracker: &mut DeliveryTracker,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
    _noise_session_manager: &mut NoiseSessionManager,
) -> bool {
    if line.starts_with("/dm ") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        
        // Check if it's just "/dm nickname" (enter DM mode) or "/dm nickname message" (quick send)
        if parts.len() < 2 {
            let _ = ui_tx.send("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m\n".to_string()).await;
            let _ = ui_tx.send("\x1b[90mExample: /dm Bob Hey there!\x1b[0m\n".to_string()).await;
            return true;
        }
        
        let target_nickname = parts[1];
        
        // Find peer ID for nickname
        let peer_id = {
            peers.lock().await.iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(target_nickname))
                .map(|(id, _)| id.clone())
        };
        
        if let Some(target_peer_id) = peer_id {
            // If no message provided, enter DM mode
            if parts.len() == 2 {
                chat_context.enter_dm_mode(target_nickname, &target_peer_id);
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send(format!("{}\n", chat_context.get_status_line())).await;
                }
                return true;
            }
            
            // Otherwise send the message directly
            let private_message = parts[2];
            // Create private message
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx.send(format!("[PRIVATE] Sending encrypted message to {}\n", target_nickname)).await;
            }
            
            // Create message payload with private flag
            let (message_payload, message_id) = create_bitchat_message_payload_full(nickname, private_message, None, true, my_peer_id);
            
            // Track private message for delivery confirmation
            delivery_tracker.track_message(message_id.clone(), private_message.to_string(), true);
            
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
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send(format!("[PRIVATE] Added {} bytes of PKCS#7 padding\n", padding_needed)).await;
                }
            } else if padding_needed == 0 {
                // If already at block size, don't add more padding - Android doesn't do this
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send("[PRIVATE] Message already at block size, no padding needed\n".to_string()).await;
                }
            }
            
            // Try Noise encryption first (preferred for established sessions)
            let encrypted = if _noise_session_manager.is_session_ready(&target_peer_id) {
                match _noise_session_manager.encrypt_message(&target_peer_id, &padded_payload) {
                    Ok(encrypted) => {
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[PRIVATE] Encrypted with Noise transport cipher: {} bytes\n", encrypted.len())).await;
                        }
                        encrypted
                    }
                    Err(e) => {
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[PRIVATE] Noise encryption failed: {:?}, falling back to legacy\n", e)).await;
                        }
                        // Fallback to legacy encryption
                        match encryption_service.encrypt(&padded_payload, &target_peer_id) {
                            Ok(encrypted) => {
                                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                                    let _ = ui_tx.send(format!("[PRIVATE] Encrypted with legacy method: {} bytes\n", encrypted.len())).await;
                                }
                                encrypted
                            }
                            Err(e) => {
                                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                                    let _ = ui_tx.send(format!("[PRIVATE] All encryption methods failed: {:?}\n", e)).await;
                                }
                                return true;
                            }
                        }
                    }
                }
            } else {
                // Use legacy encryption if no Noise session
                match encryption_service.encrypt(&padded_payload, &target_peer_id) {
                    Ok(encrypted) => {
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[PRIVATE] Encrypted with legacy method: {} bytes\n", encrypted.len())).await;
                        }
                        encrypted
                    }
                    Err(e) => {
                        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                            let _ = ui_tx.send(format!("[PRIVATE] Legacy encryption failed: {:?}\n", e)).await;
                        }
                        return true;
                    }
                }
            };
            
            // Sign the encrypted payload
            let signature = encryption_service.sign(&encrypted);
            
            // Create packet with recipient ID for private routing
            let packet = create_bitchat_packet_with_recipient_and_signature(
                my_peer_id,
                &target_peer_id,  // Specify the recipient
                MessageType::Message,
                encrypted,
                Some(signature)
            );
            
            // Send the private message
            if let Err(_e) = send_packet_with_fragmentation(peripheral, cmd_char, packet, my_peer_id).await {
                let _ = ui_tx.send("\n\x1b[91m❌ Failed to send private message\x1b[0m\n".to_string()).await;
                let _ = ui_tx.send("\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m\n".to_string()).await;
            } else {
                // Add the message to the TUI's DM conversation
                app.add_dm_message(target_nickname.to_string(), private_message.to_string());
                
                // Add a system message to the current conversation to confirm the DM was sent
                let timestamp = chrono::Local::now();
                let system_msg = format!("[{}|DM] <you → {}> {}", timestamp.format("%H:%M"), target_nickname, private_message);
                app.add_log_message(format!("system: {}", system_msg));
                
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx.send(format!("[PRIVATE] Message sent to {}\n", target_nickname)).await;
                }
            }
            return true;
        } else {
            let _ = ui_tx.send(format!("\x1b[93m⚠ User '{}' not found\x1b[0m\n", target_nickname)).await;
            let _ = ui_tx.send("\x1b[90mThey may be offline or using a different nickname.\x1b[0m\n".to_string()).await;
            return true;
        }
    }
    false
}

pub async fn handle_block_command(
    line: &str,
    blocked_peers: &mut HashSet<String>,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    encryption_service: &EncryptionService,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line.starts_with("/block") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        // Handle /block without arguments - show list of blocked users
        if parts.len() == 1 {
            let blocked_nicknames: Vec<String> = peers.lock().await.iter()
                .filter_map(|(peer_id, peer)| {
                    if let Some(fp) = encryption_service.get_peer_fingerprint(peer_id) {
                        if blocked_peers.contains(&fp) {
                            peer.nickname.clone()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
            
            if blocked_nicknames.is_empty() {
                let _ = ui_tx.send("system: No users are currently blocked.".to_string()).await;
            } else {
                let blocked_list = blocked_nicknames.join(", ");
                let _ = ui_tx.send(format!("system: Blocked users: {}", blocked_list)).await;
            }
            return true;
        }
        
        // Handle /block with username argument
        if parts.len() == 2 {
            let target_name = parts[1].trim_start_matches('@');
            let peer_id_to_block = peers.lock().await.iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(target_name))
                .map(|(id, _)| id.clone());

            if let Some(peer_id) = peer_id_to_block {
                if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&peer_id) {
                    blocked_peers.insert(fingerprint);
                    let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
                    let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, nickname);
                    if let Err(e) = save_state(&state_to_save) {
                        let _ = ui_tx.send(format!("Warning: Could not save state: {}\n", e)).await;
                    }
                    
                    // Update TUI blocked list
                    let blocked_nicknames: Vec<String> = peers.lock().await.iter()
                        .filter_map(|(peer_id, peer)| {
                            if let Some(fp) = encryption_service.get_peer_fingerprint(peer_id) {
                                if blocked_peers.contains(&fp) {
                                    peer.nickname.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect();
                    app.update_blocked_list(blocked_nicknames);
                    
                    let _ = ui_tx.send(format!("\n\x1b[92m✓ Blocked {}\x1b[0m\n", target_name)).await;
                }
            } else {
                let _ = ui_tx.send(format!("\x1b[93m⚠ User '{}' not found\x1b[0m\n", target_name)).await;
            }
        }
        return true;
    }
    false
}

pub async fn handle_unblock_command(
    line: &str,
    blocked_peers: &mut HashSet<String>,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    encryption_service: &EncryptionService,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line.starts_with("/unblock ") {
        // If there are no blocked users, show a system message
        if blocked_peers.is_empty() {
            app.add_log_message("system: No users are currently blocked.".to_string());
            return true;
        }
        let target_name = line.trim_start_matches("/unblock ").trim().trim_start_matches('@');
        let peer_id_to_unblock = peers.lock().await.iter()
            .find(|(_, peer)| peer.nickname.as_deref() == Some(target_name))
            .map(|(id, _)| id.clone());

        if let Some(peer_id) = peer_id_to_unblock {
            if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&peer_id) {
                if blocked_peers.remove(&fingerprint) {
                    let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
                    let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, nickname);
                     if let Err(e) = save_state(&state_to_save) {
                        let _ = ui_tx.send(format!("Warning: Could not save state: {}\n", e)).await;
                     }
                     // Update TUI blocked list
                     let blocked_nicknames: Vec<String> = peers.lock().await.iter()
                         .filter_map(|(peer_id, peer)| {
                             if let Some(fp) = encryption_service.get_peer_fingerprint(peer_id) {
                                 if blocked_peers.contains(&fp) {
                                     peer.nickname.clone()
                                 } else {
                                     None
                                 }
                             } else {
                                 None
                             }
                         })
                         .collect();
                     app.update_blocked_list(blocked_nicknames);
                     let _ = ui_tx.send(format!("\n\x1b[92m✓ Unblocked {}\x1b[0m\n", target_name)).await;
                } else {
                    // User exists but is not blocked
                    app.add_log_message(format!("system: User '{}' is not blocked.", target_name));
                }
            } else {
                // User exists but has no fingerprint (shouldn't happen)
                app.add_log_message(format!("system: Could not find fingerprint for user '{}'.", target_name));
            }
        } else {
            // User does not exist
            app.add_log_message(format!("system: User '{}' not found.", target_name));
        }
        return true;
    }
    false
}

pub async fn handle_clear_command(line: &str, _chat_context: &ChatContext, _ui_tx: mpsc::Sender<String>) -> bool {
    if line == "/clear" {
        // Don't send any output here - let the main loop handle it via the pending_clear_conversation signal
        return true;
    }
    false
}



pub async fn handle_leave_command(
    line: &str,
    chat_context: &mut ChatContext,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    app_state: &mut AppState,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line == "/leave" {
        if let ChatMode::Channel(channel) = &chat_context.current_mode.clone() {
            let leave_payload = channel.as_bytes().to_vec();
            let mut leave_packet = create_bitchat_packet(my_peer_id, MessageType::Leave, leave_payload);
            if leave_packet.len() > 2 { leave_packet[2] = 3; } // Set TTL
            let _ = peripheral.write(cmd_char, &leave_packet, WriteType::WithoutResponse).await;
            
            channel_keys.remove(channel);
            app_state.encrypted_channel_passwords.remove(channel);
            chat_context.remove_channel(channel);
            chat_context.switch_to_public();
            
            // Remove channel from TUI sidebar
            app.channels.retain(|c| c != channel);
            
            let _ = ui_tx.send(format!("\x1b[90m» Left channel {}\x1b[0m\n", channel)).await;
        } else {
            let _ = ui_tx.send("» You're not in a channel. Use /j #channel to join one.\n".to_string()).await;
        }
        return true;
    }
    false
}


pub async fn handle_pass_command(
    line: &str,
    chat_context: &ChatContext,
    channel_creators: &mut HashMap<String, String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    password_protected_channels: &mut HashSet<String>,
    app_state: &mut AppState,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line.starts_with("/pass ") {
        if let ChatMode::Channel(channel) = &chat_context.current_mode {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                let _ = ui_tx.send("\x1b[93m⚠ Usage: /pass <new password>\x1b[0m\n".to_string()).await;
                return true;
            }
            let new_password = parts[1];

            // Only owner can set/change password
            if channel_creators.get(channel).map_or(true, |owner| owner == my_peer_id) {
                 if !channel_creators.contains_key(channel) {
                     channel_creators.insert(channel.clone(), my_peer_id.to_string());
                 }
                 let new_key = EncryptionService::derive_channel_key(new_password, channel);
                 channel_keys.insert(channel.clone(), new_key);
                 password_protected_channels.insert(channel.clone());

                 if let Some(identity_key) = &app_state.identity_key {
                    if let Ok(encrypted) = encrypt_password(new_password, identity_key) {
                        app_state.encrypted_channel_passwords.insert(channel.clone(), encrypted);
                    }
                 }
                 
                 let commitment_hex = hex::encode(Sha256::digest(&new_key));
                 let _ = send_channel_announce(peripheral, cmd_char, my_peer_id, channel, true, Some(&commitment_hex)).await;
                 let _ = ui_tx.send(format!("» Password set for {}. Others must rejoin with the new password.\n", channel)).await;

            } else {
                let _ = ui_tx.send("» Only the channel owner can change the password.\n".to_string()).await;
            }
        } else {
            let _ = ui_tx.send("» You must be in a channel to use /pass.\n".to_string()).await;
        }
        return true;
    }
    false
}


pub async fn handle_fingerprint_command(
    line: &str,
    encryption_service: &EncryptionService,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/fingerprint" {
        let fingerprint = encryption_service.get_identity_fingerprint();
        let _ = ui_tx.send(format!("\x1b[96m🔒 Your Identity Fingerprint:\x1b[0m\n\x1b[90m{}\x1b[0m\n", fingerprint)).await;
        return true;
    }
    false
}

pub async fn handle_transfer_command(
    line: &str,
    chat_context: &ChatContext,
    channel_creators: &mut HashMap<String, String>,
    password_protected_channels: &HashSet<String>,
    channel_keys: &HashMap<String, [u8; 32]>,
    my_peer_id: &str,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line.starts_with("/transfer ") {
        if let ChatMode::Channel(channel) = &chat_context.current_mode {
            if channel_creators.get(channel).map_or(false, |owner| owner == my_peer_id) {
                let target_name = line.trim_start_matches("/transfer ").trim().trim_start_matches('@');
                let target_peer_id = peers.lock().await.iter()
                    .find(|(_, peer)| peer.nickname.as_deref() == Some(target_name))
                    .map(|(id, _)| id.clone());

                if let Some(new_owner_id) = target_peer_id {
                    channel_creators.insert(channel.clone(), new_owner_id.clone());
                    let is_protected = password_protected_channels.contains(channel);
                    let commitment = if is_protected { channel_keys.get(channel).map(|k| hex::encode(Sha256::digest(k))) } else { None };
                    if send_channel_announce(peripheral, cmd_char, &new_owner_id, channel, is_protected, commitment.as_deref()).await.is_ok() {
                        let _ = ui_tx.send(format!("» Transferred ownership of {} to {}\n", channel, target_name)).await;
                    }
                } else {
                    let _ = ui_tx.send(format!("\x1b[93m⚠ User '{}' not found\x1b[0m\n", target_name)).await;
                }
            } else {
                 let _ = ui_tx.send("» Only the channel owner can transfer ownership.\n".to_string()).await;
            }
        } else {
            let _ = ui_tx.send("» You must be in a channel to use /transfer.\n".to_string()).await;
        }
        return true;
    }
    false
}
