use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::io::Write;
use btleplug::api::{WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use sha2::{Sha256, Digest};
use crate::data_structures::{
    MessageType, Peer, DeliveryTracker, VERSION
};
use crate::terminal_ux::{ChatContext, ChatMode, print_help};
use crate::persistence::{AppState, save_state, encrypt_password, EncryptedPassword};
use crate::encryption::EncryptionService;
use crate::packet_creation::{create_bitchat_packet, create_bitchat_packet_with_recipient_and_signature};
use crate::packet_delivery::send_channel_announce;
use crate::payload_handling::{
    create_bitchat_message_payload_full, create_encrypted_channel_message_payload
};
use crate::fragmentation::send_packet_with_fragmentation;
use crate::debug_println;

pub fn handle_number_switching(line: &str, chat_context: &mut ChatContext) -> bool {
    if line.len() == 1 {
        if let Ok(num) = line.parse::<usize>() {
            if chat_context.switch_to_number(num) {
                debug_println!("{}", chat_context.get_status_line());
            } else {
                println!("» Invalid conversation number");
            }
            return true;
        }
    }
    false
}

pub fn handle_help_command(line: &str) -> bool {
    if line == "/help" {
        print_help();
        return true;
    }
    false
}

pub async fn handle_name_command(
    line: &str,
    nickname: &mut String,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
) -> bool {
    if line.starts_with("/name ") {
        let new_name = line[6..].trim();
        if new_name.is_empty() {
            println!("\x1b[93m⚠ Usage: /name <new_nickname>\x1b[0m");
            println!("\x1b[90mExample: /name Alice\x1b[0m");
        } else if new_name.len() > 20 {
            println!("\x1b[93m⚠ Nickname too long\x1b[0m");
            println!("\x1b[90mMaximum 20 characters allowed.\x1b[0m");
        } else if new_name.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
            println!("\x1b[93m⚠ Invalid nickname\x1b[0m");
            println!("\x1b[90mNicknames can only contain letters, numbers, hyphens and underscores.\x1b[0m");
        } else if new_name == "system" || new_name == "all" {
            println!("\x1b[93m⚠ Reserved nickname\x1b[0m");
            println!("\x1b[90mThis nickname is reserved and cannot be used.\x1b[0m");
        } else {
            *nickname = new_name.to_string();
            let announce_packet = create_bitchat_packet(my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());
            if peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await.is_err() {
                println!("[!] Failed to announce new nickname");
            } else {
                println!("\x1b[90m» Nickname changed to: {}\x1b[0m", nickname);
                let state_to_save = create_app_state(
                    blocked_peers,
                    channel_creators,
                    &chat_context.active_channels,
                    password_protected_channels,
                    channel_key_commitments,
                    &app_state.encrypted_channel_passwords,
                    nickname
                );
                if let Err(e) = save_state(&state_to_save) {
                    eprintln!("Warning: Could not save nickname: {}", e);
                }
            }
        }
        return true;
    }
    false
}

pub fn handle_list_command(line: &str, chat_context: &mut ChatContext) -> bool {
    if line == "/list" {
        chat_context.show_conversation_list();
        return true;
    }
    false
}

// Handler for /j command (join channel)
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
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    channel_creators: &HashMap<String, String>,
    blocked_peers: &HashSet<String>,
) -> bool {
    if line.starts_with("/j ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let channel_name = parts.get(1).unwrap_or(&"").to_string();
        
        // Validate channel name
        if channel_name.is_empty() {
            println!("\x1b[93m⚠ Usage: /j #<channel> [password]\x1b[0m");
            println!("\x1b[90mExample: /j #general\x1b[0m");
            println!("\x1b[90mExample: /j #private mysecret\x1b[0m");
            return true;
        }
        
        if !channel_name.starts_with("#") {
            println!("\x1b[93m⚠ Channel names must start with #\x1b[0m");
            println!("\x1b[90mExample: /j #{}\x1b[0m", channel_name);
            return true;
        }
        
        if channel_name.len() > 25 {
            println!("\x1b[93m⚠ Channel name too long\x1b[0m");
            println!("\x1b[90mMaximum 25 characters allowed.\x1b[0m");
            return true;
        }
        
        if channel_name[1..].contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
            println!("\x1b[93m⚠ Invalid channel name\x1b[0m");
            println!("\x1b[90mChannel names can only contain letters, numbers, hyphens and underscores.\x1b[0m");
            return true;
        }

        if channel_name.starts_with("#") {
            // Check if channel is password-protected
            if password_protected_channels.contains(&channel_name) {
                // Check if we already have a key (from auto-restore)
                if channel_keys.contains_key(&channel_name) {
                    // We have the key from restoration, just switch to the channel
                    discovered_channels.insert(channel_name.clone());
                    chat_context.switch_to_channel(&channel_name);
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    return true;
                }
                // We don't have the key, require password
                if let Some(password) = parts.get(2) {
                    if password.len() < 4 {
                        println!("\x1b[93m⚠ Password too short\x1b[0m");
                        println!("\x1b[90mMinimum 4 characters required.\x1b[0m");
                        return true;
                    }
                    let key = EncryptionService::derive_channel_key(password, &channel_name);
                    
                    // Verify password against stored key commitment (iOS compatibility)
                    if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                        let test_commitment = {
                            let hash = sha2::Sha256::digest(&key);
                            hex::encode(hash)
                        };
                        
                        if &test_commitment != expected_commitment {
                            // Match iOS error message exactly
                            println!("❌ wrong password for channel {}. please enter the correct password.", channel_name);
                            return true;
                        }
                        debug_println!("[CHANNEL] Password verified for {}", channel_name);
                    }
                    
                    channel_keys.insert(channel_name.clone(), key);
                    discovered_channels.insert(channel_name.clone());
                    
                    // Save encrypted password (matching iOS Keychain behavior)
                    if let Some(identity_key) = &app_state.identity_key {
                        match encrypt_password(password, identity_key) {
                            Ok(encrypted) => {
                                app_state.encrypted_channel_passwords.insert(channel_name.clone(), encrypted);
                                debug_println!("[CHANNEL] Saved encrypted password for {}", channel_name);
                                
                                // Save state immediately
                                let state_to_save = create_app_state(
                                    blocked_peers,
                                    channel_creators,
                                    &chat_context.active_channels,
                                    password_protected_channels,
                                    channel_key_commitments,
                                    &app_state.encrypted_channel_passwords,
                                    nickname
                                );
                                if let Err(e) = save_state(&state_to_save) {
                                    eprintln!("Warning: Could not save state: {}", e);
                                }
                            }
                            Err(e) => {
                                debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                            }
                        }
                    }
                    
                    discovered_channels.insert(channel_name.clone());
                    chat_context.switch_to_channel_silent(&channel_name);
                    // Clear the prompt that was already printed by the input reader
                    print!("\r\x1b[K");
                    println!("\x1b[90m─────────────────────────\x1b[0m");
                    println!("\x1b[90m» Joined password-protected channel: {} 🔒\x1b[0m", channel_name);
                    
                    // Send channel announce to let others know we joined with correct password
                    // This matches iOS behavior
                    if let Some(owner) = channel_creators.get(&channel_name) {
                        let key_commitment = {
                            let hash = sha2::Sha256::digest(&key);
                            hex::encode(hash)
                        };
                        debug_println!("[CHANNEL] Sending join announce for password channel {}", channel_name);
                        let _ = send_channel_announce(
                            peripheral,
                            cmd_char,
                            owner, // Use existing owner
                            &channel_name,
                            true,
                            Some(&key_commitment)
                        ).await;
                    }
                    
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                } else {
                    println!("❌ Channel {} is password-protected. Use: /j {} <password>", channel_name, channel_name);
                    return true;
                }
            } else {
                // Not password-protected or we have the key
                if let Some(password) = parts.get(2) {
                    // User provided password for a channel we haven't seen as protected yet
                    let key = EncryptionService::derive_channel_key(password, &channel_name);
                    channel_keys.insert(channel_name.clone(), key);
                    discovered_channels.insert(channel_name.clone());
                    chat_context.switch_to_channel_silent(&channel_name);
                    // Clear the prompt that was already printed by the input reader
                    print!("\r\x1b[K");
                    println!("\x1b[90m─────────────────────────\x1b[0m");
                    println!("\x1b[90m» Joined password-protected channel: {} 🔒. Just type to send messages.\x1b[0m", channel_name);
                    
                    // Send channel announce to let others know we joined with correct password
                    // This matches iOS behavior
                    if let Some(owner) = channel_creators.get(&channel_name) {
                        let key_commitment = {
                            let hash = sha2::Sha256::digest(&key);
                            hex::encode(hash)
                        };
                        debug_println!("[CHANNEL] Sending join announce for password channel {}", channel_name);
                        let _ = send_channel_announce(
                            peripheral,
                            cmd_char,
                            owner, // Use existing owner
                            &channel_name,
                            true,
                            Some(&key_commitment)
                        ).await;
                    }
                    
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                } else {
                    // Regular channel join
                    discovered_channels.insert(channel_name.clone());
                    print!("\r\x1b[K");
                    chat_context.switch_to_channel(&channel_name);
                    channel_keys.remove(&channel_name); // Remove any previous key
                    
                    // Don't claim ownership - let it be established when first password is set
                    // This matches iOS behavior
                    if !channel_creators.contains_key(&channel_name) {
                        debug_println!("[CHANNEL] No owner recorded for {}. First to set password will become owner.", channel_name);
                    }
                    
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                }
            }
            debug_println!("{}", chat_context.get_status_line());
        } else {
            println!("» Invalid channel name. It must start with #.");
        }
        return true;
    }
    false
}

// Handler for /exit command
pub fn handle_exit_command(
    line: &str,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
) -> bool {
    if line == "/exit" { 
        // Save state before exiting
        let state_to_save = create_app_state(
            blocked_peers,
            channel_creators,
            &chat_context.active_channels,
            password_protected_channels,
            channel_key_commitments,
            &app_state.encrypted_channel_passwords,
            nickname
        );
        if let Err(e) = save_state(&state_to_save) {
            eprintln!("Warning: Could not save state: {}", e);
        }
        return true;
    }
    false
}

// Handler for /reply command
pub fn handle_reply_command(line: &str, chat_context: &mut ChatContext) -> bool {
    if line == "/reply" {
        if let Some((peer_id, nickname)) = chat_context.last_private_sender.clone() {
            chat_context.enter_dm_mode(&nickname, &peer_id);
            debug_println!("{}", chat_context.get_status_line());
        } else {
            println!("» No private messages received yet.");
        }
        return true;
    }
    false
}

// Handler for /public command
pub fn handle_public_command(line: &str, chat_context: &mut ChatContext) -> bool {
    if line == "/public" {
        chat_context.switch_to_public();
        debug_println!("{}", chat_context.get_status_line());
        return true;
    }
    false
}

// Handler for /online command
pub fn handle_online_command(line: &str, peers: &Arc<Mutex<HashMap<String, Peer>>>) -> bool {
    if line == "/online" || line == "/w" {
        let peers_lock = peers.lock().unwrap();
        if peers_lock.is_empty() {
            println!("» No one else is online right now.");
        } else {
            let mut online_list: Vec<String> = peers_lock.iter()
                .filter_map(|(_, peer)| peer.nickname.clone())
                .collect();
            online_list.sort();
            println!("» Online users: {}", online_list.join(", "));
        }
        print!("> ");
        std::io::stdout().flush().unwrap();
        return true;
    }
    false
}

// Handler for /channels command
pub fn handle_channels_command(
    line: &str,
    chat_context: &ChatContext,
    channel_keys: &HashMap<String, [u8; 32]>,
    password_protected_channels: &HashSet<String>,
) -> bool {
    if line == "/channels" {
        let mut all_channels: HashSet<String> = HashSet::new();
        
        // Add channels from chat context
        all_channels.extend(chat_context.active_channels.iter().cloned());
        
        // Add channels from channel_keys (password protected ones we know about)
        all_channels.extend(channel_keys.keys().cloned());
        
        if all_channels.is_empty() {
            println!("» No channels discovered yet. Channels appear as people use them.");
        } else {
            let mut channel_list: Vec<String> = all_channels.into_iter().collect();
            channel_list.sort();
            
            println!("» Discovered channels:");
            for channel in channel_list {
                let mut status = String::new();
                
                // Check if joined
                if chat_context.active_channels.contains(&channel) {
                    status.push_str(" ✓");
                }
                
                // Check if password protected
                if password_protected_channels.contains(&channel) {
                    status.push_str(" 🔒");
                    if channel_keys.contains_key(&channel) {
                        status.push_str(" 🔑"); // We have the key
                    }
                }
                
                println!("  {}{}", channel, status);
            }
            println!("\n✓ = joined, 🔒 = password protected, 🔑 = authenticated");
        }
        print!("> ");
        std::io::stdout().flush().unwrap();
        return true;
    }
    false
}

// Handler for /dm command (direct message)
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
) -> bool {
    if line.starts_with("/dm ") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        
        // Check if it's just "/dm nickname" (enter DM mode) or "/dm nickname message" (quick send)
        if parts.len() < 2 {
            println!("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m");
            println!("\x1b[90mExample: /dm Bob Hey there!\x1b[0m");
            return true;
        }
        
        let target_nickname = parts[1];
        
        // Find peer ID for nickname
        let peer_id = {
            let peers = peers.lock().unwrap();
            peers.iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(target_nickname))
                .map(|(id, _)| id.clone())
        };
        
        if let Some(target_peer_id) = peer_id {
            // If no message provided, enter DM mode
            if parts.len() == 2 {
                chat_context.enter_dm_mode(target_nickname, &target_peer_id);
                debug_println!("{}", chat_context.get_status_line());
                return true;
            }
            
            // Otherwise send the message directly
            let private_message = parts[2];
            // Create private message
            debug_println!("[PRIVATE] Sending encrypted message to {}", target_nickname);
            
            // Create message payload with private flag
            let (message_payload, message_id) = create_bitchat_message_payload_full(&nickname, private_message, None, true, &my_peer_id);
            
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
                debug_println!("[PRIVATE] Added {} bytes of PKCS#7 padding", padding_needed);
            } else if padding_needed == 0 {
                // If already at block size, don't add more padding - Android doesn't do this
                debug_println!("[PRIVATE] Message already at block size, no padding needed");
            }
            
            // Encrypt the padded payload for the recipient
            match encryption_service.encrypt(&padded_payload, &target_peer_id) {
                Ok(encrypted) => {
                    debug_println!("[PRIVATE] Encrypted payload: {} bytes", encrypted.len());
                    
                    // Sign the encrypted payload
                    let signature = encryption_service.sign(&encrypted);
                    
                    // Create packet with recipient ID for private routing
                    let packet = create_bitchat_packet_with_recipient_and_signature(
                        &my_peer_id,
                        &target_peer_id,  // Specify the recipient
                        MessageType::Message,
                        encrypted,
                        Some(signature)
                    );
                    
                    // Send the private message
                    if let Err(_e) = send_packet_with_fragmentation(&peripheral, cmd_char, packet, &my_peer_id).await {
                        println!("\n\x1b[91m❌ Failed to send private message\x1b[0m");
                        println!("\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m");
                    } else {
                        debug_println!("[PRIVATE] Message sent to {}", target_nickname);
                    }
                },
                Err(e) => {
                    println!("[!] Failed to encrypt private message: {:?}", e);
                    println!("[!] Make sure you have received key exchange from {}", target_nickname);
                }
            }
            return true;
        } else {
            println!("\x1b[93m⚠ User '{}' not found\x1b[0m", target_nickname);
            println!("\x1b[90mThey may be offline or using a different nickname.\x1b[0m");
            return true;
        }
    }
    false
}

// Handler for /block command
pub fn handle_block_command(
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
    _nickname: &str,
) -> bool {
    if line.starts_with("/block") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() == 1 {
            // List blocked peers
            if blocked_peers.is_empty() {
                println!("» No blocked peers.");
            } else {
                // Find nicknames for blocked fingerprints
                let peers_guard = peers.lock().unwrap();
                let mut blocked_nicknames = Vec::new();
                
                for (peer_id, peer) in peers_guard.iter() {
                    if let Some(fingerprint) = encryption_service.get_peer_fingerprint(peer_id) {
                        if blocked_peers.contains(&fingerprint) {
                            if let Some(nickname) = &peer.nickname {
                                blocked_nicknames.push(nickname.clone());
                            }
                        }
                    }
                }
                
                if blocked_nicknames.is_empty() {
                    println!("» Blocked peers (not currently online): {}", blocked_peers.len());
                } else {
                    println!("» Blocked peers: {}", blocked_nicknames.join(", "));
                }
            }
        } else if parts.len() == 2 {
            // Block a specific peer
            let target_name = parts[1];
            let nickname = if target_name.starts_with("@") {
                &target_name[1..]
            } else {
                target_name
            };
            
            // Find peer ID for nickname
            let peer_id = {
                let peers_guard = peers.lock().unwrap();
                peers_guard.iter()
                    .find(|(_, peer)| peer.nickname.as_deref() == Some(nickname))
                    .map(|(id, _)| id.clone())
            };
            
            if let Some(target_peer_id) = peer_id {
                if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&target_peer_id) {
                    if blocked_peers.contains(&fingerprint) {
                        println!("» {} is already blocked.", nickname);
                    } else {
                        blocked_peers.insert(fingerprint.clone());
                        
                        // Save state
                        let state_to_save = create_app_state(
                            blocked_peers,
                            channel_creators,
                            &chat_context.active_channels,
                            password_protected_channels,
                            channel_key_commitments,
                            &app_state.encrypted_channel_passwords,
                            nickname
                        );
                        if let Err(e) = save_state(&state_to_save) {
                            eprintln!("Warning: Could not save state: {}", e);
                        }
                        
                        println!("\n\x1b[92m✓ Blocked {}\x1b[0m", nickname);
                        println!("\x1b[90m{} will no longer be able to send you messages.\x1b[0m", nickname);
                    }
                } else {
                    println!("» Cannot block {}: No identity key received yet.", nickname);
                }
            } else {
                println!("\x1b[93m⚠ User '{}' not found\x1b[0m", nickname);
                println!("\x1b[90mThey may be offline or haven't sent any messages yet.\x1b[0m");
            }
        } else {
            println!("\x1b[93m⚠ Usage: /block @<nickname>\x1b[0m");
            println!("\x1b[90mExample: /block @spammer\x1b[0m");
        }
        return true;
    }
    false
}

// Handler for /unblock command
pub fn handle_unblock_command(
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
    _nickname: &str,
) -> bool {
    if line.starts_with("/unblock ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() != 2 {
            println!("\x1b[93m⚠ Usage: /unblock @<nickname>\x1b[0m");
            println!("\x1b[90mExample: /unblock @friend\x1b[0m");
            return true;
        }
        
        let target_name = parts[1];
        let nickname = if target_name.starts_with("@") {
            &target_name[1..]
        } else {
            target_name
        };
        
        // Find peer ID for nickname
        let peer_id = {
            let peers_guard = peers.lock().unwrap();
            peers_guard.iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(nickname))
                .map(|(id, _)| id.clone())
        };
        
        if let Some(target_peer_id) = peer_id {
            if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&target_peer_id) {
                if blocked_peers.contains(&fingerprint) {
                    blocked_peers.remove(&fingerprint);
                    
                    // Save state
                    let state_to_save = create_app_state(
                        blocked_peers,
                        channel_creators,
                        &chat_context.active_channels,
                        password_protected_channels,
                        channel_key_commitments,
                        &app_state.encrypted_channel_passwords,
                        nickname
                    );
                    if let Err(e) = save_state(&state_to_save) {
                        eprintln!("Warning: Could not save state: {}", e);
                    }
                    
                    println!("\n\x1b[92m✓ Unblocked {}\x1b[0m", nickname);
                    println!("\x1b[90m{} can now send you messages again.\x1b[0m", nickname);
                } else {
                    println!("\x1b[93m⚠ {} is not blocked\x1b[0m", nickname);
                }
            } else {
                println!("» Cannot unblock {}: No identity key received.", nickname);
            }
        } else {
            println!("\x1b[93m⚠ User '{}' not found\x1b[0m", nickname);
            println!("\x1b[90mThey may be offline or haven't sent any messages yet.\x1b[0m");
        }
        return true;
    }
    false
}

// Handler for /clear command
pub fn handle_clear_command(line: &str, chat_context: &ChatContext) -> bool {
    if line == "/clear" {
        // Clear the terminal screen
        print!("\x1b[2J\x1b[1;1H");
        
        // Reprint the ASCII art logo in Matrix green
        println!("\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\");
        println!("## |      \\__|  ## |              ## |                 ## |");
        println!("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\");
        println!("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|");
        println!("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |");
        println!("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\");
        println!("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |");
        println!("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m");
        println!("\n\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
        println!("\x1b[38;5;40mDecentralized • Encrypted • Peer-to-Peer • Open Source\x1b[0m");
        println!("\x1b[38;5;40m                bitchat@ the terminal {}\x1b[0m", VERSION);
        println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
        
        // Show current context
        match &chat_context.current_mode {
            ChatMode::Public => {
                println!("» Cleared public chat");
            },
            ChatMode::Channel(channel) => {
                println!("» Cleared channel {}", channel);
            },
            ChatMode::PrivateDM { nickname, .. } => {
                println!("» Cleared DM with {}", nickname);
            }
        }
        
        print!("> ");
        std::io::stdout().flush().unwrap();
        return true;
    }
    false
}

// Handler for /status command
pub fn handle_status_command(
    line: &str,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    chat_context: &ChatContext,
    nickname: &str,
    my_peer_id: &str,
) -> bool {
    if line == "/status" {
        let peer_count = peers.lock().unwrap().len();
        let channel_count = chat_context.active_channels.len();
        let dm_count = chat_context.active_dms.len();
        
        println!("\n╭─── Connection Status ───╮");
        println!("│ Peers connected: {:3}    │", peer_count);
        println!("│ Active channels: {:3}    │", channel_count);
        println!("│ Active DMs:      {:3}    │", dm_count);
        println!("│                         │");
        println!("│ Your nickname: {:^9}│", if nickname.len() > 9 { &nickname[..9] } else { &nickname });
        println!("│ Your ID: {}...│", &my_peer_id[..8]);
        println!("╰─────────────────────────╯");
        print!("> ");
        std::io::stdout().flush().unwrap();
        return true;
    }
    false
}

// Handler for /leave command
pub async fn handle_leave_command(
    line: &str,
    chat_context: &mut ChatContext,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    password_protected_channels: &mut HashSet<String>,
    channel_creators: &mut HashMap<String, String>,
    channel_key_commitments: &mut HashMap<String, String>,
    app_state: &mut AppState,
    blocked_peers: &HashSet<String>,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
) -> bool {
    if line == "/leave" {
        match &chat_context.current_mode {
            ChatMode::Channel(channel) => {
                let channel_name = channel.clone();
                
                // Send leave notification packet (iOS compatible)
                let leave_payload = channel_name.as_bytes().to_vec();
                let leave_packet = create_bitchat_packet(&my_peer_id, MessageType::Leave, leave_payload);
                
                // Set TTL to 3 for leave messages (matching iOS)
                let mut leave_packet_with_ttl = leave_packet;
                if leave_packet_with_ttl.len() > 2 {
                    leave_packet_with_ttl[2] = 3; // TTL position
                }
                
                if let Err(_e) = peripheral.write(cmd_char, &leave_packet_with_ttl, WriteType::WithoutResponse).await {
                    // Silently ignore leave notification failures - not critical
                }
                
                // Clean up local state
                channel_keys.remove(&channel_name);
                password_protected_channels.remove(&channel_name);
                channel_creators.remove(&channel_name);
                channel_key_commitments.remove(&channel_name);
                
                // Remove from encrypted passwords
                app_state.encrypted_channel_passwords.remove(&channel_name);
                
                // Update chat context
                chat_context.remove_channel(&channel_name);
                chat_context.switch_to_public();
                
                // Save state
                let state_to_save = create_app_state(
                    blocked_peers,
                    channel_creators,
                    &chat_context.active_channels,
                    password_protected_channels,
                    channel_key_commitments,
                    &app_state.encrypted_channel_passwords,
                    nickname
                );
                if let Err(e) = save_state(&state_to_save) {
                    eprintln!("Warning: Could not save state: {}", e);
                }
                
                println!("\x1b[90m» Left channel {}\x1b[0m", channel_name);
                print!("> ");
                std::io::stdout().flush().unwrap();
            },
            _ => {
                println!("» You're not in a channel. Use /j #channel to join one.");
            }
        }
        return true;
    }
    false
}

// Handler for /pass command (set/change channel password)
pub async fn handle_pass_command(
    line: &str,
    chat_context: &ChatContext,
    channel_creators: &mut HashMap<String, String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    password_protected_channels: &mut HashSet<String>,
    channel_key_commitments: &mut HashMap<String, String>,
    app_state: &mut AppState,
    blocked_peers: &HashSet<String>,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    my_peer_id: &str,
    encryption_service: &EncryptionService,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
) -> bool {
    if line.starts_with("/pass ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        // Check if user is in a channel
        if let ChatMode::Channel(channel) = &chat_context.current_mode {
            // Check if user is the channel owner
            if let Some(owner) = channel_creators.get(channel) {
                if owner == &my_peer_id {
                    if parts.len() >= 2 {
                        let new_password = parts[1..].join(" ");
                        
                        if new_password.len() < 4 {
                            println!("\x1b[93m⚠ Password too short\x1b[0m");
                            println!("\x1b[90mMinimum 4 characters required.\x1b[0m");
                            return true;
                        }
                        
                        // Derive new key
                        let new_key = EncryptionService::derive_channel_key(&new_password, channel);
                        
                        // Store old key for notification
                        let old_key = channel_keys.get(channel).cloned();
                        
                        // Update keys and mark as protected
                        channel_keys.insert(channel.clone(), new_key);
                        password_protected_channels.insert(channel.clone());
                        
                        // Save encrypted password (matching iOS Keychain behavior)
                        if let Some(identity_key) = &app_state.identity_key {
                            match encrypt_password(&new_password, identity_key) {
                                Ok(encrypted) => {
                                    app_state.encrypted_channel_passwords.insert(channel.clone(), encrypted);
                                    debug_println!("[CHANNEL] Saved encrypted password for {}", channel);
                                }
                                Err(e) => {
                                    debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                                }
                            }
                        }
                        
                        // Calculate key commitment (SHA256 of key)
                        use sha2::Digest;
                        let mut hasher = Sha256::new();
                        hasher.update(&new_key);
                        let commitment = hasher.finalize();
                        let commitment_hex = hex::encode(&commitment);
                        
                        // Send notification with old key if exists
                        if let Some(old_key) = old_key {
                            let notify_msg = "🔐 Password changed by channel owner. Please update your password.";
                            let encrypted_notify = match encryption_service.encrypt_with_key(notify_msg.as_bytes(), &old_key) {
                                Ok(enc) => enc,
                                Err(_) => Vec::new(),
                            };
                            
                            if !encrypted_notify.is_empty() {
                                let (notify_payload, _) = create_encrypted_channel_message_payload(
                                    &nickname, notify_msg, channel, &old_key, &encryption_service, &my_peer_id
                                );
                                let notify_packet = create_bitchat_packet(&my_peer_id, MessageType::Message, notify_payload);
                                let _ = send_packet_with_fragmentation(&peripheral, cmd_char, notify_packet, &my_peer_id).await;
                            }
                        }
                        
                        // Send channel announce with new key commitment
                        if let Err(e) = send_channel_announce(
                            &peripheral,
                            cmd_char,
                            &my_peer_id,
                            channel,
                            true,
                            Some(&commitment_hex),
                        ).await {
                            println!("[!] Failed to announce password change: {}", e);
                        }
                        
                        // Send initialization message with new key
                        let init_msg = format!("🔑 Password {} | Channel {} password {} by {} | Metadata: {}",
                            if old_key.is_some() { "changed" } else { "set" },
                            channel,
                            if old_key.is_some() { "updated" } else { "protected" },
                            nickname,
                            hex::encode(&my_peer_id.as_bytes())
                        );
                        
                        let (init_payload, _) = create_encrypted_channel_message_payload(
                            &nickname, &init_msg, channel, &new_key, &encryption_service, &my_peer_id
                        );
                        let init_packet = create_bitchat_packet(&my_peer_id, MessageType::Message, init_payload);
                        let _ = send_packet_with_fragmentation(&peripheral, cmd_char, init_packet, &my_peer_id).await;
                        
                        // Save state
                        let state_to_save = create_app_state(
                            blocked_peers,
                            channel_creators,
                            &chat_context.active_channels,
                            password_protected_channels,
                            channel_key_commitments,
                            &app_state.encrypted_channel_passwords,
                            nickname
                        );
                        if let Err(e) = save_state(&state_to_save) {
                            eprintln!("Warning: Could not save state: {}", e);
                        }
                        
                        println!("» Password {} for {}.", 
                            if old_key.is_some() { "changed" } else { "set" },
                            channel
                        );
                        println!("» Members will need to rejoin with: /j {} {}", channel, new_password);
                    } else {
                        println!("\x1b[93m⚠ Usage: /pass <new password>\x1b[0m");
                        println!("\x1b[90mExample: /pass mysecret123\x1b[0m");
                    }
                } else {
                    println!("» Only the channel owner can change the password.");
                }
            } else {
                // No owner recorded - first to set password becomes owner (iOS behavior)
                if parts.len() >= 2 {
                    let new_password = parts[1..].join(" ");
                    
                    // Claim ownership
                    channel_creators.insert(channel.clone(), my_peer_id.to_string());
                    
                    // Derive key
                    let new_key = EncryptionService::derive_channel_key(&new_password, channel);
                    
                    // Update keys and mark as protected
                    channel_keys.insert(channel.clone(), new_key);
                    password_protected_channels.insert(channel.clone());
                    
                    // Save encrypted password (matching iOS Keychain behavior)
                    if let Some(identity_key) = &app_state.identity_key {
                        match encrypt_password(&new_password, identity_key) {
                            Ok(encrypted) => {
                                app_state.encrypted_channel_passwords.insert(channel.clone(), encrypted);
                                debug_println!("[CHANNEL] Saved encrypted password for {}", channel);
                            }
                            Err(e) => {
                                debug_println!("[CHANNEL] Failed to encrypt password: {}", e);
                            }
                        }
                    }
                    
                    // Calculate key commitment
                    use sha2::Digest;
                    let mut hasher = Sha256::new();
                    hasher.update(&new_key);
                    let commitment = hasher.finalize();
                    let commitment_hex = hex::encode(&commitment);
                    
                    // Send channel announce to claim ownership and announce password
                    debug_println!("[CHANNEL] Claiming ownership of {} and setting password", channel);
                    if let Err(e) = send_channel_announce(
                        &peripheral,
                        cmd_char,
                        &my_peer_id,
                        channel,
                        true,
                        Some(&commitment_hex)
                    ).await {
                        eprintln!("Failed to send channel announce: {}", e);
                    }
                    
                    // Save state
                    let state_to_save = create_app_state(
                        blocked_peers,
                        channel_creators,
                        &chat_context.active_channels,
                        password_protected_channels,
                        channel_key_commitments,
                        &app_state.encrypted_channel_passwords,
                        nickname
                    );
                    if let Err(e) = save_state(&state_to_save) {
                        eprintln!("Warning: Could not save state: {}", e);
                    }
                    
                    println!("» Password set for {}. You are now the channel owner.", channel);
                    println!("» Members will need to rejoin with: /j {} {}", channel, new_password);
                } else {
                    println!("\x1b[93m⚠ Usage: /pass <new password>\x1b[0m");
                    println!("\x1b[90mExample: /pass mysecret123\x1b[0m");
                }
            }
        } else {
            println!("» You must be in a channel to use /pass.");
        }
        return true;
    }
    false
}

// Handler for /transfer command (transfer channel ownership)
pub async fn handle_transfer_command(
    line: &str,
    chat_context: &ChatContext,
    channel_creators: &mut HashMap<String, String>,
    password_protected_channels: &HashSet<String>,
    channel_keys: &HashMap<String, [u8; 32]>,
    blocked_peers: &HashSet<String>,
    create_app_state: &dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, EncryptedPassword>, &str) -> AppState,
    nickname: &str,
    my_peer_id: &str,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
) -> bool {
    if line.starts_with("/transfer ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        // Check if user is in a channel
        if let ChatMode::Channel(channel) = &chat_context.current_mode {
            // Check if user is the channel owner
            if let Some(owner_id) = channel_creators.get(channel) {
                if owner_id == &my_peer_id {
                    if parts.len() >= 2 {
                        let target_name = parts[1];
                        
                        // Remove @ prefix if present
                        let target_name = if target_name.starts_with('@') {
                            &target_name[1..]
                        } else {
                            target_name
                        };
                        
                        // Find the peer ID for the target nickname
                        let peers_lock = peers.lock().unwrap();
                        let target_peer_id = peers_lock.iter()
                            .find(|(_, peer)| peer.nickname.as_ref().map(|n| n == target_name).unwrap_or(false))
                            .map(|(id, _)| id.clone());
                        drop(peers_lock);
                        
                        if let Some(new_owner_id) = target_peer_id {
                            // Update the channel owner
                            channel_creators.insert(channel.clone(), new_owner_id.clone());
                            
                            // Save the updated state
                            let state_to_save = create_app_state(
                                blocked_peers,
                                channel_creators,
                                &Vec::new(), // Not persisting joined channels yet
                                password_protected_channels,
                                &HashMap::new(), // channel_key_commitments
                                &HashMap::new(), // app_state.encrypted_channel_passwords
                                nickname
                            );
                            if let Err(e) = save_state(&state_to_save) {
                                eprintln!("Failed to save state: {}", e);
                            }
                            
                            // Send channel announce to notify everyone
                            debug_println!("[CHANNEL] Transferring ownership of {} to {}", channel, target_name);
                            
                            // Check if channel is password protected to get key commitment
                            let is_protected = password_protected_channels.contains(channel);
                            
                            let key_commitment = if is_protected {
                                channel_keys.get(channel).map(|key| {
                                    let hash = sha2::Sha256::digest(key);
                                    hex::encode(hash)
                                })
                            } else {
                                None
                            };
                            
                            // Send announce packet with new owner
                            match send_channel_announce(&peripheral, &cmd_char, &new_owner_id, channel, is_protected, key_commitment.as_deref()).await {
                                Ok(_) => {
                                    println!("» Transferred ownership of {} to {}", channel, target_name);
                                }
                                Err(e) => {
                                    eprintln!("Failed to send ownership transfer announcement: {}", e);
                                }
                            }
                        } else {
                            println!("\x1b[93m⚠ User '{}' not found\x1b[0m", target_name);
                            println!("\x1b[90mMake sure they are online and you have the correct nickname.\x1b[0m");
                        }
                    } else {
                        println!("\x1b[93m⚠ Usage: /transfer @<username>\x1b[0m");
                        println!("\x1b[90mExample: /transfer @newowner\x1b[0m");
                    }
                } else {
                    println!("» Only the channel owner can transfer ownership.");
                }
            } else {
                println!("» Only the channel owner can transfer ownership.");
            }
        } else {
            println!("» You must be in a channel to use /transfer.");
        }
        return true;
    }
    false
}
