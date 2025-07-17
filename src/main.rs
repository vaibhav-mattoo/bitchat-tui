use btleplug::api::{Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType};

use btleplug::platform::{Manager, Peripheral};

use tokio::io::{self, AsyncBufReadExt, BufReader};
use std::io::Write;

use tokio::sync::mpsc;

use tokio::time::{self, Duration};

use uuid::Uuid;

use futures::stream::StreamExt;

use std::collections::{HashMap, HashSet};

use std::convert::TryInto;

use std::sync::{Arc, Mutex};

use std::time::SystemTime;

use std::env;

use bloomfilter::Bloom;

// use ed25519_dalek::SigningKey; // Removed: unused

// use x25519_dalek::StaticSecret; // Removed: unused

// use rand::rngs::OsRng; // Removed: unused
use rand::Rng;
use sha2::{Sha256, Digest};
use serde_json;

mod compression;
mod fragmentation;
mod encryption;
mod terminal_ux;
mod persistence;
mod data_structures;
mod payload_handling;
mod packet_parser;
mod packet_creation;
mod packet_delivery;
mod command_handling;
mod message_handlers;
mod notification_handlers;

use compression::decompress;
use fragmentation::{send_packet_with_fragmentation, should_fragment};
use encryption::EncryptionService;
use terminal_ux::{ChatContext, ChatMode, format_message_display, print_help};
use persistence::{AppState, load_state, save_state, encrypt_password, decrypt_password};
use payload_handling::{
    unpad_message, parse_bitchat_message_payload, create_bitchat_message_payload,
    create_bitchat_message_payload_full, create_encrypted_channel_message_payload
};
use packet_parser::{parse_bitchat_packet, generate_keys_and_payload};
use packet_creation::{
    create_bitchat_packet, create_bitchat_packet_with_signature,
    create_bitchat_packet_with_recipient_and_signature, create_bitchat_packet_with_recipient
};
use packet_delivery::{create_delivery_ack, should_send_ack, send_channel_announce};
use command_handling::{
    handle_number_switching, handle_help_command, handle_name_command, handle_list_command,
    handle_join_command, handle_exit_command, handle_reply_command, handle_public_command,
    handle_online_command, handle_channels_command, handle_dm_command, handle_block_command,
    handle_unblock_command, handle_clear_command, handle_status_command, handle_leave_command,
    handle_pass_command, handle_transfer_command
};
use message_handlers::{handle_private_dm_message, handle_regular_message};
use notification_handlers::{
    handle_announce_message, handle_message_relay, handle_private_message_decryption,
    handle_message_packet, handle_fragment_packet, handle_key_exchange_message,
    handle_leave_message, handle_channel_announce_message, handle_delivery_ack_message,
    handle_delivery_status_request_message, handle_read_receipt_message
};

use crate::data_structures::{
    DebugLevel, DEBUG_LEVEL, MessageType, Peer, BitchatPacket, DeliveryAck,
    DeliveryTracker, FragmentCollector, VERSION, BITCHAT_SERVICE_UUID, BITCHAT_CHARACTERISTIC_UUID,
    COVER_TRAFFIC_PREFIX, FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE, FLAG_IS_COMPRESSED,
    BROADCAST_RECIPIENT,
};

// Function to handle input and display ASCII art
fn spawn_input_handler(tx: mpsc::Sender<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stdin = BufReader::new(io::stdin()).lines();

        // Display ASCII art logo in Matrix green
        println!("\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\");
        println!("## |      \\__|  ## |              ## |                 ## |");
        println!("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\");
        println!("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|");
        println!("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |");
        println!("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\");
        println!("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |");
        println!("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m");
        println!("\n\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
        println!("\x1b[37mDecentralized • Encrypted • Peer-to-Peer • Open Source\x1b[0m");
        println!("\x1b[37m                bitch@ the terminal {}\x1b[0m", VERSION);
        println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");

        loop {
            // Note: We can't access chat_context here directly, but we'll improve this later
            print!("> ");
            use std::io::{self as stdio, Write};
            let _ = stdio::stdout().flush();

            if let Ok(Some(line)) = stdin.next_line().await {
                if tx.send(line).await.is_err() { break; }
            } else { break; }
        }
    })
        }

// Function to handle Bluetooth setup and connection
async fn setup_bluetooth_connection() -> Result<Peripheral, Box<dyn std::error::Error>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().nth(0) {
        Some(adapter) => adapter,
        None => {
            println!("\n\x1b[91m❌ No Bluetooth adapter found\x1b[0m");
            println!("\x1b[90mPlease check:\x1b[0m");
            println!("\x1b[90m  • Your device has Bluetooth hardware\x1b[0m");
            println!("\x1b[90m  • Bluetooth is enabled in system settings\x1b[0m");
            println!("\x1b[90m  • You have permission to use Bluetooth\x1b[0m");
            return Err("No Bluetooth adapter found.".into());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    println!("\x1b[90m» Scanning for bitchat service...\x1b[0m");
    debug_println!("[1] Scanning for bitchat service...");

    let peripheral = loop {
        if let Some(p) = find_peripheral(&adapter).await? {
            println!("\x1b[90m» Found bitchat service! Connecting...\x1b[0m");
            debug_println!("[1] Match Found! Connecting...");

            adapter.stop_scan().await?;

            break p;
        }

        time::sleep(Duration::from_secs(1)).await;
    };

    if let Err(e) = peripheral.connect().await {
        println!("\n\x1b[91m❌ Connection failed\x1b[0m");
        println!("\x1b[90mReason: {}\x1b[0m", e);
        println!("\x1b[90mPlease check:\x1b[0m");
        println!("\x1b[90m  • Bluetooth is enabled\x1b[0m");
        println!("\x1b[90m  • The other device is running BitChat\x1b[0m");
        println!("\x1b[90m  • You're within range\x1b[0m");
        println!("\n\x1b[90mTry running the command again.\x1b[0m");
        return Err(format!("Connection failed: {}", e).into());
    }

    Ok(peripheral)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check for debug flags
    unsafe {
        if args.iter().any(|arg| arg == "-dd" || arg == "--debug-full") {
            DEBUG_LEVEL = DebugLevel::Full;
            println!("🐛 Debug mode: FULL (verbose output)");
        } else if args.iter().any(|arg| arg == "-d" || arg == "--debug") {
            DEBUG_LEVEL = DebugLevel::Basic;
            println!("🐛 Debug mode: BASIC (connection info)");
        }
        // Otherwise stays at Clean (default)
    }

    let (tx, mut rx) = mpsc::channel::<String>(10);

    let _input_handle = spawn_input_handler(tx);

    let peripheral = setup_bluetooth_connection().await?;

    peripheral.discover_services().await?;

    let characteristics = peripheral.characteristics();

    let cmd_char = characteristics.iter().find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID).expect("Characteristic not found.");

    peripheral.subscribe(cmd_char).await?;

    let mut notification_stream = peripheral.notifications().await?;

    debug_println!("[2] Connection established.");
    
    // TODO: Implement MTU negotiation
    // Swift calls: peripheral.maximumWriteValueLength(for: .withoutResponse)
    // Default BLE MTU is 23 bytes (20 data), extended can be up to 512


    debug_println!("[3] Performing handshake...");

    // Generate peer ID like Swift does (4 random bytes as hex)
    let mut peer_id_bytes = [0u8; 4];
    rand::thread_rng().fill(&mut peer_id_bytes);
    let my_peer_id = hex::encode(&peer_id_bytes);
    debug_full_println!("[DEBUG] My peer ID: {}", my_peer_id);
    
    // Load persisted state early to get saved nickname
    let mut app_state = load_state();
    let mut nickname = app_state.nickname.clone().unwrap_or_else(|| "my-rust-client".to_string());

    // Create encryption service
    let encryption_service = Arc::new(EncryptionService::new());
    let (key_exchange_payload, _) = generate_keys_and_payload(&encryption_service);

    let key_exchange_packet = create_bitchat_packet(&my_peer_id, MessageType::KeyExchange, key_exchange_payload);

    peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await?;

    // Add delay between key exchange and announce to ensure Android processes them properly
    time::sleep(Duration::from_millis(500)).await;

    let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());

    peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await?;

    debug_println!("[3] Handshake sent. You can now chat.");
    if app_state.nickname.is_some() {
        println!("\x1b[90m» Using saved nickname: {}\x1b[0m", nickname);
    }
    println!("\x1b[90m» Type /status to see connection info\x1b[0m");


    let peers: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut bloom = Bloom::new_for_fp_rate(500, 0.01);

    let mut fragment_collector = FragmentCollector::new();
    let mut delivery_tracker = DeliveryTracker::new();

    let mut chat_context = ChatContext::new();
    let mut channel_keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut _chat_messages: HashMap<String, Vec<String>> = HashMap::new();  // for /clear command - stores messages by context
    
    // Already loaded app_state above for nickname
    let mut blocked_peers = app_state.blocked_peers.clone();
    let mut channel_creators = app_state.channel_creators.clone();
    let mut password_protected_channels = app_state.password_protected_channels.clone();
    let mut channel_key_commitments = app_state.channel_key_commitments.clone();
    let mut discovered_channels: HashSet<String> = HashSet::new();  // Track all discovered channels
    
    // Auto-restore channel keys from saved passwords (matching iOS behavior)
    if let Some(identity_key) = &app_state.identity_key {
        for (channel, encrypted_password) in &app_state.encrypted_channel_passwords {
            match decrypt_password(encrypted_password, identity_key) {
                Ok(password) => {
                    let key = EncryptionService::derive_channel_key(&password, channel);
                    channel_keys.insert(channel.clone(), key);
                    debug_println!("[CHANNEL] Restored key for password-protected channel: {}", channel);
                }
                Err(e) => {
                    debug_println!("[CHANNEL] Failed to restore key for {}: {}", channel, e);
                }
            }
        }
    }
    // Note: We don't restore joined_channels as they need to be re-joined via announce
    
    // Clone fields that will be used in the closure to avoid borrow checker issues
    let favorites = app_state.favorites.clone();
    let identity_key = app_state.identity_key.clone();
    
    // Helper to create AppState for saving
    let create_app_state = |blocked: &HashSet<String>, 
                           creators: &HashMap<String, String>,
                           channels: &Vec<String>,
                           protected: &HashSet<String>,
                           commitments: &HashMap<String, String>,
                           encrypted_passwords: &HashMap<String, persistence::EncryptedPassword>,
                           current_nickname: &str| -> AppState {
        AppState {
            nickname: Some(current_nickname.to_string()),
            blocked_peers: blocked.clone(),
            channel_creators: creators.clone(),
            joined_channels: channels.clone(),
            password_protected_channels: protected.clone(),
            channel_key_commitments: commitments.clone(),
            favorites: favorites.clone(),
            identity_key: identity_key.clone(),
            encrypted_channel_passwords: encrypted_passwords.clone(),
        }
    };


    loop {

        tokio::select! {

            Some(line) = rx.recv() => {

                if handle_number_switching(&line, &mut chat_context) {
                    continue;
                }
                if handle_help_command(&line) {
                    continue;
                }
                if handle_list_command(&line, &mut chat_context) {
                    continue;
                }
                if handle_name_command(
                    &line,
                    &mut nickname,
                    &my_peer_id,
                    &peripheral,
                    cmd_char,
                    &blocked_peers,
                    &channel_creators,
                    &chat_context,
                    &password_protected_channels,
                    &channel_key_commitments,
                    &app_state,
                    &create_app_state,
                ).await {
                    continue;
                }

                // Handle /j command
                if handle_join_command(
                    &line,
                    &password_protected_channels,
                    &mut channel_keys,
                    &mut discovered_channels,
                    &mut chat_context,
                    &channel_key_commitments,
                    &mut app_state,
                    &create_app_state,
                    &nickname,
                    &peripheral,
                    cmd_char,
                    &channel_creators,
                    &blocked_peers,
                ).await {
                    continue;
                }

                if handle_exit_command(
                    &line,
                    &blocked_peers,
                    &channel_creators,
                    &chat_context,
                    &password_protected_channels,
                    &channel_key_commitments,
                    &app_state,
                    &create_app_state,
                    &nickname,
                ) {
                    break;
                }
                
                // Handle /reply command
                if handle_reply_command(&line, &mut chat_context) {
                    continue;
                }
                
                // Handle /public command
                if handle_public_command(&line, &mut chat_context) {
                    continue;
                }
                
                // Handle /online command
                if handle_online_command(&line, &peers) {
                    continue;
                }
                
                // Handle /channels command
                if handle_channels_command(&line, &chat_context, &channel_keys, &password_protected_channels) {
                    continue;
                }
                
                // Handle private messages
                if handle_dm_command(
                    &line,
                    &mut chat_context,
                    &peers,
                    &nickname,
                    &my_peer_id,
                    &mut delivery_tracker,
                    &encryption_service,
                    &peripheral,
                    cmd_char,
                ).await {
                    continue;
                }

                // NOTE: DM mode handling removed from here - moved after command checks to allow commands in DM mode
                
                // Handle /block command
                if handle_block_command(
                    &line,
                    &mut blocked_peers,
                    &peers,
                    &encryption_service,
                    &channel_creators,
                    &chat_context,
                    &password_protected_channels,
                    &channel_key_commitments,
                    &app_state,
                    &create_app_state,
                    &nickname,
                ) {
                    continue;
                }
                
                // Handle /unblock command
                if handle_unblock_command(
                    &line,
                    &mut blocked_peers,
                    &peers,
                    &encryption_service,
                    &channel_creators,
                    &chat_context,
                    &password_protected_channels,
                    &channel_key_commitments,
                    &app_state,
                    &create_app_state,
                    &nickname,
                ) {
                    continue;
                }
                
                // Handle /clear command
                if handle_clear_command(&line, &chat_context) {
                    continue;
                }
                
                // Handle /channels command
                if handle_channels_command(&line, &chat_context, &channel_keys, &password_protected_channels) {
                    continue;
                }
                
                // Handle /status command
                if handle_status_command(&line, &peers, &chat_context, &nickname, &my_peer_id) {
                    continue;
                }
                
                // Handle /leave command
                if handle_leave_command(
                    &line,
                    &mut chat_context,
                    &mut channel_keys,
                    &mut password_protected_channels,
                    &mut channel_creators,
                    &mut channel_key_commitments,
                    &mut app_state,
                    &blocked_peers,
                    &create_app_state,
                    &nickname,
                    &my_peer_id,
                    &peripheral,
                    cmd_char,
                ).await {
                    continue;
                }
                
                // Handle /pass command
                if handle_pass_command(
                    &line,
                    &chat_context,
                    &mut channel_creators,
                    &mut channel_keys,
                    &mut password_protected_channels,
                    &mut channel_key_commitments,
                    &mut app_state,
                    &blocked_peers,
                    &create_app_state,
                    &nickname,
                    &my_peer_id,
                    &encryption_service,
                    &peripheral,
                    cmd_char,
                ).await {
                    continue;
                }
                
                // Handle /transfer command
                if handle_transfer_command(
                    &line,
                    &chat_context,
                    &mut channel_creators,
                    &password_protected_channels,
                    &channel_keys,
                    &blocked_peers,
                    &create_app_state,
                    &nickname,
                    &my_peer_id,
                    &peers,
                    &peripheral,
                    cmd_char,
                ).await {
                    continue;
                }
                
                // Check for unknown commands
                if line.starts_with("/") {
                    println!("\x1b[93m⚠ Unknown command: {}\x1b[0m", line.split_whitespace().next().unwrap_or(""));
                    println!("\x1b[90mType /help to see available commands.\x1b[0m");
                    continue;
                }
                
                // Check if in DM mode first
                if let ChatMode::PrivateDM { nickname: target_nickname, peer_id: target_peer_id } = &chat_context.current_mode {
                    handle_private_dm_message(
                        &line,
                        &nickname,
                        &my_peer_id,
                        target_nickname,
                        target_peer_id,
                        &mut delivery_tracker,
                        &encryption_service,
                        &peripheral,
                        cmd_char,
                        &chat_context,
                    ).await;
                    continue;
                }
                
                // Regular public/channel message
                handle_regular_message(
                    &line,
                    &nickname,
                    &my_peer_id,
                    &chat_context,
                    &password_protected_channels,
                    &mut channel_keys,
                    &encryption_service,
                    &mut delivery_tracker,
                    &peripheral,
                    cmd_char,
                ).await;

            },

            Some(notification) = notification_stream.next() => {
                // Simple packet logging
                if notification.value.len() >= 2 {
                    let msg_type = notification.value[1];
                    debug_full_println!("[PACKET] Received {} bytes, type: 0x{:02X}", notification.value.len(), msg_type);
                }
                
                match parse_bitchat_packet(&notification.value) {
                    Ok(packet) => {
                        // Ignore our own messages
                        if packet.sender_id_str == my_peer_id {
                            continue;
                        }

                        let mut peers_lock = peers.lock().unwrap();

                     match packet.msg_type {

                         MessageType::Announce => {
                             handle_announce_message(&packet, &mut peers_lock);

                         },

                         MessageType::Message => {
                             handle_message_packet(
                                 &packet,
                                 &notification.value,
                                 &mut peers_lock,
                                 &mut bloom,
                                 &mut discovered_channels,
                                 &mut password_protected_channels,
                                 &mut channel_keys,
                                 &mut chat_context,
                                 &mut delivery_tracker,
                                 &encryption_service,
                                 &peripheral,
                                 cmd_char,
                                 &nickname,
                                 &my_peer_id,
                                 &blocked_peers,
                             ).await;

                         },
                         MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                             handle_fragment_packet(
                                 &packet,
                                 &notification.value,
                                 &mut fragment_collector,
                                 &mut peers_lock,
                                 &mut bloom,
                                 &mut discovered_channels,
                                 &mut password_protected_channels,
                                 &mut chat_context,
                                 &encryption_service,
                                 &peripheral,
                                 cmd_char,
                                 &nickname,
                                 &my_peer_id,
                                 &blocked_peers,
                             ).await;
                         },
                         MessageType::KeyExchange => {
                             handle_key_exchange_message(
                                 &packet,
                                 &mut peers_lock,
                                 &encryption_service,
                                 &peripheral,
                                 cmd_char,
                                 &my_peer_id,
                             ).await;
                         },
                         MessageType::Leave => {
                             handle_leave_message(
                                 &packet,
                                 &mut peers_lock,
                                 &chat_context,
                             );
                         },
                         
                         MessageType::ChannelAnnounce => {
                             handle_channel_announce_message(
                                 &packet,
                                 &mut channel_creators,
                                 &mut password_protected_channels,
                                 &mut channel_keys,
                                 &mut channel_key_commitments,
                                 &mut chat_context,
                                 &blocked_peers,
                                 &app_state.encrypted_channel_passwords,
                                 &nickname,
                                 &create_app_state,
                             );
                         },

                         MessageType::DeliveryAck => {
                             handle_delivery_ack_message(
                                 &packet,
                                 &notification.value,
                                 &encryption_service,
                                 &mut delivery_tracker,
                                 &peripheral,
                                 cmd_char,
                                 &my_peer_id,
                             ).await;
                         },
                        
                        MessageType::DeliveryStatusRequest => {
                            handle_delivery_status_request_message(&packet);
                        },
                        
                        MessageType::ReadReceipt => {
                            handle_read_receipt_message(&packet);
                        },
                        
                        _ => {}

                     }
                    },
                    Err(_e) => {
                        // Silently ignore unparseable packets (following working example)
                    }
                }
            },

             _ = tokio::signal::ctrl_c() => { break; }

        }

    }


    debug_println!("\n[+] Disconnecting...");

    Ok(())

}


async fn find_peripheral(adapter: &btleplug::platform::Adapter) -> Result<Option<Peripheral>, btleplug::Error> {

    for p in adapter.peripherals().await? {

        if let Ok(Some(properties)) = p.properties().await {

            if properties.services.contains(&BITCHAT_SERVICE_UUID) { return Ok(Some(p)); }

        }

    }

    Ok(None)

}





#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_values() {
        // Verify MessageType enum values match the protocol specification
        // This ensures compatibility with Swift and Android implementations
        assert_eq!(MessageType::Announce as u8, 0x01);
        assert_eq!(MessageType::KeyExchange as u8, 0x02);
        assert_eq!(MessageType::Leave as u8, 0x03);
        assert_eq!(MessageType::Message as u8, 0x04);
        assert_eq!(MessageType::FragmentStart as u8, 0x05);
        assert_eq!(MessageType::FragmentContinue as u8, 0x06);
        assert_eq!(MessageType::FragmentEnd as u8, 0x07);
        assert_eq!(MessageType::ChannelAnnounce as u8, 0x08);
        assert_eq!(MessageType::ChannelRetention as u8, 0x09);
        assert_eq!(MessageType::DeliveryAck as u8, 0x0A);
        assert_eq!(MessageType::DeliveryStatusRequest as u8, 0x0B);
        assert_eq!(MessageType::ReadReceipt as u8, 0x0C);
    }

    #[test]
    fn test_protocol_constants() {
        // Verify protocol constants match Swift/Android implementations
        assert_eq!(FLAG_HAS_RECIPIENT, 0x01);
        assert_eq!(FLAG_HAS_SIGNATURE, 0x02);
        assert_eq!(FLAG_IS_COMPRESSED, 0x04);
        assert_eq!(FLAG_HAS_CHANNEL, 0x40);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(BROADCAST_RECIPIENT, [0xFF; 8]);
    }
} 





