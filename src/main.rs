use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Manager, Peripheral};

use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use futures::stream::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;

use bloomfilter::Bloom;
use rand::Rng;
mod tui;
use tui::app::{App, TuiPhase};
use tui::tui as tui_mod;
use tui::ui;
use tui::event;
use crossterm::event as crossterm_event;
use crossterm::event::Event as CrosstermEvent;
use std::time::Duration as StdDuration;



// Debug logging function
fn write_debug_log(message: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = std::io::Write::write_all(&mut file, log_entry.as_bytes());
    }
}

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
mod binary_protocol_utils;
mod binary_encoding;
mod noise_protocol;
mod noise_session;

use encryption::EncryptionService;
use terminal_ux::{ChatContext, ChatMode};
use persistence::{AppState, load_state, save_state};
use packet_parser::{parse_bitchat_packet, generate_keys_and_payload};
use packet_creation::create_bitchat_packet;
use command_handling::{
    handle_name_command,
    handle_join_command, handle_exit_command, handle_reply_command, handle_public_command,
    handle_online_command, handle_channels_command, handle_dm_command, handle_block_command,
    handle_unblock_command, handle_clear_command, handle_leave_command,
    handle_pass_command, handle_transfer_command, handle_fingerprint_command
};
use message_handlers::{handle_private_dm_message, handle_regular_message};
use notification_handlers::{
    handle_announce_message,
    handle_message_packet, handle_fragment_packet, handle_key_exchange_message,
    handle_leave_message, handle_channel_announce_message, handle_delivery_ack_message,
    handle_delivery_status_request_message, handle_read_receipt_message,
    handle_noise_handshake_init, handle_noise_handshake_resp, handle_noise_encrypted_message,
    handle_noise_identity_announce
};
use crate::data_structures::{
    DebugLevel, DEBUG_LEVEL, MessageType, Peer,
    DeliveryTracker, FragmentCollector, BITCHAT_SERVICE_UUID, BITCHAT_CHARACTERISTIC_UUID,
};
use crate::noise_session::NoiseSessionManager;
use x25519_dalek::StaticSecret;
use crate::notification_handlers::{handle_handshake_request_message};

// This function now takes a UI channel sender to direct its output.
// It still reads from stdin directly but sends user input over its own channel.
async fn setup_bluetooth_connection(ui_tx: mpsc::Sender<String>) -> Result<Peripheral, Box<dyn std::error::Error + Send + Sync>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().nth(0) {
        Some(adapter) => adapter,
        None => {
            let error_message = [
                "\n\x1b[91m❌ No Bluetooth adapter found\x1b[0m",
                "\x1b[90mPlease check:\x1b[0m",
                "\x1b[90m  • Your device has Bluetooth hardware\x1b[0m",
                "\x1b[90m  • Bluetooth is enabled in system settings\x1b[0m",
                "\x1b[90m  • You have permission to use Bluetooth\x1b[0m",
            ].join("\n");
            ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
            return Err("No Bluetooth adapter found.".into());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    ui_tx.send("\x1b[90m» Scanning for bitchat service...\x1b[0m\n".to_string()).await.map_err(|e| e.to_string())?;

    // We can't use debug_println! here directly as it's not async-aware and prints directly.
    // Instead, we replicate its logic and send to the UI channel.
    if unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
        ui_tx.send("[1] Scanning for bitchat service...\n".to_string()).await.map_err(|e| e.to_string())?;
    }
    
    let start_time = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(15);
    
    let peripheral = loop {
        if let Some(p) = find_peripheral(&adapter).await? {
            ui_tx.send("\x1b[90m» Found bitchat service! Connecting...\x1b[0m\n".to_string()).await.map_err(|e| e.to_string())?;
            if unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
                ui_tx.send("[1] Match Found! Connecting...\n".to_string()).await.map_err(|e| e.to_string())?;
            }
            adapter.stop_scan().await?;
            break p;
        }
        
        // Check if we've exceeded the timeout
        if start_time.elapsed() >= timeout_duration {
            adapter.stop_scan().await?;
            let error_message = [
                "\n\x1b[91m❌ No BitChat service found\x1b[0m",
                "\x1b[90mScan timed out after 15 seconds.\x1b[0m",
                "\x1b[90mPlease check:\x1b[0m",
                "\x1b[90m  • Another device is running BitChat\x1b[0m",
                "\x1b[90m  • Bluetooth is enabled on both devices\x1b[0m",
                "\x1b[90m  • You're within Bluetooth range\x1b[0m",
                "\x1b[90m  • The other device is advertising the BitChat service\x1b[0m",
            ].join("\n");
            ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
            return Err("No BitChat service found within 30 seconds.".into());
        }
        
        time::sleep(Duration::from_secs(1)).await;
    };

    if let Err(e) = peripheral.connect().await {
        let error_message = format!("\n\x1b[91m❌ Connection failed\x1b[0m\n\x1b[90mReason: {}\x1b[0m\n\x1b[90mPlease check:\x1b[0m\n\x1b[90m  • Bluetooth is enabled\x1b[0m\n\x1b[90m  •  The other device is running BitChat\x1b[0m\n\x1b[90m •  You're within range\x1b[0m\n\n\x1b[90mTry running the command again.\x1b[0m\n", e);
        ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
        return Err(format!("Connection failed: {}", e).into());
    }

    Ok(peripheral)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Channel for user input from the TUI input box
    let (input_tx, mut input_rx) = mpsc::channel::<String>(10);
    // Channel for all UI output. All parts of the application will send strings here.
    let (ui_tx, mut ui_rx) = mpsc::channel::<String>(100);

    // Load saved state to get the nickname before initializing TUI
    let saved_state = load_state();
    let saved_nickname = saved_state.nickname.clone().unwrap_or_else(|| "anonymous".to_string());
    let saved_nickname_clone = saved_nickname.clone();
    
    // Initialize the TUI with the saved nickname
    let mut terminal = tui_mod::init().expect("Failed to initialize TUI");
    let mut app = App::new_with_nickname(saved_nickname);

    // Spawn Bluetooth connection setup in the background
    let ui_tx_clone = ui_tx.clone();
    let mut bt_handle = Some(tokio::spawn(async move {
        match setup_bluetooth_connection(ui_tx_clone.clone()).await {
            Ok(peripheral) => {
                let _ = ui_tx_clone.send("__CONNECTED__".to_string()).await;
                Ok(peripheral)
            },
            Err(e) => {
                let _ = ui_tx_clone.send(format!("__ERROR__{}", e)).await;
                Err(e)
            }
        }
    }));

    // State for after connection
    let mut peripheral: Option<Peripheral> = None;
    let mut notification_stream = None;
    let mut _characteristics = None;
    let mut cmd_char = None;
    let mut post_connect_initialized = false;
    let mut my_peer_id = String::new();
    let mut app_state: Option<persistence::AppState> = None;
    let mut nickname = String::new();
    let mut encryption_service = None;
    let mut _key_exchange_payload = None;
    let mut _key_exchange_packet = None;
    let mut peers: Option<Arc<Mutex<HashMap<String, Peer>>>> = None;
    let mut bloom: Option<Bloom<String>> = None;
    let mut fragment_collector: Option<FragmentCollector> = None;
    let mut delivery_tracker: Option<DeliveryTracker> = None;
    let mut chat_context: Option<ChatContext> = None;
    let mut channel_keys: Option<HashMap<String, [u8; 32]>> = None;
    let mut _chat_messages: Option<HashMap<String, Vec<String>>> = None;
    let mut blocked_peers: Option<HashSet<String>> = None;
    let mut channel_creators: Option<HashMap<String, String>> = None;
    let mut password_protected_channels: Option<HashSet<String>> = None;
    let mut channel_key_commitments: Option<HashMap<String, String>> = None;
    let mut discovered_channels: Option<HashSet<String>> = None;
    let mut _favorites: Option<HashSet<String>> = None;
    let mut _identity_key: Option<Vec<u8>> = None;
    let mut create_app_state: Option<Box<dyn Fn(&HashSet<String>, &HashMap<String, String>, &Vec<String>, &HashSet<String>, &HashMap<String, String>, &HashMap<String, persistence::EncryptedPassword>, &str) -> AppState + Send + Sync>> = None;
    let mut noise_session_manager: Option<NoiseSessionManager> = None;

    let mut last_tick = std::time::Instant::now();
    let tick_rate = StdDuration::from_millis(100);
    'mainloop: loop {
        // 1. Handle UI messages
        while let Ok(msg) = ui_rx.try_recv() {
            if msg == "__CONNECTED__" {
                app.transition_to_connected();
                // Await the bt_handle to get the peripheral
                if peripheral.is_none() {
                    if let Ok(Ok(periph)) = bt_handle.take().unwrap().await {
                        peripheral = Some(periph);
                    }
                }
            } else if msg.starts_with("__ERROR__") {
                let err = msg.trim_start_matches("__ERROR__").to_string();
                app.transition_to_error(err);
            } else if matches!(app.phase, tui::app::TuiPhase::Connecting) {
                app.add_popup_message(msg);
            } else {
                app.add_log_message(msg);
            }
        }

        // Post-connection initialization (only once)
        if !post_connect_initialized && matches!(app.phase, tui::app::TuiPhase::Connected) {
            if let Some(peripheral) = &peripheral {
                // Discover services, get characteristics, subscribe, etc.
                let _ = peripheral.discover_services().await;
                let chars = peripheral.characteristics();
                let cmd = chars.iter().find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID).expect("Characteristic not found.").clone();
                let _ = peripheral.subscribe(&cmd).await;
                notification_stream = Some(peripheral.notifications().await.unwrap());
                _characteristics = Some(chars);
                cmd_char = Some(cmd);
                // All the rest of the state initialization from the old main goes here
                // ...
                // Generate peer_id, load state, etc.
                let mut peer_id_bytes = [0u8; 4];
                rand::thread_rng().fill(&mut peer_id_bytes);
                my_peer_id = hex::encode(&peer_id_bytes);
                app_state = Some(saved_state.clone());
                nickname = saved_nickname_clone.clone();
                encryption_service = Some(Arc::new(EncryptionService::new()));
                let (kxp, _) = generate_keys_and_payload(encryption_service.as_ref().unwrap());
                _key_exchange_payload = Some(kxp.clone());
                _key_exchange_packet = Some(create_bitchat_packet(&my_peer_id, MessageType::KeyExchange, kxp));
                let _ = peripheral.write(&cmd_char.as_ref().unwrap(), &_key_exchange_packet.as_ref().unwrap(), WriteType::WithoutResponse).await;
                time::sleep(Duration::from_millis(500)).await;
                let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());
                let _ = peripheral.write(&cmd_char.as_ref().unwrap(), &announce_packet, WriteType::WithoutResponse).await;
                // ... (rest of state initialization as before)
                // Set up all the state variables as in the old main
                peers = Some(Arc::new(Mutex::new(HashMap::new())));
                bloom = Some(Bloom::new_for_fp_rate(500, 0.01));
                fragment_collector = Some(FragmentCollector::new());
                delivery_tracker = Some(DeliveryTracker::new());
                chat_context = Some(ChatContext::new());
                channel_keys = Some(HashMap::new());
                _chat_messages = Some(HashMap::new());
                blocked_peers = Some(app_state.as_ref().unwrap().blocked_peers.clone());
                channel_creators = Some(app_state.as_ref().unwrap().channel_creators.clone());
                password_protected_channels = Some(app_state.as_ref().unwrap().password_protected_channels.clone());
                channel_key_commitments = Some(app_state.as_ref().unwrap().channel_key_commitments.clone());
                discovered_channels = Some(HashSet::new());
                _favorites = Some(app_state.as_ref().unwrap().favorites.clone());
                _identity_key = app_state.as_ref().unwrap().identity_key.clone();
                // ...
                // Set up the create_app_state closure
                let favs = _favorites.clone();
                let id_key = _identity_key.clone();
                let noise_static_key = app_state.as_ref().unwrap().noise_static_key.clone();
                create_app_state = Some(Box::new(move |blocked, creators, channels, protected, commitments, encrypted_passwords, current_nickname| {
        AppState {
            nickname: Some(current_nickname.to_string()),
            blocked_peers: blocked.clone(),
            channel_creators: creators.clone(),
            joined_channels: channels.clone(),
            password_protected_channels: protected.clone(),
            channel_key_commitments: commitments.clone(),
                        favorites: favs.clone().unwrap_or_default(),
                        identity_key: id_key.clone(),
                        noise_static_key: noise_static_key.clone(),
            encrypted_channel_passwords: encrypted_passwords.clone(),
        }
                }));
                post_connect_initialized = true;
                
                // Initialize TUI blocked list with current blocked users
                if let (Some(blocked_peers), Some(peers), Some(encryption_service)) = (
                    blocked_peers.as_ref(), peers.as_ref(), encryption_service.as_ref()
                ) {
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
                }
                // Initialize Noise session manager
                let static_secret = if let Some(noise_key_bytes) = &app_state.as_ref().unwrap().noise_static_key {
                    let key_array: [u8; 32] = noise_key_bytes.as_slice().try_into().unwrap();
                    StaticSecret::from(key_array)
                } else {
                    StaticSecret::random_from_rng(&mut rand::thread_rng())
                };
                
                let mut temp_noise_session_manager = NoiseSessionManager::new(static_secret);
                
                // Set up session callbacks (matching Swift implementation)
                temp_noise_session_manager.set_on_session_established(|peer_id, remote_static_key| {
                    debug_full_println!("[NOISE] Session established with {} (remote key: {:?})", peer_id, &remote_static_key.to_bytes()[..8]);
                });
                
                temp_noise_session_manager.set_on_session_failed(|peer_id, error| {
                    debug_full_println!("[NOISE] Session failed with {}: {:?}", peer_id, error);
                });

                // Set up peer authentication callback (matching Swift implementation)
                temp_noise_session_manager.set_on_peer_authenticated(|peer_id, fingerprint| {
                    debug_full_println!("[NOISE] Peer authenticated: {} (fingerprint: {})", peer_id, &fingerprint[..16]);
                    // TODO: Update UI encryption status here
                });

                // Set up handshake required callback (matching Swift implementation)
                temp_noise_session_manager.set_on_handshake_required(|peer_id| {
                    debug_full_println!("[NOISE] Handshake required for peer: {}", peer_id);
                    // TODO: Update UI encryption status here
                });
                
                noise_session_manager = Some(temp_noise_session_manager);
                
                // Set the noise session manager in the encryption service
                if let Some(encryption_service) = &mut encryption_service {
                    // We can't clone NoiseSessionManager, so we'll set it up later
                    // The encryption service will be updated when needed
                }
            }
        }

        // 2. Handle Bluetooth notifications (async)
        if let (Some(notification_stream), true) = (notification_stream.as_mut(), post_connect_initialized) {
            if let Ok(Some(notification)) = tokio::time::timeout(std::time::Duration::from_millis(1), notification_stream.next()).await {
                let mut peers_lock = peers.as_ref().unwrap().lock().await;
                let ui_tx = ui_tx.clone();
                
                // Process notification
                write_debug_log(&format!("Processing notification from characteristic"));
                write_debug_log(&format!("Raw notification data: {} bytes", notification.value.len()));
                
                // Log the raw bytes for debugging
                write_debug_log(&format!("Raw bytes: {:?}", notification.value));
                
                match parse_bitchat_packet(&notification.value) {
                    Ok(packet) => {
                        if packet.sender_id_str == my_peer_id { continue; }
                        
                        write_debug_log(&format!("Successfully parsed packet: type={:?}, sender_id='{}', recipient_id='{:?}'", 
                            packet.msg_type, packet.sender_id_str, packet.recipient_id_str));
                        
                        // Handle different packet types
                        match packet.msg_type {
                            MessageType::Announce => {
                                write_debug_log("Processing Announce packet");
                                handle_announce_message(&packet, &mut peers_lock, ui_tx.clone()).await;
                            }
                            MessageType::Message => {
                                write_debug_log("Processing Message packet");
                                handle_message_packet(&packet, &notification.value, &mut peers_lock, bloom.as_mut().unwrap(), discovered_channels.as_mut().unwrap(), password_protected_channels.as_mut().unwrap(), channel_keys.as_mut().unwrap(), chat_context.as_mut().unwrap(), delivery_tracker.as_mut().unwrap(), encryption_service.as_ref().unwrap(), noise_session_manager.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &nickname, &my_peer_id, blocked_peers.as_ref().unwrap(), ui_tx.clone()).await;
                            }
                            MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                                write_debug_log("Processing Fragment packet");
                                handle_fragment_packet(&packet, &notification.value, fragment_collector.as_mut().unwrap(), &mut peers_lock, bloom.as_mut().unwrap(), discovered_channels.as_mut().unwrap(), password_protected_channels.as_mut().unwrap(), chat_context.as_mut().unwrap(), encryption_service.as_ref().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &nickname, &my_peer_id, blocked_peers.as_ref().unwrap(), ui_tx.clone()).await;
                            }
                            MessageType::KeyExchange => {
                                write_debug_log("Processing KeyExchange packet");
                                handle_key_exchange_message(&packet, &mut peers_lock, encryption_service.as_ref().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await;
                            }
                            MessageType::Leave => {
                                write_debug_log("Processing Leave packet");
                                handle_leave_message(&packet, &mut peers_lock, chat_context.as_ref().unwrap(), ui_tx.clone()).await;
                            }
                            MessageType::ChannelAnnounce => {
                                write_debug_log("Processing ChannelAnnounce packet");
                                // Get the channel name from the packet payload
                                let payload_str = String::from_utf8_lossy(&packet.payload);
                                let parts: Vec<&str> = payload_str.split('|').collect();
                                if parts.len() >= 3 {
                                    let channel_name = parts[0].to_string();
                                    // Don't add #public as a regular channel
                                    if channel_name != "#public" && !app.channels.contains(&channel_name) {
                                        app.channels.push(channel_name.clone());
                                    }
                                }
                                handle_channel_announce_message(&packet, channel_creators.as_mut().unwrap(), password_protected_channels.as_mut().unwrap(), channel_keys.as_mut().unwrap(), channel_key_commitments.as_mut().unwrap(), chat_context.as_mut().unwrap(), blocked_peers.as_ref().unwrap(), &app_state.as_ref().unwrap().encrypted_channel_passwords, &nickname, create_app_state.as_ref().unwrap().as_ref(), ui_tx.clone()).await;
                            }
                            MessageType::DeliveryAck => {
                                write_debug_log("Processing DeliveryAck packet");
                                handle_delivery_ack_message(&packet, &notification.value, encryption_service.as_ref().unwrap(), delivery_tracker.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await;
                            }
                            MessageType::DeliveryStatusRequest => {
                                write_debug_log("Processing DeliveryStatusRequest packet");
                                handle_delivery_status_request_message(&packet, ui_tx.clone()).await;
                            }
                            MessageType::ReadReceipt => {
                                write_debug_log("Processing ReadReceipt packet");
                                handle_read_receipt_message(&packet, ui_tx.clone()).await;
                            }
                            MessageType::NoiseHandshakeInit => {
                                write_debug_log("Processing NoiseHandshakeInit packet");
                                handle_noise_handshake_init(&packet, noise_session_manager.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await;
                            }
                            MessageType::NoiseHandshakeResp => {
                                write_debug_log("Processing NoiseHandshakeResp packet");
                                handle_noise_handshake_resp(&packet, noise_session_manager.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await;
                            }
                            MessageType::NoiseEncrypted => {
                                write_debug_log(&format!("Processing NoiseEncrypted packet from peer: {}", packet.sender_id_str));
                                write_debug_log(&format!("Packet payload length: {}", packet.payload.len()));
                                write_debug_log(&format!("Packet first 16 bytes: {:?}", &packet.payload[..std::cmp::min(16, packet.payload.len())]));
                                handle_noise_encrypted_message(
                                    &packet, 
                                    noise_session_manager.as_mut().unwrap(), 
                                    &mut peers_lock, 
                                    bloom.as_mut().unwrap(), 
                                    discovered_channels.as_mut().unwrap(), 
                                    password_protected_channels.as_mut().unwrap(), 
                                    channel_keys.as_mut().unwrap(), 
                                    chat_context.as_mut().unwrap(), 
                                    delivery_tracker.as_mut().unwrap(), 
                                    encryption_service.as_ref().unwrap(), 
                                    peripheral.as_ref().unwrap(), 
                                    cmd_char.as_ref().unwrap(), 
                                    &nickname, 
                                    &my_peer_id, 
                                    blocked_peers.as_ref().unwrap(), 
                                    ui_tx.clone()
                                ).await;
                            }
                            MessageType::NoiseIdentityAnnounce => {
                                write_debug_log(&format!("Processing NoiseIdentityAnnounce from peer: {}", packet.sender_id_str));
                                handle_noise_identity_announce(
                                    &packet,
                                    &mut peers_lock,
                                    noise_session_manager.as_mut().unwrap(),
                                    ui_tx.clone(),
                                ).await;
                            }
                            MessageType::HandshakeRequest => {
                                write_debug_log("Processing HandshakeRequest packet");
                                handle_handshake_request_message(&packet, noise_session_manager.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await;
                            }
                            _ => {
                                write_debug_log(&format!("Ignoring unknown packet type: {:?}", packet.msg_type));
                            }
                        }
                    }
                    Err(e) => {
                        write_debug_log(&format!("Failed to parse packet: {}", e));
                    }
                }
            }
        }

        // 3. Handle input events
        if crossterm_event::poll(tick_rate.saturating_sub(last_tick.elapsed())).unwrap_or(false) {
            if let CrosstermEvent::Key(key_event) = crossterm_event::read().unwrap() {
                event::handle_key_event(&mut app, key_event, &input_tx);
            }
        }
        // 4. Handle pending channel switches
        if let Some(channel_name) = app.pending_channel_switch.take() {
            // Update backend chat_context to switch to the selected channel
            if channel_name == "#public" {
                chat_context.as_mut().unwrap().switch_to_public();
            } else {
                chat_context.as_mut().unwrap().switch_to_channel(&channel_name);
            }
        }
        
        // 4.5. Handle pending DM switches
        if let Some((target_nickname, _)) = app.pending_dm_switch.take() {
            // Find the peer ID for the nickname and switch to DM mode
            let peer_id = {
                let peers = peers.as_ref().unwrap().lock().await;
                peers.iter()
                    .find(|(_, peer)| peer.nickname.as_deref() == Some(&target_nickname))
                    .map(|(id, _)| id.clone())
            };
            
            if let Some(target_peer_id) = peer_id {
                chat_context.as_mut().unwrap().enter_dm_mode(&target_nickname, &target_peer_id);
            }
        }
        
        // 4.6. Handle pending nickname updates
        if let Some(new_nickname) = app.pending_nickname_update.take() {
            // Update backend nickname
            nickname = new_nickname.clone();
            // Update app state if it exists
            if let Some(state) = app_state.as_mut() {
                state.nickname = Some(new_nickname.clone());
            }
            // Update TUI nickname immediately
            app.nickname = new_nickname.clone();
            
            // Announce the new nickname to other peers
            if let (Some(peripheral), Some(cmd_char)) = (peripheral.as_ref(), cmd_char.as_ref()) {
                let announce_packet = create_bitchat_packet(&my_peer_id, crate::data_structures::MessageType::Announce, new_nickname.as_bytes().to_vec());
                if peripheral.write(cmd_char, &announce_packet, btleplug::api::WriteType::WithoutResponse).await.is_err() {
                    let error_msg = "Failed to announce new nickname";
                    app.add_log_message(format!("system: {}", error_msg));
                }
            }
            
            // Save the updated state
            if let (Some(chat_context), Some(blocked_peers), Some(channel_creators), Some(password_protected_channels), Some(channel_key_commitments), Some(app_state), Some(create_app_state)) = (
                chat_context.as_ref(), blocked_peers.as_ref(), channel_creators.as_ref(), 
                password_protected_channels.as_ref(), channel_key_commitments.as_ref(), 
                app_state.as_ref(), create_app_state.as_ref()
            ) {
                let channels_vec: Vec<String> = chat_context.active_channels.iter().cloned().collect();
                let state_to_save = create_app_state(blocked_peers, channel_creators, &channels_vec, password_protected_channels, channel_key_commitments, &app_state.encrypted_channel_passwords, &new_nickname);
                if let Err(e) = save_state(&state_to_save) {
                    let error_msg = format!("Warning: Could not save nickname: {}", e);
                    app.add_log_message(format!("system: {}", error_msg));
                }
            }
            
            // Send system message to confirm nickname change
            let system_msg = format!("Nickname changed to: {}", new_nickname);
            app.add_log_message(format!("system: {}", system_msg));
        }
        
        // 4.7. Handle pending conversation clear
        if app.pending_clear_conversation {
            app.pending_clear_conversation = false;
            app.clear_current_conversation();
            // Send confirmation message
            let context_msg = match &chat_context.as_ref().unwrap().current_mode {
                ChatMode::Public => "Cleared public chat".to_string(),
                ChatMode::Channel(channel) => format!("Cleared channel {}", channel),
                ChatMode::PrivateDM { nickname, .. } => format!("Cleared DM with {}", nickname),
            };
            app.add_log_message(format!("system: {}", context_msg));
        }
        
        // 4.7. Handle pending connection retry
        if app.pending_connection_retry {
            app.pending_connection_retry = false;
            
            // Reset all connection-related state
            peripheral = None;
            notification_stream = None;
            _characteristics = None;
            cmd_char = None;
            post_connect_initialized = false;
            my_peer_id = String::new();
            app_state = None;
            nickname = String::new();
            encryption_service = None;
            _key_exchange_payload = None;
            _key_exchange_packet = None;
            peers = None;
            bloom = None;
            fragment_collector = None;
            delivery_tracker = None;
            chat_context = None;
            channel_keys = None;
            _chat_messages = None;
            blocked_peers = None;
            channel_creators = None;
            password_protected_channels = None;
            channel_key_commitments = None;
            discovered_channels = None;
            _favorites = None;
            _identity_key = None;
            create_app_state = None;
            noise_session_manager = None;
            
            // Spawn new Bluetooth connection setup
            let ui_tx_clone = ui_tx.clone();
            bt_handle = Some(tokio::spawn(async move {
                match setup_bluetooth_connection(ui_tx_clone.clone()).await {
                    Ok(peripheral) => {
                        let _ = ui_tx_clone.send("__CONNECTED__".to_string()).await;
                        Ok(peripheral)
                    },
                    Err(e) => {
                        let _ = ui_tx_clone.send(format!("__ERROR__{}", e)).await;
                        Err(e)
                    }
                }
            }));
        }
        
        // 5. Handle input from the input box (from input_rx)
        while let Ok(line) = input_rx.try_recv() {
            let ui_tx = ui_tx.clone();
            // Handle /exit immediately to avoid panics during connecting phase
            if line.trim() == "/exit" {
                app.should_quit = true;
                break 'mainloop;
            }
            // Check if we're in connecting phase (popup is shown) and show wait message for any command
            if matches!(app.phase, TuiPhase::Connecting) && line.starts_with("/") {
                app.add_log_message("system: Please wait for Bluetooth connection to be established before using commands.".to_string());
                continue;
            }
            if line == "/help" {
                let help_text = terminal_ux::get_help_text();
                let lines: Vec<&str> = help_text.split('\n').collect();
                for line in lines {
                    let trimmed_line = line.trim();
                    if !trimmed_line.is_empty() {
                        app.add_log_message(format!("system: {}", trimmed_line));
                    }
                }
                continue;
            }
            
            // Check if we're connected before handling commands that require connection
            if !app.connected && !line.starts_with("/help") && !line.starts_with("/exit") {
                app.add_log_message("system: Please wait for Bluetooth connection to be established before using commands.".to_string());
                continue;
            }
            
            if handle_name_command(&line, &mut nickname, &my_peer_id, peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), blocked_peers.as_ref().unwrap(), channel_creators.as_ref().unwrap(), chat_context.as_mut().unwrap(), password_protected_channels.as_ref().unwrap(), channel_key_commitments.as_ref().unwrap(), app_state.as_ref().unwrap(), create_app_state.as_ref().unwrap().as_ref(), ui_tx.clone()).await { 
                // Set the pending nickname update signal to trigger TUI update
                app.pending_nickname_update = Some(nickname.clone());
                continue; 
            }
            if line.starts_with("/j ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let channel_name = parts.get(1).unwrap_or(&"").to_string();
                
                if !channel_name.is_empty() && channel_name.starts_with('#') {
                    // Update TUI state
                    app.join_channel(channel_name.clone());
                    
                    // Check if this is a password-protected channel
                    let is_password_protected = password_protected_channels.as_ref().unwrap().contains(&channel_name);
                    let has_password = channel_keys.as_ref().unwrap().contains_key(&channel_name);
                    
                    // Send appropriate system message to TUI
                    let system_msg = if is_password_protected && has_password {
                        format!("Joined password-protected channel {}", channel_name)
                    } else {
                        format!("Joined channel {}", channel_name)
                    };
                    app.add_log_message(format!("system: {}", system_msg));
                    
                    // Handle backend join logic
                    if handle_join_command(&line, password_protected_channels.as_ref().unwrap(), channel_keys.as_mut().unwrap(), discovered_channels.as_mut().unwrap(), chat_context.as_mut().unwrap(), channel_key_commitments.as_mut().unwrap(), app_state.as_mut().unwrap(), create_app_state.as_ref().unwrap().as_ref(), &nickname, peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), channel_creators.as_ref().unwrap(), blocked_peers.as_ref().unwrap(), ui_tx.clone(), &mut app).await { 
                        // Explicitly switch UI to the joined channel after successful join
                        app.switch_to_channel(channel_name.clone());
                        continue;
                    }
                } else {
                    let _ = ui_tx.send("\x1b[93m⚠ Usage: /j #<channel> [password]\x1b[0m\n".to_string()).await;
                    continue;
                }
            }
            if handle_exit_command(&line, blocked_peers.as_ref().unwrap(), channel_creators.as_ref().unwrap(), chat_context.as_ref().unwrap(), password_protected_channels.as_ref().unwrap(), channel_key_commitments.as_ref().unwrap(), app_state.as_ref().unwrap(), create_app_state.as_ref().unwrap().as_ref(), &nickname, ui_tx.clone(), &mut app).await { break; }
            if handle_reply_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await { 
                // Update TUI to reflect DM mode if we entered DM mode
                if let ChatMode::PrivateDM { nickname: target_nickname, .. } = &chat_context.as_ref().unwrap().current_mode {
                    app.switch_to_dm(target_nickname.clone());
                }
                continue; 
            }
            if handle_public_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await { 
                // Update TUI to reflect public chat mode
                app.switch_to_public();
                continue; 
            }
            if handle_online_command(&line, peers.as_ref().unwrap(), ui_tx.clone()).await { continue; }
            if handle_channels_command(&line, chat_context.as_ref().unwrap(), channel_keys.as_ref().unwrap(), password_protected_channels.as_ref().unwrap(), ui_tx.clone()).await { continue; }
            if handle_dm_command(&line, chat_context.as_mut().unwrap(), peers.as_ref().unwrap(), &nickname, &my_peer_id, delivery_tracker.as_mut().unwrap(), encryption_service.as_ref().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), ui_tx.clone(), &mut app, noise_session_manager.as_mut().unwrap()).await { 
                // Update TUI to reflect DM mode if we entered DM mode
                if let ChatMode::PrivateDM { nickname: target_nickname, .. } = &chat_context.as_ref().unwrap().current_mode {
                    app.switch_to_dm(target_nickname.clone());
                }
                continue; 
            }
            if handle_block_command(&line, blocked_peers.as_mut().unwrap(), peers.as_ref().unwrap(), encryption_service.as_ref().unwrap(), channel_creators.as_ref().unwrap(), chat_context.as_mut().unwrap(), password_protected_channels.as_ref().unwrap(), channel_key_commitments.as_ref().unwrap(), app_state.as_ref().unwrap(), create_app_state.as_ref().unwrap().as_ref(), &nickname, ui_tx.clone(), &mut app).await { continue; }
            if handle_unblock_command(&line, blocked_peers.as_mut().unwrap(), peers.as_ref().unwrap(), encryption_service.as_ref().unwrap(), channel_creators.as_ref().unwrap(), chat_context.as_mut().unwrap(), password_protected_channels.as_ref().unwrap(), channel_key_commitments.as_ref().unwrap(), app_state.as_ref().unwrap(), create_app_state.as_ref().unwrap().as_ref(), &nickname, ui_tx.clone(), &mut app).await { continue; }
            if handle_clear_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await { 
                app.pending_clear_conversation = true;
                continue; 
            }
            if line == "/status" {
                let peer_count = peers.as_ref().unwrap().lock().await.len();
                let channel_count = chat_context.as_ref().unwrap().active_channels.len();
                let dm_count = chat_context.as_ref().unwrap().active_dms.len();
                
                let status_lines = vec![
                    "━━━ Connection Status ━━━".to_string(),
                    "▶ Network".to_string(),
                    format!("  Connected peers: {}", peer_count),
                    format!("  Active channels: {}", channel_count),
                    format!("  Active DMs: {}", dm_count),
                    "▶ Your Info".to_string(),
                    format!("  Nickname: {}", nickname),
                    format!("  ID: {}", my_peer_id),
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string(),
                ];
                
                for line in status_lines {
                    app.add_log_message(format!("system: {}", line));
                }
                continue;
            }
            if handle_leave_command(&line, chat_context.as_mut().unwrap(), channel_keys.as_mut().unwrap(), app_state.as_mut().unwrap(), &my_peer_id, peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), ui_tx.clone(), &mut app).await { 
                // Update TUI to reflect public chat mode (since leaving a channel switches to public)
                app.switch_to_public();
                continue; 
            }
            if handle_pass_command(&line, chat_context.as_ref().unwrap(), channel_creators.as_mut().unwrap(), channel_keys.as_mut().unwrap(), password_protected_channels.as_mut().unwrap(), app_state.as_mut().unwrap(), &my_peer_id, peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), ui_tx.clone()).await { 
                // Add system message to TUI to indicate password was set
                if let ChatMode::Channel(channel) = &chat_context.as_ref().unwrap().current_mode {
                    let system_msg = format!("Password set for channel {}", channel);
                    app.add_log_message(format!("system: {}", system_msg));
                }
                continue; 
            }
            if handle_transfer_command(&line, chat_context.as_ref().unwrap(), channel_creators.as_mut().unwrap(), password_protected_channels.as_ref().unwrap(), channel_keys.as_ref().unwrap(), &my_peer_id, peers.as_ref().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), ui_tx.clone()).await { continue; }
            if handle_fingerprint_command(&line, encryption_service.as_ref().unwrap(), ui_tx.clone()).await { continue; }
            if line.starts_with("/") {
                let unknown_cmd = line.split_whitespace().next().unwrap_or("");
                let unknown_cmd_msg = format!("⚠  Unknown command: {}", unknown_cmd);
                app.add_log_message(format!("system: {}", unknown_cmd_msg));
                app.add_log_message("system: Type /help to see available commands.".to_string());
                continue;
            }
            // Check if we're connected before handling regular messages
            if !app.connected {
                app.add_log_message("system: Please wait for Bluetooth connection to be established before sending messages.".to_string());
                continue;
            }
            
            if let ChatMode::PrivateDM { nickname: target_nickname, peer_id: target_peer_id } = &chat_context.as_ref().unwrap().current_mode {
                if let Err(e) = handle_private_dm_message(&line, target_peer_id, &mut noise_session_manager, peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), &my_peer_id, ui_tx.clone()).await {
                    app.add_log_message(format!("system: Failed to send DM: {}", e));
                }
                continue;
            }
            handle_regular_message(&line, &nickname, &my_peer_id, chat_context.as_ref().unwrap(), password_protected_channels.as_ref().unwrap(), channel_keys.as_mut().unwrap(), encryption_service.as_ref().unwrap(), delivery_tracker.as_mut().unwrap(), peripheral.as_ref().unwrap(), cmd_char.as_ref().unwrap(), ui_tx.clone(), &mut app).await;
        }
        // 6. Render the UI
        terminal.draw(|f| ui::render(&mut app, f)).unwrap();
        // 7. Exit if requested
        if app.should_quit {
            break 'mainloop;
        }
        last_tick = std::time::Instant::now();
    }
    // Restore the terminal
    tui_mod::restore().expect("Failed to restore terminal");
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
        assert_eq!(crate::data_structures::FLAG_HAS_RECIPIENT, 0x01);
        assert_eq!(crate::data_structures::FLAG_HAS_SIGNATURE, 0x02);
        assert_eq!(crate::data_structures::FLAG_IS_COMPRESSED, 0x04);
        assert_eq!(crate::data_structures::SIGNATURE_SIZE, 64);
        assert_eq!(crate::data_structures::BROADCAST_RECIPIENT, [0xFF; 8]);
    }
}
