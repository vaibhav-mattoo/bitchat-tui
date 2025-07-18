use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Manager, Peripheral};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use futures::stream::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::env;
use bloomfilter::Bloom;
use rand::Rng;

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

use encryption::EncryptionService;
use terminal_ux::{ChatContext, ChatMode};
use persistence::{AppState, load_state, decrypt_password};
use packet_parser::{parse_bitchat_packet, generate_keys_and_payload};
use packet_creation::create_bitchat_packet;
use command_handling::{
    handle_number_switching, handle_help_command, handle_name_command, handle_list_command,
    handle_join_command, handle_exit_command, handle_reply_command, handle_public_command,
    handle_online_command, handle_channels_command, handle_dm_command, handle_block_command,
    handle_unblock_command, handle_clear_command, handle_status_command, handle_leave_command,
    handle_pass_command, handle_transfer_command
};
use message_handlers::{handle_private_dm_message, handle_regular_message};
use notification_handlers::{
    handle_announce_message,
    handle_message_packet, handle_fragment_packet, handle_key_exchange_message,
    handle_leave_message, handle_channel_announce_message, handle_delivery_ack_message,
    handle_delivery_status_request_message, handle_read_receipt_message
};
use crate::data_structures::{
    DebugLevel, DEBUG_LEVEL, MessageType, Peer,
    DeliveryTracker, FragmentCollector, VERSION, BITCHAT_SERVICE_UUID, BITCHAT_CHARACTERISTIC_UUID,
};

// This function now takes a UI channel sender to direct its output.
// It still reads from stdin directly but sends user input over its own channel.
fn spawn_input_handler(input_tx: mpsc::Sender<String>, ui_tx: mpsc::Sender<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stdin = BufReader::new(io::stdin()).lines();

        // Send ASCII art and startup messages to the UI task
        let logo_and_header = [
            "\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\",
            "## |      \\__|  ## |              ## |                 ## |",
            "#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\",
            "##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|",
            "## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |",
            "## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\",
            "#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |",
            "\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m",
            &format!("\n\x1b[38;5;40mâ”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\x1b[0m"),
            "\x1b[37mDecentralized â€¢ Encrypted â€¢ Peer-to-Peer â€¢ Open Source\x1b[0m",
            &format!("\x1b[37m                bitch@ the terminal {}\x1b[0m", VERSION),
            &format!("\x1b[38;5;40mâ”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\x1b[0m\n"),
        ];

        for line in logo_and_header {
            if ui_tx.send(format!("{}\n", line)).await.is_err() { return; }
        }

        loop {
            // Send the prompt to the UI task
            if ui_tx.send("> ".to_string()).await.is_err() { break; }

            match stdin.next_line().await {
                Ok(Some(line)) => {
                    if input_tx.send(line).await.is_err() { break; }
                }
                _ => break, // Error or EOF
            }
        }
    })
}

// This function now takes a UI channel sender to direct its status and error messages.
async fn setup_bluetooth_connection(ui_tx: mpsc::Sender<String>) -> Result<Peripheral, Box<dyn std::error::Error>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().nth(0) {
        Some(adapter) => adapter,
        None => {
            let error_message = [
                "\n\x1b[91mâŒ No Bluetooth adapter found\x1b[0m",
                "\x1b[90mPlease check:\x1b[0m",
                "\x1b[90m  â€¢ Your device has Bluetooth hardware\x1b[0m",
                "\x1b[90m  â€¢ Bluetooth is enabled in system settings\x1b[0m",
                "\x1b[90m  â€¢ You have permission to use Bluetooth\x1b[0m",
            ].join("\n");
            ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
            return Err("No Bluetooth adapter found.".into());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    ui_tx.send("\x1b[90mÂ» Scanning for bitchat service...\x1b[0m\n".to_string()).await.map_err(|e| e.to_string())?;

    // We can't use debug_println! here directly as it's not async-aware and prints directly.
    // Instead, we replicate its logic and send to the UI channel.
    if unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
        ui_tx.send("[1] Scanning for bitchat service...\n".to_string()).await.map_err(|e| e.to_string())?;
    }
    
    let peripheral = loop {
        if let Some(p) = find_peripheral(&adapter).await? {
            ui_tx.send("\x1b[90mÂ» Found bitchat service! Connecting...\x1b[0m\n".to_string()).await.map_err(|e| e.to_string())?;
            if unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
                ui_tx.send("[1] Match Found! Connecting...\n".to_string()).await.map_err(|e| e.to_string())?;
            }
            adapter.stop_scan().await?;
            break p;
        }
        time::sleep(Duration::from_secs(1)).await;
    };

    if let Err(e) = peripheral.connect().await {
        let error_message = format!("\n\x1b[91mâŒ Connection failed\x1b[0m\n\x1b[90mReason: {}\x1b[0m\n\x1b[90mPlease check:\x1b[0m\n\x1b[90m  â€¢ Bluetooth is enabled\x1b[0m\n\x1b[90m  â€¢ The other device is running BitChat\x1b[0m\n\x1b[90m  â€¢ You're within range\x1b[0m\n\n\x1b[90mTry running the command again.\x1b[0m\n", e);
        ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
        return Err(format!("Connection failed: {}", e).into());
    }

    Ok(peripheral)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Start of I/O Refactoring ---
    // Channel for user input from the input handler task
    let (input_tx, mut input_rx) = mpsc::channel::<String>(10);
    // Channel for all UI output. All parts of the application will send strings here.
    let (ui_tx, mut ui_rx) = mpsc::channel::<String>(100);

    // The UI task. It's the ONLY part of the app that writes to stdout.
    // To switch to a TUI, you would only need to change this task.
    let _ui_handle = tokio::spawn(async move {
        while let Some(output) = ui_rx.recv().await {
            print!("{}", output);
            // We need to flush to ensure prompts are displayed immediately.
            use std::io::{self as stdio, Write};
            let _ = stdio::stdout().flush();
        }
    });
    // --- End of I/O Refactoring ---

    let args: Vec<String> = env::args().collect();
    
    // Check for debug flags and send output to the UI channel
    unsafe {
        if args.iter().any(|arg| arg == "-dd" || arg == "--debug-full") {
            DEBUG_LEVEL = DebugLevel::Full;
            ui_tx.send("ðŸ› Debug mode: FULL (verbose output)\n".to_string()).await?;
        } else if args.iter().any(|arg| arg == "-d" || arg == "--debug") {
            DEBUG_LEVEL = DebugLevel::Basic;
            ui_tx.send("ðŸ› Debug mode: BASIC (connection info)\n".to_string()).await?;
        }
    }

    // Spawn the input handler, giving it the input channel sender and the UI channel sender
    let _input_handle = spawn_input_handler(input_tx, ui_tx.clone());

    // Setup bluetooth, passing the UI channel sender for status messages
    let peripheral = setup_bluetooth_connection(ui_tx.clone()).await?;

    peripheral.discover_services().await?;
    let characteristics = peripheral.characteristics();
    let cmd_char = characteristics.iter().find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID).expect("Characteristic not found.");
    peripheral.subscribe(cmd_char).await?;
    let mut notification_stream = peripheral.notifications().await?;
    
    // Replicate debug_println! logic using the UI channel
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        ui_tx.send("[2] Connection established.\n".to_string()).await?;
    }
    
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        ui_tx.send("[3] Performing handshake...\n".to_string()).await?;
    }

    let mut peer_id_bytes = [0u8; 4];
    rand::thread_rng().fill(&mut peer_id_bytes);
    let my_peer_id = hex::encode(&peer_id_bytes);
    
    if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
        ui_tx.send(format!("[DEBUG] My peer ID: {}\n", my_peer_id)).await?;
    }
    
    let mut app_state = load_state();
    let mut nickname = app_state.nickname.clone().unwrap_or_else(|| "my-rust-client".to_string());
    
    let encryption_service = Arc::new(EncryptionService::new());
    let (key_exchange_payload, _) = generate_keys_and_payload(&encryption_service);
    let key_exchange_packet = create_bitchat_packet(&my_peer_id, MessageType::KeyExchange, key_exchange_payload);
    peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await?;
    
    time::sleep(Duration::from_millis(500)).await;

    let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());
    peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await?;

    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        ui_tx.send("[3] Handshake sent. You can now chat.\n".to_string()).await?;
    }
    if app_state.nickname.is_some() {
        ui_tx.send(format!("\x1b[90mÂ» Using saved nickname: {}\x1b[0m\n", nickname)).await?;
    }
    ui_tx.send("\x1b[90mÂ» Type /status to see connection info\x1b[0m\n".to_string()).await?;

    // --- State Initialization (unchanged) ---
    let peers: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut bloom = Bloom::new_for_fp_rate(500, 0.01);
    let mut fragment_collector = FragmentCollector::new();
    let mut delivery_tracker = DeliveryTracker::new();
    let mut chat_context = ChatContext::new();
    let mut channel_keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut _chat_messages: HashMap<String, Vec<String>> = HashMap::new();
    let mut blocked_peers = app_state.blocked_peers.clone();
    let mut channel_creators = app_state.channel_creators.clone();
    let mut password_protected_channels = app_state.password_protected_channels.clone();
    let mut channel_key_commitments = app_state.channel_key_commitments.clone();
    let mut discovered_channels: HashSet<String> = HashSet::new();
    
    if let Some(identity_key) = &app_state.identity_key {
        for (channel, encrypted_password) in &app_state.encrypted_channel_passwords {
            match decrypt_password(encrypted_password, identity_key) {
                Ok(password) => {
                    let key = EncryptionService::derive_channel_key(&password, channel);
                    channel_keys.insert(channel.clone(), key);
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                         ui_tx.send(format!("[CHANNEL] Restored key for password-protected channel: {}\n", channel)).await?;
                    }
                }
                Err(e) => {
                    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                        ui_tx.send(format!("[CHANNEL] Failed to restore key for {}: {}\n", channel, e)).await?;
                   }
                }
            }
        }
    }
    
    let favorites = app_state.favorites.clone();
    let identity_key = app_state.identity_key.clone();
    
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
    // --- End of State Initialization ---

    loop {
        tokio::select! {
            // Receive user input from the input channel
            // In main.rs, inside the `loop` and `tokio::select!`

            Some(line) = input_rx.recv() => {
                // Clone the UI transmitter for each handler call
                let ui_tx = ui_tx.clone();

                if handle_number_switching(&line, &mut chat_context, ui_tx.clone()).await { continue; }
                if handle_help_command(&line, ui_tx.clone()).await { continue; }
                if handle_list_command(&line, &mut chat_context, ui_tx.clone()).await { continue; }
                if handle_name_command(&line, &mut nickname, &my_peer_id, &peripheral, cmd_char, &blocked_peers, &channel_creators, &chat_context, &password_protected_channels, &channel_key_commitments, &app_state, &create_app_state, ui_tx.clone()).await { continue; }
                if handle_join_command(&line, &password_protected_channels, &mut channel_keys, &mut discovered_channels, &mut chat_context, &channel_key_commitments, &mut app_state, &create_app_state, &nickname, &peripheral, cmd_char, &channel_creators, &blocked_peers, ui_tx.clone()).await { continue; }
                if handle_exit_command(&line, &blocked_peers, &channel_creators, &chat_context, &password_protected_channels, &channel_key_commitments, &app_state, &create_app_state, &nickname, ui_tx.clone()).await { break; }
                if handle_reply_command(&line, &mut chat_context, ui_tx.clone()).await { continue; }
                if handle_public_command(&line, &mut chat_context, ui_tx.clone()).await { continue; }
                if handle_online_command(&line, &peers, ui_tx.clone()).await { continue; }
                if handle_channels_command(&line, &chat_context, &channel_keys, &password_protected_channels, ui_tx.clone()).await { continue; }
                if handle_dm_command(&line, &mut chat_context, &peers, &nickname, &my_peer_id, &mut delivery_tracker, &encryption_service, &peripheral, cmd_char, ui_tx.clone()).await { continue; }
                if handle_block_command(&line, &mut blocked_peers, &peers, &encryption_service, &channel_creators, &chat_context, &password_protected_channels, &channel_key_commitments, &app_state, &create_app_state, &nickname, ui_tx.clone()).await { continue; }
                if handle_unblock_command(&line, &mut blocked_peers, &peers, &encryption_service, &channel_creators, &chat_context, &password_protected_channels, &channel_key_commitments, &app_state, &create_app_state, &nickname, ui_tx.clone()).await { continue; }
                if handle_clear_command(&line, &chat_context, ui_tx.clone()).await { continue; }
                if handle_status_command(&line, &peers, &chat_context, &nickname, &my_peer_id, ui_tx.clone()).await { continue; }
                if handle_leave_command(&line, &mut chat_context, &mut channel_keys, &mut app_state, &my_peer_id, &peripheral, cmd_char, ui_tx.clone()).await { continue; }
                if handle_pass_command(&line, &chat_context, &mut channel_creators, &mut channel_keys, &mut password_protected_channels, &mut app_state, &my_peer_id, &peripheral, cmd_char, ui_tx.clone()).await { continue; }
                if handle_transfer_command(&line, &chat_context, &mut channel_creators, &password_protected_channels, &channel_keys, &my_peer_id, &peers, &peripheral, cmd_char, ui_tx.clone()).await { continue; }
                
                if line.starts_with("/") {
                    let unknown_cmd_msg = format!("\x1b[93mâš  Unknown command: {}\x1b[0m\n\x1b[90mType /help to see available commands.\x1b[0m\n", line.split_whitespace().next().unwrap_or(""));
                    let _ = ui_tx.send(unknown_cmd_msg).await;
                    continue;
                }
                
                if let ChatMode::PrivateDM { nickname: target_nickname, peer_id: target_peer_id } = &chat_context.current_mode {
                    handle_private_dm_message(&line, &nickname, &my_peer_id, target_nickname, target_peer_id, &mut delivery_tracker, &encryption_service, &peripheral, cmd_char, &chat_context, ui_tx.clone()).await;
                    continue;
                }
                
                handle_regular_message(&line, &nickname, &my_peer_id, &chat_context, &password_protected_channels, &mut channel_keys, &encryption_service, &mut delivery_tracker, &peripheral, cmd_char, ui_tx.clone()).await;
            },


            Some(notification) = notification_stream.next() => {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Full } {
        if notification.value.len() >= 2 {
            let msg_type = notification.value[1];
            // The ui_tx channel is already available here.
            let _ = ui_tx.send(format!("[PACKET] Received {} bytes, type: 0x{:02X}\n", notification.value.len(), msg_type)).await;
        }
    }
    
    match parse_bitchat_packet(&notification.value) {
        Ok(packet) => {
            if packet.sender_id_str == my_peer_id { continue; }
            let mut peers_lock = peers.lock().unwrap();

            // Clone the UI channel for each handler
            let ui_tx = ui_tx.clone();

            match packet.msg_type {
                MessageType::Announce => handle_announce_message(&packet, &mut peers_lock, ui_tx).await,
                MessageType::Message => handle_message_packet(&packet, &notification.value, &mut peers_lock, &mut bloom, &mut discovered_channels, &mut password_protected_channels, &mut channel_keys, &mut chat_context, &mut delivery_tracker, &encryption_service, &peripheral, cmd_char, &nickname, &my_peer_id, &blocked_peers, ui_tx).await,
                MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => handle_fragment_packet(&packet, &notification.value, &mut fragment_collector, &mut peers_lock, &mut bloom, &mut discovered_channels, &mut password_protected_channels, &mut chat_context, &encryption_service, &peripheral, cmd_char, &nickname, &my_peer_id, &blocked_peers, ui_tx).await,
                MessageType::KeyExchange => handle_key_exchange_message(&packet, &mut peers_lock, &encryption_service, &peripheral, cmd_char, &my_peer_id, ui_tx).await,
                MessageType::Leave => handle_leave_message(&packet, &mut peers_lock, &chat_context, ui_tx).await,
                MessageType::ChannelAnnounce => handle_channel_announce_message(&packet, &mut channel_creators, &mut password_protected_channels, &mut channel_keys, &mut channel_key_commitments, &mut chat_context, &blocked_peers, &app_state.encrypted_channel_passwords, &nickname, &create_app_state, ui_tx).await,
                MessageType::DeliveryAck => handle_delivery_ack_message(&packet, &notification.value, &encryption_service, &mut delivery_tracker, &peripheral, cmd_char, &my_peer_id, ui_tx).await,
                MessageType::DeliveryStatusRequest => handle_delivery_status_request_message(&packet, ui_tx).await,
                MessageType::ReadReceipt => handle_read_receipt_message(&packet, ui_tx).await,
                _ => {}
            }
        },
        Err(_e) => { /* Silently ignore unparseable packets */ }
    }
},

             _ = tokio::signal::ctrl_c() => { break; }
        }
    }

    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        ui_tx.send("\n[+] Disconnecting...\n".to_string()).await?;
    }

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
