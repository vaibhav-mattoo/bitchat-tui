
// File: src/terminal_ux.rs

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Local};

// This enum is correct.
#[derive(Clone, Debug, PartialEq)]
pub enum ChatMode {
    Public,
    Channel(String),
    PrivateDM { nickname: String, peer_id: String },
}

// FIX 1: Added `conversation_map` field.
// FIX 2: Changed `active_channels` from Vec to HashSet for consistency and efficiency.
#[derive(Debug, Clone)]
pub struct ChatContext {
    pub current_mode: ChatMode,
    pub active_channels: HashSet<String>,
    pub active_dms: HashMap<String, String>, // nickname -> peer_id
    pub last_private_sender: Option<(String, String)>, // (peer_id, nickname)
    pub conversation_map: HashMap<usize, ChatMode>,
}

impl ChatContext {
    // FIX 3: Initialize the new `conversation_map` field.
    pub fn new() -> Self {
        Self {
            current_mode: ChatMode::Public,
            active_channels: HashSet::new(),
            active_dms: HashMap::new(),
            last_private_sender: None,
            conversation_map: HashMap::new(),
        }
    }

    pub fn format_prompt(&self) -> String {
        match &self.current_mode {
            ChatMode::Public => "[Public]".to_string(),
            ChatMode::Channel(name) => format!("[{}]", name),
            ChatMode::PrivateDM { nickname, .. } => format!("[DM: {}]", nickname),
        }
    }

    pub fn get_status_line(&self) -> String {
        self.format_prompt()
    }

    // FIX 4: Made this function silent. It only changes state and returns a boolean.
    // The UI feedback ("Switched to...") should be handled by the caller.
    pub fn switch_to_number(&mut self, num: usize) -> bool {
        if let Some(mode) = self.conversation_map.get(&num).cloned() {
            self.current_mode = mode;
            true
        } else {
            false
        }
    }

    // FIX 5: Made all state-changing methods silent.
    pub fn add_channel(&mut self, channel: &str) {
        self.active_channels.insert(channel.to_string());
    }

    pub fn add_dm(&mut self, nickname: &str, peer_id: &str) {
        self.active_dms.insert(nickname.to_string(), peer_id.to_string());
    }

    pub fn enter_dm_mode(&mut self, nickname: &str, peer_id: &str) {
        self.add_dm(nickname, peer_id);
        self.current_mode = ChatMode::PrivateDM {
            nickname: nickname.to_string(),
            peer_id: peer_id.to_string(),
        };
    }

    pub fn switch_to_channel(&mut self, channel: &str) {
        self.add_channel(channel);
        self.current_mode = ChatMode::Channel(channel.to_string());
    }
    
    pub fn switch_to_channel_silent(&mut self, channel: &str) {
        self.add_channel(channel);
        self.current_mode = ChatMode::Channel(channel.to_string());
    }

    pub fn switch_to_public(&mut self) {
        self.current_mode = ChatMode::Public;
    }
    
    pub fn remove_channel(&mut self, channel: &str) {
        self.active_channels.remove(channel);
    }
    
    // This function is fully corrected.
    pub fn get_conversation_list(&mut self) -> String {
        let mut output = String::new();
        let mut append_line = |s: String| {
            output.push_str(&s);
            output.push('\n');
        };

        append_line("\n╭─── Active Conversations ───╮".to_string());
        append_line("│                            │".to_string());

        let current_indicator = |is_current: bool| if is_current { "→" } else { " " };
        
        self.conversation_map.clear();

        // --- Public Chat ---
        let is_public_current = matches!(&self.current_mode, ChatMode::Public);
        self.conversation_map.insert(1, ChatMode::Public);
        append_line(format!("│ {} [1] Public              │", current_indicator(is_public_current)));
        
        let mut num = 2;

        // --- Channels ---
        let mut sorted_channels = self.active_channels.iter().cloned().collect::<Vec<_>>();
        sorted_channels.sort();

        for channel in &sorted_channels {
            let is_channel_current = matches!(&self.current_mode, ChatMode::Channel(ch) if ch == channel);
            let display_name = if channel.len() > 18 {
                format!("{}..", &channel[..16])
            } else {
                channel.clone()
            };
            append_line(format!("│ {} [{}] {}{}│",
                current_indicator(is_channel_current),
                num,
                display_name,
                " ".repeat(20 - display_name.len())
            ));
            self.conversation_map.insert(num, ChatMode::Channel(channel.clone()));
            num += 1;
        }

        // --- DMs ---
        // FIX 6: Correctly iterate over the HashMap.
        let mut sorted_dms = self.active_dms.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        sorted_dms.sort_by(|a, b| a.0.cmp(&b.0)); // Sort by nickname

        for (nick, peer_id) in &sorted_dms {
            let is_dm_current = matches!(&self.current_mode, ChatMode::PrivateDM { nickname, .. } if nickname == nick);
            let dm_text = format!("DM: {}", nick);
            let display_name = if dm_text.len() > 18 {
                format!("{}..", &dm_text[..16])
            } else {
                dm_text
            };
            append_line(format!("│ {} [{}] {}{}│",
                current_indicator(is_dm_current),
                num,
                display_name,
                " ".repeat(20 - display_name.len())
            ));
            self.conversation_map.insert(num, ChatMode::PrivateDM { nickname: nick.clone(), peer_id: peer_id.clone() });
            num += 1;
        }

        append_line("│                            │".to_string());
        append_line("╰────────────────────────────╯".to_string());

        output
    }
}

pub fn format_message_display(
    timestamp: DateTime<Local>,
    sender: &str,
    content: &str,
    is_private: bool,
    is_channel: bool,
    channel_name: Option<&str>,
    recipient: Option<&str>,
    my_nickname: &str,
) -> String {
    let time_str = timestamp.format("%H:%M").to_string();
    
    if is_private {
        if sender == my_nickname {
            if let Some(recipient) = recipient {
                format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;214m<you → {}>\x1b[0m {}", time_str, recipient, content)
            } else {
                format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;214m<you → ???>\x1b[0m {}", time_str, content)
            }
        } else {
            format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;208m<{} → you>\x1b[0m {}", time_str, sender, content)
        }
    } else if is_channel {
        if sender == my_nickname {
            if let Some(channel) = channel_name {
                format!("\x1b[2;34m[{}|{}]\x1b[0m \x1b[38;5;117m<{} @ {}>\x1b[0m {}", time_str, channel, sender, channel, content)
            } else {
                format!("\x1b[2;34m[{}|Ch]\x1b[0m \x1b[38;5;117m<{} @ ???>\x1b[0m {}", time_str, sender, content)
            }
        } else {
            if let Some(channel) = channel_name {
                format!("\x1b[2;34m[{}|{}]\x1b[0m \x1b[34m<{} @ {}>\x1b[0m {}", time_str, channel, sender, channel, content)
            } else {
                format!("\x1b[2;34m[{}|Ch]\x1b[0m \x1b[34m<{} @ ???>\x1b[0m {}", time_str, sender, content)
            }
        }
    } else {
        if sender == my_nickname {
            format!("\x1b[2;32m[{}]\x1b[0m \x1b[38;5;120m<{}>\x1b[0m {}", time_str, sender, content)
        } else {
            format!("\x1b[2;32m[{}]\x1b[0m \x1b[32m<{}>\x1b[0m {}", time_str, sender, content)
        }
    }
}

// FIX 7: Converted print_help to return a string.
pub fn get_help_text() -> String {
    vec![
        "\n\x1b[38;5;46m━━━ BitChat Commands ━━━\x1b[0m\n",
        "\x1b[38;5;40m▶ General\x1b[0m",
        "  \x1b[36m/help\x1b[0m         Show this help menu",
        "  \x1b[36m/name\x1b[0m \x1b[90m<name>\x1b[0m  Change your nickname",
        "  \x1b[36m/status\x1b[0m       Show connection info",
        "  \x1b[36m/clear\x1b[0m        Clear the screen",
        "  \x1b[36m/exit\x1b[0m         Quit BitChat\n",
        "\x1b[38;5;40m▶ Navigation\x1b[0m",
        "  \x1b[36m1-9\x1b[0m           Quick switch to conversation",
        "  \x1b[36m/list\x1b[0m         Show all conversations",
        "  \x1b[36m/public\x1b[0m       Go to public chat\n",
        "\x1b[38;5;40m▶ Messaging\x1b[0m",
        "  \x1b[90m(type normally to send in current mode)\x1b[0m",
        "  \x1b[36m/dm\x1b[0m \x1b[90m<name> [msg]\x1b[0m    Start or send a private message",
        "  \x1b[36m/reply\x1b[0m        Reply to last private message\n",
        "\x1b[38;5;40m▶ Channels\x1b[0m",
        "  \x1b[36m/j\x1b[0m \x1b[90m#channel [pwd]\x1b[0m Join/create a channel",
        "  \x1b[36m/leave\x1b[0m        Leave current channel",
        "  \x1b[36m/pass\x1b[0m \x1b[90m<pwd>\x1b[0m   Set channel password (owner only)",
        "  \x1b[36m/transfer\x1b[0m \x1b[90m@user\x1b[0m Transfer ownership (owner only)\n",
        "\x1b[38;5;40m▶ Discovery\x1b[0m",
        "  \x1b[36m/channels\x1b[0m     List all discovered channels",
        "  \x1b[36m/w\x1b[0m, \x1b[36m/online\x1b[0m  Show who's online\n",
        "\x1b[38;5;40m▶ Privacy & Security\x1b[0m",
        "  \x1b[36m/block\x1b[0m \x1b[90m@user\x1b[0m  Block a user",
        "  \x1b[36m/block\x1b[0m        List blocked users",
        "  \x1b[36m/unblock\x1b[0m \x1b[90m@user\x1b[0m Unblock a user\n",
        "\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m",
    ].join("\n")
}

// Helper to extract message target from chat mode
impl ChatMode {
    pub fn get_channel(&self) -> Option<&str> {
        match self {
            ChatMode::Channel(name) => Some(name),
            _ => None,
        }
    }
}
