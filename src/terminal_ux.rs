
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

// FIX 2: Changed `active_channels` from Vec to HashSet for consistency and efficiency.
#[derive(Debug, Clone)]
pub struct ChatContext {
    pub current_mode: ChatMode,
    pub active_channels: HashSet<String>,
    pub active_dms: HashMap<String, String>, // nickname -> peer_id
    pub last_private_sender: Option<(String, String)>, // (peer_id, nickname)
}

impl ChatContext {
    pub fn new() -> Self {
        Self {
            current_mode: ChatMode::Public,
            active_channels: HashSet::new(),
            active_dms: HashMap::new(),
            last_private_sender: None,
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
        "\n━━━ BitChat Commands ━━━\n",
        "▶ General",
        "  /help                    Show this help menu",
        "  /name <name>           Change your nickname",
        "  /status                  Show connection info",
        "  /clear                   Clear the screen",
        "  /exit                    Quit BitChat\n",
        "▶ Navigation",
        "  /public                  Go to public chat\n",
        "▶ Messaging",
        "  /dm <name> [msg]       Start or send a private message",
        "  /reply                   Reply to last private message\n",
        "▶ Channels",
        "  /j #channel [pwd]      Join/create a channel",
        "  /leave                   Leave current channel",
        "  /pass <pwd>            Set channel password (owner only)",
        "  /transfer @user        Transfer ownership (owner only)\n",
        "▶ Discovery",
        "  /channels                List all discovered channels",
        "  /w, /online           Show who's online\n",
        "▶ Privacy & Security",
        "  /block @user           Block a user",
        "  /block                   List blocked users",
        "  /unblock @user         Unblock a user\n",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
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
