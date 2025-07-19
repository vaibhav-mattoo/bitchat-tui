
// src/tui/app.rs

use tui_input::Input;
use std::collections::HashMap;
use regex::Regex;
use chrono;

#[derive(Debug, Clone)]
pub struct Message {
    pub sender: String,
    pub timestamp: String,
    pub content: String,
    pub is_self: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarSection {
    Channels,
    People,
    Blocked,
    Settings,
}

pub struct SidebarMenuState {
    pub expanded: [bool; 5], // Public, Channels, People, Blocked, Settings
    pub public_selected: Option<bool>,
    pub channel_selected: Option<usize>,
    pub people_selected: Option<usize>,
    pub blocked_selected: Option<usize>,
}

impl SidebarMenuState {
    pub fn new() -> Self {
        Self {
            expanded: [true, true, false, false, false], // Public, Channels expanded by default
            public_selected: Some(true), // Default to public selected
            channel_selected: None, // No channel selected by default since public is selected
            people_selected: None,
            blocked_selected: None,
        }
    }

    pub fn toggle_expand(&mut self, section_index: usize) {
        if section_index < self.expanded.len() {
            self.expanded[section_index] = !self.expanded[section_index];
        }
    }
}

pub enum TuiPhase {
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    MainPanel,
    InputBox,
}

pub struct App {
    // UI state
    pub input: Input,
    pub phase: TuiPhase,
    pub should_quit: bool,
    pub focus_area: FocusArea,
    pub sidebar_flat_selected: usize,
    pub msg_scroll: usize,
    
    // Data state for rendering
    pub nickname: String,
    pub network_name: String,
    pub connected: bool,
    pub channels: Vec<String>,
    pub people: Vec<String>,
    pub blocked: Vec<String>, // Note: For display only, blocking logic is in backend
    
    // Message storage
    pub channel_messages: HashMap<String, Vec<Message>>,
    pub dm_messages: HashMap<String, Vec<Message>>,
    
    // Navigation and Popups
    pub sidebar_state: SidebarMenuState,
    pub popup_messages: Vec<String>,
    
    // To track current conversation for message routing and scroll reset
    pub current_conv: Option<(Option<String>, Option<String>)>, // (DM target, Channel name)
    
    // To signal when backend channel switch is needed
    pub pending_channel_switch: Option<String>,
    // To signal when backend DM switch is needed
    pub pending_dm_switch: Option<(String, String)>, // (nickname, peer_id)
}

impl App {
    pub fn new() -> Self {
        let channels = Vec::new(); // Start with no channels, only public
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new()); // Still need to store public messages
        
        let mut app = Self {
            input: Input::default(),
            phase: TuiPhase::Connecting,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            nickname: "my-rust-client".to_string(),
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            channels,
            people: Vec::new(),
            blocked: Vec::new(),
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))), // Start in public
            pending_channel_switch: None,
            pending_dm_switch: None,
        };
        
        app.update_current_conversation();
        app
    }
    
    // Gets the currently selected conversation messages
    pub fn get_current_messages(&self) -> (&[Message], Option<String>, Option<String>) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                let messages = self.dm_messages.get(user).map(|v| v.as_slice()).unwrap_or(&[]);
                return (messages, Some(user.clone()), None);
            }
        }
        
        let ch = self.get_selected_channel_name();
        let messages = self.channel_messages.get(&ch).map(|v| v.as_slice()).unwrap_or(&[]);
        (messages, None, Some(ch))
    }

    pub fn get_selected_channel_name(&self) -> String {
        // Check if public is selected first
        if self.sidebar_state.public_selected.unwrap_or(false) {
            return "#public".to_string();
        }
        
        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        "#public".to_string() // Default to public
    }

    pub fn update_current_conversation(&mut self) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                self.current_conv = Some((Some(user.clone()), None));
                return;
            }
        }
        
        // Check if public is selected
        if self.sidebar_state.public_selected.unwrap_or(false) {
            self.current_conv = Some((None, Some("#public".to_string())));
            return;
        }
        
        if let Some(channel_idx) = self.sidebar_state.channel_selected {
            if let Some(channel) = self.channels.get(channel_idx) {
                self.current_conv = Some((None, Some(channel.clone())));
                return;
            }
        }
        
        // Default to public if nothing is selected
        self.current_conv = Some((None, Some("#public".to_string())));
    }

    // A smart message handler that parses strings from the backend
    pub fn add_log_message(&mut self, raw_message: String) {
        let cleaned_message = String::from_utf8(strip_ansi_escapes::strip(&raw_message)).unwrap_or_default();
        let trimmed = cleaned_message.trim();
        
        if trimmed.is_empty() || trimmed.starts_with('>') || trimmed.starts_with("»") {
            return;
        }

        // --- Parsing logic for common backend messages ---
        if let Some(captures) = Regex::new(r"(\w+) connected").unwrap().captures(trimmed) {
            let name = captures.get(1).unwrap().as_str().to_string();
            if !self.people.contains(&name) {
                self.people.push(name);
            }
            return;
        }
        
        if let Some(captures) = Regex::new(r"\[(\d{2}:\d{2})\] <(\w+)> (.*)").unwrap().captures(trimmed) {
            let timestamp = captures.get(1).unwrap().as_str().to_string();
            let sender = captures.get(2).unwrap().as_str().to_string();
            let content = captures.get(3).unwrap().as_str().to_string();
            
            // Skip messages from the current user to avoid echo
            if sender == self.nickname {
                return;
            }
            
            let msg = Message { sender, timestamp, content, is_self: false };
            let current_channel = self.get_selected_channel_name();
            self.channel_messages.entry(current_channel).or_default().push(msg);
            self.scroll_to_bottom_current_conversation();
            return;
        }

        // Handle system messages (format: "system: message")
        if let Some(captures) = Regex::new(r"^system: (.+)$").unwrap().captures(trimmed) {
            let content = captures.get(1).unwrap().as_str().to_string();
            let msg = Message {
                sender: "system".to_string(),
                timestamp: chrono::Local::now().format("%H:%M").to_string(),
                content,
                is_self: false,
            };
            let current_channel = self.get_selected_channel_name();
            self.channel_messages.entry(current_channel).or_default().push(msg);
            self.scroll_to_bottom_current_conversation();
            return;
        }

        // Skip system messages that contain the current user's nickname to avoid echo
        if trimmed.contains(&self.nickname) {
            return;
        }
        
        let msg = Message {
            sender: "system".to_string(),
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            content: trimmed.to_string(),
            is_self: false,
        };
        let current_channel = self.get_selected_channel_name();
        self.channel_messages.entry(current_channel).or_default().push(msg);
        self.scroll_to_bottom_current_conversation();
    }
    
    pub fn add_sent_message(&mut self, text: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            timestamp,
            content: text,
            is_self: true,
        };

        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            self.dm_messages.entry(target).or_default().push(msg);
        } else if let Some(channel) = channel_name {
            self.channel_messages.entry(channel).or_default().push(msg);
        }
        self.scroll_to_bottom_current_conversation();
    }

    pub fn add_dm_message(&mut self, target_nickname: String, content: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            timestamp,
            content,
            is_self: true,
        };
        
        self.dm_messages.entry(target_nickname).or_default().push(msg);
        self.scroll_to_bottom_current_conversation();
    }

    pub fn scroll_to_bottom_current_conversation(&mut self) {
        let (messages, _, _) = self.get_current_messages();
        if messages.len() > 0 {
            self.msg_scroll = messages.len() - 1;
        } else {
            self.msg_scroll = 0;
        }
    }
    
    pub fn transition_to_connected(&mut self) {
        self.phase = TuiPhase::Connected;
        self.connected = true;
        let mut final_messages = self.popup_messages.drain(..).map(|content| Message {
            sender: "system".to_string(),
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            content,
            is_self: false,
        }).collect();
        self.channel_messages.entry("#public".to_string()).or_default().append(&mut final_messages);
    }

    pub fn transition_to_error(&mut self, error: String) {
        self.phase = TuiPhase::Error(error);
    }

    pub fn add_popup_message(&mut self, message: String) {
        let cleaned_message = message.trim().to_string();
        if !cleaned_message.is_empty() {
           self.popup_messages.push(cleaned_message);
        }
    }

    pub fn join_channel(&mut self, channel_name: String) {
        // Don't add #public as a regular channel
        if channel_name == "#public" {
            return;
        }
        
        // Add the channel to the list if it's not already there
        if !self.channels.contains(&channel_name) {
            self.channels.push(channel_name.clone());
        }
        
        // Clear public selection and select the new channel
        self.sidebar_state.public_selected = None;
        
        // Find the index of the channel and select it
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            // Signal that backend should switch to this channel
            self.pending_channel_switch = Some(channel_name.clone());
        }
        
        // Initialize message storage for the channel if it doesn't exist
        self.channel_messages.entry(channel_name).or_default();
    }

    pub fn switch_to_channel(&mut self, channel_name: String) {
        // Find the index of the channel and select it
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            // Signal that backend should switch to this channel
            self.pending_channel_switch = Some(channel_name);
        }
    }

    pub fn switch_to_public(&mut self) {
        // Clear other selections and select public
        self.sidebar_state.public_selected = Some(true);
        self.sidebar_state.channel_selected = None;
        self.sidebar_state.people_selected = None;
        self.update_current_conversation();
        // Signal that backend should switch to public
        self.pending_channel_switch = Some("#public".to_string());
    }

    pub fn switch_to_dm(&mut self, target_nickname: String) {
        // Clear other selections and select the DM target
        self.sidebar_state.public_selected = None;
        self.sidebar_state.channel_selected = None;
        
        // Find the person in the people list and select them
        if let Some(person_idx) = self.people.iter().position(|p| p == &target_nickname) {
            self.sidebar_state.people_selected = Some(person_idx);
            self.update_current_conversation();
            // Signal that backend should switch to DM mode
            // Note: We'll need to get the peer_id from the backend, so we'll just signal the nickname for now
            self.pending_dm_switch = Some((target_nickname, String::new())); // peer_id will be filled by backend
        }
    }
}
