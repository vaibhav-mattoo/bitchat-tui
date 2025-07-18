
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
    pub expanded: [bool; 4], // Channels, People, Blocked, Settings
    pub channel_selected: Option<usize>,
    pub people_selected: Option<usize>,
    pub blocked_selected: Option<usize>,
}

impl SidebarMenuState {
    pub fn new() -> Self {
        Self {
            expanded: [true, true, false, false], // Channels and People expanded by default
            channel_selected: Some(0), // Default to first channel
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
}

impl App {
    pub fn new() -> Self {
        let channels = vec!["#public".to_string()];
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new());
        
        Self {
            input: Input::default(),
            phase: TuiPhase::Connecting,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            nickname: "bitchat-user".to_string(),
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            channels,
            people: Vec::new(),
            blocked: Vec::new(),
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))), // Start in #public
        }
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
        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        self.channels.get(0).cloned().unwrap_or("#public".to_string())
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
            
            let msg = Message { sender, timestamp, content, is_self: false };
            self.channel_messages.entry("#public".to_string()).or_default().push(msg);
            self.scroll_to_bottom_current_conversation();
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
}
