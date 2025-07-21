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
#[allow(dead_code)]
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
            expanded: [true, true, true, true, true], // All sections expanded by default
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
    pub message_viewport_height: usize, // ADDED: To store the height of the message panel
    
    // Data state for rendering
    pub nickname: String,
    #[allow(dead_code)]
    pub network_name: String,
    pub connected: bool,
    pub channels: Vec<String>,
    pub people: Vec<String>,
    pub blocked: Vec<String>,
    
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
    // To signal when backend nickname update is needed
    pub pending_nickname_update: Option<String>,
    // To signal when backend should retry connection
    pub pending_connection_retry: bool,
    // To signal when conversation should be cleared
    pub pending_clear_conversation: bool,
    
    // Unread message tracking
    pub unread_counts: HashMap<String, usize>, // Channel/DM name -> unread count
    pub last_read_messages: HashMap<String, usize>, // Channel/DM name -> last read message count
    
    // Popup state
    pub popup_active: bool,
    pub popup_input: Input,
    pub popup_title: String,
}

impl App {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::new_with_nickname("anonymous".to_string())
    }

    pub fn new_with_nickname(nickname: String) -> Self {
        let channels = Vec::new();
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new());
        
        let mut app = Self {
            input: Input::default(),
            phase: TuiPhase::Connecting,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            message_viewport_height: 10, // ADDED: Default value
            nickname,
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            channels,
            people: Vec::new(),
            blocked: Vec::new(),
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))),
            pending_channel_switch: None,
            pending_dm_switch: None,
            pending_nickname_update: None,
            pending_connection_retry: false,
            pending_clear_conversation: false,
            unread_counts: HashMap::new(),
            last_read_messages: HashMap::new(),
            popup_active: false,
            popup_input: Input::default(),
            popup_title: String::new(),
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
        if self.sidebar_state.public_selected.unwrap_or(false) {
            return "#public".to_string();
        }
        
        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        "#public".to_string()
    }

    pub fn update_current_conversation(&mut self) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                self.current_conv = Some((Some(user.clone()), None));
                return;
            }
        }
        
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
        
        self.current_conv = Some((None, Some("#public".to_string())));
    }

    pub fn add_log_message(&mut self, raw_message: String) {
        let cleaned_message = String::from_utf8(strip_ansi_escapes::strip(&raw_message)).unwrap_or_default();
        let trimmed = cleaned_message.trim();
        
        if trimmed.is_empty() || trimmed.starts_with('>') || trimmed.starts_with("Â»") {
            return;
        }

        if trimmed.starts_with("__DM__:") {
            let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
            if parts.len() >= 4 {
                let sender = parts[1].to_string();
                let timestamp_raw = parts[2].to_string();
                let content = parts[3].to_string();
                
                let timestamp = if timestamp_raw.len() == 4 { format!("{}:{}", &timestamp_raw[0..2], &timestamp_raw[2..4]) } else { timestamp_raw };
                
                let sender_clone = sender.clone();
                let msg = Message { sender, timestamp, content, is_self: false };
                
                self.dm_messages.entry(sender_clone.clone()).or_default().push(msg);
                
                let dm_key = format!("dm:{}", sender_clone);
                let (_, current_dm_target, _) = self.get_current_messages();
                if current_dm_target.as_ref() != Some(&sender_clone) {
                    self.add_unread_message(dm_key);
                }
                
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if trimmed.starts_with("__CHANNEL__:") {
            let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
            if parts.len() >= 5 {
                let channel = parts[1].to_string();
                let sender = parts[2].to_string();
                let timestamp_raw = parts[3].to_string();
                let content = parts[4].to_string();
                
                let timestamp = if timestamp_raw.len() == 4 { format!("{}:{}", &timestamp_raw[0..2], &timestamp_raw[2..4]) } else { timestamp_raw };
                
                let msg = Message { sender, timestamp, content, is_self: false };
                
                self.channel_messages.entry(channel.clone()).or_default().push(msg);
                
                let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
                let in_dm = dm_target.is_some();
                if channel == "#public" {
                    // If not currently viewing public (i.e., in DM or in another channel), add unread
                    if !self.sidebar_state.public_selected.unwrap_or(false) {
                        self.add_unread_message("#public".to_string());
                    }
                } else {
                    // For other channels, only add unread if not currently viewing that channel
                    if channel_name.as_deref() != Some(&channel) || in_dm {
                        self.add_unread_message(channel);
                    }
                }
                
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

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
            
            if sender == self.nickname { return; }
            
            let msg = Message { sender, timestamp, content, is_self: false };
            let current_channel = self.get_selected_channel_name();
            self.channel_messages.entry(current_channel).or_default().push(msg);
            self.scroll_to_bottom_current_conversation();
            return;
        }

        if Regex::new(r"^system: (.+)$").unwrap().is_match(trimmed) {
            // For system messages, we need to preserve the original message with colors
            // So we'll work with the original raw_message instead of the cleaned one
            if let Some(captures_raw) = Regex::new(r"^system: (.+)$").unwrap().captures(&raw_message) {
                let content = captures_raw.get(1).unwrap().as_str().to_string();
                let lines: Vec<&str> = content.split('\n').collect();
                
                for line in lines {
                    let trimmed_line = line.trim();
                    if !trimmed_line.is_empty() {
                        let msg = Message { sender: "system".to_string(), timestamp: chrono::Local::now().format("%H:%M").to_string(), content: trimmed_line.to_string(), is_self: false };
                        
                        // Check if we're in a DM conversation or channel conversation
                        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
                        if let Some(target) = dm_target {
                            // We're in a DM, add to DM messages
                            self.dm_messages.entry(target).or_default().push(msg);
                        } else if let Some(channel) = channel_name {
                            // We're in a channel, add to channel messages
                            self.channel_messages.entry(channel).or_default().push(msg);
                        } else {
                            // Fallback to current channel (shouldn't happen but just in case)
                            let current_channel = self.get_selected_channel_name();
                            self.channel_messages.entry(current_channel.clone()).or_default().push(msg);
                        }
                    }
                }
                self.scroll_to_bottom_current_conversation();
                return;
            }
        }

        if trimmed.contains(&self.nickname) { return; }
        
        let lines: Vec<&str> = trimmed.split('\n').collect();
        let current_channel = self.get_selected_channel_name();
        
        for line in lines {
            let trimmed_line = line.trim();
            if !trimmed_line.is_empty() {
                let msg = Message { sender: "system".to_string(), timestamp: chrono::Local::now().format("%H:%M").to_string(), content: trimmed_line.to_string(), is_self: false };
                self.channel_messages.entry(current_channel.clone()).or_default().push(msg);
            }
        }
        self.scroll_to_bottom_current_conversation();
    }
    
    pub fn add_sent_message(&mut self, text: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message { sender: self.nickname.clone(), timestamp, content: text, is_self: true };

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
        let msg = Message { sender: self.nickname.clone(), timestamp, content, is_self: true };
        self.dm_messages.entry(target_nickname).or_default().push(msg);
        self.scroll_to_bottom_current_conversation();
    }

    pub fn scroll_to_bottom_current_conversation(&mut self) {
        self.msg_scroll = 0;
    }
    
    pub fn transition_to_connected(&mut self) {
        self.phase = TuiPhase::Connected;
        self.connected = true;
        let mut final_messages = self.popup_messages.drain(..).map(|content| Message { sender: "system".to_string(), timestamp: chrono::Local::now().format("%H:%M").to_string(), content, is_self: false }).collect();
        self.channel_messages.entry("#public".to_string()).or_default().append(&mut final_messages);
    }

    pub fn transition_to_error(&mut self, error: String) {
        let cleaned_error = String::from_utf8(strip_ansi_escapes::strip(&error)).unwrap_or_default();
        self.phase = TuiPhase::Error(cleaned_error);
    }

    pub fn add_popup_message(&mut self, message: String) {
        let cleaned_message = String::from_utf8(strip_ansi_escapes::strip(&message)).unwrap_or_default();
        let trimmed = cleaned_message.trim().to_string();
        if !trimmed.is_empty() { self.popup_messages.push(trimmed); }
    }

    pub fn join_channel(&mut self, channel_name: String) {
        if channel_name == "#public" { return; }
        if !self.channels.contains(&channel_name) { self.channels.push(channel_name.clone()); }
        self.sidebar_state.public_selected = None;
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_channel_switch = Some(channel_name.clone());
        }
        self.channel_messages.entry(channel_name).or_default();
    }

    pub fn switch_to_channel(&mut self, channel_name: String) {
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            // Clear other selections when switching to a channel
            self.sidebar_state.public_selected = None;
            self.sidebar_state.people_selected = None;
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_channel_switch = Some(channel_name);
        }
    }

    pub fn switch_to_public(&mut self) {
        self.sidebar_state.public_selected = Some(true);
        self.sidebar_state.channel_selected = None;
        self.sidebar_state.people_selected = None;
        self.update_current_conversation();
        self.update_sidebar_flat_selection();
        self.mark_current_conversation_as_read();
        self.pending_channel_switch = Some("#public".to_string());
    }

    pub fn switch_to_dm(&mut self, target_nickname: String) {
        self.sidebar_state.public_selected = None;
        self.sidebar_state.channel_selected = None;
        if let Some(person_idx) = self.people.iter().position(|p| p == &target_nickname) {
            self.sidebar_state.people_selected = Some(person_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_dm_switch = Some((target_nickname, String::new()));
        }
    }

    pub fn mark_current_conversation_as_read(&mut self) {
        let (messages, dm_target, channel_name) = self.get_current_messages();
        let conversation_key = if let Some(target) = dm_target { format!("dm:{}", target) } else if let Some(channel) = channel_name { channel } else { return; };
        let message_count = messages.len();
        self.last_read_messages.insert(conversation_key.clone(), message_count);
        self.unread_counts.remove(&conversation_key);
    }

    pub fn add_unread_message(&mut self, conversation_key: String) {
        let (_, dm_target, channel_name) = self.get_current_messages();
        let current_key = if let Some(target) = dm_target { format!("dm:{}", target) } else if let Some(channel) = channel_name { channel } else { return; };
        if current_key == conversation_key { return; }
        *self.unread_counts.entry(conversation_key).or_insert(0) += 1;
    }

    pub fn get_unread_count(&self, conversation_key: &str) -> usize {
        self.unread_counts.get(conversation_key).copied().unwrap_or(0)
    }

    pub fn get_section_unread_count(&self, section: usize) -> usize {
        match section {
            0 => { if self.get_unread_count("#public") > 0 { 1 } else { 0 } }
            1 => { self.channels.iter().map(|ch| self.get_unread_count(ch)).sum() }
            2 => { self.people.iter().map(|person| self.get_unread_count(&format!("dm:{}", person))).sum() }
            _ => 0,
        }
    }

    pub fn open_nickname_popup(&mut self) {
        self.popup_active = true;
        self.popup_title = "Edit Nickname".to_string();
        self.popup_input = Input::default();
        self.focus_area = FocusArea::InputBox;
    }

    pub fn close_popup(&mut self) {
        self.popup_active = false;
        self.popup_input = Input::default();
        self.popup_title = String::new();
        self.focus_area = FocusArea::Sidebar;
    }

    pub fn update_nickname(&mut self, new_nickname: String) {
        self.nickname = new_nickname.clone();
        self.pending_nickname_update = Some(new_nickname);
    }

    pub fn trigger_connection_retry(&mut self) {
        self.pending_connection_retry = true;
        self.phase = TuiPhase::Connecting;
        self.connected = false;
        self.popup_messages.clear();
    }

    pub fn clear_current_conversation(&mut self) {
        // Check if we're in a DM conversation
        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            // We're in a DM, clear DM messages
            if let Some(messages) = self.dm_messages.get_mut(&target) {
                messages.clear();
            }
        } else if let Some(channel) = channel_name {
            // We're in a channel, clear channel messages
            if let Some(messages) = self.channel_messages.get_mut(&channel) {
                messages.clear();
            }
        } else {
            // Fallback to current channel (shouldn't happen but just in case)
            let current_channel = self.get_selected_channel_name();
            if let Some(messages) = self.channel_messages.get_mut(&current_channel) {
                messages.clear();
            }
        }
        self.msg_scroll = 0;
    }

    pub fn update_blocked_list(&mut self, blocked_nicknames: Vec<String>) {
        self.blocked = blocked_nicknames;
    }

    pub fn update_sidebar_flat_selection(&mut self) {
        let mut flat_idx = 0;
        for section in 0..5 {
            flat_idx += 1;
            if self.sidebar_state.expanded[section] {
                let count = match section {
                    0 => 1,
                    1 => self.channels.len(),
                    2 => self.people.len(),
                    3 => self.blocked.len(),
                    4 => 2,
                    _ => 0,
                };
                let is_current_section = match section {
                    0 => self.sidebar_state.public_selected.unwrap_or(false),
                    1 => self.sidebar_state.channel_selected.is_some(),
                    2 => self.sidebar_state.people_selected.is_some(),
                    _ => false,
                };
                if is_current_section {
                    let item_idx = match section {
                        0 => 0,
                        1 => self.sidebar_state.channel_selected.unwrap_or(0),
                        2 => self.sidebar_state.people_selected.unwrap_or(0),
                        _ => 0,
                    };
                    self.sidebar_flat_selected = flat_idx + item_idx;
                    return;
                }
                flat_idx += count;
            }
        }
    }
    
    pub fn get_input_box_height(&self, available_width: usize) -> usize {
        let input_text = self.input.value();
        if input_text.is_empty() {
            return 3; // Minimum height
        }
        
        // Calculate how many lines the input text would need
        let chars: Vec<char> = input_text.chars().collect();
        let mut lines_needed = 1;
        let mut current_line_length = 0;
        
        for &ch in &chars {
            if ch == '\n' {
                lines_needed += 1;
                current_line_length = 0;
            } else {
                current_line_length += 1;
                if current_line_length >= available_width.saturating_sub(2) { // Account for borders
                    lines_needed += 1;
                    current_line_length = 0;
                }
            }
        }
        
        // Ensure minimum height and reasonable maximum
        std::cmp::max(3, std::cmp::min(lines_needed + 2, 10)) // +2 for borders, max 10 lines
    }
}
