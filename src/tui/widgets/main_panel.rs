// src/tui/widgets/main_panel.rs

use ratatui::{
    prelude::{Constraint, Direction, Frame, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Message history
        ])
        .split(area);
    
    let header_area = chunks[0];
    let messages_area = chunks[1];
    
    // Update the viewport height before borrowing `app` for messages
    app.message_viewport_height = messages_area.height.saturating_sub(2) as usize;
    
    // Get the current conversation messages
    let (messages, dm_target, channel_name) = app.get_current_messages();
    
    // --- Header Rendering ---
    let header_text = if let Some(user) = dm_target {
        format!("Direct Message with {}", user)
    } else if let Some(channel) = channel_name {
        if channel == "#public" { "Public Chat".to_string() } else { format!("Channel: {}", channel) }
    } else {
        if app.get_selected_channel_name() == "#public" { "Public Chat".to_string() } else { format!("Channel: {}", app.get_selected_channel_name()) }
    };
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("Conversation"))
        .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
    f.render_widget(header, header_area);

    // --- Message Panel Rendering ---
    let messages_height = app.message_viewport_height;
    let total_messages = messages.len();

    // Calculate visible message range
    let end = total_messages.saturating_sub(app.msg_scroll);
    let start = end.saturating_sub(messages_height);
    let visible_messages = if start < end && !messages.is_empty() {
        &messages[start..end]
    } else {
        &[]
    };

    let msg_items: Vec<ListItem> = visible_messages.iter().flat_map(|msg| {
        let color = if msg.sender == "system" { Color::White } else if msg.is_self { Color::Cyan } else { Color::LightGreen };
        
        // Calculate available width for content (accounting for timestamp, sender, and spacing)
        let timestamp_width = msg.timestamp.len() + 2; // [timestamp]
        let sender_width = msg.sender.len() + 1; // sender:
        let prefix_width = timestamp_width + 1 + sender_width + 1; // [time] sender: 
        let available_width = messages_area.width.saturating_sub(2) as usize; // Account for borders
        let content_width = available_width.saturating_sub(prefix_width);
        
        if content_width == 0 {
            // Fallback if no space for content
            let line = Line::from(vec![
                Span::styled(format!("[{}]", msg.timestamp), Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::styled(format!("{}:", msg.sender), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::raw(&msg.content),
            ]);
            vec![ListItem::new(line)]
        } else {
            // Split content into lines that fit the available width using character-based operations
            let mut lines = Vec::new();
            let content = &msg.content;
            
            // Convert to character vector for safe operations
            let chars: Vec<char> = content.chars().collect();
            let mut current_pos = 0;
            let mut first_line = true;
            
            while current_pos < chars.len() {
                // Calculate how many characters can fit on this line
                let remaining_chars = chars.len() - current_pos;
                let max_chars_for_line = content_width.min(remaining_chars);
                
                // Find the best break point (prefer space, fallback to character limit)
                let break_point = if max_chars_for_line == remaining_chars {
                    // Last line, take all remaining characters
                    max_chars_for_line
                } else {
                    // Look for the last space in the available range
                    let search_range = &chars[current_pos..current_pos + max_chars_for_line];
                    if let Some(last_space_idx) = search_range.iter().rposition(|&c| c == ' ') {
                        last_space_idx + 1 // +1 to include the space
                    } else {
                        // No space found, break at character limit
                        max_chars_for_line
                    }
                };
                
                // Extract the line content
                let line_chars = &chars[current_pos..current_pos + break_point];
                let line_content: String = line_chars.iter().collect();
                
                // Create the line
                if first_line {
                    let line = Line::from(vec![
                        Span::styled(format!("[{}]", msg.timestamp), Style::default().fg(Color::DarkGray)),
                        Span::raw(" "),
                        Span::styled(format!("{}:", msg.sender), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        Span::raw(" "),
                        Span::raw(line_content.clone()),
                    ]);
                    lines.push(ListItem::new(line));
                    first_line = false;
                } else {
                    let line = Line::from(vec![
                        Span::raw(" ".repeat(prefix_width)),
                        Span::raw(line_content.clone()),
                    ]);
                    lines.push(ListItem::new(line));
                }
                
                // Move to next position, skipping leading spaces on continuation lines
                current_pos += break_point;
                if !first_line && current_pos < chars.len() && chars[current_pos] == ' ' {
                    current_pos += 1; // Skip the space at the beginning of continuation lines
                }
            }
            
            lines
        }
    }).collect();

    let border_style = if app.focus_area == FocusArea::MainPanel { Style::default().fg(Color::Green) } else { Style::default() };
    
    let list = List::new(msg_items)
        .block(Block::default().borders(Borders::ALL).title("Messages").border_style(border_style))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, messages_area);
    
    // --- Scrollbar Rendering ---
    let max_scroll = total_messages.saturating_sub(messages_height);

    // Fix: Use scroll positions as content length, and invert app.msg_scroll for correct direction
    let (scrollbar_content_length, scrollbar_viewport_length, scrollbar_position) = if total_messages > messages_height {
        let content_length = max_scroll + 1;
        let position = max_scroll.saturating_sub(app.msg_scroll);
        // Set viewport length to a reasonable fraction of the content length for consistent thumb size
        let viewport_length = std::cmp::max(1, content_length / 10);
        (content_length, viewport_length, position)
    } else {
        (1, 1, 0)
    };

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(scrollbar_content_length)
        .viewport_content_length(scrollbar_viewport_length)
        .position(scrollbar_position);

    // Render the scrollbar only if scrolling is actually possible (prevents unnecessary rendering)
    if total_messages > messages_height {
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            messages_area, // Use full area to allow scrollbar to extend to bottom
            &mut scrollbar_state,
        );
    }
}
