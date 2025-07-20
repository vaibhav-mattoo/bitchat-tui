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

    let msg_items: Vec<ListItem> = visible_messages.iter().map(|msg| {
        let color = if msg.sender == "system" { Color::White } else if msg.is_self { Color::Cyan } else { Color::LightGreen };
        let line = Line::from(vec![
            Span::styled(format!("[{}]", msg.timestamp), Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(format!("{}:", msg.sender), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::raw(&msg.content),
        ]);
        ListItem::new(line)
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
