
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

    let (messages, dm_target, channel_name) = app.get_current_messages();
    
    // Render Header
    let header_text = if let Some(user) = dm_target {
        format!("Direct Message with {}", user)
    } else if let Some(channel) = channel_name {
        if channel == "#public" {
            "Public Chat".to_string()
        } else {
            format!("Channel: {}", channel)
        }
    } else {
        if app.get_selected_channel_name() == "#public" {
            "Public Chat".to_string()
        } else {
            format!("Channel: {}", app.get_selected_channel_name())
        }
    };
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("Conversation"))
        .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
    f.render_widget(header, header_area);

    // Render Messages
    let msg_items: Vec<ListItem> = messages.iter().map(|msg| {
        let color = if msg.sender == "system" { 
            Color::White 
        } else if msg.is_self { 
            Color::Cyan 
        } else { 
            Color::LightGreen 
        };
        let line = Line::from(vec![
            Span::styled(format!("[{}]", msg.timestamp), Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(format!("{}:", msg.sender), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::raw(&msg.content),
        ]);
        ListItem::new(line)
    }).collect();

    let border_style = if app.focus_area == FocusArea::MainPanel {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let list = List::new(msg_items)
        .block(Block::default().borders(Borders::ALL).title("Messages").border_style(border_style));

    f.render_widget(list, messages_area);
    
    // Render scrollbar
    let mut scrollbar_state = ScrollbarState::default()
        .content_length(messages.len())
        .position(app.msg_scroll);
        
    f.render_stateful_widget(
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼")),
        messages_area.inner(&ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
        &mut scrollbar_state,
    );
}
