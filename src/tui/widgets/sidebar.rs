
// src/tui/widgets/sidebar.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::tui::app::{App, FocusArea};

// Helper to calculate what items are visible for navigation
pub fn sidebar_visible_items(app: &App) -> Vec<(usize, Option<usize>)> {
    let mut items = Vec::new();
    for section in 0..5 { // Now 5 sections: Public, Channels, People, Blocked, Settings
        items.push((section, None)); // Section header
        if app.sidebar_state.expanded[section] {
            let count = match section {
                0 => 1, // Public: always 1 item
                1 => app.channels.len(),
                2 => app.people.len(),
                3 => app.blocked.len(),
                4 => 2, // Settings: Nickname, Network
                _ => 0,
            };
            for idx in 0..count {
                items.push((section, Some(idx)));
            }
        }
    }
    items
}


pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let mut items: Vec<ListItem> = Vec::new();
    let section_titles = ["Public", "Channels", "People", "Blocked", "Settings"];
    let icons = ["🌐", "#", "@", "🚫", "⚙"];
    
    let _visible_items = sidebar_visible_items(app);
    let mut flat_idx = 0;

    for (i, section_title) in section_titles.iter().enumerate() {
        let is_selected = app.sidebar_flat_selected == flat_idx;
        let mut style = if is_selected && app.focus_area == FocusArea::Sidebar {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else {
            Style::default()
        };
        
        let arrow = if app.sidebar_state.expanded[i] { "▼" } else { "▶" };
        
        // Add unread indicator for sections that can have unread messages
        let unread_count = app.get_section_unread_count(i);
        let unread_indicator = if unread_count > 0 {
            Span::styled(" ●", Style::default().fg(Color::Rgb(255, 165, 0))) // Orange circle
        } else {
            Span::raw("")
        };
        
        let section_line = Line::from(vec![
            Span::styled(format!("{} {}", icons[i], section_title), Style::default().bold()),
            unread_indicator,
            Span::raw(format!(" {}", arrow)),
        ]);
        items.push(ListItem::new(section_line).style(style));
        flat_idx += 1;

        if app.sidebar_state.expanded[i] {
            let list: Vec<(&str, Color, bool)> = match i {
                0 => vec![(&"Public Chat", Color::Yellow, app.sidebar_state.public_selected.unwrap_or(false))], // Public section
                1 => app.channels.iter().enumerate().map(|(idx, s)| (s.as_str(), Color::Cyan, app.sidebar_state.channel_selected == Some(idx))).collect(),
                2 => app.people.iter().enumerate().map(|(idx, s)| (s.as_str(), Color::Green, app.sidebar_state.people_selected == Some(idx))).collect(),
                3 => app.blocked.iter().map(|s| (s.as_str(), Color::Red, false)).collect(),
                _ => vec![],
            };

            for (item_str, color, is_active_conv) in list {
                let is_selected = app.sidebar_flat_selected == flat_idx;
                
                // Add unread count for individual items
                let unread_count = match i {
                    0 => app.get_unread_count("#public"), // Public
                    1 => app.get_unread_count(item_str), // Channels
                    2 => app.get_unread_count(&format!("dm:{}", item_str)), // People (DMs)
                    _ => 0,
                };
                
                let unread_indicator = if unread_count > 0 {
                    Span::styled(format!(" ({})", unread_count), Style::default().fg(Color::Rgb(255, 165, 0)))
                } else {
                    Span::raw("")
                };

                // Create the line with proper styling for active conversation
                let mut spans = vec![Span::raw("  ")];
                
                if is_selected && app.focus_area == FocusArea::Sidebar {
                    // Cursor selection: blue background, white text
                    spans.push(Span::styled(item_str, Style::default().bg(Color::Blue).fg(Color::White)));
                } else if is_active_conv {
                    // Active conversation: green background, white text (only for the item text)
                    spans.push(Span::styled(item_str, Style::default().bg(Color::Green).fg(Color::White)));
                } else {
                    // Normal item: colored text
                    spans.push(Span::styled(item_str, Style::default().fg(color)));
                }
                
                spans.push(unread_indicator);
                
                items.push(ListItem::new(Line::from(spans)));
                flat_idx += 1;
            }
            
            if i == 4 { // Settings
                 // Nickname
                let is_selected = app.sidebar_flat_selected == flat_idx;
                style = if is_selected && app.focus_area == FocusArea::Sidebar { Style::default().bg(Color::Blue).fg(Color::White) } else { Style::default() };
                items.push(ListItem::new(Line::from(vec![Span::raw("  "), Span::styled(format!("Nick: {}", app.nickname), style)])));
                flat_idx += 1;
                // Status
                let is_selected = app.sidebar_flat_selected == flat_idx;
                style = if is_selected && app.focus_area == FocusArea::Sidebar { Style::default().bg(Color::Blue).fg(Color::White) } else { Style::default() };
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("  "),
                    Span::styled("Status: ", style),
                    Span::styled(
                        if app.connected { "Connected" } else { "Offline" },
                        if app.connected { Style::default().fg(Color::Green) } else { Style::default().fg(Color::Red) },
                    ),
                ])));
                flat_idx += 1;
            }
        }
    }

    let border_style = if app.focus_area == FocusArea::Sidebar {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Navigation").border_style(border_style));
    f.render_widget(list, area);
}
