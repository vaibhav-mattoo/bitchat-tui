
// src/tui/widgets/sidebar.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::tui::app::{App, FocusArea};

// Helper to calculate what items are visible for navigation
pub fn sidebar_visible_items(app: &App) -> Vec<(usize, Option<usize>)> {
    let mut items = Vec::new();
    for section in 0..4 {
        items.push((section, None)); // Section header
        if app.sidebar_state.expanded[section] {
            let count = match section {
                0 => app.channels.len(),
                1 => app.people.len(),
                2 => app.blocked.len(),
                3 => 2, // Settings: Nickname, Network
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
    let section_titles = ["Channels", "People", "Blocked", "Settings"];
    let icons = ["#", "@", "🚫", "⚙"];
    
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
        let section_line = Line::from(vec![
            Span::styled(format!("{} {}", icons[i], section_title), Style::default().bold()),
            Span::raw(format!(" {}", arrow)),
        ]);
        items.push(ListItem::new(section_line).style(style));
        flat_idx += 1;

        if app.sidebar_state.expanded[i] {
            let list: Vec<(&String, Color, bool)> = match i {
                0 => app.channels.iter().map(|s| (s, Color::Cyan, app.sidebar_state.channel_selected == Some(items.len() - (i + 1)))).collect(),
                1 => app.people.iter().map(|s| (s, Color::Green, app.sidebar_state.people_selected == Some(items.len() - (i + 1)))).collect(),
                2 => app.blocked.iter().map(|s| (s, Color::Red, false)).collect(),
                _ => vec![],
            };

            for (item_str, color, is_active_conv) in list {
                let is_selected = app.sidebar_flat_selected == flat_idx;
                style = if is_selected && app.focus_area == FocusArea::Sidebar {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else {
                    Style::default().fg(color)
                };

                if is_active_conv {
                    style = style.add_modifier(Modifier::REVERSED);
                }

                items.push(ListItem::new(Line::from(vec![Span::raw("  "), Span::styled(item_str, style)])));
                flat_idx += 1;
            }
            
            if i == 3 { // Settings
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
