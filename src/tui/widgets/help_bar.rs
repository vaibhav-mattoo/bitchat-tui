use ratatui::{
    prelude::{Frame, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::tui::app::{App, FocusArea};
use crate::tui::widgets::sidebar::sidebar_visible_items;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let help_text = get_help_text(app);
    
    let help_line = Line::from(help_text);
    let help_paragraph = Paragraph::new(help_line)
        .block(Block::default().borders(Borders::NONE))
        .style(Style::default().fg(Color::Gray));
    
    f.render_widget(help_paragraph, area);
}

fn get_help_text(app: &App) -> Vec<Span> {
    let mut spans = Vec::new();
    
    // Add timestamp color indicator
    spans.push(Span::styled("● ", Style::default().fg(Color::Gray)));
    
    match app.focus_area {
        FocusArea::Sidebar => {
            spans.extend_from_slice(&[
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::raw(": Switch focus • "),
                Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate • "),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw(": Select/Expand • "),
                Span::styled("Ctrl+C", Style::default().fg(Color::Yellow)),
                Span::raw(": Exit"),
            ]);
            
            // Add context-specific help for sidebar
            if let Some(&(section_idx, _)) = sidebar_visible_items(app).get(app.sidebar_flat_selected) {
                match section_idx {
                    0 => spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Public chat", Style::default().fg(Color::Cyan))]),
                    1 => spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Channel navigation", Style::default().fg(Color::Cyan))]),
                    2 => spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Direct messages", Style::default().fg(Color::Cyan))]),
                    3 => spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Blocked users", Style::default().fg(Color::Cyan))]),
                    4 => spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Settings & Nickname", Style::default().fg(Color::Cyan))]),
                    _ => {}
                }
            }
        }
        FocusArea::MainPanel => {
            spans.extend_from_slice(&[
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::raw(": Switch focus • "),
                Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
                Span::raw(": Scroll • "),
                Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow)),
                Span::raw(": Page scroll • "),
                Span::styled("Home", Style::default().fg(Color::Yellow)),
                Span::raw(": Top • "),
                Span::styled("End", Style::default().fg(Color::Yellow)),
                Span::raw(": Bottom • "),
                Span::styled("Ctrl+C", Style::default().fg(Color::Yellow)),
                Span::raw(": Exit"),
            ]);
            
            // Add context-specific help for main panel
            let (_, dm_target, channel) = app.get_current_messages();
            if let Some(target) = dm_target {
                spans.extend_from_slice(&[Span::raw(" • "), Span::styled(format!("DM with {}", target), Style::default().fg(Color::Cyan))]);
            } else if let Some(ch) = channel {
                spans.extend_from_slice(&[Span::raw(" • "), Span::styled(format!("Channel {}", ch), Style::default().fg(Color::Cyan))]);
            }
        }
        FocusArea::InputBox => {
            if app.popup_active {
                spans.extend_from_slice(&[
                    Span::styled("Enter", Style::default().fg(Color::Yellow)),
                    Span::raw(": Confirm • "),
                    Span::styled("Esc", Style::default().fg(Color::Yellow)),
                    Span::raw(": Cancel • "),
                    Span::styled("Ctrl+C", Style::default().fg(Color::Yellow)),
                    Span::raw(": Exit"),
                ]);
                spans.extend_from_slice(&[Span::raw(" • "), Span::styled("Nickname popup", Style::default().fg(Color::Cyan))]);
            } else {
                spans.extend_from_slice(&[
                    Span::styled("Tab", Style::default().fg(Color::Yellow)),
                    Span::raw(": Switch focus • "),
                    Span::styled("Enter", Style::default().fg(Color::Yellow)),
                    Span::raw(": Send message • "),
                    Span::styled("Ctrl+C", Style::default().fg(Color::Yellow)),
                    Span::raw(": Exit"),
                ]);
                
                // Add command hints
                spans.extend_from_slice(&[
                    Span::raw(" • "),
                    Span::styled("/help", Style::default().fg(Color::Green)),
                    Span::raw(": Commands • "),
                    Span::styled("/j #channel", Style::default().fg(Color::Green)),
                    Span::raw(": Join • "),
                    Span::styled("/dm user", Style::default().fg(Color::Green)),
                    Span::raw(": Direct message • "),
                    Span::styled(format!("Nick: {}", app.nickname), Style::default().fg(Color::Blue)),
                ]);
            }
        }
    }
    
    // Add connection status and phase information
    match app.phase {
        crate::tui::app::TuiPhase::Connecting => {
            spans.push(Span::raw(" • "));
            spans.push(Span::styled("Connecting to Bluetooth mesh...", Style::default().fg(Color::Yellow)));
        }
        crate::tui::app::TuiPhase::Connected => {
            if app.connected {
                spans.push(Span::raw(" • "));
                spans.push(Span::styled("Connected", Style::default().fg(Color::Green)));
            }
        }
        crate::tui::app::TuiPhase::Error(_) => {
            spans.push(Span::raw(" • "));
            spans.push(Span::styled("Press 'r' to retry connection", Style::default().fg(Color::Red)));
        }
    }
    
    spans
} 