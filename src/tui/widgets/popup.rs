// src/tui/widgets/popup.rs

use ratatui::{
    prelude::{Alignment, Constraint, Direction, Frame, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::tui::app::{App, TuiPhase, FocusArea};

/// Renders a centered popup block.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    // Handle nickname editing popup
    if app.popup_active {
        render_nickname_popup(f, app, area);
        return;
    }

    // Handle connection popup
    render_connection_popup(f, app, area);
}

fn render_nickname_popup(f: &mut Frame, app: &mut App, area: Rect) {
    // Use a smaller popup for nickname editing
    let popup_area = centered_rect(40, 25, area);

    // Create the popup container with borders
    let border_style = if app.focus_area == FocusArea::InputBox {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::White)
    };

    let popup_block = Block::default()
        .title(app.popup_title.as_str())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(border_style);

    // Get the inner area (content area) of the popup
    let content_area = popup_block.inner(popup_area);

    // Create layout for content inside the popup
    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Current nickname info
            Constraint::Length(1),  // Spacing
            Constraint::Length(2),  // Input field
            Constraint::Length(1),  // Spacing
            Constraint::Length(1),  // Instructions
            Constraint::Min(0),     // Fill remaining space
        ])
        .split(content_area);

    // Current nickname section
    let current_nickname_text = format!("Current nickname: {}", app.nickname);
    let current_nickname_para = Paragraph::new(current_nickname_text)
        .style(Style::default().fg(Color::Cyan).bold())
        .alignment(Alignment::Center);

    // Input field section
    let input_text = format!("New nickname: {}", app.popup_input.value());
    let input_para = Paragraph::new(input_text)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Left);

    // Instructions section
    let instructions_text = "Press Enter to confirm, Esc to cancel";
    let instructions_para = Paragraph::new(instructions_text)
        .style(Style::default().fg(Color::Gray).italic())
        .alignment(Alignment::Center);

    // Render the popup container first
    f.render_widget(Clear, popup_area);
    f.render_widget(popup_block, popup_area);

    // Render content inside the popup
    f.render_widget(current_nickname_para, content_chunks[0]);
    f.render_widget(input_para, content_chunks[2]);
    f.render_widget(instructions_para, content_chunks[4]);

    // Set cursor position for the input field
    let input_start = content_chunks[2].x + 14; // "New nickname: " is 14 characters
    let input_y = content_chunks[2].y;
    let cursor_x = input_start + app.popup_input.visual_cursor() as u16;
    f.set_cursor(cursor_x, input_y);
}

fn render_connection_popup(f: &mut Frame, app: &mut App, area: Rect) {
    // Use a fixed 60% width and 35% height for the popup, always centered
    // Ensure minimum size to prevent border issues
    let popup_area = centered_rect(60, 35, area);
    
    // Ensure the popup area is large enough to render properly
    if popup_area.width < 20 || popup_area.height < 10 {
        return; // Don't render if area is too small
    }

    // Create the popup container with borders
    let border_style = match &app.phase {
        TuiPhase::Error(_) => Style::default().fg(Color::Red),
        _ => Style::default().fg(Color::Cyan),
    };

    let popup_block = Block::default()
        .title(match &app.phase {
            TuiPhase::Error(_) => "Connection Error",
            _ => "Connecting to BitChat Mesh",
        })
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(border_style);

    // Get the inner area (content area) of the popup
    let content_area = popup_block.inner(popup_area);

    // Create layout for content inside the popup with horizontal padding
    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Status/icon
            Constraint::Length(1),  // Spacing
            Constraint::Min(1),     // Messages
            Constraint::Length(1),  // Spacing
            Constraint::Length(1),  // Instructions
            Constraint::Min(0),     // Fill remaining space
        ])
        .split(content_area);

    // Add horizontal padding to the messages area to prevent text from touching borders
    let messages_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(1),  // Left padding
            Constraint::Min(0),     // Content
            Constraint::Length(1),  // Right padding
        ])
        .split(content_chunks[2]);

    // Status section
    let status_text = match &app.phase {
        TuiPhase::Error(_) => "❌ Connection Failed",
        TuiPhase::Connecting => "⏳ Establishing Connection...",
        _ => "✅ Connected",
    };
    let status_para = Paragraph::new(status_text)
        .style(match &app.phase {
            TuiPhase::Error(_) => Style::default().fg(Color::Red).bold(),
            TuiPhase::Connecting => Style::default().fg(Color::Yellow).bold(),
            _ => Style::default().fg(Color::Green).bold(),
        })
        .alignment(Alignment::Center);

    // Messages section
    let popup_text = match &app.phase {
        TuiPhase::Error(err) => err.clone(),
        _ => app.popup_messages.join("\n"),
    };
    let messages_para = Paragraph::new(popup_text)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
        .wrap(ratatui::widgets::Wrap { trim: true });

    // Instructions section
    let instructions_text = match &app.phase {
        TuiPhase::Error(_) => "Press 'r' to retry connection, Ctrl+C to exit",
        _ => "Please wait while connecting...",
    };
    let instructions_para = Paragraph::new(instructions_text)
        .style(match &app.phase {
            TuiPhase::Error(_) => Style::default().fg(Color::Yellow).italic(),
            _ => Style::default().fg(Color::Gray).italic(),
        })
        .alignment(Alignment::Center);

    // Render the popup container first
    f.render_widget(Clear, popup_area);
    f.render_widget(popup_block, popup_area);

    // Render content inside the popup
    f.render_widget(status_para, content_chunks[0]);
    f.render_widget(messages_para, messages_area[1]); // Use the padded area
    f.render_widget(instructions_para, content_chunks[4]);
}
