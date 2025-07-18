// src/tui/widgets/popup.rs

use ratatui::{
    prelude::{Alignment, Constraint, Direction, Frame, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::tui::app::{App, TuiPhase};

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
    // Use a fixed 60% width and 30% height for the popup, always centered
    let popup_area = centered_rect(60, 30, area);

    let popup_text = match &app.phase {
        TuiPhase::Error(err) => err.clone(),
        _ => app.popup_messages.join("\n"),
    };

    let popup = Paragraph::new(popup_text)
        .block(
            Block::default()
                .title(match &app.phase {
                    TuiPhase::Error(_) => "Connection Error",
                    _ => "Connecting to BitChat Mesh",
                })
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Left)
        .wrap(ratatui::widgets::Wrap { trim: false });

    // Render the popup on a cleared area to make it "float"
    f.render_widget(Clear, popup_area);
    f.render_widget(popup, popup_area);
}
