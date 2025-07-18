
// src/tui/widgets/input_box.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::Style,
    widgets::{Block, Borders, Paragraph},
};

use crate::tui::app::App;

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let input = Paragraph::new(app.input.value())
        .style(Style::default().fg(ratatui::style::Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Message"));

    f.render_widget(input, area);

    // Set the cursor position for the input field
    f.set_cursor(
        area.x + app.input.visual_cursor() as u16 + 1,
        area.y + 1,
    );
}
