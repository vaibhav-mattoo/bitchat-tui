
// src/tui/widgets/input_box.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::Style,
    widgets::{Block, Borders, Paragraph},
};

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let border_style = if app.focus_area == FocusArea::InputBox {
        Style::default().fg(ratatui::style::Color::Green)
    } else {
        Style::default().fg(ratatui::style::Color::White)
    };
    
    // Create wrapped text for the input
    let input_text = app.input.value();
    let available_width = area.width.saturating_sub(2) as usize; // Account for borders
    
    // Split text into lines based on available width
    let lines = wrap_text(&input_text, available_width);
    
    let input = Paragraph::new(lines)
        .style(Style::default().fg(ratatui::style::Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Type a message").border_style(border_style));

    f.render_widget(input, area);

    // Calculate cursor position for multi-line input
    let cursor_pos = app.input.visual_cursor();
    let (cursor_line, cursor_col) = calculate_cursor_position(&input_text, cursor_pos, available_width);
    
    f.set_cursor(
        area.x + cursor_col as u16 + 1,
        area.y + cursor_line as u16 + 1,
    );
}

fn wrap_text(text: &str, max_width: usize) -> Vec<ratatui::text::Line<'static>> {
    if text.is_empty() {
        return vec![ratatui::text::Line::from("")];
    }
    
    let mut lines = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut current_pos = 0;
    
    while current_pos < chars.len() {
        let remaining_chars = chars.len() - current_pos;
        let max_chars_for_line = max_width.min(remaining_chars);
        
        // Find the best break point
        let break_point = if max_chars_for_line == remaining_chars {
            max_chars_for_line
        } else {
            // Look for the last space in the available range
            let search_range = &chars[current_pos..current_pos + max_chars_for_line];
            if let Some(last_space_idx) = search_range.iter().rposition(|&c| c == ' ') {
                last_space_idx + 1
            } else {
                max_chars_for_line
            }
        };
        
        let line_chars = &chars[current_pos..current_pos + break_point];
        let line_content: String = line_chars.iter().collect();
        lines.push(ratatui::text::Line::from(line_content));
        
        current_pos += break_point;
        if current_pos < chars.len() && chars[current_pos] == ' ' {
            current_pos += 1; // Skip leading space on continuation lines
        }
    }
    
    if lines.is_empty() {
        lines.push(ratatui::text::Line::from(""));
    }
    
    lines
}

fn calculate_cursor_position(text: &str, cursor_pos: usize, max_width: usize) -> (usize, usize) {
    if text.is_empty() {
        return (0, 0);
    }
    
    let chars: Vec<char> = text.chars().collect();
    let cursor_chars = chars.len().min(cursor_pos);
    
    let mut line = 0;
    let mut col = 0;
    let mut _char_count = 0;
    
    for &ch in &chars[..cursor_chars] {
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
            if col >= max_width {
                line += 1;
                col = 0;
            }
        }
        _char_count += 1;
    }
    
    (line, col)
}
