
// src/tui/ui.rs

use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::Frame,
};

use crate::tui::{
    app::{App, TuiPhase},
    widgets,
};

pub fn render(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0), // Main panel takes remaining space
            Constraint::Length(30), // Sidebar has a fixed width
        ])
        .split(f.size());
    
    let main_panel_area = chunks[0];
    let sidebar_area = chunks[1];

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // Message history
            Constraint::Length(3), // Input box
            Constraint::Length(1), // Help bar
        ])
        .split(main_panel_area);

    // Render the main message panel
    widgets::main_panel::render(f, app, main_chunks[0]);
    
    // Render the input box
    widgets::input_box::render(f, app, main_chunks[1]);

    // Render the help bar
    widgets::help_bar::render(f, app, main_chunks[2]);

    // Render the sidebar
    widgets::sidebar::render(f, app, sidebar_area);

    // Render popups if needed (covers everything)
    if app.popup_active {
        widgets::popup::render(f, app, f.size());
    } else {
        match &app.phase {
            TuiPhase::Connecting | TuiPhase::Error(_) => {
                widgets::popup::render(f, app, f.size());
            }
            TuiPhase::Connected => {}
        }
    }
}
