// src/tui/event.rs

use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers, KeyEventKind};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;

use crate::tui::app::{App, FocusArea};
use crate::tui::widgets::sidebar::sidebar_visible_items;

pub fn handle_key_event(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    if key_event.kind != KeyEventKind::Press {
        return;
    }
    if key_event.code == KeyCode::Char('c') && key_event.modifiers == KeyModifiers::CONTROL {
        app.should_quit = true;
        return;
    }
    if matches!(app.phase, crate::tui::app::TuiPhase::Error(_)) && key_event.code == KeyCode::Char('r') {
        app.trigger_connection_retry();
        return;
    }
    if app.popup_active {
        handle_popup_events(app, key_event, input_tx);
        return;
    }
    if key_event.code == KeyCode::Tab {
        app.focus_area = match app.focus_area {
            FocusArea::Sidebar => FocusArea::MainPanel,
            FocusArea::MainPanel => FocusArea::InputBox,
            FocusArea::InputBox => FocusArea::Sidebar,
        };
        return;
    }
    match app.focus_area {
        FocusArea::Sidebar => handle_sidebar_events(app, key_event),
        FocusArea::MainPanel => handle_main_panel_events(app, key_event),
        FocusArea::InputBox => handle_input_events(app, key_event, input_tx),
    }
}

fn handle_sidebar_events(app: &mut App, key_event: KeyEvent) {
    let visible_items = sidebar_visible_items(app);
    let current_selection = app.sidebar_flat_selected;
    match key_event.code {
        KeyCode::Tab => app.focus_area = FocusArea::MainPanel,
        KeyCode::Down => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = (current_selection + 1) % visible_items.len();
            }
        }
        KeyCode::Up => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = if current_selection == 0 { visible_items.len() - 1 } else { current_selection - 1 };
            }
        }
        KeyCode::Enter => {
            if let Some(&(section_idx, child_opt)) = visible_items.get(app.sidebar_flat_selected) {
                if let Some(child_idx) = child_opt {
                    app.sidebar_state.people_selected = None;
                    app.sidebar_state.channel_selected = None;
                    app.sidebar_state.public_selected = None;
                    match section_idx {
                        0 => { app.sidebar_state.public_selected = Some(true); app.switch_to_public(); }
                        1 => { if let Some(channel_name) = app.channels.get(child_idx) { app.switch_to_channel(channel_name.clone()); } }
                        2 => { if let Some(person_name) = app.people.get(child_idx) { app.switch_to_dm(person_name.clone()); } }
                        3 => app.sidebar_state.blocked_selected = Some(child_idx),
                        4 => { if child_idx == 0 { app.open_nickname_popup(); } }
                        _ => {}
                    }
                    if section_idx != 1 { app.update_current_conversation(); }
                } else {
                    app.sidebar_state.toggle_expand(section_idx);
                }
            }
        }
        _ => {}
    }
}

fn handle_main_panel_events(app: &mut App, key_event: KeyEvent) {
    let (messages, _, _) = app.get_current_messages();
    let total_messages = messages.len();
    let messages_height = app.message_viewport_height;
    
    let max_scroll = total_messages.saturating_sub(messages_height);

    match key_event.code {
        KeyCode::Tab => app.focus_area = FocusArea::InputBox,
        KeyCode::Up => {
            app.msg_scroll = (app.msg_scroll + 1).min(max_scroll);
        }
        KeyCode::Down => {
            app.msg_scroll = app.msg_scroll.saturating_sub(1);
        }
        KeyCode::PageUp => {
            app.msg_scroll = (app.msg_scroll + messages_height).min(max_scroll);
        }
        KeyCode::PageDown => {
            app.msg_scroll = app.msg_scroll.saturating_sub(messages_height);
        }
        KeyCode::Home => {
            app.msg_scroll = max_scroll;
        }
        KeyCode::End => {
            app.scroll_to_bottom_current_conversation();
        }
        _ => {}
    }
}

fn handle_popup_events(app: &mut App, key_event: KeyEvent, _input_tx: &mpsc::Sender<String>) {
    match key_event.code {
        KeyCode::Enter => {
            let new_nickname = app.popup_input.value().to_string();
            if !new_nickname.is_empty() {
                app.update_nickname(new_nickname);
                app.close_popup();
            }
        }
        KeyCode::Esc => app.close_popup(),
        _ => {
            // FIX: Ignore the return value of handle_event
            let _ = app.popup_input.handle_event(&CrosstermEvent::Key(key_event));
        }
    }
}

fn handle_input_events(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    match key_event.code {
        KeyCode::Enter => {
            let input_str = app.input.value().to_string();
            if !input_str.is_empty() {
                if input_tx.try_send(input_str.clone()).is_ok() {
                    if !input_str.starts_with('/') {
                        app.add_sent_message(input_str);
                    }
                    app.input.reset();
                }
            }
        }
        _ => {
            // FIX: Ignore the return value of handle_event
            let _ = app.input.handle_event(&CrosstermEvent::Key(key_event));
        }
    }
}
