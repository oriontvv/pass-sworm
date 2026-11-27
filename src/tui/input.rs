//! Minimal single-line text input with a visible cursor.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

#[derive(Debug, Clone, Default)]
pub struct Input {
    pub value: String,
    /// Byte offset of the cursor; always on a char boundary.
    cursor: usize,
}

impl Input {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.len();
        Self { value, cursor }
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn insert(&mut self, c: char) {
        self.value.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.prev_boundary();
        self.value.replace_range(prev..self.cursor, "");
        self.cursor = prev;
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.value.len() {
            return;
        }
        let next = self.next_boundary();
        self.value.replace_range(self.cursor..next, "");
    }

    pub fn left(&mut self) {
        self.cursor = self.prev_boundary();
    }

    pub fn right(&mut self) {
        self.cursor = self.next_boundary();
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// Apply a key event to the input. Returns true when the key was consumed.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert(c);
                true
            }
            KeyCode::Backspace => {
                self.backspace();
                true
            }
            KeyCode::Delete => {
                self.delete();
                true
            }
            KeyCode::Left => {
                self.left();
                true
            }
            KeyCode::Right => {
                self.right();
                true
            }
            KeyCode::Home => {
                self.home();
                true
            }
            KeyCode::End => {
                self.end();
                true
            }
            _ => false,
        }
    }

    /// Render the value, optionally masked, with a reverse-video cursor when
    /// the field is focused.
    pub fn line(&self, mask: bool, focused: bool) -> Line<'static> {
        let chars: Vec<char> = self.value.chars().collect();
        let cursor_idx = self.value[..self.cursor].chars().count();
        let show = |c: char| if mask { '•' } else { c };

        if !focused {
            let text: String = chars.iter().map(|c| show(*c)).collect();
            return Line::from(text);
        }

        let before: String = chars[..cursor_idx].iter().map(|c| show(*c)).collect();
        let at = chars.get(cursor_idx).map(|c| show(*c)).unwrap_or(' ');
        let after: String = if cursor_idx < chars.len() {
            chars[cursor_idx + 1..].iter().map(|c| show(*c)).collect()
        } else {
            String::new()
        };

        Line::from(vec![
            Span::raw(before),
            Span::styled(
                at.to_string(),
                Style::default().add_modifier(Modifier::REVERSED),
            ),
            Span::raw(after),
        ])
    }

    fn prev_boundary(&self) -> usize {
        self.value[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    fn next_boundary(&self) -> usize {
        self.value[self.cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| self.cursor + i)
            .unwrap_or(self.value.len())
    }
}

#[cfg(test)]
#[path = "../tests/tui/input.rs"]
mod tests;
