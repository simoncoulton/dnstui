//! Application state and input handling. No rendering and no I/O here, so it
//! can be unit-tested without a terminal or a resolver.

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::{
    query::{self, Check, Query},
    report::Report,
    theme::{self, Theme},
};

/// How long a status message stays visible.
const STATUS_TTL: Duration = Duration::from_secs(6);
/// Reports kept for `p` / `n`.
const HISTORY_LEN: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Browsing the result.
    Normal,
    /// Typing a query.
    Input,
    /// Theme picker with live preview; state in [`App::theme_cursor`].
    Theme,
    Help,
}

/// Side effects requested by input handling; executed by the event loop.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Quit,
    /// Run a query; `id` lets the loop drop answers to superseded runs.
    Run {
        id: u64,
        query: Query,
    },
    SaveTheme {
        name: String,
        transparent: Option<bool>,
    },
    EditConfig,
}

pub struct App {
    pub mode: Mode,
    pub check: Check,
    pub input: String,
    /// Cursor position in `input`, in characters.
    pub cursor: usize,
    /// The query being run, if any.
    pub running: Option<Query>,
    run_id: u64,
    /// Finished reports, oldest first.
    pub history: Vec<Report>,
    /// Which of `history` is shown.
    pub selected: usize,
    pub scroll: usize,
    /// Set by the renderer: the furthest the result can scroll.
    pub scroll_limit: Cell<usize>,
    status: Option<(String, bool, Instant)>,
    pub themes: Vec<Theme>,
    pub theme: Theme,
    pub transparent: bool,
    pub theme_cursor: usize,
    /// The theme and background in effect before the picker opened.
    theme_before: Option<(Theme, bool)>,
}

impl App {
    pub fn new(default_check: Check) -> Self {
        Self {
            mode: Mode::Input,
            check: default_check,
            input: String::new(),
            cursor: 0,
            running: None,
            run_id: 0,
            history: Vec::new(),
            selected: 0,
            scroll: 0,
            scroll_limit: Cell::new(0),
            status: None,
            themes: vec![theme::default_theme()],
            theme: theme::default_theme(),
            transparent: true,
            theme_cursor: 0,
            theme_before: None,
        }
    }

    pub fn set_themes(&mut self, themes: Vec<Theme>, name: &str) {
        let current = theme::find(&themes, name)
            .cloned()
            .unwrap_or_else(theme::default_theme);
        self.theme_cursor = themes
            .iter()
            .position(|t| t.name == current.name)
            .unwrap_or(0);
        self.theme = current.transparent(self.transparent);
        self.themes = themes;
    }

    pub fn set_status(&mut self, text: impl Into<String>, is_error: bool) {
        self.status = Some((text.into(), is_error, Instant::now()));
    }

    pub fn clear_status(&mut self) {
        self.status = None;
    }

    /// The status message, unless it has expired.
    pub fn status(&self) -> Option<(&str, bool)> {
        self.status
            .as_ref()
            .filter(|(_, _, at)| at.elapsed() < STATUS_TTL)
            .map(|(t, e, _)| (t.as_str(), *e))
    }

    /// The report on screen.
    pub fn report(&self) -> Option<&Report> {
        self.history.get(self.selected)
    }

    /// Start a query typed on the command line (`mx:example.com dkim:...`).
    pub fn start(&mut self, text: &str) -> Option<Action> {
        match query::parse(text, self.check) {
            Ok(q) => Some(self.run(q)),
            Err(e) => {
                self.set_status(format!("{e}"), true);
                None
            }
        }
    }

    fn run(&mut self, q: Query) -> Action {
        self.check = q.check;
        self.input = match &q.selector {
            Some(s) => format!("{}:{s}", q.target),
            None => q.target.clone(),
        };
        self.cursor = self.input.chars().count();
        self.run_id += 1;
        self.running = Some(q.clone());
        self.clear_status();
        Action::Run {
            id: self.run_id,
            query: q,
        }
    }

    /// Show a finished run. Answers to superseded runs are dropped.
    pub fn apply_report(&mut self, id: u64, report: Report) {
        if id != self.run_id {
            return;
        }
        self.running = None;
        self.history.push(report);
        if self.history.len() > HISTORY_LEN {
            self.history.remove(0);
        }
        self.selected = self.history.len() - 1;
        self.scroll = 0;
    }

    /// Show an older or newer report and make its query the current one.
    fn step_history(&mut self, delta: isize) {
        if self.history.is_empty() {
            return;
        }
        let last = self.history.len() - 1;
        self.selected = (self.selected as isize + delta).clamp(0, last as isize) as usize;
        self.scroll = 0;
        if let Some(q) = self.report().map(|r| r.query.clone()) {
            self.check = q.check;
            self.input = match &q.selector {
                Some(s) => format!("{}:{s}", q.target),
                None => q.target,
            };
            self.cursor = self.input.chars().count();
        }
    }

    /// The target of the last query, to re-run under another check.
    fn last_target(&self) -> Option<String> {
        self.report().map(|r| r.query.target.clone())
    }

    fn select_check(&mut self, check: Check) -> Option<Action> {
        self.check = check;
        // With a target on screen, switching tabs asks the new question about it.
        let target = self.last_target()?;
        let selector = (check == Check::Dkim)
            .then(|| self.report().and_then(|r| r.query.selector.clone()))
            .flatten();
        Some(self.run(Query {
            check,
            target,
            selector,
        }))
    }

    pub fn handle_paste(&mut self, text: &str) {
        if self.mode != Mode::Input {
            return;
        }
        // One line only: a pasted newline would otherwise be swallowed silently.
        let line = text.lines().next().unwrap_or("").trim();
        for c in line.chars() {
            self.insert(c);
        }
    }

    fn insert(&mut self, c: char) {
        let at = self.byte_index(self.cursor);
        self.input.insert(at, c);
        self.cursor += 1;
    }

    fn byte_index(&self, chars: usize) -> usize {
        self.input
            .char_indices()
            .nth(chars)
            .map_or(self.input.len(), |(i, _)| i)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Action::Quit);
        }
        match self.mode {
            Mode::Input => self.key_input(key),
            Mode::Normal => self.key_normal(key),
            Mode::Theme => self.key_theme(key),
            Mode::Help => {
                self.mode = Mode::Normal;
                None
            }
        }
    }

    fn key_input(&mut self, key: KeyEvent) -> Option<Action> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let len = self.input.chars().count();
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                let text = self.input.clone();
                if let Some(action) = self.start(&text) {
                    self.mode = Mode::Normal;
                    return Some(action);
                }
            }
            KeyCode::Tab | KeyCode::Down => self.check = self.check.next(),
            KeyCode::BackTab | KeyCode::Up => self.check = self.check.prev(),
            KeyCode::Char('u') if ctrl => {
                self.input.clear();
                self.cursor = 0;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = len,
            KeyCode::Char('w') if ctrl => {
                let chars: Vec<char> = self.input.chars().collect();
                let mut start = self.cursor;
                while start > 0 && chars[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && chars[start - 1] != ' ' {
                    start -= 1;
                }
                let (a, b) = (self.byte_index(start), self.byte_index(self.cursor));
                self.input.replace_range(a..b, "");
                self.cursor = start;
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            KeyCode::Backspace if self.cursor > 0 => {
                let at = self.byte_index(self.cursor - 1);
                self.input.remove(at);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < len => {
                let at = self.byte_index(self.cursor);
                self.input.remove(at);
            }
            KeyCode::Char(c) if !ctrl && !c.is_whitespace() => self.insert(c),
            _ => {}
        }
        None
    }

    fn scroll_by(&mut self, delta: isize) {
        let limit = self.scroll_limit.get();
        self.scroll = (self.scroll as isize + delta).clamp(0, limit as isize) as usize;
    }

    fn key_normal(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Char('/' | 'i') | KeyCode::Enter => self.mode = Mode::Input,
            KeyCode::Esc => self.clear_status(),
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('E') => return Some(Action::EditConfig),
            KeyCode::Char('T') => {
                self.theme_before = Some((self.theme.clone(), self.transparent));
                self.theme_cursor = self
                    .themes
                    .iter()
                    .position(|t| t.name == self.theme.name)
                    .unwrap_or(0);
                self.mode = Mode::Theme;
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                return self.select_check(self.check.next());
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::BackTab => {
                return self.select_check(self.check.prev());
            }
            KeyCode::Char('r') => {
                let q = self.report().map(|r| r.query.clone());
                return q.map(|q| self.run(q));
            }
            KeyCode::Char('p') => self.step_history(-1),
            KeyCode::Char('n') => self.step_history(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll_by(10),
            KeyCode::PageUp => self.scroll_by(-10),
            KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.scroll = self.scroll_limit.get(),
            _ => {}
        }
        None
    }

    fn preview_theme(&mut self) {
        if let Some(t) = self.themes.get(self.theme_cursor) {
            self.theme = t.clone().transparent(self.transparent);
        }
    }

    fn key_theme(&mut self, key: KeyEvent) -> Option<Action> {
        let last = self.themes.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                if let Some((theme, transparent)) = self.theme_before.take() {
                    self.theme = theme;
                    self.transparent = transparent;
                }
                self.mode = Mode::Normal;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.theme_cursor = (self.theme_cursor + 1).min(last);
                self.preview_theme();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.theme_cursor = self.theme_cursor.saturating_sub(1);
                self.preview_theme();
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.theme_cursor = 0;
                self.preview_theme();
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.theme_cursor = last;
                self.preview_theme();
            }
            KeyCode::Char('b') => {
                self.transparent = !self.transparent;
                self.preview_theme();
            }
            KeyCode::Enter => {
                let before = self.theme_before.take();
                self.mode = Mode::Normal;
                let name = self.themes.get(self.theme_cursor)?.name.clone();
                let background_changed = before.is_none_or(|(_, t)| t != self.transparent);
                return Some(Action::SaveTheme {
                    name,
                    transparent: background_changed.then_some(self.transparent),
                });
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
    }

    fn report(check: Check, target: &str) -> Report {
        Report::new(Query {
            check,
            target: target.into(),
            selector: None,
        })
    }

    fn finish(app: &mut App, action: Option<Action>, r: Report) {
        let Some(Action::Run { id, .. }) = action else {
            panic!("expected a run, got {action:?}");
        };
        app.apply_report(id, r);
    }

    #[test]
    fn enter_runs_the_typed_query_and_adopts_its_check() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "spf:Example.com");
        let action = app.handle_key(key(KeyCode::Enter));
        let Some(Action::Run { query, .. }) = action else {
            panic!("no run")
        };
        assert_eq!(
            (query.check, query.target.as_str()),
            (Check::Spf, "example.com")
        );
        assert_eq!(app.check, Check::Spf);
        assert_eq!(app.input, "example.com");
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn bad_input_stays_in_the_box_with_an_error() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "mx:");
        assert!(app.handle_key(key(KeyCode::Enter)).is_none());
        assert_eq!(app.mode, Mode::Input);
        assert!(app.status().is_some_and(|(_, err)| err));
    }

    #[test]
    fn stale_answers_are_dropped() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "a.com");
        let first = app.handle_key(key(KeyCode::Enter));
        let Some(Action::Run { id: old, .. }) = first else {
            panic!()
        };
        app.apply_report(old, report(Check::Mx, "a.com"));
        // A second run starts; the first one's late answer must not replace it.
        assert!(matches!(
            app.handle_key(key(KeyCode::Char('r'))),
            Some(Action::Run { .. })
        ));
        app.apply_report(old, report(Check::Mx, "late.com"));
        assert_eq!(app.history.len(), 1);
        assert!(app.running.is_some());
    }

    #[test]
    fn switching_tabs_reruns_on_the_same_target() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "example.com");
        let a = app.handle_key(key(KeyCode::Enter));
        finish(&mut app, a, report(Check::Mx, "example.com"));
        let action = app.handle_key(key(KeyCode::Right));
        let Some(Action::Run { query, .. }) = action else {
            panic!("no run")
        };
        assert_eq!(
            (query.check, query.target.as_str()),
            (Check::A, "example.com")
        );
    }

    #[test]
    fn switching_tabs_with_nothing_run_just_selects() {
        let mut app = App::new(Check::Mx);
        app.mode = Mode::Normal;
        assert!(app.handle_key(key(KeyCode::Right)).is_none());
        assert_eq!(app.check, Check::A);
    }

    #[test]
    fn history_steps_and_restores_the_query() {
        let mut app = App::new(Check::Mx);
        for (check, host) in [(Check::Mx, "a.com"), (Check::Spf, "b.com")] {
            type_text(&mut app, &format!("{}:{host}", check.prefix()));
            app.mode = Mode::Input;
            let a = app.handle_key(key(KeyCode::Enter));
            finish(&mut app, a, report(check, host));
            app.input.clear();
        }
        assert_eq!(app.selected, 1);
        app.handle_key(key(KeyCode::Char('p')));
        assert_eq!(
            (app.selected, app.check, app.input.as_str()),
            (0, Check::Mx, "a.com")
        );
        app.handle_key(key(KeyCode::Char('p')));
        assert_eq!(app.selected, 0);
        app.handle_key(key(KeyCode::Char('n')));
        assert_eq!(app.input, "b.com");
    }

    #[test]
    fn editing_the_input_line() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "exmple.com");
        app.handle_key(key(KeyCode::Home));
        for _ in 0..2 {
            app.handle_key(key(KeyCode::Right));
        }
        app.handle_key(key(KeyCode::Char('a')));
        assert_eq!(app.input, "example.com");
        app.handle_key(key(KeyCode::Backspace));
        app.handle_key(key(KeyCode::Delete));
        assert_eq!(app.input, "exple.com");
        // Ctrl-W deletes the word before the cursor, not the whole line.
        app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(app.input, "ple.com");
    }

    #[test]
    fn multibyte_input_does_not_panic() {
        let mut app = App::new(Check::Mx);
        type_text(&mut app, "é");
        app.handle_key(key(KeyCode::Left));
        app.handle_key(key(KeyCode::Delete));
        assert_eq!(app.input, "");
        type_text(&mut app, "éb");
        app.handle_key(key(KeyCode::Backspace));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.input, "");
    }

    #[test]
    fn paste_takes_the_first_line() {
        let mut app = App::new(Check::Mx);
        app.handle_paste("  example.com \nsecond");
        assert_eq!(app.input, "example.com");
    }

    #[test]
    fn scroll_is_clamped_to_what_the_renderer_reported() {
        let mut app = App::new(Check::Mx);
        app.mode = Mode::Normal;
        app.scroll_limit.set(3);
        for _ in 0..10 {
            app.handle_key(key(KeyCode::Char('j')));
        }
        assert_eq!(app.scroll, 3);
        app.handle_key(key(KeyCode::Char('g')));
        assert_eq!(app.scroll, 0);
        app.handle_key(key(KeyCode::Char('G')));
        assert_eq!(app.scroll, 3);
    }

    #[test]
    fn theme_picker_previews_and_cancel_restores() {
        let mut app = App::new(Check::Mx);
        app.set_themes(theme::builtin_themes(), "default");
        app.mode = Mode::Normal;
        app.handle_key(key(KeyCode::Char('T')));
        app.handle_key(key(KeyCode::Down));
        assert_ne!(app.theme.name, "default");
        app.handle_key(key(KeyCode::Char('b')));
        assert!(!app.transparent);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.theme.name, "default");
        assert!(app.transparent);
    }

    #[test]
    fn theme_enter_saves_name_and_changed_background() {
        let mut app = App::new(Check::Mx);
        app.set_themes(theme::builtin_themes(), "default");
        app.mode = Mode::Normal;
        app.handle_key(key(KeyCode::Char('T')));
        app.handle_key(key(KeyCode::Down));
        let action = app.handle_key(key(KeyCode::Enter));
        let Some(Action::SaveTheme { name, transparent }) = action else {
            panic!()
        };
        assert_eq!(name, app.themes[1].name);
        assert_eq!(transparent, None);
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let mut app = App::new(Check::Mx);
        let ev = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(app.handle_key(ev), Some(Action::Quit));
    }
}
