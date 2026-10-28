//! The terminal UI event loop.

use std::{path::PathBuf, sync::Arc, time::Duration};

use color_eyre::eyre::{Result, WrapErr, bail};
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyEventKind},
    execute,
};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use tokio::{sync::mpsc, time::MissedTickBehavior};

use crate::{
    app::{Action, App},
    config,
    engine::Engine,
    query::Check,
    report::Report,
    theme::Theme,
};

/// How often the screen is redrawn even when nothing happened (so status
/// messages expire).
const REDRAW: Duration = Duration::from_millis(500);

/// What `run` needs besides the engine.
pub struct Settings {
    pub config_path: PathBuf,
    pub themes: Vec<Theme>,
    pub theme_name: String,
    pub transparent: bool,
    pub default_check: Check,
    /// A query to run as soon as the window opens.
    pub initial: Option<String>,
}

/// Enter the alternate screen / raw mode. `ratatui::init` also installs a panic
/// hook that restores the terminal; we extend it to undo bracketed paste.
pub fn init_terminal() -> Result<DefaultTerminal> {
    let terminal = ratatui::init();
    execute!(std::io::stdout(), EnableBracketedPaste)?;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableBracketedPaste);
        prev(info);
    }));
    Ok(terminal)
}

pub fn restore_terminal() {
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
}

/// The editor command: `$VISUAL`, else `$EDITOR`, else `vi`, split on
/// whitespace so `code -w` works.
fn editor_command(visual: Option<&str>, editor: Option<&str>) -> Vec<String> {
    let spec = [visual, editor]
        .into_iter()
        .flatten()
        .find(|s| !s.trim().is_empty())
        .unwrap_or("vi");
    spec.split_whitespace().map(str::to_string).collect()
}

/// Give the terminal to an editor and wait for it to exit.
fn run_editor(path: &std::path::Path) -> Result<()> {
    let parts = editor_command(
        std::env::var("VISUAL").ok().as_deref(),
        std::env::var("EDITOR").ok().as_deref(),
    );
    let Some((program, args)) = parts.split_first() else {
        bail!("$VISUAL/$EDITOR is empty");
    };
    let status = std::process::Command::new(program)
        .args(args)
        .arg(path)
        .status()
        .wrap_err_with(|| format!("cannot start the editor '{program}'"))?;
    if !status.success() {
        bail!("{program} exited with {status}");
    }
    Ok(())
}

pub async fn run(mut terminal: DefaultTerminal, engine: Engine, settings: Settings) -> Result<()> {
    let engine = Arc::new(engine);
    let mut app = App::new(settings.default_check);
    app.transparent = settings.transparent;
    app.set_themes(settings.themes, &settings.theme_name);
    let config_path = settings.config_path;
    let (tx, mut rx) = mpsc::unbounded_channel::<(u64, Report)>();
    let mut term_events = EventStream::new();
    let mut tick = tokio::time::interval(REDRAW);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let spawn_run = |engine: &Arc<Engine>, tx: &mpsc::UnboundedSender<(u64, Report)>, id, query| {
        let (engine, tx) = (engine.clone(), tx.clone());
        tokio::spawn(async move {
            let report = engine.run(query).await;
            let _ = tx.send((id, report));
        });
    };

    if let Some(text) = settings.initial
        && let Some(Action::Run { id, query }) = app.start(&text)
    {
        app.mode = crate::app::Mode::Normal;
        spawn_run(&engine, &tx, id, query);
    }

    loop {
        terminal.draw(|f| crate::ui::draw(f, &app))?;

        tokio::select! {
            _ = tick.tick() => {}

            maybe_event = term_events.next() => {
                // Stream end means stdin closed; nothing more can be done.
                let Some(event) = maybe_event else { return Ok(()) };
                match event? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        match app.handle_key(key) {
                            None => {}
                            Some(Action::Quit) => return Ok(()),
                            Some(Action::Run { id, query }) => spawn_run(&engine, &tx, id, query),
                            Some(Action::SaveTheme { name, transparent }) => {
                                let mut note = format!("Theme: {name}");
                                let mut failed = None;
                                if let Err(e) = config::set_value(&config_path, "theme", &config::yaml_scalar(&name)) {
                                    failed = Some(e);
                                } else if let Some(on) = transparent {
                                    note.push_str(if on { ", transparent background" } else { ", theme background" });
                                    if let Err(e) = config::set_value(&config_path, "transparent_background", &on.to_string()) {
                                        failed = Some(e);
                                    }
                                }
                                match failed {
                                    None => app.set_status(format!("{note} (saved)"), false),
                                    Some(e) => app.set_status(format!("{note} applied but not saved: {e:#}"), true),
                                }
                            }
                            Some(Action::EditConfig) => {
                                let before = std::fs::read_to_string(&config_path).ok();
                                restore_terminal();
                                let outcome = run_editor(&config_path);
                                terminal = init_terminal()?;
                                // The old stream may have swallowed keys meant for the editor.
                                term_events = EventStream::new();
                                match outcome {
                                    Err(e) => app.set_status(format!("Editor: {e:#}"), true),
                                    Ok(()) if std::fs::read_to_string(&config_path).ok() == before => {}
                                    Ok(()) => match config::load(&config_path) {
                                        Err(e) => app.set_status(
                                            format!("The config has an error, fix it before restarting: {e:#}"),
                                            true,
                                        ),
                                        Ok(_) => app.set_status("Config changed: restart dnstui to apply it", false),
                                    },
                                }
                            }
                        }
                    }
                    Event::Paste(text) => app.handle_paste(&text),
                    // Resize and everything else just triggers the redraw at the loop top.
                    _ => {}
                }
            }

            Some((id, report)) = rx.recv() => app.apply_report(id, report),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_prefers_visual_then_editor_then_vi() {
        assert_eq!(editor_command(Some("nvim"), Some("nano")), ["nvim"]);
        assert_eq!(editor_command(None, Some("code -w")), ["code", "-w"]);
        assert_eq!(editor_command(Some("  "), Some("nano")), ["nano"]);
        assert_eq!(editor_command(None, None), ["vi"]);
    }
}
