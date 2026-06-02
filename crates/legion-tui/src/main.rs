//! Legion TUI entry point – terminal setup, event loop, async refresh.

mod app;
mod ui;

use anyhow::Result;
use app::App;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use legion_core::{data_dir, Database};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, path::PathBuf, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    // Determine DB and scan root from args
    let args: Vec<String> = std::env::args().collect();
    let scan_root = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // The TUI runs in the current terminal, so we don't relaunch through a GUI
    // elevation prompt (that would detach it from the tty). Instead, if we lack
    // administrator rights, advise re-running under the OS elevation tool.
    if !legion_core::is_elevated() && !args.iter().any(|a| a == "--no-elevate") {
        let hint = if cfg!(windows) {
            "right-click → Run as administrator"
        } else {
            "re-run with `sudo legion-tui`"
        };
        eprintln!(
            "legion-tui: not elevated — some telemetry (full process list, security logs) \
             may be limited. For complete data, {hint}."
        );
    }

    let db_path = data_dir().join("legion.db");
    let db = Database::open(&db_path)?;

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run(&mut terminal, db, scan_root).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    db: Database,
    scan_root: PathBuf,
) -> Result<()> {
    let mut app = App::new(db, scan_root);

    // Initial fast load from DB
    app.refresh_fast()?;

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Non-blocking event poll
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.status_msg = Some("Refreshing...".into());
                        terminal.draw(|f| ui::draw(f, &app))?;
                        app.full_refresh().await?;
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        app.status_msg = Some("Scanning...".into());
                        terminal.draw(|f| ui::draw(f, &app))?;
                        app.full_refresh().await?;
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        app.ack_selected()?;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.next_alert();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.prev_alert();
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }

        // Auto-refresh in the background
        if app.should_auto_refresh() {
            app.full_refresh().await?;
        }
    }

    Ok(())
}
