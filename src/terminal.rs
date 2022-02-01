use crossterm::{
    event::{self, DisableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, ErrorKind, Stdout};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

type Term = Terminal<CrosstermBackend<Stdout>>;

fn init_terminal() -> Result<Term, io::Error> {
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, DisableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn setup() -> Result<Term, io::Error> {
    enable_raw_mode()?;

    let mut terminal = init_terminal().unwrap();

    let _ = tui_main(&mut terminal);

    Ok(terminal)
}

pub fn exit(terminal: &mut Term) -> Result<(), io::Error> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

#[derive(Debug)]
pub enum TuiMainExitStatus {
    PressCtrlC,
}

pub fn tui_main(term: &mut Term) -> crossterm::Result<TuiMainExitStatus> {
    loop {
        if event::poll(std::time::Duration::from_millis(500))? {
            match event::read()? {
                Event::Key(ke) => {
                    if ke.code == KeyCode::Char('c') && ke.modifiers == KeyModifiers::CONTROL {
                        break;
                    }
                    if let KeyCode::Char(c) = ke.code {
                        let c = c.to_string();
                    }
                }
                Event::Mouse(_me) => {}
                Event::Resize(_width, _height) => {}
            }
        }
        term.draw(|f| {
            ui(f);
        })
        .unwrap();
    }
    crossterm::Result::Ok(TuiMainExitStatus::PressCtrlC)
}

fn ui<B: Backend>(f: &mut Frame<B>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Percentage(10),
            Constraint::Percentage(60),
            Constraint::Percentage(30),
        ])
        .split(f.size());
    for (i, chunk) in chunks.iter().enumerate() {
        let block = Block::default()
            .title(format!("Block {i}"))
            .borders(Borders::all());
        let p = Paragraph::new(format!("aaaaa {i}"))
            .block(block)
            .style(Style::default().fg(Color::White).bg(Color::Black))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(p, *chunk);
    }
}
