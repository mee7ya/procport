use std::{io, net::SocketAddr, thread, time::Duration};

use anyhow::Result;
use clap::Parser;
use crossterm::{cursor, execute, style, terminal};
use tabled::{
    Table, Tabled,
    settings::{Modify, Settings, Style, Theme, Width, object::Columns, style::HorizontalLine},
};

use crate::windows::{Connection, Protocol};

#[derive(Parser, Debug)]
#[command(name = "procport")]
#[command(about = "Display ports used by a process", long_about = None)]
pub struct Cli {
    /// Process name to search for
    process_name: String,
}

impl Cli {
    pub fn new() -> Self {
        let mut cli = Cli::parse();

        if !cli.process_name.ends_with(".exe") {
            cli.process_name.push_str(".exe");
        }

        cli
    }

    fn get_pids(&self) -> Result<Vec<u32>, ::windows::core::Error> {
        crate::windows::get_pids_by_name(&self.process_name)
    }

    fn get_connections(&self, pids: &[u32]) -> Result<Vec<Connection>, ::windows::core::Error> {
        crate::windows::get_connections_by_pids(pids)
    }

    fn build_output(&self, connections: &[Connection]) -> String {
        let connections = connections.iter().map(ConnectionOutput::from);

        let mut theme = Theme::from_style(Style::blank());
        theme.insert_horizontal_line(1, HorizontalLine::filled('-'));

        let settings = Settings::default()
            .with(theme)
            .with(Modify::new(Columns::one(0)).with(Width::increase(8)))
            .with(Modify::new(Columns::one(1)).with(Width::wrap(10)))
            .with(Modify::new(Columns::new(2..=4)).with(Width::increase(20)));

        Table::new(connections).with(settings).to_string()
    }

    pub fn start(&self) -> Result<()> {
        ctrlc::try_set_handler(|| {
            execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen).unwrap();
            std::process::exit(0);
        })?;

        let mut stdout = io::stdout();

        execute!(
            stdout,
            terminal::EnterAlternateScreen,
            cursor::Hide,
            cursor::MoveTo(0, 0),
            cursor::SavePosition,
            style::Print(format!("Waiting for process '{}'...\n", self.process_name)),
        )?;

        loop {
            match self.get_pids() {
                Ok(p) if !p.is_empty() => break,
                Ok(_) => thread::sleep(Duration::from_millis(500)),
                Err(e) => {
                    return Err(io::Error::other(e).into());
                }
            }
        }

        execute!(
            stdout,
            cursor::RestorePosition,
            terminal::Clear(terminal::ClearType::FromCursorDown)
        )?;

        loop {
            match self.get_pids() {
                Ok(pids) if !pids.is_empty() => {
                    match self.get_connections(&pids) {
                        Ok(connections) => {
                            execute!(
                                stdout,
                                cursor::RestorePosition,
                                style::Print(self.build_output(&connections)),
                                terminal::Clear(terminal::ClearType::FromCursorDown),
                            )?;
                        }
                        Err(e) => {
                            return Err(io::Error::other(e).into());
                        }
                    }
                    thread::sleep(Duration::from_millis(1000));
                }
                Ok(_) => {
                    execute!(
                        stdout,
                        style::Print("Process has exited. Use Ctrl+C to exit.")
                    )?;
                    return Ok(());
                }
                Err(e) => {
                    return Err(io::Error::other(e).into());
                }
            }
        }
    }
}

#[derive(Debug, Tabled)]
struct ConnectionOutput {
    #[tabled(rename = "Protocol", order = 1)]
    protocol: Protocol,
    #[tabled(rename = "Local", order = 2)]
    local: SocketAddr,
    #[tabled(rename = "Remote", order = 3)]
    remote: SocketAddr,
    #[tabled(rename = "PID", order = 0)]
    pid: u32,
}

impl From<&Connection> for ConnectionOutput {
    fn from(conn: &Connection) -> Self {
        ConnectionOutput {
            protocol: conn.protocol,
            local: conn.local,
            remote: conn.remote,
            pid: conn.pid,
        }
    }
}
