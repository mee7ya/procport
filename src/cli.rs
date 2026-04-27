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
#[command(about = "Displays active TCP connections associated with a process", long_about = None)]
pub struct Cli {
    /// Process name to search for
    process_name: String,
    /// Keep history of connections
    #[arg(long)]
    preserve_history: bool,

    #[arg(skip)]
    pids: Vec<u32>,
    #[arg(skip)]
    connections: Vec<Connection>,
}

impl Cli {
    pub fn new() -> Self {
        let mut cli = Cli::parse();

        if !cli.process_name.ends_with(".exe") {
            cli.process_name.push_str(".exe");
        }

        cli
    }

    fn get_pids(&mut self) -> Result<()> {
        self.pids = crate::windows::get_pids_by_name(&self.process_name)?;
        Ok(())
    }

    fn get_connections(&mut self) -> Result<()> {
        let connections = crate::windows::get_connections_by_pids(&self.pids)?;

        if !self.preserve_history {
            // No need to merge with history
            self.connections = connections;
        } else {
            let mut active_connections = vec![];

            // Iterate over new active connections
            // If they exist in history, replace the history one with the new one
            // If they don't exist in history, add them to history
            // Store the indices of all active ones

            // Surely there won't be big enough input for this to be a performance issue
            for connection in connections {
                let idx = self
                    .connections
                    .iter()
                    .position(|_connection| _connection == &connection);

                if let Some(idx) = idx {
                    self.connections[idx] = connection;
                    active_connections.push(idx);
                } else {
                    self.connections.push(connection);
                    active_connections.push(self.connections.len() - 1);
                }
            }

            // Deactivate all the connections that didn't appear in the new active list
            for (i, connection) in self.connections.iter_mut().enumerate() {
                if !active_connections.contains(&i) {
                    connection.active = false;
                }
            }
        }
        Ok(())
    }

    fn build_output(&self) -> String {
        let connections = self.connections.iter().map(ConnectionOutput::from);

        let mut theme = Theme::from_style(Style::blank());
        theme.insert_horizontal_line(1, HorizontalLine::filled('-'));

        let settings = Settings::default()
            .with(theme)
            .with(Modify::new(Columns::one(0)).with(Width::increase(8)))
            .with(Modify::new(Columns::one(1)).with(Width::wrap(10)))
            .with(Modify::new(Columns::new(2..=3)).with(Width::increase(20)))
            .with(Modify::new(Columns::one(4)).with(Width::increase(12)));

        Table::new(connections).with(settings).to_string()
    }

    /// Waits for at least one process to appear
    /// Sleeps for `sleep_duration` between each check
    fn wait_for_process(&mut self, sleep_duration: Duration) -> Result<()> {
        execute!(
            io::stdout(),
            style::Print(format!("Waiting for process '{}'...\n", self.process_name))
        )?;

        loop {
            self.get_pids()?;
            if !self.pids.is_empty() {
                break;
            }
            thread::sleep(sleep_duration);
        }

        Ok(())
    }

    /// Keep polling pids and related TCP connections until the process exits
    fn poll_connections(&mut self, sleep_duration: Duration) -> Result<()> {
        let mut stdout = io::stdout();
        loop {
            self.get_pids()?;

            if self.pids.is_empty() {
                execute!(
                    stdout,
                    style::Print("Process has exited. Use Ctrl+C to exit.")
                )?;
                return Ok(());
            }

            self.get_connections()?;

            execute!(
                stdout,
                cursor::RestorePosition,
                style::Print(self.build_output()),
                terminal::Clear(terminal::ClearType::FromCursorDown),
            )?;

            thread::sleep(sleep_duration);
        }
    }

    pub fn start(&mut self) -> Result<()> {
        // Set up Ctrl+C handler to clean up terminal state
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

        // Wait for the process to appear before starting the main loop
        self.wait_for_process(Duration::from_millis(500))?;

        execute!(
            stdout,
            cursor::RestorePosition,
            terminal::Clear(terminal::ClearType::FromCursorDown)
        )?;

        // Main loop, poll connections
        self.poll_connections(Duration::from_millis(500))?;

        Ok(())
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
    #[tabled(rename = "Status", order = 4, format("{}", if self.active { "CONNECTED" } else { "DROPPED" }))]
    active: bool,
}

impl From<&Connection> for ConnectionOutput {
    fn from(conn: &Connection) -> Self {
        ConnectionOutput {
            protocol: conn.protocol,
            local: conn.local,
            remote: conn.remote,
            pid: conn.pid,
            active: conn.active,
        }
    }
}
