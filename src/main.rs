use crossterm::{
    cursor, execute,
    style::{self, Print},
    terminal,
};

use crate::cli::Cli;
use crate::windows::Connection;
use std::{io, thread, time::Duration};

mod cli;
mod windows;

fn output(pids: &[u32], connections: &[Connection]) -> String {
    let rows: Vec<String> = connections
        .iter()
        .map(|c| {
            format!(
                "{:<8} {:<8} {:<45} {:<45}",
                format!("{:?}", c.protocol),
                c.pid,
                c.local,
                c.remote,
            )
        })
        .collect();

    let out = format!(
        "PIDs: {}\n{:<8} {:<8} {:<45} {:<45}\n{}\n{}",
        pids.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        "Proto",
        "PID",
        "Local Address",
        "Remote Address",
        "-".repeat(104),
        rows.join("\n"),
    );

    out
}

fn main() -> io::Result<()> {
    let cli = Cli::new();
    let mut stdout = io::stdout();

    execute!(
        stdout,
        cursor::Hide,
        cursor::SavePosition,
        Print(format!("Waiting for process '{}'...\n", cli.process_name())),
    )?;

    loop {
        match cli.get_pids() {
            Ok(p) if !p.is_empty() => break,
            Ok(_) => thread::sleep(Duration::from_millis(500)),
            Err(e) => {
                return Err(io::Error::other(e));
            }
        }
    }

    execute!(
        stdout,
        cursor::RestorePosition,
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )?;

    loop {
        match cli.get_pids() {
            Ok(pids) if !pids.is_empty() => {
                match cli.get_connections(&pids) {
                    Ok(connections) => {
                        execute!(
                            stdout,
                            cursor::RestorePosition,
                            style::Print(output(&pids, &connections)),
                            terminal::Clear(terminal::ClearType::FromCursorDown),
                        )?;
                    }
                    Err(e) => {
                        return Err(io::Error::other(e));
                    }
                }
                thread::sleep(Duration::from_millis(1000));
            }
            Ok(_) => {
                execute!(stdout, style::Print("Process has exited"))?;
                return Ok(());
            }
            Err(e) => {
                return Err(io::Error::other(e));
            }
        }
    }
}
