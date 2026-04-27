use anyhow::Result;

use crate::cli::Cli;

mod cli;
mod windows;

fn main() -> Result<()> {
    let mut cli = Cli::new();

    cli.start()?;

    Ok(())
}
