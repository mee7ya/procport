use clap::Parser;

use crate::windows::Connection;

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

    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    pub fn get_pids(&self) -> Result<Vec<u32>, ::windows::core::Error> {
        crate::windows::get_pids_by_name(&self.process_name)
    }

    pub fn get_connections(&self, pids: &[u32]) -> Result<Vec<Connection>, ::windows::core::Error> {
        crate::windows::get_connections_by_pids(pids)
    }
}
