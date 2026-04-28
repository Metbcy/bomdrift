use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = bomdrift::cli::Cli::parse();
    bomdrift::run(cli)
}
