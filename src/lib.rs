pub mod cli;
pub mod diff;
pub mod model;
pub mod parse;

use anyhow::{Result, bail};

use crate::cli::{Cli, Command};

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Diff(_) => bail!("`diff` is not implemented yet — tracking issue: v0.1.0"),
        Command::RefreshTyposquat => {
            bail!("`refresh-typosquat` is not implemented yet — tracking issue: v0.1.0")
        }
    }
}
