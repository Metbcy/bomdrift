mod baseline;
mod calibration;
mod diff;
mod init;
mod predicates;
#[cfg(test)]
mod tests;

use anyhow::Result;

use crate::cli::{Cli, Command};
use crate::refresh;

/// Process exit code emitted when `--fail-on` trips. Distinct from clap's
/// usage-error exit (`2`-ish on parse failure) because clap exits before
/// `run` is called — there's no overlap window where this code is ambiguous.
pub const FAIL_ON_EXIT_CODE: i32 = 2;

pub use predicates::{any_epss_at_or_above, any_kev, budget_tripped, tripped};
// Re-export crate-private calibration helpers so they remain reachable as
// `crate::run::<name>` for tests and any future cross-module consumers.
#[allow(unused_imports)]
pub(crate) use calibration::{
    CalibrationOverrides, CalibrationScore, CalibrationThreshold, write_calibration_row,
};

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Diff(args) => diff::run_diff(*args),
        Command::RefreshTyposquat(args) => refresh::run(args),
        Command::Baseline { action } => baseline::run_baseline(action),
        Command::Init(args) => init::run_init(args),
    }
}
