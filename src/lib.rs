#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::unwrap_used, clippy::expect_used)]
#![warn(clippy::panic, clippy::todo, clippy::unimplemented)]

//! Crate root: declares the public module tree and re-exports the
//! orchestration entry points.
//!
//! The `run` / `run_diff` orchestration plus its private helpers live
//! in [`mod@run`]; this file is a thin shim so that `bomdrift::run(...)`
//! and the public predicates (`tripped`, `any_kev`, ...) keep their
//! historical paths.

pub mod attestation;
pub mod baseline;
pub mod cli;
pub mod clock;
pub mod config;
pub mod diff;
pub mod enrich;
pub mod model;
pub mod parse;
pub mod plugin;
pub mod refresh;
pub mod render;
pub mod run;
pub mod vex;

pub use crate::run::{
    FAIL_ON_EXIT_CODE, any_epss_at_or_above, any_kev, budget_tripped, run, tripped,
};
pub use crate::vex::{SyntheticFindingKind, parse_synthetic_id};
