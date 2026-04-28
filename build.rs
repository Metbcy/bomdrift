//! Build script: re-run `cargo build` whenever the embedded typosquat reference
//! lists change. The lists themselves are pulled in via `include_str!` in
//! `src/enrich/typosquat.rs`; this script's only job is to make sure cargo
//! invalidates the cache when the txt files are edited.

fn main() {
    println!("cargo:rerun-if-changed=data/npm-top1k.txt");
    println!("cargo:rerun-if-changed=build.rs");
}
