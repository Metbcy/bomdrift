//! Output renderers. Each takes a [`crate::diff::ChangeSet`] and produces a
//! string in a target format. Rendering is pure (no I/O, no allocations beyond the
//! output buffer) so the same `ChangeSet` always renders to byte-identical output —
//! a hard requirement for `peter-evans/create-or-update-comment` upsert behavior.

pub mod json;
pub mod markdown;
