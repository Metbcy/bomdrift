use anyhow::{Context, Result};

use crate::baseline;
use crate::cli::BaselineAction;
use crate::clock;

pub(super) fn run_baseline(action: BaselineAction) -> Result<()> {
    match action {
        BaselineAction::Add(args) => {
            // Validate --expires upfront so a typo'd date doesn't write a
            // bad entry that errors on the NEXT diff load.
            if let Some(s) = &args.expires {
                clock::parse_ymd(s)
                    .with_context(|| format!("--expires must be YYYY-MM-DD, got {s:?}"))?;
            }

            // --from-comment overrides positional id/reason. Used by the
            // GitLab webhook bridge (Phase L). Non-zero exit when the
            // body has no directive — silent no-op would let mis-configured
            // bridges look like they worked.
            let (id, reason_owned) = if let Some(body) = &args.from_comment {
                match baseline::parse_comment_directive(body)? {
                    Some((id, reason)) => (id, reason),
                    None => {
                        eprintln!(
                            "bomdrift: --from-comment body contained no `/bomdrift suppress <ID>` directive"
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                let Some(id) = args.id.clone() else {
                    eprintln!(
                        "bomdrift baseline add: missing required ADVISORY_ID (use a positional argument or --from-comment <BODY>)"
                    );
                    std::process::exit(2);
                };
                (id, args.reason.clone())
            };

            let outcome = baseline::add_suppression_full(
                &args.path,
                &id,
                args.expires.as_deref(),
                reason_owned.as_deref(),
            )?;
            match outcome {
                baseline::AddOutcome::Added => {
                    eprintln!(
                        "bomdrift: added '{id}' to {path}",
                        id = id.trim(),
                        path = args.path.display(),
                    );
                }
                baseline::AddOutcome::AlreadyPresent => {
                    eprintln!(
                        "bomdrift: '{id}' already present in {path}; no change",
                        id = id.trim(),
                        path = args.path.display(),
                    );
                }
            }
            Ok(())
        }
    }
}
