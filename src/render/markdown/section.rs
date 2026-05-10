use std::fmt::Write;
/// Open a per-category collapsible section. The `### {label} ({count})`
/// markdown header stays outside the `<details>` block so it remains
/// visible (and TOC-eligible) even when the section is collapsed; the
/// `<details>` wrapper hides the body table by default to keep the comment
/// scannable for big diffs. `teaser` populates the `<summary>` line with
/// the most-actionable item in the section (e.g. `top severity: CRITICAL`)
/// so the reviewer knows whether expanding is worth their time.
pub fn open(out: &mut String, label: &str, count: usize, teaser: Option<&str>) {
    let _ = writeln!(out, "### {label} ({count})\n");
    out.push_str("<details><summary>Show details");
    if let Some(t) = teaser {
        let _ = write!(out, " · {t}");
    }
    // Blank line after `</summary>` is required by GitHub-Flavored Markdown
    // for the markdown body inside `<details>` to render as markdown rather
    // than as raw HTML. Same blank line on close.
    out.push_str("</summary>\n\n");
}

pub fn close(out: &mut String) {
    out.push_str("\n</details>\n\n");
}
