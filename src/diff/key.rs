//! Component keying. The diff core uses [`ComponentKey`] to match the same
//! component across `before` and `after` SBOMs; the canonical key is the purl with
//! its version stripped, falling back to `(ecosystem, name)` when no purl is
//! available.

use crate::model::{Component, Ecosystem};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentKey {
    /// Canonical key when a purl is available: `pkg:type/namespace/name`
    /// with version, qualifiers, and subpath all stripped.
    Purl(String),
    /// Fallback when purl is absent: pair of ecosystem and name. Ecosystem
    /// participation in the key prevents `npm:requests` and `pypi:requests`
    /// from colliding.
    NameTuple(Ecosystem, String),
}

pub fn key(c: &Component) -> ComponentKey {
    if let Some(p) = &c.purl {
        ComponentKey::Purl(purl_without_version(p).to_string())
    } else {
        ComponentKey::NameTuple(c.ecosystem.clone(), c.name.clone())
    }
}

/// Strip qualifiers (`?`), subpath (`#`), and version (everything after the last
/// `@`) from a purl, leaving just `pkg:type/namespace/name`.
///
/// `rfind('@')` correctly handles npm scoped packages like
/// `pkg:npm/@scope/name@1.0.0` because the `@` in `@scope` is earlier than the
/// version separator.
pub fn purl_without_version(purl: &str) -> &str {
    let head = purl.split(['?', '#']).next().unwrap_or(purl);
    if let Some(at) = head.rfind('@') {
        &head[..at]
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use crate::model::Relationship;

    #[test]
    fn strips_simple_version() {
        assert_eq!(
            purl_without_version("pkg:npm/axios@1.14.0"),
            "pkg:npm/axios"
        );
        assert_eq!(
            purl_without_version("pkg:cargo/serde@1.0.228"),
            "pkg:cargo/serde"
        );
    }

    #[test]
    fn strips_version_with_qualifiers() {
        assert_eq!(
            purl_without_version("pkg:npm/axios@1.14.0?vcs_url=https://github.com/axios/axios"),
            "pkg:npm/axios"
        );
    }

    #[test]
    fn strips_subpath() {
        assert_eq!(
            purl_without_version("pkg:golang/github.com/foo/bar@v1.0.0#subpath"),
            "pkg:golang/github.com/foo/bar"
        );
    }

    #[test]
    fn handles_npm_scoped_with_at_in_namespace() {
        // Both encoded and unencoded scope forms; rfind('@') always returns the
        // version separator regardless of the leading scope `@`.
        assert_eq!(
            purl_without_version("pkg:npm/@scope/name@1.0.0"),
            "pkg:npm/@scope/name"
        );
        assert_eq!(
            purl_without_version("pkg:npm/%40scope/name@1.0.0"),
            "pkg:npm/%40scope/name"
        );
    }

    #[test]
    fn passes_through_when_no_version() {
        assert_eq!(purl_without_version("pkg:npm/axios"), "pkg:npm/axios");
    }

    fn make(name: &str, eco: Ecosystem, purl: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: "0".to_string(),
            ecosystem: eco,
            purl: purl.map(str::to_string),
            licenses: Vec::new(),
            supplier: None,
            hashes: Vec::new(),
            relationship: Relationship::Unknown,
            source_url: None,
            bom_ref: None,
        }
    }

    #[test]
    fn key_uses_purl_when_present() {
        let c = make("axios", Ecosystem::Npm, Some("pkg:npm/axios@1.14.0"));
        assert_eq!(key(&c), ComponentKey::Purl("pkg:npm/axios".to_string()));
    }

    #[test]
    fn key_falls_back_to_name_tuple() {
        let c = make("custom", Ecosystem::Cargo, None);
        assert_eq!(
            key(&c),
            ComponentKey::NameTuple(Ecosystem::Cargo, "custom".to_string())
        );
    }
}
