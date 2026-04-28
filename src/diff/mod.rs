//! Core SBOM diff. Produces a [`ChangeSet`] listing components added, removed,
//! version-changed, and license-changed between a `before` and `after` [`Sbom`].
//!
//! # Determinism
//!
//! Output ordering is fully determined by [`ComponentKey`]'s `Ord` impl (BTreeMap
//! iteration); no timestamps, no insertion-order leakage. Identical input pairs
//! produce byte-identical renders, which is what `peter-evans/create-or-update-comment`
//! relies on for upsert behavior in CI.
//!
//! # Limitation (v0)
//!
//! When an SBOM contains multiple instances of the same component at different
//! versions (legitimate in ecosystems with non-flat dep trees), only the
//! last-inserted entry is kept by the BTreeMap collector. Proper handling needs
//! the dependency-graph relationships (CDX `dependencies`, SPDX `relationships`)
//! which are deferred to a follow-up PR.

pub mod key;

use std::collections::BTreeMap;

use crate::model::{Component, Sbom};
use key::{ComponentKey, key};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub added: Vec<Component>,
    pub removed: Vec<Component>,
    /// Pairs of (before, after) where the component's version changed. License
    /// changes accompanying a version bump are folded in here — they're expected.
    pub version_changed: Vec<(Component, Component)>,
    /// Pairs of (before, after) where licenses changed but version did NOT.
    /// This is the suspicious case: a re-publish under a different license can
    /// indicate a corrected SBOM, a license-rug-pull, or a supply-chain swap.
    pub license_changed: Vec<(Component, Component)>,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.version_changed.is_empty()
            && self.license_changed.is_empty()
    }
}

pub fn diff(before: &Sbom, after: &Sbom) -> ChangeSet {
    let bmap: BTreeMap<ComponentKey, &Component> =
        before.components.iter().map(|c| (key(c), c)).collect();
    let amap: BTreeMap<ComponentKey, &Component> =
        after.components.iter().map(|c| (key(c), c)).collect();

    let mut changeset = ChangeSet::default();

    for (k, &acomp) in &amap {
        match bmap.get(k) {
            None => changeset.added.push(acomp.clone()),
            Some(&bcomp) => {
                if bcomp.version != acomp.version {
                    changeset
                        .version_changed
                        .push((bcomp.clone(), acomp.clone()));
                } else if bcomp.licenses != acomp.licenses {
                    changeset
                        .license_changed
                        .push((bcomp.clone(), acomp.clone()));
                }
            }
        }
    }

    for (k, &bcomp) in &bmap {
        if !amap.contains_key(k) {
            changeset.removed.push(bcomp.clone());
        }
    }

    changeset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, Relationship, SbomFormat};

    fn comp(name: &str, version: &str, eco: Ecosystem, purl: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
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

    fn sbom(components: Vec<Component>) -> Sbom {
        Sbom {
            format: SbomFormat::CycloneDx,
            serial: None,
            components,
        }
    }

    #[test]
    fn diff_with_self_is_empty() {
        let s = sbom(vec![
            comp(
                "axios",
                "1.14.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.0"),
            ),
            comp(
                "serde",
                "1.0.228",
                Ecosystem::Cargo,
                Some("pkg:cargo/serde@1.0.228"),
            ),
        ]);
        assert!(diff(&s, &s).is_empty());
    }

    #[test]
    fn detects_added_and_removed() {
        let before = sbom(vec![
            comp(
                "axios",
                "1.14.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.0"),
            ),
            comp(
                "lodash",
                "4.17.21",
                Ecosystem::Npm,
                Some("pkg:npm/lodash@4.17.21"),
            ),
        ]);
        let after = sbom(vec![
            comp(
                "axios",
                "1.14.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.0"),
            ),
            comp(
                "react",
                "18.3.1",
                Ecosystem::Npm,
                Some("pkg:npm/react@18.3.1"),
            ),
        ]);
        let cs = diff(&before, &after);
        assert_eq!(cs.added.len(), 1);
        assert_eq!(cs.added[0].name, "react");
        assert_eq!(cs.removed.len(), 1);
        assert_eq!(cs.removed[0].name, "lodash");
    }

    #[test]
    fn detects_version_change() {
        let before = sbom(vec![comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        )]);
        let after = sbom(vec![comp(
            "axios",
            "1.14.1",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.1"),
        )]);
        let cs = diff(&before, &after);
        assert_eq!(cs.version_changed.len(), 1);
        let (b, a) = &cs.version_changed[0];
        assert_eq!(b.version, "1.14.0");
        assert_eq!(a.version, "1.14.1");
    }

    #[test]
    fn license_change_without_version_bump_is_suspicious() {
        let mut before_c = comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        );
        before_c.licenses = vec!["MIT".to_string()];
        let mut after_c = comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        );
        after_c.licenses = vec!["GPL-3.0".to_string()];

        let cs = diff(&sbom(vec![before_c]), &sbom(vec![after_c]));
        assert_eq!(cs.license_changed.len(), 1);
        assert!(
            cs.version_changed.is_empty(),
            "version-stable license change must not double-count"
        );
    }

    #[test]
    fn license_change_with_version_bump_only_flags_version() {
        let mut before_c = comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        );
        before_c.licenses = vec!["MIT".to_string()];
        let mut after_c = comp(
            "axios",
            "1.15.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.15.0"),
        );
        after_c.licenses = vec!["Apache-2.0".to_string()];

        let cs = diff(&sbom(vec![before_c]), &sbom(vec![after_c]));
        assert_eq!(cs.version_changed.len(), 1);
        assert!(cs.license_changed.is_empty());
    }

    #[test]
    fn cardinality_symmetry() {
        // Property: |diff(a,b).added| == |diff(b,a).removed|
        let a = sbom(vec![comp(
            "axios",
            "1.14.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.14.0"),
        )]);
        let b = sbom(vec![
            comp(
                "axios",
                "1.14.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.14.0"),
            ),
            comp(
                "lodash",
                "4.17.21",
                Ecosystem::Npm,
                Some("pkg:npm/lodash@4.17.21"),
            ),
        ]);
        let ab = diff(&a, &b);
        let ba = diff(&b, &a);
        assert_eq!(ab.added.len(), ba.removed.len());
        assert_eq!(ba.added.len(), ab.removed.len());
    }

    #[test]
    fn no_purl_components_match_by_name_and_ecosystem() {
        let before = sbom(vec![comp("custom", "0.1.0", Ecosystem::Cargo, None)]);
        let after = sbom(vec![comp("custom", "0.2.0", Ecosystem::Cargo, None)]);
        let cs = diff(&before, &after);
        assert_eq!(
            cs.version_changed.len(),
            1,
            "name+ecosystem keying should match across SBOMs"
        );
    }

    #[test]
    fn no_purl_same_name_different_ecosystem_does_not_collide() {
        let before = sbom(vec![comp("foo", "1.0.0", Ecosystem::Npm, None)]);
        let after = sbom(vec![comp("foo", "1.0.0", Ecosystem::PyPI, None)]);
        let cs = diff(&before, &after);
        assert_eq!(cs.added.len(), 1);
        assert_eq!(cs.removed.len(), 1);
        assert!(cs.version_changed.is_empty());
    }
}
