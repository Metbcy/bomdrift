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
//! # Multi-version components
//!
//! When an SBOM contains multiple instances of the same component at different
//! versions (legitimate in ecosystems with non-flat dep trees, e.g. npm), per-key
//! grouping is preserved and the diff is computed pair-by-version. For each
//! `ComponentKey` K with `B = before[K]` and `A = after[K]`:
//!
//! - Versions in `A \ B` → [`ChangeSet::added`].
//! - Versions in `B \ A` → [`ChangeSet::removed`].
//! - Versions in `A ∩ B` with differing license sets → [`ChangeSet::license_changed`].
//! - The legacy single-version case (`|B| = |A| = 1`, versions differ) collapses
//!   into [`ChangeSet::version_changed`] for backward-compatible rendering.
//!
//! When both sides have multi-version sets, no `version_changed` pair is
//! synthesized — pair-by-version assignment is ambiguous without the dep graph
//! (`dependencies` / `relationships`), so all changes route through `added` /
//! `removed`. A reviewer reading the comment still sees every relevant version
//! transition; correlating them is unambiguous when both sides are visible.

pub mod key;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::model::{Component, Sbom};
use key::{ComponentKey, key};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
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
    let bmap = group_by_key(&before.components);
    let amap = group_by_key(&after.components);

    let mut changeset = ChangeSet::default();

    let all_keys: BTreeSet<&ComponentKey> = bmap.keys().chain(amap.keys()).collect();
    for k in all_keys {
        let bs = bmap.get(k).map(Vec::as_slice).unwrap_or(&[]);
        let as_ = amap.get(k).map(Vec::as_slice).unwrap_or(&[]);
        diff_one_key(bs, as_, &mut changeset);
    }

    changeset
}

/// Group components by [`ComponentKey`], preserving every distinct version that
/// shares a key. The returned `BTreeMap` is the basis for deterministic
/// per-key iteration in [`diff`].
fn group_by_key(comps: &[Component]) -> BTreeMap<ComponentKey, Vec<&Component>> {
    let mut out: BTreeMap<ComponentKey, Vec<&Component>> = BTreeMap::new();
    for c in comps {
        out.entry(key(c)).or_default().push(c);
    }
    out
}

/// Reconcile a single component key's `before` and `after` versions against the
/// changeset. The legacy 1-vs-1 case is preserved as a `version_changed` pair so
/// existing renderers and the JSON contract don't see a behavior shift; every
/// other shape is reported as a combination of added / removed / license-changed
/// entries (see module-level "Multi-version components" notes).
fn diff_one_key(bs: &[&Component], as_: &[&Component], cs: &mut ChangeSet) {
    match (bs, as_) {
        ([], []) => {}
        ([], a) => {
            for c in a {
                cs.added.push((*c).clone());
            }
        }
        (b, []) => {
            for c in b {
                cs.removed.push((*c).clone());
            }
        }
        ([b], [a]) => {
            if b.version != a.version {
                cs.version_changed.push(((*b).clone(), (*a).clone()));
            } else if b.licenses != a.licenses {
                cs.license_changed.push(((*b).clone(), (*a).clone()));
            }
        }
        (b, a) => {
            // Multi-version on at least one side: pair by exact version match.
            // The BTreeMap-by-version below preserves deterministic iteration.
            let by_version_b: BTreeMap<&str, &Component> =
                b.iter().map(|c| (c.version.as_str(), *c)).collect();
            let by_version_a: BTreeMap<&str, &Component> =
                a.iter().map(|c| (c.version.as_str(), *c)).collect();

            for (v, &acomp) in &by_version_a {
                match by_version_b.get(v) {
                    None => cs.added.push(acomp.clone()),
                    Some(&bcomp) if bcomp.licenses != acomp.licenses => {
                        cs.license_changed.push((bcomp.clone(), acomp.clone()));
                    }
                    Some(_) => {}
                }
            }
            for (v, &bcomp) in &by_version_b {
                if !by_version_a.contains_key(v) {
                    cs.removed.push(bcomp.clone());
                }
            }
        }
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
    fn multi_version_same_component_does_not_collapse() {
        // Pre-fix behavior: BTreeMap keyed by ComponentKey silently dropped the
        // duplicate at axios@2.0, so `before` would look like `{axios@2.0}`
        // and the diff would produce a single version_changed pair instead of
        // surfacing both the removal of @1.0 and the additions of @3.0/@4.0.
        let before = sbom(vec![
            comp(
                "axios",
                "1.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@1.0.0"),
            ),
            comp(
                "axios",
                "2.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@2.0.0"),
            ),
        ]);
        let after = sbom(vec![
            comp(
                "axios",
                "2.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@2.0.0"),
            ),
            comp(
                "axios",
                "3.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@3.0.0"),
            ),
            comp(
                "axios",
                "4.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@4.0.0"),
            ),
        ]);

        let cs = diff(&before, &after);

        // Both new versions must appear in `added`.
        let added_versions: Vec<&str> = cs.added.iter().map(|c| c.version.as_str()).collect();
        assert_eq!(added_versions, vec!["3.0.0", "4.0.0"]);

        // The dropped version must appear in `removed`.
        let removed_versions: Vec<&str> = cs.removed.iter().map(|c| c.version.as_str()).collect();
        assert_eq!(removed_versions, vec!["1.0.0"]);

        // No `version_changed` synthesized — pair-by-version assignment is
        // ambiguous when both sides have multiple versions, so the diff stays
        // honest and routes everything through added/removed.
        assert!(cs.version_changed.is_empty());
        assert!(cs.license_changed.is_empty());
    }

    #[test]
    fn multi_version_intersecting_license_changes_route_to_license_changed() {
        // Both sides ship axios@2.0; only the license differs at that exact
        // version. The intersecting same-version-different-license case is the
        // suspicious one and must still surface.
        let mut b1 = comp(
            "axios",
            "1.0.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.0.0"),
        );
        b1.licenses = vec!["MIT".to_string()];
        let mut b2 = comp(
            "axios",
            "2.0.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@2.0.0"),
        );
        b2.licenses = vec!["MIT".to_string()];
        let mut a2 = comp(
            "axios",
            "2.0.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@2.0.0"),
        );
        a2.licenses = vec!["GPL-3.0".to_string()];

        let cs = diff(&sbom(vec![b1, b2]), &sbom(vec![a2]));
        assert_eq!(cs.license_changed.len(), 1);
        assert_eq!(cs.license_changed[0].1.version, "2.0.0");
        assert_eq!(cs.removed.len(), 1);
        assert_eq!(cs.removed[0].version, "1.0.0");
        assert!(cs.added.is_empty());
        assert!(cs.version_changed.is_empty());
    }

    #[test]
    fn single_to_multi_version_does_not_synthesize_version_changed() {
        // before: axios@1.0 (single); after: axios@2.0, axios@3.0 (two).
        // No clear "before-vs-after pair" — surface as removal + two adds.
        let before = sbom(vec![comp(
            "axios",
            "1.0.0",
            Ecosystem::Npm,
            Some("pkg:npm/axios@1.0.0"),
        )]);
        let after = sbom(vec![
            comp(
                "axios",
                "2.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@2.0.0"),
            ),
            comp(
                "axios",
                "3.0.0",
                Ecosystem::Npm,
                Some("pkg:npm/axios@3.0.0"),
            ),
        ]);
        let cs = diff(&before, &after);
        assert_eq!(cs.added.len(), 2);
        assert_eq!(cs.removed.len(), 1);
        assert!(cs.version_changed.is_empty());
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

    // ---- Property-based tests --------------------------------------------

    use proptest::prelude::*;

    /// Strategy: generate an `Sbom` with up to 16 npm components.
    /// Components are keyed by `name` only (no purl) for simplicity.
    /// Versions cycle from a small pool so add/remove/version_changed
    /// paths all see realistic input.
    fn arb_sbom() -> impl Strategy<Value = Sbom> {
        proptest::collection::vec(
            (
                "[a-z][a-z0-9_-]{0,15}",
                proptest::sample::select(vec!["1.0.0", "1.0.1", "2.0.0", "3.0.0"]),
            ),
            0..16,
        )
        .prop_map(|pairs| {
            let components = pairs
                .into_iter()
                .map(|(name, ver)| comp(&name, ver, Ecosystem::Npm, None))
                .collect();
            sbom(components)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Identity: diff(a, a) is always empty. Self-diffs of any input
        /// must produce no changes.
        #[test]
        fn diff_self_is_empty(a in arb_sbom()) {
            let cs = diff(&a, &a);
            prop_assert!(cs.is_empty(), "self-diff produced non-empty changeset: {:?}", cs);
        }

        /// Symmetry: `diff(a, b)` swaps `added` and `removed` from
        /// `diff(b, a)`. version_changed pairs reverse, license_changed
        /// pairs reverse. The ChangeSet shape is otherwise stable.
        #[test]
        fn diff_swap_roles_when_inputs_swapped(a in arb_sbom(), b in arb_sbom()) {
            let ab = diff(&a, &b);
            let ba = diff(&b, &a);

            // Cardinalities flip.
            prop_assert_eq!(ab.added.len(), ba.removed.len());
            prop_assert_eq!(ab.removed.len(), ba.added.len());
            prop_assert_eq!(ab.version_changed.len(), ba.version_changed.len());
            prop_assert_eq!(ab.license_changed.len(), ba.license_changed.len());
        }

        /// Determinism: two diff() calls on the same input produce
        /// byte-equal ChangeSet structures. This is the upsert contract
        /// for the PR-comment renderer.
        #[test]
        fn diff_is_deterministic(a in arb_sbom(), b in arb_sbom()) {
            let cs1 = diff(&a, &b);
            let cs2 = diff(&a, &b);
            prop_assert_eq!(cs1, cs2);
        }
    }
}
