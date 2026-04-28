//! End-to-end parser tests over committed SBOM fixtures.

use std::fs;
use std::path::PathBuf;

use bomdrift::diff;
use bomdrift::model::{Ecosystem, HashAlg, SbomFormat};
use bomdrift::parse;

fn fixture(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    fs::read_to_string(&path).expect("read fixture")
}

#[test]
fn cdx_minimal_parses() {
    let raw = fixture("cdx-minimal.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let sbom = parse::parse(value).expect("parse cdx fixture");

    assert_eq!(sbom.format, SbomFormat::CycloneDx);
    assert_eq!(
        sbom.serial.as_deref(),
        Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
    );
    assert_eq!(sbom.components.len(), 3);

    let axios = &sbom.components[0];
    assert_eq!(axios.name, "axios");
    assert_eq!(axios.version, "1.14.0");
    assert_eq!(axios.ecosystem, Ecosystem::Npm);
    assert_eq!(axios.purl.as_deref(), Some("pkg:npm/axios@1.14.0"));
    assert_eq!(axios.licenses, vec!["MIT".to_string()]);
    assert_eq!(axios.hashes.len(), 1);
    assert_eq!(axios.hashes[0].alg, HashAlg::Sha256);
    assert_eq!(axios.supplier.as_deref(), Some("Matt Zabriskie"));
    assert_eq!(
        axios.source_url.as_deref(),
        Some("https://github.com/axios/axios"),
        "vcs externalReference should be picked over website"
    );

    let serde = &sbom.components[1];
    assert_eq!(serde.name, "serde");
    assert_eq!(serde.ecosystem, Ecosystem::Cargo);
    assert_eq!(serde.licenses, vec!["MIT OR Apache-2.0".to_string()]);
    assert!(serde.hashes.is_empty());
    assert!(serde.supplier.is_none());
    assert!(serde.source_url.is_none());

    let no_purl = &sbom.components[2];
    assert_eq!(no_purl.name, "no-purl-component");
    assert_eq!(no_purl.ecosystem, Ecosystem::Other("library".to_string()));
    assert!(no_purl.purl.is_none());
}

#[test]
fn spdx_minimal_parses() {
    let raw = fixture("spdx-minimal.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let sbom = parse::parse(value).expect("parse spdx fixture");

    assert_eq!(sbom.format, SbomFormat::Spdx);
    assert_eq!(
        sbom.serial.as_deref(),
        Some("https://github.com/Metbcy/bomdrift/dependency_graph/sbom-abc123")
    );
    assert_eq!(sbom.components.len(), 3);

    let axios = &sbom.components[0];
    assert_eq!(axios.name, "axios");
    assert_eq!(axios.version, "1.14.0");
    assert_eq!(axios.ecosystem, Ecosystem::Npm);
    assert_eq!(axios.purl.as_deref(), Some("pkg:npm/axios@1.14.0"));
    assert_eq!(axios.licenses, vec!["MIT".to_string()]);
    assert_eq!(axios.hashes.len(), 1);
    assert_eq!(axios.hashes[0].alg, HashAlg::Sha256);
    assert_eq!(axios.supplier.as_deref(), Some("Matt Zabriskie"));
    assert_eq!(
        axios.source_url.as_deref(),
        Some("https://github.com/axios/axios"),
        "git+ prefix should be stripped from downloadLocation"
    );
    assert_eq!(axios.bom_ref.as_deref(), Some("SPDXRef-npm-axios-1.14.0"));

    let requests = &sbom.components[1];
    assert_eq!(requests.ecosystem, Ecosystem::PyPI);
    assert_eq!(
        requests.licenses,
        vec!["Apache-2.0".to_string()],
        "should fall back to licenseDeclared when concluded is NOASSERTION"
    );
    assert!(
        requests.supplier.is_none(),
        "supplier=NOASSERTION should not produce a value"
    );
    assert!(
        requests.source_url.is_none(),
        "downloadLocation=NOASSERTION should not produce a source URL"
    );

    let no_purl = &sbom.components[2];
    assert_eq!(no_purl.name, "no-purl-component");
    assert_eq!(
        no_purl.ecosystem,
        Ecosystem::Other("spdx-package".to_string())
    );
    assert!(no_purl.purl.is_none());
    assert!(no_purl.licenses.is_empty());
}

#[test]
fn syft_minimal_parses() {
    let raw = fixture("syft-minimal.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let sbom = parse::parse(value).expect("parse syft fixture");

    assert_eq!(sbom.format, SbomFormat::Syft);
    assert_eq!(
        sbom.serial.as_deref(),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        "Syft `source.id` should map to Sbom.serial"
    );
    assert_eq!(sbom.components.len(), 3);

    let axios = &sbom.components[0];
    assert_eq!(axios.name, "axios");
    assert_eq!(axios.ecosystem, Ecosystem::Npm);
    assert_eq!(axios.licenses, vec!["MIT".to_string()]);
    assert_eq!(axios.bom_ref.as_deref(), Some("axios-1.14.0-syft-id"));

    let requests = &sbom.components[1];
    assert_eq!(requests.ecosystem, Ecosystem::PyPI);
    assert_eq!(
        requests.licenses,
        vec!["Apache-2.0".to_string()],
        "plain-string license entry should also be supported"
    );

    let no_purl = &sbom.components[2];
    assert_eq!(
        no_purl.ecosystem,
        Ecosystem::Cargo,
        "Syft `type: rust-crate` should map to Cargo when purl is absent"
    );
    assert!(no_purl.purl.is_none());
}

#[test]
fn diff_cdx_minimal_against_cdx_after() {
    // The "after" fixture mirrors the axios incident shape: axios bumped to
    // 1.14.1 (the compromised version), `plain-crypto-js@4.2.1` newly added
    // (the malicious typosquat), and a no-purl component removed.
    let before = parse_fixture("cdx-minimal.json");
    let after = parse_fixture("cdx-after.json");

    let cs = diff::diff(&before, &after);

    assert_eq!(cs.added.len(), 1, "plain-crypto-js should be added");
    assert_eq!(cs.added[0].name, "plain-crypto-js");
    assert_eq!(cs.added[0].version, "4.2.1");

    assert_eq!(
        cs.removed.len(),
        1,
        "no-purl-component should be removed (no purl, NameTuple keying)"
    );
    assert_eq!(cs.removed[0].name, "no-purl-component");

    assert_eq!(
        cs.version_changed.len(),
        1,
        "axios should be version-bumped"
    );
    let (b, a) = &cs.version_changed[0];
    assert_eq!(b.name, "axios");
    assert_eq!(b.version, "1.14.0");
    assert_eq!(a.version, "1.14.1");

    assert!(cs.license_changed.is_empty());
}

#[test]
fn diff_is_deterministic_across_runs() {
    let before = parse_fixture("cdx-minimal.json");
    let after = parse_fixture("cdx-after.json");

    let a = diff::diff(&before, &after);
    let b = diff::diff(&before, &after);
    assert_eq!(a, b, "diff output must be byte-identical for same inputs");
}

fn parse_fixture(name: &str) -> bomdrift::model::Sbom {
    let raw = fixture(name);
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    parse::parse(value).expect("parse fixture")
}
