//! End-to-end parser tests over committed SBOM fixtures.

use std::fs;
use std::path::PathBuf;

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
