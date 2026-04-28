# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository scaffold: CLI surface, module layout, CI workflow, license, README.
- Typosquat enricher: flags newly added npm components whose name is suspiciously
  similar to a top-1000 package, using Jaro-Winkler plus a suffix-containment
  boost rule. Embedded reference list (`data/npm-top1k.txt`, ~16 KB) sourced from
  anvaka/npmrank. Catches the `plain-crypto-js` → `crypto-js` axios-incident
  pattern that pure JW alone misses.
