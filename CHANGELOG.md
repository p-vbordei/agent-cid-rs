# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-05-19

### Added
- Initial Rust port of [@p-vbordei/agent-cid](https://github.com/p-vbordei/agent-cid) v1.0.
- `build`, `verify`, `verify_chain` with Ed25519 over JCS-canonical manifest bytes.
- `did:key` codec and `did:web` resolution (https-only, 64 KiB cap, 5 s timeout default), with a 5-minute per-resolver pubkey cache.
- Passes all C1–C5 conformance vectors byte-identical with the TS reference.

[Unreleased]: https://github.com/p-vbordei/agent-cid-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/p-vbordei/agent-cid-rs/releases/tag/v0.1.0
