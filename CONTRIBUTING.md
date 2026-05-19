# Contributing

Thanks for the interest. This is a port — the contract lives in the [TypeScript reference](https://github.com/p-vbordei/agent-cid).

## Dev setup

```bash
git clone https://github.com/p-vbordei/agent-cid-rs
cd agent-cid-rs
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo run --example quickstart
```

## What can change here vs. upstream

- **Wire format is fixed.** Conformance vectors in `vectors/` are the contract. Any change to manifest fields, canonical encoding, signature scope, or CID computation MUST be proposed in the TS reference first; the vectors are regenerated there and copied here verbatim. PRs that change wire output will be rejected.
- **Idiomatic Rust is welcome.** Use traits, generics, error enums, async patterns — whatever makes the API ergonomic — as long as the public surface stays close to the TS API and the conformance suite passes byte-identical.
- **New deps need justification.** This port deliberately keeps the dep tree small. Adding a crate needs a one-line rationale in the PR.

## PR rules

1. Open the PR against `main`.
2. `cargo test` must pass — all conformance vectors green.
3. `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.
4. Include a short note in `CHANGELOG.md` under `[Unreleased]`.
5. Commits in the form `Subject line (≤72 chars)` + optional body explaining the why.

## Releasing

1. Bump `version` in `Cargo.toml`.
2. Move `[Unreleased]` notes under a new `## [x.y.z] — YYYY-MM-DD` heading in `CHANGELOG.md`.
3. Tag `vx.y.z` and push. CI publishes to crates.io.
