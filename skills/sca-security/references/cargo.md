# Rust / Cargo Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `Cargo.toml` | manifest |
| `Cargo.lock` | lockfile (always commit for apps; libs: commit if you have a binary target) |
| `rust-toolchain.toml` | toolchain pin |
| `.cargo/config.toml` | registry + build config |

## SBOM generation

```bash
# CycloneDX cargo plugin
cargo install cargo-cyclonedx
cargo cyclonedx --format json
# produces Cargo.cdx.json

# Syft
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# cargo-audit (RustSec Advisory DB)
cargo install cargo-audit
cargo audit
cargo audit --json > audit.json
cargo audit --deny unmaintained   # also fail on unmaintained crates
cargo audit fix                   # experimental auto-fix

# cargo-deny (licenses + advisories + sources + bans, unified)
cargo install cargo-deny
cargo deny check                  # all checks
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources

# OSV-Scanner
osv-scanner --lockfile=Cargo.lock

# Snyk (beta for Rust)
snyk test --file=Cargo.toml
```

## cargo-deny configuration (`deny.toml`)

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016"]
deny = ["GPL-3.0", "AGPL-3.0"]
copyleft = "warn"

[bans]
multiple-versions = "warn"
wildcards = "deny"
# Ban specific crates
deny = [
    { name = "openssl", reason = "use rustls" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

## Dependency inspection

```bash
cargo tree
cargo tree -i <crate>              # inverse tree (who depends on this?)
cargo tree -d                       # duplicate versions (common supply chain risk)
cargo tree --format '{p} {l}'       # show licenses inline

# Outdated
cargo install cargo-outdated
cargo outdated

# Unused deps
cargo install cargo-udeps
cargo +nightly udeps
```

## Unsafe code reachability (proxy)

```bash
cargo install cargo-geiger
cargo geiger
# Reports unsafe-code usage per crate, transitively.
# Useful for memory-safety reachability — unsafe blocks are the locus of most
# memory-corruption CVEs in Rust.
```

## License extraction

`cargo deny check licenses` is the canonical path. For a flat list:

```bash
cargo install cargo-license
cargo license --json > licenses.json
```

## Common vulnerability patterns

| Class | Example | DB |
|-------|---------|-----|
| Memory safety in unsafe | RUSTSEC-2021-0001 | RustSec |
| Dependency version yanked | yanked upstream | cargo-audit |
| Integer overflow | RUSTSEC-2021-0093 | RustSec |
| Proc-macro supply chain | multiple 2024 incidents | RustSec + advisory watch |

## Crates.io supply chain

- All published crates are immutable (no unpublish after 72h).
- Yanked crates cannot be new-installed but remain in existing `Cargo.lock`.
- No mandatory signing yet (2026-04); sigstore integration in beta.
- Git dependencies bypass crates.io entirely — treat with higher scrutiny.

## Gotchas

- `build.rs` runs arbitrary code at build time — same supply chain risk as npm postinstall. Audit before enabling a new dep.
- `proc-macro` crates run at compile time with full file-system + network access in the compiler process. Extra scrutiny.
- Workspace crates: scan from workspace root; `cargo audit` is workspace-aware.
- `[patch]` and `[replace]` sections in `Cargo.toml` can swap in forks — audit.

## Tool minimums (2026-04)

- cargo >= 1.82
- cargo-audit >= 0.21
- cargo-deny >= 0.16
- cargo-cyclonedx >= 0.5
