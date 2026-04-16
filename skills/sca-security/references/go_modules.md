# Go Modules Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `go.mod` | manifest (module graph + version selections) |
| `go.sum` | checksums (not a lockfile — the MVS algorithm + go.mod is the "lockfile") |
| `vendor/` | optional vendored deps |
| `go.work` / `go.work.sum` | multi-module workspace |

Go's Minimum Version Selection (MVS) algorithm makes `go.mod` deterministic: given the same `go.mod`, you always get the same versions. `go.sum` is a trust-on-first-use checksum register.

## SBOM generation

```bash
# CycloneDX Go plugin
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod mod -json -output sbom.cdx.json
cyclonedx-gomod app -json -output sbom.cdx.json    # for applications (resolves main module)
cyclonedx-gomod bin -json -output sbom.cdx.json -main . ./bin/myapp   # from compiled binary

# Syft
syft dir:. -o cyclonedx-json=sbom.cdx.json
syft binary:./bin/myapp -o cyclonedx-json=binary.cdx.json
```

## Vulnerability scanning

```bash
# govulncheck (official — ONLY reports reachable vulns by default)
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
govulncheck -json ./... > vuln.json
govulncheck -scan=module ./...    # module-level (no call graph)
govulncheck -scan=package ./...   # package-level
govulncheck -scan=symbol ./...    # symbol-level (default; reachability!)

# govulncheck on binary (post-build)
govulncheck -mode=binary ./bin/myapp

# OSV-Scanner (has Go call analysis)
osv-scanner --experimental-call-analysis ./...

# Nancy (Sonatype)
go install github.com/sonatype-nexus-community/nancy@latest
go list -json -deps ./... | nancy sleuth

# Snyk
snyk test --file=go.mod
```

## Why govulncheck is special

govulncheck reads the Go Vuln DB (`vuln.go.dev`) which annotates each vuln with the specific **symbols** (functions/methods) that are affected. It then runs static analysis on your code and only reports vulns where the affected symbol is actually called.

This is the built-in reachability analysis for Go — no separate tooling required. Prefer `govulncheck` over generic scanners for Go projects.

## Dependency inspection

```bash
go list -m all                   # flat list of all modules
go mod graph                     # edge list of module graph
go mod why github.com/foo/bar    # why is this dep included?
go mod why -m github.com/foo/bar # module-level reason

# Upgrades
go list -m -u all                # show available upgrades
go get -u ./...                  # upgrade all
go get github.com/foo/bar@latest
```

## Integrity / supply chain

```bash
# Verify go.sum
go mod verify

# Public Go checksum DB (automatic for GOPRIVATE-excluded modules)
# env: GOSUMDB=sum.golang.org (default)
# Private: GOPRIVATE=*.internal.example.com

# Vendor + verify
go mod vendor
go mod tidy
```

## License extraction

```bash
go install github.com/google/go-licenses@latest
go-licenses report ./... --template report.tpl > licenses.csv
go-licenses check ./... --disallowed_types=forbidden,restricted,unknown
```

Common restricted licenses in Go ecosystem:
- `GPL-3.0` — rare in Go; some CLI tools use it
- `AGPL-3.0` — ditto
- `BSL-1.1` — HashiCorp's relicensing (Terraform, Vault, Consul) triggered this category for many orgs

## Common vulnerability patterns

| Class | Example | Scanner catch |
|-------|---------|---------------|
| stdlib vuln | CVE-2023-24539 (html/template) | govulncheck |
| Unsafe deserialization | encoding/gob on untrusted | manual |
| Path traversal | archive/zip, CVE-2024-24789 | govulncheck |
| HTTP smuggling | net/http, various | govulncheck |
| gRPC / protobuf CVEs | CVE-2023-44487 (HTTP/2 Rapid Reset) | govulncheck |

## Gotchas

- Binaries embed the Go version + module list (readable with `go version -m bin/app`). Always scan the **binary** in production — source scans miss stdlib CVEs when the binary is built with an older Go toolchain.
- `replace` directives in `go.mod` can point to forks with unknown provenance — audit them.
- Private modules behind `GOPRIVATE` skip checksum DB — rely on internal proxy trust.
- `go.sum` entries can accumulate for removed deps — run `go mod tidy` before scanning or you get false leads.

## Tool minimums (2026-04)

- go >= 1.23
- govulncheck >= 1.1
- cyclonedx-gomod >= 1.7
- osv-scanner >= 2.1 (for call analysis)
