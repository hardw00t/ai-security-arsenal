# npm / yarn / pnpm Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `package.json` | manifest (declared deps) |
| `package-lock.json` | npm lockfile (v3 default, npm >= 7) |
| `yarn.lock` | Yarn Classic v1 lockfile |
| `.yarn/install-state.gz` + `yarn.lock` | Yarn Berry (>=2) |
| `pnpm-lock.yaml` | pnpm lockfile |
| `npm-shrinkwrap.json` | published-with-package lockfile |

## SBOM generation

```bash
# CycloneDX npm
npx @cyclonedx/cyclonedx-npm --output-file sbom.cdx.json --output-format json

# Yarn (Berry)
yarn dlx @cyclonedx/cyclonedx-yarn --output-file sbom.cdx.json

# pnpm
pnpm dlx @cyclonedx/cyclonedx-pnpm --output-file sbom.cdx.json

# Syft multi-eco (always works)
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# npm (built-in)
npm audit --json > audit.json
npm audit --audit-level=high
npm audit fix           # safe fixes
npm audit fix --force   # may introduce breaking changes
npm audit signatures    # sigstore provenance check (npm >= 9)

# Yarn Classic (v1)
yarn audit --json > audit.json
yarn audit --level high

# Yarn Berry (>=2)
yarn npm audit --recursive --json > audit.json

# pnpm
pnpm audit --json > audit.json
pnpm audit --prod       # runtime-only

# OSV-Scanner
osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=yarn.lock
osv-scanner --lockfile=pnpm-lock.yaml

# Snyk
snyk test --file=package.json
snyk test --all-projects --yarn-workspaces
```

## Dependency tree inspection

```bash
# npm
npm ls --all                         # full tree
npm ls <pkg>                         # why is this installed?
npm explain <pkg>                    # explicit why output
npm why <pkg>                        # pnpm-style (npm >= 10)

# yarn
yarn why <pkg>

# pnpm
pnpm why <pkg>
pnpm list --depth Infinity
```

## Integrity / provenance

```bash
# npm lockfile has "integrity": "sha512-..." per package
# Re-verify without installing:
npm install --package-lock-only --ignore-scripts
npm audit signatures   # verifies sigstore attestations

# Yarn Berry checksum policy
# yarn.config.yml:
#   checksumBehavior: "throw"   # fail on mismatch
```

## Install script control (supply chain hardening)

```bash
# Globally disable scripts
npm config set ignore-scripts true
yarn config set enableScripts false
pnpm config set side-effects-cache false && pnpm install --ignore-scripts

# Per-install
npm ci --ignore-scripts
```

Audit scripts before enabling:
```bash
jq -r '.scripts | to_entries[] | "\(.key): \(.value)"' package.json
grep -r '"scripts"' node_modules/*/package.json | grep -E 'preinstall|install|postinstall'
```

## License extraction

```bash
npx license-checker --json > licenses.json
npx license-checker --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC'
npx license-checker --failOn 'GPL-3.0;AGPL-3.0'
```

## Common vulnerability patterns in npm

| Class | Example CVE | Detection |
|-------|-------------|-----------|
| Prototype pollution | CVE-2019-10744 (lodash) | Grype, Snyk |
| ReDoS | CVE-2021-3807 (ansi-regex) | OSV |
| Command injection | CVE-2024-21538 (cross-spawn) | all |
| Arbitrary file write | CVE-2022-25883 (semver) | GHSA |
| Supply chain (account takeover) | ua-parser-js 2021 | provenance + install-script review |

## Gotchas

- `package-lock.json` v1 (npm 5/6) has less data than v2/v3 — upgrade before scanning for best results.
- Yarn Berry's Plug'n'Play (`pnp.cjs`) stores resolved versions inline; Syft handles it but older scanners may miss.
- Workspaces / monorepos: always scan with `--all-projects` or the root lockfile — per-package `npm ls` misses hoisted deps.
- `devDependencies` still ship in published packages if listed in `files` — don't assume dev-only = safe.

## Tool minimums (2026-04)

- npm >= 10.5
- yarn >= 4.3 (Berry) or 1.22 (Classic, EOL-ish)
- pnpm >= 9.6
- @cyclonedx/cyclonedx-npm >= 2.0
