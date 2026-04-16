# Supply Chain Review Workflow

Detect typosquatting, dependency confusion, and malicious-package indicators. Run this on **every newly introduced dependency** (direct or transitive) — not just at release time.

## Trigger

- A lockfile adds a package that was not present before (see `lockfile_diff.md`).
- A package's maintainer set, version, or install scripts change.
- A package publishes its first version in the last 30 days.

## Step 1 — Typosquat detection

For each new package name `P`:

1. Look up the top-N packages in the same ecosystem (npm top 10k, PyPI top 5k, etc.).
2. Compute edit distance: if `levenshtein(P, popular) <= 2` and `P != popular`, flag.
3. Check homoglyph substitutions: `l` vs `1`, `o` vs `0`, Cyrillic `а` vs Latin `a`.
4. Check scope/namespace confusion: `lodash` vs `lodash-es` vs `lodash.es` — legit variants exist, but `lodahs` / `loadash` / `lodash-tools` are suspicious.

Tools:
- `typosquatter` npm package (simple Levenshtein)
- Socket CLI (`socket npm install ...` warns before install)
- `pypi-typosquat-detection` for PyPI

## Step 2 — Dependency confusion

Dependency confusion happens when a public package with the same name as an internal/scoped package exists and has a higher version number — some resolvers pull the public one.

Checks:
- For every `@company/*` or `internal-*` or `org-*` package, query the public registry: does a package with that exact name exist?
- If yes: is it owned by your org? Check `maintainers[*].email` against your org domain.
- Enforce `.npmrc` / `pip.conf` to pin internal namespaces to the internal registry.

```bash
# npm
npm config get @company:registry  # must be internal URL
npm view @company/internal-tool  # MUST fail against public registry, or return your own org

# pip
pip config list  # index-url must be internal for internal packages
```

## Step 3 — Malicious package indicators

For each new package, pull its metadata and compute signals (see `references/malicious_package_indicators.md` for the full catalog).

Fast signals (auto-flag, block install):
- Install script present (`scripts.preinstall|install|postinstall` in npm, `setup.py` code execution in Python sdists).
- Obfuscated code in published tarball (eval + hex/base64 strings, self-decrypting payload).
- Outbound network calls from install script (DNS / HTTP).
- Binary blobs shipped without source.

Slow signals (flag for review):
- Package age < 30 days.
- Single maintainer with disposable email (gmail/proton with random handle).
- No GitHub repo or broken repo link.
- No downloads before this week.
- Version jumps (0.0.1 → 9.9.9 in one release — common takeover pattern).
- Abandoned package recently republished by a new maintainer.

```bash
# npm metadata
npm view <pkg> --json | jq '{maintainers, time, scripts: .scripts}'

# PyPI metadata
curl -s https://pypi.org/pypi/<pkg>/json | jq '{releases: (.releases|keys), author: .info.author}'

# Tarball inspection (npm)
npm pack <pkg>
tar tzf *.tgz  # list contents
tar xzf *.tgz && grep -r 'eval\|base64\|child_process' package/
```

## Step 4 — Provenance / attestation check

```bash
# npm provenance (sigstore-backed)
npm audit signatures
npm view <pkg> --json | jq '.dist.attestations'

# Python PEP 740 attestations (rolling out 2025-2026)
pip install --require-hashes -r requirements.txt

# Go — sum.golang.org verification is automatic
go mod verify

# Containers — cosign
cosign verify --certificate-identity=... ghcr.io/org/app:tag
```

Prefer packages with sigstore/cosign provenance from a known CI identity (e.g. GitHub Actions with a pinned repo).

## Step 5 — Emit findings

For supply-chain hits, populate finding with:
- `finding_type: "malicious_package" | "typosquat" | "dependency_confusion"`
- `malicious_indicators: [...]` (enum values)
- `confidence`: `"suspected"` for slow-signal only, `"likely"` for obfuscated code, `"confirmed"` for known-bad from public advisory.
- Severity:
  - Confirmed malicious / typosquat on critical path: `critical`
  - Dependency confusion misconfig: `high`
  - Suspicious-but-unclear: `medium` (requires human)

## Parallelism

- Registry metadata lookups: parallel, one per package.
- Tarball inspection: parallel, CPU-bound.
- Sub-agent delegation: for 50+ new packages, spawn one sub-agent per 10 packages.

## Reasoning budget

**High for triage** — distinguishing "new legitimate maintainer" from "account takeover" requires weighing many weak signals. Use extended thinking.

Low for static-signal blocks (install script + obfuscated code → auto-reject).

## References

- `references/malicious_package_indicators.md` — full signal catalog
- `references/vuln_databases.md` — GHSA malware advisories, PyPI advisory DB

## Known incidents to pattern-match against

- ua-parser-js (2021) — maintainer account takeover + cryptominer
- event-stream (2018) — gradual maintainer handoff + targeted payload
- colors.js / faker.js (2022) — protestware
- PyTorch / `torchtriton` (2022) — dependency confusion
- node-ipc (2022) — protestware targeting RU/BY IPs
- `xz-utils` (2024) — long-con maintainer infiltration + build-time injection (not an SCA-detectable case pre-disclosure — included for context)
