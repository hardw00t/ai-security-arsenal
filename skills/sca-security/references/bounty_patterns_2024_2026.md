# Bug Bounty Patterns 2024-2026 — sca-security

## Overview

Post-2023 supply-chain / dependency attack patterns from Unit 42 (Shai-Hulud npm worm),
GitHub Security Advisories (tj-actions/changed-files compromise, March 2025), Datadog
Security Labs (CVE-2025-48384 Git arbitrary file write), and HackerOne / OWASP MCP supply
chain research. Last validated: 2026-04. Emit findings via `../schemas/finding.json`.

## Pattern Index

| #   | Pattern                                                  | Severity | Primary Source                         |
|-----|----------------------------------------------------------|----------|----------------------------------------|
| P30 | Shai-Hulud 2.0 — npm supply-chain worm (Nov 2025)        | Critical | Unit 42 Paloaltonetworks 2025          |
| P31 | GitHub Action `tj-actions/changed-files` compromise      | Critical | GitHub Security Advisory 2025          |
| P32 | Git arbitrary file write (CVE-2025-48384)                | Critical | Datadog Security Labs 2025             |
| P33 | Transitive dependency reachability blind spots           | High     | HackerOne SCA writeups 2024-2025       |

---

## Patterns

### P30. Shai-Hulud 2.0 — npm Supply-Chain Worm (Nov 2025)

- **CVE / Source:** Unit 42 (Palo Alto Networks) — "npm Supply Chain Attack (November 2025)"; OWASP MCP04:2025.
- **Summary:** Self-replicating npm worm that uses maintainer-token theft from one package to publish malicious versions of every package that maintainer can publish; 2.0 wave (Nov 2025) runs payload in `preinstall`, with aggressive fallback (posts stolen secrets to multiple C2s, then wipes `$HOME`).
- **Affected surface:** Any JS project resolving latest/tagged versions without lockfile pinning; CI pipelines running `npm install` (not `npm ci`); developer workstations fetching fresh packages.
- **Detection (automated):**
  ```bash
  # Hunt for preinstall / postinstall pulls pulling unfamiliar packages
  jq -r '.. | objects | select(.scripts) | .scripts | to_entries[] |
         select(.key | test("^(pre|post)?install$"))' package.json
  npm ls --all | grep -E '(shai|hulud|bundle-stealer|env-dump)'
  # Enforce lockfile:
  npm ci --ignore-scripts
  # Verify integrity hashes:
  jq -r '.packages | to_entries[] | select(.value.integrity|not)' package-lock.json
  ```
- **Exploitation / PoC (defender reproduction):** Install the malicious version in an isolated VM with `--ignore-scripts=false`; inspect the `preinstall` entry for credential-harvesting shell.
- **Indicators:** Outbound from CI to unfamiliar hosts during `npm install`; new publish on packages whose maintainer showed no activity; sudden `~/.npmrc` / `~/.aws` / `~/.ssh` reads from node process.
- **Mitigation:** `npm ci --ignore-scripts` in CI; lockfile + `integrity` field required; Sigstore/npm provenance verification (`npm audit signatures`); workstation EDR rules on install-time script spawning curl/bash.
- **Cross-refs:** CWE-506, CWE-829; related → P31, LLM P8.

### P31. GitHub Action `tj-actions/changed-files` Compromise

- **CVE / Source:** GitHub Security Advisory (March 2025) — `tj-actions/changed-files` tag-retargeting attack; ~23,000 repos affected.
- **Summary:** Attacker obtained push access, retargeted many *version tags* (e.g., `v35`, `v41`) to a malicious commit that exfiltrated GitHub Actions secrets from calling workflows. Every consumer pinning by tag (the default) was impacted.
- **Affected surface:** Any GitHub Action referenced by floating tag (`@v1`, `@main`) rather than immutable SHA; Action consumers without egress-restricted runners.
- **Detection (automated):**
  ```bash
  # Enumerate floating-tag references across repos
  for wf in .github/workflows/*.y*ml; do
    grep -E 'uses:\s+[^@]+@(v?[0-9]+(\.[0-9]+)?|main|master|latest)' "$wf"
  done
  # Hunt for new SHA behind an old tag:
  gh api repos/tj-actions/changed-files/git/ref/tags/v41 | jq -r .object.sha
  # Diff against pinned baseline you record in dependency-lock.
  ```
- **Exploitation / PoC (defender reproduction):** In a throw-away org, re-point a tag to a commit that prints `${{ secrets.* }}` via `echo` into an attacker-controlled Pastebin; observe secrets leakage.
- **Indicators:** Action consumer workflows uploading artefacts to unfamiliar hosts; Audit log `workflow_run` with unusual env access; new SHA under an old tag.
- **Mitigation:** Pin Actions by commit SHA (`uses: tj-actions/changed-files@<sha>`); enable GitHub's allow-list for Actions; use OIDC with tight `sub` instead of long-lived secrets; enforce `permissions: {}` minimal scopes.
- **Cross-refs:** CWE-1357 (supply-chain); SLSA levels; related → P30, IaC P26.

### P32. Git Arbitrary File Write (CVE-2025-48384)

- **CVE / Source:** Datadog Security Labs — CVE-2025-48384 (Git arbitrary file write via recursive clone on non-Windows).
- **Summary:** Crafted `.gitmodules` / symlinks in a repository used with `git clone --recurse-submodules` let attacker write to arbitrary paths outside the working tree, enabling supply-chain code injection on developer and CI machines.
- **Affected surface:** Git < patched version on Linux/macOS; CI runners that recursively clone untrusted repos; developers running `git pull` on compromised forks.
- **Detection (automated):**
  ```bash
  git --version
  # Scan repos for suspicious .gitmodules targeting paths like ../../../
  git ls-files --error-unmatch .gitmodules 2>/dev/null && \
    grep -E 'path\s*=\s*\.\.\/' .gitmodules
  # CI: sandbox git clone in a container with read-only bind mounts
  ```
- **Exploitation / PoC (defender reproduction):** Use the Datadog Security Labs published reproducer in an isolated container; do not run against production workstations.
- **Indicators:** Unexpected writes to `~/.ssh`, `~/.aws`, `~/.bashrc` during git operations.
- **Mitigation:** Update Git to patched release; restrict transports with `GIT_ALLOW_PROTOCOL=https:git:ssh` (blocks `file://`, `ext::` which carry the submodule vector); forbid recursive submodule init for untrusted sources; run clone in ephemeral container.
- **Cross-refs:** CWE-22, CWE-59; related → P30, P31.

### P33. Transitive Dependency Reachability Blind Spots

- **CVE / Source:** HackerOne SCA reports 2024-2025; OWASP MCP supply-chain guidance.
- **Summary:** Vulnerability tooling that reports on *direct* dependencies misses the majority of real exploitable issues which sit 3-6 hops deep. Reachability-aware triage reduces noise but also surfaces genuine criticals that severity-only triage drops.
- **Affected surface:** Projects with large lockfiles (>1k transitives), polyglot mono-repos, ML projects (torch, tensorflow pull chains); customers using Dependabot without reachability.
- **Detection (automated):**
  ```bash
  # Generate full SBOM including transitives
  syft packages dir:. -o cyclonedx-json > sbom.json
  grype sbom:sbom.json --scope all-layers --fail-on medium
  # Reachability: semgrep 'pro' + call-graph analysis, or osv-scanner --experimental-licenses
  osv-scanner --lockfile=./package-lock.json --experimental-call-analysis
  # Prune: keep only findings where reachable=true
  ```
- **Exploitation / PoC:** Reachability-positive transitive CVE → craft input exercising the vulnerable call path from user-reachable surface.
- **Indicators:** SBOM counts per-package depth > 5 hops; CVE in transitive shows up in call graph starting at an exposed HTTP handler.
- **Mitigation:** SBOM + reachability gate in CI; vendor dependencies where possible; prefer libraries with shallow graphs; policy: "no transitive adoption without ownership plan".
- **Cross-refs:** CWE-1104, CWE-937; related → P30, P31, LLM P8.

---

## Cross-skill links
- LLM: MCP-server packages as malicious supply-chain vectors — `../../llm-security/references/bounty_patterns_2024_2026.md` (P8).
- SAST: static-taint reachability that complements P33 — `../../sast-orchestration/references/bounty_patterns_2024_2026.md`.
- IaC: Terraform module supply-chain — `../../iac-security/references/bounty_patterns_2024_2026.md` (P26).
