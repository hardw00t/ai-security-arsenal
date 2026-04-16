# Workflow: SBOM Diff — New CVE Detection Across Image Versions

**Flagship workflow for frontier models.** Compares a prior SBOM against a
current SBOM (same image, newer tag/digest) and flags newly-introduced
packages, version bumps, and — most importantly — *newly-exposed CVEs*.

Long context wins here: the full prior + current SBOM and the full CVE DB
responses can sit in context simultaneously so the model reasons across
thousands of package-version rows in one pass.

## Inputs

- `prior.cdx.json` (or Syft JSON) — baseline, typically the last released tag
- `current.cdx.json` — the candidate release
- Optional: CVE advisory database (Grype's `vulnerability.db` or NVD feed)

## Steps

1. **Canonicalize SBOMs** (sort by `purl`, strip volatile fields):
   ```bash
   jq -S '.components |= sort_by(.purl)' prior.cdx.json   > p.json
   jq -S '.components |= sort_by(.purl)' current.cdx.json > c.json
   ```

2. **Package-level diff** — four buckets: added, removed, upgraded,
   downgraded. Reference `prior.version` and `current.version` via `purl`.
   ```bash
   jq -r '.components[] | "\(.purl)\t\(.version)"' p.json | sort > p.tsv
   jq -r '.components[] | "\(.purl)\t\(.version)"' c.json | sort > c.tsv
   comm -23 p.tsv c.tsv > removed_or_changed.tsv
   comm -13 p.tsv c.tsv > added_or_changed.tsv
   ```

3. **Scan both SBOMs with Grype in parallel**:
   ```bash
   grype sbom:./prior.cdx.json   -o json > prior.vulns.json   &
   grype sbom:./current.cdx.json -o json > current.vulns.json &
   wait
   ```

4. **Compute newly-introduced CVEs** — the high-signal output:
   ```bash
   jq -r '.matches[].vulnerability.id' prior.vulns.json   | sort -u > prior.cves
   jq -r '.matches[].vulnerability.id' current.vulns.json | sort -u > current.cves
   comm -13 prior.cves current.cves > newly_introduced.cves
   comm -23 prior.cves current.cves > newly_fixed.cves
   ```

5. **Correlate CVEs to changed packages** — every newly-introduced CVE
   should map to an added-or-upgraded package. If a new CVE appears on a
   package that *didn't* change version, the upstream advisory was updated
   — still worth reporting, but categorize as "advisory-disclosed" vs
   "version-introduced".

6. **Score exposure**: for each `newly_introduced` CVE, pull CVSS +
   exploit-maturity (EPSS if available), fixed-version, and nearest
   reachable call path (via `trivy image --scanners vuln --list-all-pkgs`
   with package-usage metadata).

7. **Emit findings** with the `sbom_diff` block populated:
   ```json
   {
     "id": "CS-2026-0042",
     "title": "New CRITICAL CVE-2026-1234 introduced via openssl 3.0.8 → 3.1.0 bump",
     "severity": "critical",
     "cve": "CVE-2026-1234",
     "cvss": 9.8,
     "fixed_version": "3.1.2",
     "sbom_diff": {
       "prior_sbom": "app@sha256:aaa...",
       "current_sbom": "app@sha256:bbb...",
       "change_type": "version-bumped",
       "prior_version": "3.0.8",
       "current_version": "3.1.0",
       "newly_introduced_cves": ["CVE-2026-1234"]
     }
   }
   ```

## Output Sections

A frontier model should produce, in a single response:

1. **Summary** — N added, N removed, N upgraded, N downgraded packages
2. **Newly-introduced CVEs** (by severity)
3. **Newly-fixed CVEs** (positive delta — good for PR approval signal)
4. **Risky upgrades** — any major version jumps in security-critical libs
   (crypto, auth, serialization)
5. **Transitive surprises** — packages that appeared without a direct
   dependency change (detect via SBOM dependency graph)
6. **Recommendation** — ship / block / pin-rollback / require-waiver

## Parallelism

- Two Grype scans: parallel
- Per-package CVE lookups (step 6): parallel, batch sized to provider limits
- Advisory fetches (NVD, GHSA, distro trackers): parallel

## Reasoning Budget

**Extended thinking strongly recommended.** The model must:
- Map `purl` → advisory → version-constraint → affected?
- Distinguish "version-introduced" vs "advisory-disclosed" CVEs
- Weigh exploitability (EPSS, KEV) against fixed-version availability
- Decide waiver vs block given engagement context

## When Not to Use

- Single image snapshot with no prior baseline → use `workflows/image_scan.md`
- Pre-deployment K8s manifest review → `iac-security` skill
