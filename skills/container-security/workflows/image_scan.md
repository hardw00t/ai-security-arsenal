# Workflow: Build-Time Image Vulnerability Scan

Use during CI on every built image, or ad-hoc on registry images.

## Inputs
- Image reference (`registry/repo:tag` or `sha256:` digest)
- Severity gate (default: fail on CRITICAL)
- Output dir for artifacts

## Steps

1. **Resolve to digest** (avoid tag-race):
   ```bash
   DIGEST=$(crane digest "$IMAGE")
   REF="${IMAGE%%:*}@${DIGEST}"
   ```

2. **Parallel scanners** (run concurrently — they don't interfere):
   ```bash
   trivy image -f json -o trivy.json "$REF" &
   grype "$REF" -o json > grype.json &
   syft "$REF" -o cyclonedx-json=sbom.cdx.json &
   syft "$REF" -o syft-json=sbom.syft.json &
   hadolint -f json Dockerfile > hadolint.json &
   wait
   ```

3. **Secret + misconfig sweep** (Trivy extra scanners):
   ```bash
   trivy image --scanners secret,misconfig -f json -o trivy-secrets.json "$REF"
   ```

4. **Consensus merge**: intersect CVE IDs from Trivy and Grype; flag
   Trivy-only or Grype-only findings for manual confirmation (DB staleness
   is the usual cause).

5. **Severity gate**:
   ```bash
   jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' \
     trivy.json
   ```
   Fail CI if >0 and not in `exceptions.yaml`.

6. **Attach SBOM attestation** (if cosign configured):
   ```bash
   cosign attest --predicate sbom.cdx.json --type cyclonedx "$REF"
   ```

7. **Emit findings** as `schemas/finding.json` records with
   `evidence.scanner`, `affected.image_digest`, `cve`, `cvss`,
   `fixed_version` populated.

## Parallelism

| Operation                   | Parallel? |
|-----------------------------|-----------|
| Trivy + Grype + Syft + Hadolint on same image | Yes |
| Multiple images / tags      | Yes (one sub-agent per image) |
| Cosign attestation          | Sequential (needs SBOM) |
| CVE consensus merge         | Sequential (needs scanner output) |

## Exit criteria

- All scanners completed (or timeout with partial results recorded)
- Severity gate evaluated
- SBOM stored alongside image for future `sbom_diff` comparisons
