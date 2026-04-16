# Image Scanning Reference

Invocation patterns for Trivy, Grype, Syft, Clair, and Snyk Container. Minimum
validated versions (2026-04): Trivy 0.59+, Grype 0.87+, Syft 1.18+.

## Trivy

```bash
# Registry image
trivy image nginx:1.27

# Local tarball / OCI layout
trivy image --input ./image.tar
trivy image --input oci-dir:./oci-layout

# Filter and output
trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:1.27
trivy image -f json -o results.json nginx:1.27
trivy image -f sarif -o results.sarif nginx:1.27
trivy image -f cyclonedx -o sbom.cdx.json nginx:1.27
trivy image -f spdx-json -o sbom.spdx.json nginx:1.27

# Only OS, only library, or combined
trivy image --vuln-type os,library nginx:1.27

# Include secrets + misconfig scans
trivy image --scanners vuln,secret,misconfig nginx:1.27

# Gate CI on severity
trivy image --exit-code 1 --severity CRITICAL nginx:1.27

# Filesystem scan (built artifact before containerize)
trivy fs --scanners vuln,secret,misconfig /path/to/project

# Offline air-gapped DB
trivy --cache-dir /mnt/trivy-db image --skip-db-update nginx:1.27
```

## Grype

```bash
grype nginx:1.27
grype nginx:1.27 -o json > grype.json
grype nginx:1.27 --fail-on high

# SBOM-driven scan (faster, deterministic)
syft nginx:1.27 -o cyclonedx-json=sbom.json
grype sbom:./sbom.json

# Local sources
grype dir:/path/to/project
grype docker-archive:./image.tar
grype registry:registry.example.com/app:1.4.2
```

## Syft (SBOM generator)

```bash
syft nginx:1.27                                   # table
syft nginx:1.27 -o cyclonedx-json=sbom.cdx.json
syft nginx:1.27 -o spdx-json=sbom.spdx.json
syft nginx:1.27 -o syft-json=sbom.syft.json       # richest, preferred for diffs
syft dir:/app -o cyclonedx-json=sbom.cdx.json

# Attach SBOM as attestation (cosign)
cosign attest --predicate sbom.cdx.json \
  --type cyclonedx registry.example.com/app@sha256:...
```

## Clair (v4 / Quay)

```bash
# Submit manifest
clairctl report --host http://clair:6060 nginx:1.27

# JSON output
clairctl report --out json --host http://clair:6060 nginx:1.27 > clair.json
```

## Snyk Container

```bash
snyk container test nginx:1.27 --severity-threshold=high
snyk container test nginx:1.27 --json > snyk.json
snyk container monitor nginx:1.27 --project-name=prod-nginx
```

## Hadolint (Dockerfile lint)

```bash
hadolint Dockerfile
hadolint -f json Dockerfile > hadolint.json
hadolint -f sarif Dockerfile > hadolint.sarif
hadolint --ignore DL3008 --ignore DL3009 Dockerfile
hadolint --strict Dockerfile
```

## Tool Selection Matrix

| Need                                    | Prefer               |
|-----------------------------------------|----------------------|
| Fastest one-shot CVE triage             | Trivy                |
| Deepest package fingerprinting          | Syft + Grype         |
| CycloneDX/SPDX SBOM artifact            | Syft                 |
| License compliance                      | Syft, Snyk           |
| Enterprise registry integration (Quay)  | Clair                |
| Commercial policy / fix advice          | Snyk                 |
| Dockerfile static lint                  | Hadolint             |

## Cross-Scanner CVE Consensus

Run Trivy + Grype + Syft on the same digest concurrently, then intersect
their CVE sets. Disagreement usually means one DB is stale or a package
manager isn't being recognized — never silently trust a single scanner.

```bash
DIGEST="registry.example.com/app@sha256:abc..."
trivy image -f json -o t.json "$DIGEST" &
grype "$DIGEST" -o json > g.json &
syft "$DIGEST" -o cyclonedx-json=s.cdx.json &
wait
```

## Image Hygiene Checklist

- [ ] Pin by digest (`@sha256:...`), not tag
- [ ] Minimal base (distroless, alpine, scratch)
- [ ] Non-root `USER` directive
- [ ] No CRITICAL, triaged HIGH
- [ ] No secrets in layers (`trivy image --scanners secret`)
- [ ] SBOM attested and stored alongside image
