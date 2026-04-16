# Container Security Assessment Report Template

Use this template to produce the deliverable at the end of a container
security engagement. Fill in each section; delete any that don't apply.

## Executive Summary
- Assessment date: YYYY-MM-DD
- Scope: X images, Y clusters, Z namespaces
- Critical: N  |  High: N  |  Medium: N  |  Low: N
- CIS compliance score: Z%
- New CVEs since prior baseline (SBOM diff): N

## Image Scan Results

### <image>@<digest>
| CVE | Severity | CVSS | Package | Current | Fixed |
|-----|----------|------|---------|---------|-------|
|     |          |      |         |         |       |

Scanners run: Trivy vX.Y, Grype vX.Y, Syft vX.Y.
SBOM attested: yes/no (cosign).

## SBOM Diff (if applicable)

Baseline: `<prior-digest>`  ->  Current: `<current-digest>`

- Added packages: N
- Removed packages: N
- Version-bumped: N
- Newly-introduced CVEs: N (list by severity)
- Newly-fixed CVEs: N

## Kubernetes Findings

### CIS Benchmark (kube-bench vX.Y, CIS K8s vX.Y)
| Section       | Pass | Fail | Score |
|---------------|------|------|-------|
| Control plane |      |      |       |
| Worker nodes  |      |      |       |
| Policies      |      |      |       |

### RBAC
- Over-permissioned principals: N
- Shortest path(s) to cluster-admin: ...

### NetworkPolicy coverage
- Namespaces without default-deny: ...
- Over-permissive egress rules: ...

### Runtime (Falco/Tetragon)
- Alerts in window: N
- Highest-severity events: ...

## Container Escape Testing
(Only if engagement scope included active testing.)

- Vectors tested: ...
- Successful escapes: ...
- Detected by runtime sensor: yes/no per vector

## Critical Findings (top 10)

1. [CRITICAL] ...
2. [HIGH] ...

## Recommendations

1. Patch / rebuild affected images
2. Enforce Pod Security Standards (restricted)
3. Default-deny NetworkPolicy per namespace
4. Remove cluster-admin bindings for workloads
5. Enable runtime monitoring (Falco or Tetragon)
6. Pin images by digest + require signed SBOM attestation

## Appendix

- Raw scanner outputs: evidence/
- Schema: schemas/finding.json
