---
name: container-security
description: "Container and Kubernetes security audit skill using Trivy, Kube-bench, and policy engines. Performs image scanning, runtime security analysis, RBAC auditing, and CIS benchmark compliance. Use when: 'scan Docker images', 'Kubernetes security audit', 'container vulnerability scan', 'check K8s RBAC', or 'CIS Kubernetes benchmark'. (user)"
---

# Container Security

This skill enables comprehensive security assessment of containerized environments including Docker images, Kubernetes clusters, and container orchestration platforms. It covers vulnerability scanning, misconfiguration detection, RBAC analysis, network policy review, and CIS benchmark compliance.

## When to Use This Skill

This skill should be invoked when:
- Scanning Docker/OCI images for vulnerabilities
- Auditing Kubernetes cluster security
- Checking CIS Kubernetes benchmarks
- Analyzing RBAC configurations
- Reviewing network policies
- Assessing pod security standards
- Scanning Dockerfiles for best practices
- Analyzing Kubernetes manifests
- Runtime security monitoring
- Container escape testing

### Trigger Phrases
- "scan this Docker image for vulnerabilities"
- "Kubernetes security audit"
- "check container for CVEs"
- "audit K8s RBAC permissions"
- "CIS benchmark for Kubernetes"
- "scan Dockerfile for security issues"
- "review pod security policies"
- "container runtime security check"
- "assess Kubernetes network policies"

---

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Trivy | Image/IaC scanning | `apt install trivy` |
| Kube-bench | CIS benchmarks | `go install github.com/aquasecurity/kube-bench@latest` |
| Kubescape | K8s security | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| kube-hunter | K8s pentest | `pip install kube-hunter` |
| Falco | Runtime security | Helm chart |
| OPA/Gatekeeper | Policy engine | Helm chart |
| Kyverno | Policy engine | Helm chart |
| kubectl | K8s CLI | Install from kubernetes.io |
| Docker | Container runtime | Install Docker |
| Hadolint | Dockerfile linting | `brew install hadolint` |

### Environment Setup

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install kube-bench
go install github.com/aquasecurity/kube-bench@latest

# Install Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Install kube-hunter
pip install kube-hunter

# Configure kubectl (ensure cluster access)
kubectl cluster-info
```

---

## Quick Start Guide

### 1. Image Vulnerability Scanning (1 minute)

```bash
# Scan Docker image with Trivy
trivy image nginx:latest

# Scan with severity filter
trivy image --severity HIGH,CRITICAL alpine:latest

# Output to JSON
trivy image --format json -o results.json myapp:v1.0

# Scan private registry image
trivy image --username user --password pass registry.example.com/app:latest

# Scan local image
docker build -t myapp .
trivy image myapp
```

### 2. Kubernetes Cluster Audit (3 minutes)

```bash
# CIS Benchmark with kube-bench
kube-bench run --targets master,node

# Comprehensive scan with Kubescape
kubescape scan framework nsa --submit=false

# Attack simulation with kube-hunter
kube-hunter --remote <cluster-ip>
# Or from within cluster
kube-hunter --pod

# RBAC analysis
kubectl auth can-i --list --as=system:serviceaccount:default:default
```

### 3. Dockerfile Security Check (30 seconds)

```bash
# Lint Dockerfile with Hadolint
hadolint Dockerfile

# Scan Dockerfile with Trivy
trivy config Dockerfile

# Check for secrets in build context
trivy fs --scanners secret .
```

### 4. Kubernetes Manifest Scanning

```bash
# Scan manifests with Trivy
trivy config ./k8s/

# Scan with Kubescape
kubescape scan ./k8s/*.yaml

# Check against OPA policies
conftest test deployment.yaml -p policy/
```

---

## Security Audit Categories

### 1. Image Security

| Check | Tool | Command |
|-------|------|---------|
| OS vulnerabilities | Trivy | `trivy image --vuln-type os` |
| Library vulnerabilities | Trivy | `trivy image --vuln-type library` |
| Misconfigurations | Trivy | `trivy image --scanners misconfig` |
| Secrets in image | Trivy | `trivy image --scanners secret` |
| SBOM generation | Trivy | `trivy image --format spdx-json` |
| License compliance | Trivy | `trivy image --scanners license` |

### 2. Kubernetes Security

| Check | Tool | Command |
|-------|------|---------|
| CIS Benchmarks | Kube-bench | `kube-bench run` |
| NSA/CISA Framework | Kubescape | `kubescape scan framework nsa` |
| MITRE ATT&CK | Kubescape | `kubescape scan framework mitre` |
| RBAC Analysis | kubectl | `kubectl auth can-i --list` |
| Network Policies | kubectl | `kubectl get networkpolicies -A` |
| Pod Security | Kubescape | `kubescape scan control C-0057` |
| Secrets exposure | kubectl | `kubectl get secrets -A` |

### 3. Runtime Security

| Check | Tool | Purpose |
|-------|------|---------|
| Syscall monitoring | Falco | Detect anomalies |
| Container escape | kube-hunter | Test breakout |
| Privilege escalation | Kubescape | Detect misconfig |
| Network attacks | kube-hunter | Test network |

---

## Detailed Workflows

### Workflow 1: Complete Container Security Assessment

```bash
# Phase 1: Image Scanning
# Scan all images in cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u > images.txt

while read image; do
  echo "Scanning: $image"
  trivy image --format json -o "results/${image//\//_}.json" "$image"
done < images.txt

# Phase 2: Cluster Configuration
# Run CIS benchmark
kube-bench run --json > kube-bench-results.json

# Run Kubescape
kubescape scan framework nsa,mitre --format json --output kubescape-results.json

# Phase 3: RBAC Analysis
# Export all RBAC configs
kubectl get clusterroles -o yaml > clusterroles.yaml
kubectl get clusterrolebindings -o yaml > clusterrolebindings.yaml
kubectl get roles -A -o yaml > roles.yaml
kubectl get rolebindings -A -o yaml > rolebindings.yaml

# Analyze overly permissive roles
python3 scripts/rbac_analyzer.py --input clusterroles.yaml

# Phase 4: Network Policies
kubectl get networkpolicies -A -o yaml > netpols.yaml
python3 scripts/netpol_analyzer.py --input netpols.yaml

# Phase 5: Secret Analysis
# Find secrets without encryption
kubectl get secrets -A -o json | jq '.items[] | select(.type != "kubernetes.io/service-account-token")'

# Phase 6: Generate Report
python3 scripts/container_report_generator.py \
  --trivy results/ \
  --kube-bench kube-bench-results.json \
  --kubescape kubescape-results.json \
  --output report.html
```

### Workflow 2: CI/CD Image Scanning

```yaml
# GitHub Actions - .github/workflows/container-security.yml
name: Container Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Fail on Critical
        run: |
          trivy image --exit-code 1 --severity CRITICAL myapp:${{ github.sha }}

  dockerfile-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile

      - name: Trivy Config Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
```

### Workflow 3: Kubernetes RBAC Deep Dive

```bash
# Step 1: List all service accounts
kubectl get serviceaccounts -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,NAME:.metadata.name"

# Step 2: Check permissions for each SA
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  for sa in $(kubectl get sa -n $ns -o jsonpath='{.items[*].metadata.name}'); do
    echo "=== $ns/$sa ==="
    kubectl auth can-i --list --as=system:serviceaccount:$ns:$sa 2>/dev/null | head -20
  done
done

# Step 3: Find cluster-admin bindings
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  "ClusterRoleBinding: \(.metadata.name)\nSubjects: \(.subjects)"
'

# Step 4: Find dangerous permissions
# Pods with elevated privileges
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# Pods mounting host filesystem
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath != null) |
  "\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[].hostPath.path)"
'

# Step 5: Check for wildcard permissions
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]?.resources[]? == "*" or .rules[]?.verbs[]? == "*") |
  "ClusterRole: \(.metadata.name)"
'
```

### Workflow 4: Container Escape Testing

```bash
# Using kube-hunter in active mode (authorized testing only!)
# From outside cluster
kube-hunter --remote <api-server-ip> --active

# From within cluster
kubectl run hunter --image=aquasec/kube-hunter --restart=Never \
  --command -- kube-hunter --pod --active

# Manual checks for escape vectors

# Check for privileged containers
kubectl get pods -A -o json | jq -r '
  .items[] |
  .spec.containers[] |
  select(.securityContext.privileged == true) |
  "PRIVILEGED: \(.name)"
'

# Check for hostPID/hostNetwork
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.hostNetwork == true) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# Check for mounted docker socket
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath.path == "/var/run/docker.sock") |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# Check capabilities
kubectl get pods -A -o json | jq -r '
  .items[] |
  .spec.containers[] |
  select(.securityContext.capabilities.add != null) |
  "Capabilities: \(.securityContext.capabilities.add)"
'
```

### Workflow 5: Network Policy Assessment

```bash
# Step 1: Check default deny policies
kubectl get networkpolicies -A -o json | jq -r '
  .items[] |
  select(.spec.policyTypes | contains(["Ingress","Egress"])) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# Step 2: Find namespaces without network policies
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq "0" ]; then
    echo "No NetworkPolicies in: $ns"
  fi
done

# Step 3: Analyze policy coverage
python3 scripts/netpol_analyzer.py

# Step 4: Test network isolation
# Create test pod
kubectl run nettest --image=nicolaka/netshoot --restart=Never -- sleep 3600

# Test connectivity
kubectl exec nettest -- curl -s http://kubernetes.default.svc
kubectl exec nettest -- nslookup kubernetes

# Cleanup
kubectl delete pod nettest
```

---

## CIS Kubernetes Benchmark

### Control Plane Security

| CIS ID | Check | Remediation |
|--------|-------|-------------|
| 1.1.1 | API server audit logging | Enable audit logging |
| 1.1.2 | Admission controllers | Enable PodSecurity admission |
| 1.2.1 | Anonymous auth disabled | `--anonymous-auth=false` |
| 1.2.2 | Basic auth disabled | Remove `--basic-auth-file` |
| 1.2.6 | RBAC enabled | `--authorization-mode=RBAC` |
| 1.2.16 | Audit log retention | `--audit-log-maxage=30` |
| 1.3.2 | Profiling disabled | `--profiling=false` |

### Worker Node Security

| CIS ID | Check | Remediation |
|--------|-------|-------------|
| 4.1.1 | Kubelet auth | `--authentication-mode=Webhook` |
| 4.1.2 | Anonymous kubelet | `--anonymous-auth=false` |
| 4.2.1 | Read-only port | `--read-only-port=0` |
| 4.2.4 | Streaming timeout | `--streaming-connection-idle-timeout=5m` |
| 4.2.6 | Protect kernel defaults | `--protect-kernel-defaults=true` |

### Pod Security Standards

| Level | Description | Example Violations |
|-------|-------------|-------------------|
| Privileged | Unrestricted | - |
| Baseline | Minimal restrictions | privileged, hostNetwork, hostPID |
| Restricted | Hardened | runAsNonRoot, capabilities, seccomp |

---

## Dockerfile Best Practices

### Security Checklist

```dockerfile
# GOOD PRACTICES

# Use specific version tags
FROM alpine:3.19.0

# Run as non-root user
RUN adduser -D appuser
USER appuser

# Use COPY instead of ADD
COPY ./app /app

# Don't store secrets in image
# Use build args or secrets mount
ARG DB_PASS
# --mount=type=secret,id=db_pass

# Minimize layers and clean up
RUN apk add --no-cache python3 && \
    pip install --no-cache-dir requirements.txt

# Use multi-stage builds
FROM golang:1.21 AS builder
# ... build steps
FROM alpine:3.19
COPY --from=builder /app /app

# Set read-only filesystem
# (done at runtime)

# Define healthcheck
HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1

# Scan for vulnerabilities before push
```

### Common Issues (Hadolint)

| Rule | Issue | Fix |
|------|-------|-----|
| DL3000 | Use absolute WORKDIR | `WORKDIR /app` |
| DL3002 | Running as root | Add `USER` instruction |
| DL3003 | Use WORKDIR for cd | Replace `RUN cd` |
| DL3006 | Pin image version | `FROM alpine:3.19.0` |
| DL3008 | Pin apt versions | `apt-get install pkg=version` |
| DL3018 | Pin apk versions | `apk add pkg=version` |
| DL3020 | Use COPY over ADD | Replace `ADD` with `COPY` |
| DL4006 | Set SHELL option | `SHELL ["/bin/bash", "-o", "pipefail", "-c"]` |

---

## Example Claude Code Interactions

### Example 1: Complete Kubernetes Security Audit

```
User: Audit the security of my Kubernetes cluster

Claude: I'll perform a comprehensive Kubernetes security audit.

[Phase 1: CIS Benchmark Assessment]

> kube-bench run

Control Plane Components:
[FAIL] 1.1.2 Ensure API server audit logging enabled
[FAIL] 1.2.1 Anonymous authentication enabled
[PASS] 1.2.6 RBAC authorization enabled
[WARN] 1.2.16 Audit log retention < 30 days

Worker Nodes:
[FAIL] 4.1.1 Kubelet anonymous auth enabled
[WARN] 4.2.1 Read-only port enabled
[PASS] 4.2.6 Protect kernel defaults

Summary: 45 checks | 32 PASS | 8 FAIL | 5 WARN

[Phase 2: NSA/CISA Framework]

> kubescape scan framework nsa

Critical findings:
[!] C-0002: 15 pods running as root
[!] C-0013: 3 pods with hostPath mounts
[!] C-0017: 8 namespaces without NetworkPolicies
[!] C-0057: 5 pods without resource limits

Risk Score: 62% (High Risk)

[Phase 3: RBAC Analysis]

Found dangerous permissions:
[!] CRITICAL: 'default' SA in 'kube-system' has cluster-admin
[!] HIGH: ClusterRole 'developer' has wildcard permissions
[!] MEDIUM: 12 service accounts can list secrets

[Phase 4: Network Policy Review]

Namespaces without network policies:
- default
- production
- monitoring

Pods exposed to all ingress:
- frontend (production)
- api-gateway (production)

[Phase 5: Image Vulnerabilities]

Scanned 23 unique images:
- 5 images with CRITICAL CVEs
- 12 images with HIGH CVEs
- nginx:latest - 15 vulnerabilities
- redis:6 - 8 vulnerabilities

[Summary]

| Category | Critical | High | Medium |
|----------|----------|------|--------|
| CIS Benchmark | 2 | 6 | 5 |
| NSA Framework | 4 | 8 | 12 |
| RBAC | 1 | 2 | 5 |
| Network | 0 | 3 | 2 |
| Images | 5 | 12 | 45 |

Priority Remediations:
1. Enable API server audit logging
2. Disable anonymous authentication
3. Remove cluster-admin from default SA
4. Add NetworkPolicies to all namespaces
5. Update vulnerable images

Full report: reports/k8s-security-audit.html
```

### Example 2: Docker Image Security Scan

```
User: Scan my Docker image myapp:latest for vulnerabilities

Claude: I'll scan the Docker image for security issues.

[Scanning Image: myapp:latest]

> trivy image --severity HIGH,CRITICAL myapp:latest

Image Analysis:
- Base Image: python:3.9
- Size: 1.2GB
- Layers: 15

[Vulnerability Scan Results]

OS Packages (Debian):
┌────────────────┬────────────────┬──────────┬─────────┐
│ Package        │ Vulnerability  │ Severity │ Fixed   │
├────────────────┼────────────────┼──────────┼─────────┤
│ openssl        │ CVE-2024-XXXX  │ CRITICAL │ 3.0.13  │
│ curl           │ CVE-2024-XXXX  │ HIGH     │ 7.88.1  │
│ libexpat       │ CVE-2023-XXXX  │ HIGH     │ 2.5.0   │
└────────────────┴────────────────┴──────────┴─────────┘

Python Dependencies:
┌────────────────┬────────────────┬──────────┬─────────┐
│ Package        │ Vulnerability  │ Severity │ Fixed   │
├────────────────┼────────────────┼──────────┼─────────┤
│ requests       │ CVE-2023-XXXX  │ HIGH     │ 2.31.0  │
│ pillow         │ CVE-2023-XXXX  │ CRITICAL │ 10.2.0  │
│ django         │ CVE-2024-XXXX  │ HIGH     │ 4.2.10  │
└────────────────┴────────────────┴──────────┴─────────┘

[Misconfiguration Scan]

> trivy image --scanners misconfig myapp:latest

Findings:
[!] HIGH: Running as root user
    Recommendation: Add USER instruction to Dockerfile

[!] MEDIUM: No HEALTHCHECK defined
    Recommendation: Add HEALTHCHECK instruction

[!] LOW: Using 'latest' tag for base image
    Recommendation: Pin specific version

[Secret Scan]

> trivy image --scanners secret myapp:latest

[!] HIGH: AWS credentials found in /app/config.py
    Line 15: aws_secret_access_key = "AKIA..."

[!] MEDIUM: Private key found in /app/certs/
    File: server.key

[Recommendations]

1. Update base image to python:3.9-slim (reduces attack surface)
2. Upgrade packages:
   - openssl >= 3.0.13
   - pillow >= 10.2.0
   - django >= 4.2.10

3. Fix Dockerfile:
   ```dockerfile
   FROM python:3.9.18-slim
   RUN useradd -r appuser
   USER appuser
   HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1
   ```

4. Remove secrets from image - use environment variables

Severity Summary: 2 CRITICAL, 5 HIGH, 3 MEDIUM
```

---

## Scripts Reference

| Script | Description | Usage |
|--------|-------------|-------|
| `container_scanner.py` | Multi-tool container scanner | `python3 scripts/container_scanner.py` |
| `rbac_analyzer.py` | RBAC permission analysis | `python3 scripts/rbac_analyzer.py` |
| `netpol_analyzer.py` | Network policy analyzer | `python3 scripts/netpol_analyzer.py` |
| `image_inventory.py` | Cluster image inventory | `python3 scripts/image_inventory.py` |
| `container_report_generator.py` | Report generation | `python3 scripts/container_report_generator.py` |
| `escape_detector.py` | Container escape detection | `python3 scripts/escape_detector.py` |

---

## Checklists Reference

| Checklist | Purpose |
|-----------|---------|
| [checklists/cis_kubernetes.md](checklists/cis_kubernetes.md) | CIS K8s Benchmark |
| [checklists/docker_security.md](checklists/docker_security.md) | Docker Security |
| [checklists/image_security.md](checklists/image_security.md) | Image Hardening |
| [checklists/rbac_review.md](checklists/rbac_review.md) | RBAC Review |
| [checklists/network_security.md](checklists/network_security.md) | Network Policies |

---

## Policy Templates

| Policy | Purpose |
|--------|---------|
| [policies/pod-security-restricted.yaml](policies/pod-security-restricted.yaml) | Restricted pod security |
| [policies/network-deny-all.yaml](policies/network-deny-all.yaml) | Default deny network |
| [policies/rbac-least-privilege.yaml](policies/rbac-least-privilege.yaml) | Least privilege RBAC |
| [policies/opa-constraints.yaml](policies/opa-constraints.yaml) | OPA/Gatekeeper policies |

---

## Related Resources

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Falco Documentation](https://falco.org/docs/)

---

## Bundled Resources

### scripts/
- `container_scanner.py` - Multi-tool container scanner
- `rbac_analyzer.py` - RBAC permission analyzer
- `netpol_analyzer.py` - Network policy analyzer
- `image_inventory.py` - Cluster image inventory
- `container_report_generator.py` - Report generator
- `escape_detector.py` - Container escape vector detection

### policies/
- `pod-security-restricted.yaml` - Restricted PSS policy
- `network-deny-all.yaml` - Default deny NetworkPolicy
- `rbac-least-privilege.yaml` - Minimal RBAC templates
- `opa-constraints.yaml` - OPA Gatekeeper constraints
- `kyverno-policies.yaml` - Kyverno policy templates
