# Kubernetes Hardening Reference

kube-bench, Kubescape, kube-hunter invocation and CIS K8s benchmark mapping.
Validated against CIS Kubernetes Benchmark v1.9 (2026-04).

## kube-bench (CIS benchmark)

```bash
# All checks (run on the node)
kube-bench run

# Component-scoped
kube-bench run --targets master
kube-bench run --targets node
kube-bench run --targets etcd
kube-bench run --targets policies
kube-bench run --targets controlplane

# Pin Kubernetes version (default: auto-detect)
kube-bench run --version 1.30

# Output
kube-bench run --json > kube-bench.json
kube-bench run --junit > kube-bench.xml

# As an in-cluster Job (parallel across nodes via DaemonSet variant)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -l app=kube-bench
```

## Kubescape

```bash
# Full cluster scan
kubescape scan

# Framework-specific
kubescape scan framework nsa
kubescape scan framework mitre
kubescape scan framework cis-v1.23-t1.0.1
kubescape scan framework allcontrols

# Namespace filter
kubescape scan --include-namespaces production,staging

# Scan manifests offline (pre-deploy — or defer to iac-security skill)
kubescape scan *.yaml

# Output
kubescape scan -f json -o results.json
kubescape scan -f sarif -o results.sarif

# Compliance gate
kubescape scan --compliance-threshold 80

# Exceptions
kubescape scan --exceptions exceptions.json
```

## kube-hunter

```bash
# External network-based hunt
kube-hunter --remote <cluster-ip>
kube-hunter --cidr 10.0.0.0/24

# In-cluster pod hunt
kube-hunter --pod

# Active exploitation attempts (AUTHORIZED TESTING ONLY)
kube-hunter --active

kube-hunter --report json > kube-hunter.json
```

## CIS Kubernetes Benchmark — Critical Controls

| CIS Control | Check                                                      | Quick Validation                           |
|-------------|------------------------------------------------------------|--------------------------------------------|
| 1.2.5       | `--kubelet-certificate-authority` on kube-apiserver        | `ps -ef \| grep apiserver`                  |
| 1.2.6       | `--authorization-mode` not `AlwaysAllow`                   | Expect `Node,RBAC`                         |
| 1.2.16      | `--profiling=false`                                        | Disable pprof endpoint                     |
| 1.2.22      | `--audit-log-path` set                                     | Audit logging enabled                      |
| 1.2.24      | `--audit-log-maxage >=30`                                  |                                            |
| 1.2.32      | `--encryption-provider-config` set                         | etcd encryption-at-rest                    |
| 2.x         | etcd TLS client + peer auth enabled                        |                                            |
| 3.2.1       | Minimize admin-level cluster roles                         | Audit ClusterRoleBindings to cluster-admin |
| 4.2.1       | kubelet `--anonymous-auth=false`                           |                                            |
| 4.2.2       | kubelet `--authorization-mode=Webhook`                     |                                            |
| 4.2.6       | kubelet `--protect-kernel-defaults=true`                   |                                            |
| 5.1.1       | ClusterRole `cluster-admin` use minimized                  |                                            |
| 5.2.x       | Pod Security Standards (baseline/restricted) enforced      | `kubectl label ns ... pod-security.kubernetes.io/enforce=restricted` |
| 5.3.2       | NetworkPolicies defined for every namespace                |                                            |
| 5.7.x       | Seccomp `RuntimeDefault` on pods                           |                                            |

## Pod Security Standards (PSS)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Cluster Hardening Checklist

### Control plane
- [ ] RBAC enabled, ABAC disabled
- [ ] Audit logging on (`--audit-log-path`)
- [ ] etcd encrypted at rest, TLS peer + client
- [ ] Admission controllers: NodeRestriction, PodSecurity, ImagePolicyWebhook
- [ ] API server `--anonymous-auth=false`
- [ ] `--profiling=false`

### Node / kubelet
- [ ] `--anonymous-auth=false`
- [ ] `--authorization-mode=Webhook`
- [ ] Read-only port 10255 disabled
- [ ] `--protect-kernel-defaults=true`
- [ ] Container runtime hardened (containerd/CRI-O)

### Workload
- [ ] PSS `restricted` on sensitive namespaces
- [ ] No privileged pods
- [ ] `readOnlyRootFilesystem: true`
- [ ] `allowPrivilegeEscalation: false`
- [ ] `runAsNonRoot: true`
- [ ] Resource requests + limits set
- [ ] ServiceAccount per workload (no `default` SA token mount)

### Network
- [ ] Default-deny NetworkPolicy per namespace
- [ ] Egress policies scoped
- [ ] Ingress TLS
- [ ] Pod-to-pod mTLS via service mesh where applicable

### Supply chain
- [ ] Images pinned by digest
- [ ] Cosign / Notary signature verification (admission)
- [ ] SBOM attestation required
