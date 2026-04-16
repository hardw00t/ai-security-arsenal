# Kubernetes Manifest Security Reference

Static analysis of raw K8s manifests (Deployment, StatefulSet, DaemonSet, Pod, etc.). For runtime cluster/image work, use the `container-security` skill.

## Scanners

### kubesec

```bash
# Scan single manifest
kubesec scan deployment.yaml

# stdin
cat deployment.yaml | kubesec scan -

# JSON output (score + rule breakdown)
kubesec scan deployment.yaml -o json

# Remote API (no local install needed)
curl -sSX POST --data-binary @deployment.yaml https://v2.kubesec.io/scan
```

kubesec returns a numeric score and per-rule advice. Use as a triage signal; pair with Checkov/kube-linter for specific rule IDs.

### Checkov

```bash
checkov -d ./k8s-manifests --framework kubernetes
checkov -d ./kustomize     --framework kustomize
```

### Trivy config

```bash
trivy config ./k8s-manifests

# Severity gate
trivy config --severity HIGH,CRITICAL ./k8s-manifests

# Machine-readable output
trivy config -f json -o results.json ./k8s-manifests
```

### kube-linter

```bash
go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest
# or: brew install kube-linter

kube-linter lint ./k8s-manifests
kube-linter lint ./k8s-manifests --format json
kube-linter lint ./k8s-manifests --config .kube-linter.yaml
```

### Polaris

```bash
brew install fairwinds/tap/polaris
polaris audit --audit-path ./k8s-manifests --format json > polaris.json
polaris audit --audit-path ./k8s-manifests --only-show-failed-tests
```

Polaris returns a percentage score per workload; `--only-show-failed-tests` keeps the output terse.

## Security Checklist

### Pod / Container Security Context
- [ ] `runAsNonRoot: true`
- [ ] `runAsUser` set to non-zero
- [ ] `readOnlyRootFilesystem: true`
- [ ] `allowPrivilegeEscalation: false`
- [ ] `privileged: false`
- [ ] `capabilities.drop: ["ALL"]`, minimal explicit `add`
- [ ] `seccompProfile.type: RuntimeDefault` (or stricter)

### Resource Management
- [ ] `resources.limits.cpu` / `.memory` set
- [ ] `resources.requests.cpu` / `.memory` set
- [ ] No `hostPID: true`
- [ ] No `hostIPC: true`
- [ ] No `hostNetwork: true`
- [ ] No `hostPath` volumes (or tightly scoped read-only)

### Network
- [ ] NetworkPolicies defined (default-deny baseline)
- [ ] Ingress TLS configured (no `http: true` without TLS)
- [ ] Service account tokens auto-mounted only when needed (`automountServiceAccountToken: false`)

### Images
- [ ] Images from trusted registries (private / signed)
- [ ] Image tags pinned (no `:latest`)
- [ ] `imagePullPolicy: Always` for production
- [ ] Image signing verified (cosign / Sigstore) — see container-security skill

### RBAC
- [ ] Least privilege ServiceAccounts
- [ ] No `cluster-admin` RoleBindings
- [ ] Namespace-scoped Roles preferred over ClusterRoles
- [ ] No wildcard `verbs: ["*"]` or `resources: ["*"]`

## Inline Suppressions

```yaml
metadata:
  annotations:
    # Checkov
    checkov.io/skip1: CKV_K8S_8=Liveness probe not required for static service
    # kube-linter
    ignore-check.kube-linter.io/run-as-non-root: "Image requires root for legacy binary"
```
