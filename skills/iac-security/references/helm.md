# Helm Chart Security Reference

Helm adds a templating layer; most K8s rule failures are invisible until the chart is rendered. Always scan rendered output **and** raw templates.

## Scan Approaches

### 1. Render, then scan (highest fidelity)

```bash
helm template my-release ./my-chart > rendered.yaml
checkov -f rendered.yaml --framework kubernetes
kubesec scan rendered.yaml

# With production values
helm template my-release ./my-chart -f values-prod.yaml > rendered-prod.yaml
checkov -f rendered-prod.yaml --framework kubernetes
```

Render with EVERY values profile that ships (dev / staging / prod). A chart that's safe on defaults can ship a `0.0.0.0/0` LoadBalancer under a non-default values file.

### 2. Direct chart scan

```bash
checkov -d ./my-chart --framework helm
checkov -d ./my-chart --framework helm --var-file values-prod.yaml

trivy config ./my-chart
```

Direct scanning catches template issues Checkov understands natively, but will miss rules that depend on fully-resolved values.

### 3. Helm unit tests + policy gate

```bash
helm plugin install https://github.com/helm-unittest/helm-unittest
helm unittest ./my-chart

# Combined with conftest
helm template ./my-chart | conftest test - -p policy/
```

## Chart.yaml Security

- [ ] `appVersion` pinned to specific version (no floating tags)
- [ ] `dependencies[].repository` from trusted, HTTPS repos
- [ ] `dependencies[].version` pinned (exact, not `^`/`~` where possible)
- [ ] `kubeVersion` constraints set (avoid running on unsupported clusters)
- [ ] No deprecated API versions in templates (`kubectl-deprecations`, `pluto`)
- [ ] Chart provenance (`helm package --sign`, verify with `--verify`)

## values.yaml Security

- [ ] No secrets in default `values.yaml` (use `existingSecret` patterns)
- [ ] Security-sensitive defaults fail-closed (e.g. `networkPolicy.enabled: true`)
- [ ] Image tags in values are pinned digests where possible
- [ ] `serviceAccount.create: true` with minimal permissions

## Common Helm Pitfalls

1. Conditional security contexts: `securityContext` under `{{- if .Values.securityContext }}` → root-running pods if value omitted.
2. Unquoted tags: `image: myimg:{{ .Values.tag }}` where `tag: 1.0` renders as float in some cases.
3. `tpl` rendering of user input: possible SSTI if chart ingests untrusted values.
4. `lookup` function in charts: requires cluster access; can leak state across render environments.

## Using pluto for deprecated APIs

```bash
pluto detect-helm -o wide
pluto detect-files -d ./my-chart/templates
```
