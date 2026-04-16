# Runtime Security Reference

Falco, Tetragon, and eBPF-based runtime monitoring. Covers rule authoring,
deployment, and response wiring.

## Falco

### Deployment

```bash
# Helm (modern eBPF driver — preferred)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true

# Watch alerts
kubectl -n falco logs -l app.kubernetes.io/name=falco -f

# Confirm driver
kubectl -n falco exec deploy/falco -- falco --list | head
```

### Rule Authoring Grammar

A Falco rule = `rule`, `desc`, `condition` (filter expression over syscall
fields), `output`, `priority`, `tags`.

Field sources:
- `evt.*` — syscall type/args
- `proc.*` — process name, cmdline, parent
- `fd.*` — file descriptor target, IP, port
- `user.*` — UID, name
- `container.*` — image, name, id, labels
- `k8s.*` — pod name, namespace, labels (when K8s audit source)

### Starter Rule Pack

See `examples/falco_custom_rule.yaml` for a ready-to-load custom pack covering
shell spawn, sensitive file read, unexpected outbound, and escape primitives.

### Macro / List reuse

```yaml
- list: allowed_registries
  items: [registry.example.com, ghcr.io/acme]

- macro: from_allowed_registry
  condition: container.image.repository startswith (allowed_registries)

- rule: Image from Unknown Registry
  desc: Pod launched from a registry not on the allow list
  condition: container.info and not from_allowed_registry
  output: Unallowed registry image=%container.image.repository
  priority: WARNING
  tags: [supply-chain]
```

### Response wiring (falcosidekick)

Supported outputs: Slack, PagerDuty, OpsGenie, Elasticsearch, Loki, Kafka,
AWS SNS/Lambda, GCP PubSub, generic webhook. For auto-remediation, point at
Falco Talon or Kubernetes Response Engine.

## Tetragon (Cilium / eBPF)

Tetragon is observable-by-default + enforcement-capable via kprobes.

```bash
# Install
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system

# Stream events (TracingPolicy-driven)
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact
```

### Enforcement TracingPolicy

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-sensitive-file-open
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values: ["/etc/shadow", "/etc/kubernetes/pki"]
      matchActions:
      - action: Sigkill
```

## Choosing: Falco vs Tetragon

| Dimension            | Falco                           | Tetragon                             |
|----------------------|---------------------------------|--------------------------------------|
| Primary function     | Detection + alert               | Detection + in-kernel enforcement    |
| Rule language        | YAML DSL over syscall fields    | TracingPolicy CRD (kprobes)          |
| Performance          | Good (eBPF driver)              | Excellent (kernel-side filtering)    |
| Ecosystem size       | Larger rule library             | Smaller, newer                       |
| Kill-on-detect       | External (Falco Talon)          | Native (`Sigkill` action)            |
| Best for             | Broad security monitoring       | Latency-sensitive enforcement        |

## eBPF Alternatives

- **Pixie** — observability focus, security add-ons
- **Inspektor Gadget** — on-demand tracing, rich gadget library
- **Parca / bpftrace** — ad-hoc investigation

## Runtime Detection Priorities

High-signal behaviors to always alert on:

1. Shell spawn in a production container
2. Outbound connection to non-allow-listed destination
3. Writes to `/etc`, `/usr/bin`, `/usr/sbin` in running container
4. Reads of `/etc/shadow`, service account tokens across pods
5. `execve` of `nsenter`, `mount`, `unshare`, `capsh`, `docker`
6. `ptrace` or `process_vm_writev` inside container
7. Opening `/proc/1/root` or `/proc/sys/kernel/core_pattern`
8. Kernel module load (`init_module`, `finit_module`)
9. Writes to `/var/run/docker.sock`
10. Any use of `setns`, `unshare -r`
