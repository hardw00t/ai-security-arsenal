# Workflow: NetworkPolicy Coverage Review

Identify namespaces without default-deny, over-permissive ingress/egress
rules, and gaps between intended and actual pod connectivity.

## Steps

1. **Inventory**:
   ```bash
   kubectl get networkpolicies -A -o json > netpol.json
   kubectl get ns -o json > ns.json
   kubectl get pods -A -o json > pods.json
   ```

2. **Default-deny coverage**:
   For each namespace, confirm at least one NetworkPolicy with an empty
   `podSelector` and no rules (ingress-deny-all) plus one with egress deny.
   ```bash
   jq -r '
     .items[]
     | select(
         (.spec.podSelector // {}) == {}
         and (.spec.policyTypes | index("Ingress"))
         and ((.spec.ingress // []) | length == 0)
       )
     | .metadata.namespace
   ' netpol.json | sort -u > ns_with_default_deny_ingress.txt
   ```

3. **Over-permissive rules**:
   - Ingress from `0.0.0.0/0` on non-gateway pods
   - Egress to `0.0.0.0/0` without destination port restrictions
   - `namespaceSelector: {}` + `podSelector: {}` (any pod from any ns)

4. **Enforcement validation** — actually attempt the connectivity:
   ```bash
   kubectl run netshoot --rm -it --image=nicolaka/netshoot -n <src-ns> \
     -- curl -m 3 <dst-pod-ip>:<port>
   ```
   Or use `kubectl netpol-check` (if Cilium) / `np-viewer`.

5. **Cross-check CNI enforcement**: NetworkPolicies only take effect if the
   CNI enforces them (Calico, Cilium, Weave). Flannel alone does not.

6. **Egress surface**:
   - DNS policy — pods resolving external names via cluster DNS?
   - Any pod with egress to metadata service (169.254.169.254)?
   - TLS SNI inspection or L7 policy in place (Cilium, Istio)?

## Tools

| Tool               | Use                                             |
|--------------------|-------------------------------------------------|
| `cyctl netpol`     | Cilium policy inspection                        |
| `np-viewer`        | Visualize effective policy                      |
| `kubescape`        | NetworkPolicy-specific controls                 |
| `inspektor gadget` | Live traffic observation (advise-mode → policy) |

## Parallelism

- Inventory fetches: parallel
- Per-namespace evaluation: parallel
- Connectivity probes: parallel (bounded concurrency, avoid DoS)
