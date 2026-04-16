# Workflow: Kubernetes RBAC Privilege Mapping

Enumerate principals (users, groups, ServiceAccounts), the roles bound to
them, and the effective verbs/resources. Identify over-permissioned
principals and lateral-movement paths.

## Steps

1. **Harvest RBAC objects**:
   ```bash
   kubectl get clusterroles       -o json > clusterroles.json
   kubectl get roles -A           -o json > roles.json
   kubectl get clusterrolebindings -o json > clusterrolebindings.json
   kubectl get rolebindings -A    -o json > rolebindings.json
   kubectl get sa -A              -o json > serviceaccounts.json
   ```

2. **Build principal → role → rules graph**.
   For each binding, resolve `subjects[]` → `roleRef` → rules
   (verbs × apiGroups × resources × resourceNames).

3. **Flag high-risk grants**:
   - `cluster-admin` bindings outside system namespaces
   - `*` verb on `*` resource (any scope)
   - `impersonate` verb — lets the subject become any user/SA
   - `escalate` or `bind` verb on `roles`/`clusterroles` — privilege escalation
   - `create` on `pods` + `get` on `secrets` (classic SA token harvest path)
   - `exec`, `attach`, `portforward` on pods in production
   - `create` on `nodes`/`nodes/proxy` (node-level exposure)
   - `patch`/`update` on `validatingwebhookconfigurations` / `mutating…`
     (admission bypass)
   - `*` on `pods/ephemeralcontainers` (stealth debug injection)

4. **Path-finding to cluster-admin** (attack graph):
   For each low-privilege SA, BFS through RBAC graph:
   - Any verb that yields a higher-privileged token (`get secrets`)
   - Any pod-creation verb scoped to a namespace hosting privileged SAs
   - `create tokenrequest` on a higher-privileged SA
   Report shortest path and required steps as reproduction.

5. **Tool assistance**:
   ```bash
   # rbac-tool (insights-engineering)
   rbac-tool who-can get secrets
   rbac-tool policy-rules -e '^system:'
   rbac-tool viz --cluster-context <ctx>     # graphviz output

   # kubectl-who-can
   kubectl who-can create pods -n production

   # krane (static RBAC analyzer)
   krane report
   ```

6. **Emit findings** with `affected.resource_kind` ∈ `{ClusterRoleBinding,
   RoleBinding, ClusterRole, Role}`, `affected.service_account`,
   `affected.namespace`.

## Parallelism

- RBAC object fetches: parallel
- Per-principal graph expansion: parallel (stateless)
- Tool runs (rbac-tool + krane): parallel

## Reasoning Budget

**Extended thinking for privilege-graph traversal.** Finding the shortest
attack path from a compromised SA to cluster-admin is non-trivial and
benefits from deep reasoning. Scanning for single-hop violations can use
minimal budget.
