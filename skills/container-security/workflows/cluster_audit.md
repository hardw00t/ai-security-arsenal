# Workflow: Live Kubernetes Cluster Audit

End-to-end assessment of a running cluster against CIS, NSA, and MITRE.

## Preconditions
- `kubectl` context configured, read-level access minimum
- In-cluster execution permitted for node-level checks (`kube-bench`)

## Steps

1. **Cluster inventory** (cheap, always first):
   ```bash
   kubectl version
   kubectl get nodes -o wide
   kubectl get ns
   kubectl api-resources --verbs=list -o name | sort
   ```

2. **Parallel assessments**:
   ```bash
   # Kubescape (framework-level)
   kubescape scan framework nsa -f json -o kubescape-nsa.json &
   kubescape scan framework mitre -f json -o kubescape-mitre.json &
   kubescape scan framework cis-v1.23-t1.0.1 -f json -o kubescape-cis.json &

   # kube-hunter (passive — avoid --active without authorization)
   kube-hunter --pod --report json > kube-hunter.json &
   wait
   ```

3. **Node-level CIS** via in-cluster DaemonSet:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
   kubectl wait --for=condition=complete job/kube-bench --timeout=10m
   kubectl logs -l app=kube-bench > kube-bench.txt
   ```
   For multi-node: use the DaemonSet variant so each node runs in parallel;
   consider one sub-agent per node for result parsing.

4. **Delegate deeper probes** (parallel sub-agents):
   - RBAC analysis → `workflows/rbac_analysis.md`
   - NetworkPolicy gap → `workflows/network_policy_review.md`

5. **Workload posture sampling**:
   ```bash
   # Any privileged pods?
   kubectl get pods -A -o json | jq -r '
     .items[] | select(.spec.containers[].securityContext.privileged==true)
     | "\(.metadata.namespace)/\(.metadata.name)"'

   # hostNetwork / hostPID / hostIPC
   kubectl get pods -A -o json | jq -r '
     .items[] | select(.spec.hostNetwork or .spec.hostPID or .spec.hostIPC)
     | "\(.metadata.namespace)/\(.metadata.name)"'

   # Default ServiceAccount with mounted token
   kubectl get pods -A -o json | jq -r '
     .items[] | select(.spec.serviceAccountName=="default"
       and (.spec.automountServiceAccountToken // true))
     | "\(.metadata.namespace)/\(.metadata.name)"'
   ```

6. **Consolidate** into `schemas/finding.json` records with
   `affected.cluster_name`, `affected.namespace`, `affected.resource_kind`,
   `cis_control`.

## Parallelism

- Kubescape frameworks: parallel
- kube-bench per node: parallel (DaemonSet)
- RBAC + NetworkPolicy sub-workflows: parallel (independent data)

## Reasoning Budget

- **Minimal** for scanner execution and result collection
- **Extended** for correlating RBAC + workload posture + network policy into
  attack-path narratives
