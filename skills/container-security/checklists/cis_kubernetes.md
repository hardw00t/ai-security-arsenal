# CIS Kubernetes Benchmark Checklist

## 1. Control Plane Components

### 1.1 Control Plane Node Configuration Files
- [ ] 1.1.1 Ensure API server pod spec file permissions are 600
- [ ] 1.1.2 Ensure API server pod spec file ownership is root:root
- [ ] 1.1.3 Ensure controller manager pod spec file permissions are 600
- [ ] 1.1.4 Ensure controller manager pod spec file ownership is root:root
- [ ] 1.1.5 Ensure scheduler pod spec file permissions are 600
- [ ] 1.1.6 Ensure scheduler pod spec file ownership is root:root
- [ ] 1.1.7 Ensure etcd pod spec file permissions are 600
- [ ] 1.1.8 Ensure etcd pod spec file ownership is root:root

### 1.2 API Server
- [ ] 1.2.1 Ensure `--anonymous-auth` is set to false
- [ ] 1.2.2 Ensure `--token-auth-file` is not set
- [ ] 1.2.3 Ensure `--DenyServiceExternalIPs` is set
- [ ] 1.2.4 Ensure `--kubelet-client-certificate` and `--kubelet-client-key` are set
- [ ] 1.2.5 Ensure `--kubelet-certificate-authority` is set
- [ ] 1.2.6 Ensure `--authorization-mode` includes RBAC
- [ ] 1.2.7 Ensure `--authorization-mode` does not include AlwaysAllow
- [ ] 1.2.8 Ensure admission control plugin EventRateLimit is set
- [ ] 1.2.9 Ensure admission control plugin AlwaysAdmit is not set
- [ ] 1.2.10 Ensure admission control plugin ServiceAccount is set
- [ ] 1.2.11 Ensure admission control plugin NamespaceLifecycle is set
- [ ] 1.2.12 Ensure admission control plugin NodeRestriction is set
- [ ] 1.2.13 Ensure `--profiling` is set to false
- [ ] 1.2.14 Ensure audit logging is enabled
- [ ] 1.2.15 Ensure `--audit-log-path` is set
- [ ] 1.2.16 Ensure `--audit-log-maxage` is set to 30 or greater
- [ ] 1.2.17 Ensure `--audit-log-maxbackup` is set to 10 or greater
- [ ] 1.2.18 Ensure `--audit-log-maxsize` is set to 100 or greater

### 1.3 Controller Manager
- [ ] 1.3.1 Ensure `--terminated-pod-gc-threshold` is set
- [ ] 1.3.2 Ensure `--profiling` is set to false
- [ ] 1.3.3 Ensure `--use-service-account-credentials` is set to true
- [ ] 1.3.4 Ensure `--service-account-private-key-file` is set
- [ ] 1.3.5 Ensure `--root-ca-file` is set
- [ ] 1.3.6 Ensure RotateKubeletServerCertificate is set to true
- [ ] 1.3.7 Ensure `--bind-address` is set to 127.0.0.1

### 1.4 Scheduler
- [ ] 1.4.1 Ensure `--profiling` is set to false
- [ ] 1.4.2 Ensure `--bind-address` is set to 127.0.0.1

---

## 2. etcd

- [ ] 2.1 Ensure `--cert-file` and `--key-file` are set
- [ ] 2.2 Ensure `--client-cert-auth` is set to true
- [ ] 2.3 Ensure `--auto-tls` is not set to true
- [ ] 2.4 Ensure `--peer-cert-file` and `--peer-key-file` are set
- [ ] 2.5 Ensure `--peer-client-cert-auth` is set to true
- [ ] 2.6 Ensure `--peer-auto-tls` is not set to true

---

## 3. Control Plane Configuration

### 3.1 Authentication and Authorization
- [ ] 3.1.1 Ensure client certificate authentication is used
- [ ] 3.1.2 Ensure service account tokens are not used for users
- [ ] 3.1.3 Ensure bootstrap tokens are used only for joining

### 3.2 Logging
- [ ] 3.2.1 Ensure minimal audit policy is created
- [ ] 3.2.2 Ensure audit policy covers sensitive operations

---

## 4. Worker Nodes

### 4.1 Worker Node Configuration Files
- [ ] 4.1.1 Ensure kubelet service file permissions are 600
- [ ] 4.1.2 Ensure kubelet service file ownership is root:root
- [ ] 4.1.3 Ensure proxy kubeconfig file permissions are 600
- [ ] 4.1.4 Ensure proxy kubeconfig file ownership is root:root

### 4.2 Kubelet
- [ ] 4.2.1 Ensure `--anonymous-auth` is set to false
- [ ] 4.2.2 Ensure `--authorization-mode` is not AlwaysAllow
- [ ] 4.2.3 Ensure `--client-ca-file` is set
- [ ] 4.2.4 Ensure `--read-only-port` is set to 0
- [ ] 4.2.5 Ensure `--streaming-connection-idle-timeout` is not 0
- [ ] 4.2.6 Ensure `--protect-kernel-defaults` is set to true
- [ ] 4.2.7 Ensure `--make-iptables-util-chains` is set to true
- [ ] 4.2.8 Ensure `--hostname-override` is not set
- [ ] 4.2.9 Ensure `--tls-cert-file` and `--tls-private-key-file` are set
- [ ] 4.2.10 Ensure `--rotate-certificates` is set to true
- [ ] 4.2.11 Ensure RotateKubeletServerCertificate is true
- [ ] 4.2.12 Ensure Kubelet only uses strong ciphers

---

## 5. Policies

### 5.1 RBAC and Service Accounts
- [ ] 5.1.1 Ensure cluster-admin role is only used where required
- [ ] 5.1.2 Minimize access to secrets
- [ ] 5.1.3 Minimize wildcard use in Roles and ClusterRoles
- [ ] 5.1.4 Minimize access to create pods
- [ ] 5.1.5 Ensure default service account is not used
- [ ] 5.1.6 Ensure service account tokens are not mounted when unnecessary
- [ ] 5.1.7 Avoid using the system:masters group
- [ ] 5.1.8 Limit use of Bind, Impersonate, Escalate permissions

### 5.2 Pod Security
- [ ] 5.2.1 Ensure privileged containers are not used
- [ ] 5.2.2 Ensure containers do not share host process namespaces
- [ ] 5.2.3 Ensure containers do not share host network namespace
- [ ] 5.2.4 Ensure containers do not allow privilege escalation
- [ ] 5.2.5 Ensure containers do not run as root
- [ ] 5.2.6 Ensure containers drop all capabilities
- [ ] 5.2.7 Ensure containers do not mount host paths
- [ ] 5.2.8 Ensure container ports are defined

### 5.3 Network Policies and CNI
- [ ] 5.3.1 Ensure CNI supports NetworkPolicies
- [ ] 5.3.2 Ensure all namespaces have NetworkPolicies defined

### 5.4 Secrets Management
- [ ] 5.4.1 Use secrets as files instead of env vars
- [ ] 5.4.2 Ensure external secret storage is used

### 5.5 Extensible Admission Control
- [ ] 5.5.1 Configure image provenance using admission controllers

### 5.7 General Policies
- [ ] 5.7.1 Create administrative boundaries using namespaces
- [ ] 5.7.2 Ensure Seccomp profile is set
- [ ] 5.7.3 Apply Pod Security Standards
- [ ] 5.7.4 Ensure default namespace is not used

---

## Quick Check Commands

```bash
# Run kube-bench
kube-bench run --targets master,node

# Check API server settings
kubectl get pod kube-apiserver-* -n kube-system -o yaml | grep -E "anonymous-auth|authorization-mode"

# Check RBAC
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin")'

# Check privileged pods
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true)'

# Check pods running as root
kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.runAsNonRoot != true)'

# Check NetworkPolicies
kubectl get networkpolicies -A

# Check admission controllers
kubectl exec -n kube-system kube-apiserver-* -- kube-apiserver -h | grep enable-admission-plugins
```
