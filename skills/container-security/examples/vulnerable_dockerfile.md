# Vulnerable Dockerfile Anti-Patterns

Each section shows the bad pattern, why it's dangerous, and the fix.
Useful as a checklist when reviewing Dockerfiles or generating training
examples for detection rules.

## 1. Running as root

```dockerfile
# BAD
FROM python:3.11
COPY . /app
CMD ["python", "/app/main.py"]
```
Default `USER root` — any RCE is instantly root in the container, and any
capability not explicitly dropped is live.

```dockerfile
# GOOD
FROM python:3.11-slim
RUN groupadd -r app && useradd -r -g app app
COPY --chown=app:app . /app
USER app
CMD ["python", "/app/main.py"]
```

## 2. `latest` tag / unpinned base

```dockerfile
# BAD
FROM node:latest
```
Non-reproducible; supply-chain attackers can swap the tag.

```dockerfile
# GOOD — pin by digest
FROM node:20.11.1-bookworm-slim@sha256:abc123...
```

## 3. Secrets baked in

```dockerfile
# BAD
ARG AWS_SECRET_ACCESS_KEY
ENV AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
COPY .env /app/.env
```
Persists in layer history (`docker history`) and SBOM; rotatable only by
rebuilding and redeploying.

```dockerfile
# GOOD — BuildKit secrets
# syntax=docker/dockerfile:1.7
RUN --mount=type=secret,id=aws \
    aws s3 cp s3://bucket/file /tmp/
```

## 4. ADD with remote URL

```dockerfile
# BAD
ADD https://example.com/installer.sh /tmp/install.sh
RUN sh /tmp/install.sh
```
Unverified download, no checksum, TOCTOU.

```dockerfile
# GOOD
COPY installer.sh /tmp/install.sh
RUN echo "<sha256>  /tmp/install.sh" | sha256sum -c - \
 && sh /tmp/install.sh
```

## 5. Package cache left behind

```dockerfile
# BAD
RUN apt-get update && apt-get install -y curl git
```
Increases size and exposes outdated metadata.

```dockerfile
# GOOD
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl=7.88.* git=1:2.39.* \
 && rm -rf /var/lib/apt/lists/*
```

## 6. `chmod 777` / world-writable files

```dockerfile
# BAD
RUN chmod -R 777 /app
```
Any compromised process can rewrite application code.

```dockerfile
# GOOD
RUN chmod -R o-w /app
```

## 7. Curl-pipe-shell bootstrap

```dockerfile
# BAD
RUN curl -fsSL https://get.example.com | bash
```
No signature check; mirror compromise = RCE at build time.

```dockerfile
# GOOD
COPY bootstrap.sh .
RUN sha256sum -c bootstrap.sha256 && ./bootstrap.sh
```

## 8. SSH server installed

```dockerfile
# BAD
RUN apt-get install -y openssh-server
EXPOSE 22
```
Containers should be immutable — use `kubectl exec`, not SSH.

## 9. Missing HEALTHCHECK

```dockerfile
# BAD
# (no HEALTHCHECK)
```

```dockerfile
# GOOD
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8080/healthz || exit 1
```

## 10. Shell-form ENTRYPOINT

```dockerfile
# BAD — signals (SIGTERM) don't reach the process
ENTRYPOINT python /app/main.py
```

```dockerfile
# GOOD
ENTRYPOINT ["python", "/app/main.py"]
```

## Hadolint Quick Reference

| Rule   | Meaning                                           |
|--------|---------------------------------------------------|
| DL3002 | Don't switch to root USER                         |
| DL3003 | Use WORKDIR instead of `cd`                       |
| DL3007 | Don't use `latest` tag                            |
| DL3008 | Pin apt-get package versions                      |
| DL3009 | Delete apt-get lists after installing             |
| DL3020 | Use COPY not ADD for local files                  |
| DL3025 | Use JSON form for CMD/ENTRYPOINT                  |
| DL4006 | Set `SHELL ["/bin/bash", "-o", "pipefail", "-c"]` |
