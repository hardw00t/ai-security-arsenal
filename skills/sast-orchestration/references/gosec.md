# gosec Reference (Go)

AST-based Go security scanner. Fast. Run on every package in a Go module.

## Install

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
# Verify: gosec --version
```

## Invocation

```bash
# Entire module
gosec ./...

# Severity floor
gosec -severity medium ./...

# Confidence floor
gosec -confidence high ./...

# Include / exclude rules
gosec -include=G101,G102,G103 ./...
gosec -exclude=G104 ./...

# Output
gosec -fmt=json  -out=gosec.json  ./...
gosec -fmt=sarif -out=gosec.sarif ./...
gosec -fmt=text  -out=gosec.txt   ./...

# Excluding test files (default includes them)
gosec -exclude-dir=vendor -tests=false ./...

# Config file
gosec -conf=.gosec.json ./...
```

## Rule IDs

| ID | Check |
|----|-------|
| G101 | Hardcoded credentials |
| G102 | Binding to all interfaces |
| G103 | Audit `unsafe` block |
| G104 | Unchecked errors |
| G106 | `ssh.InsecureIgnoreHostKey` |
| G107 | URL from variable in HTTP request (SSRF) |
| G108 | `net/http/pprof` exposed |
| G109 | Integer overflow on `strconv.Atoi` → `int32` |
| G110 | Potential DoS via decompression bomb |
| G201-G204 | SQL injection family |
| G301-G307 | File perm / path traversal / symlink |
| G401-G408 | Weak crypto (DES, RC4, MD5, SHA1, small RSA/DSA) |
| G501-G505 | Insecure imports (md5, des, rc4, etc.) |
| G601 | Implicit memory aliasing in for-range |

## Config (`.gosec.json`)

```json
{
  "global": {
    "nosec": "enabled",
    "audit": "enabled"
  },
  "G101": {
    "pattern": "(?i)(passwd|password|pass|secret|token|key|pw|apiKey|bearer)"
  },
  "G104": {
    "ignore": ["fmt.Print", "fmt.Println"]
  }
}
```

## Suppression

Inline: `// #nosec G104 -- reason`

## Known FP patterns

- G104 (unchecked errors): often informational; filter by use case.
- G107 (URL from variable): fires on any dynamic URL; pair with taint analysis before triaging as exploitable SSRF.
- G204 (subprocess via variable): flags `exec.Command(userVar, ...)` even with a validated allowlist.

## Pair with

- `staticcheck` (quality, not security) — run alongside.
- Semgrep `p/golang` for pattern rules not in gosec.
- CodeQL Go suite for inter-procedural taint.
