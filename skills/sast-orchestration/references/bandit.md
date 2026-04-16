# Bandit Reference (Python)

AST-based Python security linter from PyCQA. Fast, noisy. Best as a first-pass Python filter.

## Install

```bash
pip install bandit              # base
pip install 'bandit[toml]'      # pyproject.toml config support
pip install 'bandit[sarif]'     # SARIF output
```

## Invocation

```bash
# Recursive scan
bandit -r ./src

# Severity floor (-l low, -ll medium, -lll high)
bandit -r ./src -ll

# Confidence floor (-i, -ii, -iii)
bandit -r ./src -iii

# Combine for high-signal output
bandit -r ./src -ll -ii

# Specific tests / skip
bandit -r ./src -t B301,B302,B303      # include
bandit -r ./src -s B101                 # skip assert_used

# Output formats
bandit -r ./src -f json   -o bandit.json
bandit -r ./src -f sarif  -o bandit.sarif
bandit -r ./src -f html   -o bandit.html

# Config file
bandit -r ./src -c bandit.yaml
```

## Config (`bandit.yaml`)

```yaml
skips: ['B101']   # assert_used is noisy in test code
tests:  # empty = run all
exclude_dirs:
  - tests
  - venv
  - .tox
  - migrations
```

## High-value test IDs

| ID | Check |
|----|-------|
| B102 | `exec` use |
| B103 | Bad file permissions (world-writable) |
| B105 / B106 / B107 | Hardcoded password string/funcarg/default |
| B108 | Hardcoded tmp directory |
| B301-B304 | Pickle / marshal / md5 / sha1 / insecure cipher |
| B306 | `mktemp_q` |
| B307 | `eval` |
| B308 | `mark_safe` (Django XSS) |
| B309 | HTTPS without cert verification |
| B310 | urllib urlopen |
| B311 | Insecure random |
| B313-B320 | XML parsing (XXE / billion-laughs) |
| B321 | FTP |
| B324 | weak hashlib.new |
| B501-B507 | `requests` / ssl / paramiko host-key |
| B601-B612 | Shell injection family |
| B701-B703 | Jinja2 / Mako / Django template autoescape off |

## Known FP patterns

- B101 (assert_used): fine in test code, exclude `tests/`.
- B404 (subprocess import): informational only; filter by confidence.
- B603/B607 (subprocess without shell): often safe when args are a list.
- Hardcoded password checks flag variable names — verify value, not name.

## When to pair with other tools

- Bandit + Semgrep (`p/python`) catches different classes; run both in parallel.
- For taint across functions, escalate to CodeQL (`python-security-extended.qls`).
- For framework-specific (Django/Flask), Semgrep rule packs outperform Bandit.
