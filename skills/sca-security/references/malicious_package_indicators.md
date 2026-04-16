# Malicious Package Indicators

Catalog of signals used by `workflows/supply_chain_review.md` to triage potentially malicious packages. Weight each signal; require multiple weak or one strong for a confirmed verdict.

## Strong signals (auto-flag, block install)

| Signal | Detection |
|--------|-----------|
| Install script that executes arbitrary code | inspect `package.json` scripts.{preinstall,install,postinstall}; Python `setup.py` with non-standard logic; Ruby `extconf.rb`; PHP `composer.json` scripts; Rust `build.rs` with net/fs ops |
| Obfuscated code (eval + hex/base64 payload) | `grep -E 'eval\(|Function\(|atob\(|_0x[a-f0-9]+|fromCharCode'` in tarball |
| Outbound network call from install script | extract install scripts, scan for `http://`, `https://`, `dns`, `socket`, `fetch`, `urllib`, `requests` |
| Binary blobs without source | look for shipped `.so`, `.dll`, `.dylib`, `.node`, `.wasm`, `.exe` not matching source build |
| Known-bad package in public advisory | GHSA Malware advisories, Socket.dev DB, Snyk malicious packages feed |
| Exact-name match to a known-malicious package | cross-check typosquat databases |

## Moderate signals (flag for human review)

| Signal | How to compute |
|--------|-----------------|
| Package age < 30 days | registry publish time |
| Single maintainer with disposable email | gmail/proton with random-looking handle, no org domain |
| Version jump 0.0.x → 9.9.x in one release | common account-takeover pattern |
| Download count < 100 before this week | registry stats |
| Missing/broken repository URL | `repository` field in manifest |
| No README or auto-generated README | tarball inspection |
| Maintainer set changed recently | compare historical metadata |
| Name similarity to a popular package (Levenshtein <=2) | typosquat heuristic |
| Homoglyph substitutions (Cyrillic а, l→1, o→0) | unicode check |
| Dependency shadows an internal-namespace name | dep confusion check |
| Abandoned package (last publish > 2 years) recently republished | time delta |
| Declared license is "UNLICENSED" or missing | manifest inspection |
| Suspiciously broad permissions requested | manifest metadata |

## Weak signals (inform, don't block alone)

- No downloads history at all
- No tests in tarball
- Very small package (single-file shim that wraps a well-known lib)
- Author's other packages are all similarly low-quality
- Package depends on another flagged package

## Per-ecosystem inspection commands

```bash
# npm tarball
npm pack <pkg>
tar tzf *.tgz
tar xzf *.tgz
jq '.scripts, .bin' package/package.json
grep -rE 'eval\(|Function\(|require\(.child_process.\)' package/

# PyPI sdist
pip download --no-deps --no-binary=:all: <pkg>
tar xzf *.tar.gz
cat */setup.py
grep -rE 'subprocess|os\.system|exec\(|eval\(|urllib|requests\.' */

# RubyGems
gem fetch <gem>
gem unpack *.gem
cat */metadata.yaml
find . -name 'extconf.rb' -exec cat {} \;

# Composer
composer require --dry-run <vendor/pkg>
cat vendor/<vendor>/<pkg>/composer.json | jq '.scripts'

# Rust
cargo download <crate>
tar xzf *.crate
cat */build.rs 2>/dev/null
```

## Reputation tools

| Tool | What it does |
|------|--------------|
| Socket.dev | Per-package risk score + install-time blocking for npm/PyPI/Go/Rust/Maven |
| Snyk Advisor | Package health score (uses maintenance, community, popularity) |
| deps.dev | Google's dep graph + license + advisory view |
| OpenSSF Scorecard | Per-repo security posture score |
| OSV Malicious Packages | github.com/ossf/malicious-packages |

## Triage decision matrix

| Strong | Moderate | Weak | Verdict |
|--------|----------|------|---------|
| 1+ | any | any | **Block / malicious confirmed** |
| 0 | 3+ | any | **Block pending human review** |
| 0 | 2 | 2+ | **Review — likely suspicious** |
| 0 | 1 | 2+ | **Flag — proceed with monitoring** |
| 0 | 0 | 1-2 | **Low concern** |
| 0 | 0 | 0 | **Clean** |

## Historical examples (pattern-match templates)

- **ua-parser-js (2021)**: account takeover → cryptominer + password-stealer in `postinstall`. Signal: sudden new maintainer + install script + obfuscated payload.
- **event-stream (2018)**: maintainer gradually handed off to attacker → targeted payload for specific wallet. Signal: rare — long-term social engineering.
- **colors.js / faker.js (2022)**: protestware (infinite-loop + garbage output). Signal: same-day commit + version jump.
- **PyTorch/torchtriton (2022)**: dependency confusion — attacker uploaded `torchtriton` to PyPI before PyTorch was namespaced. Signal: internal-namespace shadow on public registry.
- **node-ipc (2022)**: protestware targeting RU/BY IP ranges. Signal: geo-targeted runtime behavior, install script with IP lookup.
- **xz-utils (2024)**: long-con maintainer infiltration + build-time test-fixture-based payload. Signal: NONE pre-disclosure from SCA; included here as reminder that SCA is necessary-but-not-sufficient.
- **Shai-Hulud (2024-2025, npm)**: self-propagating worm via compromised maintainer tokens. Signal: install script scanning local creds + republishing other packages.

## Reasoning budget

**High — use extended thinking.** Triage requires weighing many weak signals and distinguishing legitimate "new but good" packages from account-takeover scenarios. False positives here cost engineering trust; false negatives cost a breach.
