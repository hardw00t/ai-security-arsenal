# Ruby / Bundler Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `Gemfile` | manifest |
| `Gemfile.lock` | lockfile |
| `gemspec` | library manifest |
| `.bundle/config` | bundler config |

## SBOM generation

```bash
# CycloneDX Ruby plugin
gem install cyclonedx-ruby
cyclonedx-ruby -p . -o sbom.cdx.json

# Syft
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# bundler-audit (RubySec Advisory DB)
gem install bundler-audit
bundle-audit check
bundle-audit check --update             # refresh advisory DB first
bundle-audit check --format json

# OSV-Scanner
osv-scanner --lockfile=Gemfile.lock

# Snyk
snyk test --file=Gemfile.lock
```

## Dependency inspection

```bash
bundle show                          # flat list
bundle show <gem>                    # location of gem
bundle info <gem>                    # version + deps
bundle outdated
bundle outdated --strict             # respect Gemfile constraints

# Reverse dep
gem dependency <gem> --reverse-dependencies --pipe
```

## License extraction

```bash
gem install license_finder
license_finder
license_finder report --format=json > licenses.json
license_finder approvals add 'MIT' 'Apache-2.0' 'BSD-3-Clause'
```

## Common vulnerability patterns

| Class | Example | DB |
|-------|---------|-----|
| YAML deserialization | CVE-2013-0156 (rails) | RubySec |
| Regex ReDoS | various | RubySec |
| Rails RCE | many historical | RubySec |
| Nokogiri (libxml2) XXE | CVE-2024-34459 | both RubySec + NVD |
| Rack / request smuggling | CVE-2024-26146 | RubySec |

## Gotchas

- Gems can ship C extensions (`ext/`) built at install time via `extconf.rb` — arbitrary code execution at install, like npm postinstall.
- `Gemfile` allows `gem 'foo', git: 'https://...'` — git sources bypass rubygems.org supply chain controls. Audit.
- Native gems (precompiled per platform) have per-platform `gemspec` files — SBOM tools sometimes miss the correct platform.
- Bundler's `--deployment` mode pins to `Gemfile.lock` strictly — use in CI for reproducibility.

## Supply chain checks

```bash
# Bundler signature verification (opt-in)
bundle config set --global trust-policy HighSecurity
# Requires all gems to be signed; most aren't in practice.

# Check gem metadata
gem info <gem> --remote
# Look at: authors, owners, homepage, download count
```

## Tool minimums (2026-04)

- bundler >= 2.5
- bundler-audit >= 0.9.2
- ruby >= 3.2
- license_finder >= 7.2
