# PHP / Composer Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `composer.json` | manifest |
| `composer.lock` | lockfile |
| `vendor/` | installed deps |
| `auth.json` | private registry creds (never commit) |

## SBOM generation

```bash
# CycloneDX Composer plugin
composer global require cyclonedx/cyclonedx-php-composer
composer CycloneDX:make-sbom --output-format=JSON --output-file=sbom.cdx.json

# Syft
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# Composer built-in (Composer >= 2.4)
composer audit
composer audit --format=json > audit.json
composer audit --locked                  # scan composer.lock

# Local PHP Security Checker (Symfony / FriendsOfPHP DB)
symfony security:check
# or standalone:
# https://github.com/fabpot/local-php-security-checker
local-php-security-checker

# OSV-Scanner
osv-scanner --lockfile=composer.lock

# Snyk
snyk test --file=composer.lock
```

## Dependency inspection

```bash
composer show                        # flat
composer show --tree
composer show --outdated
composer why <vendor/pkg>            # who depends on this?
composer why-not <vendor/pkg> <ver>  # why can't I upgrade?
```

## License extraction

```bash
composer licenses
composer licenses --format=json > licenses.json
```

## Common vulnerability patterns

| Class | Example | DB |
|-------|---------|-----|
| Deserialization (unserialize) | many | FriendsOfPHP |
| SQL injection (raw PDO misuse) | framework-specific | FriendsOfPHP |
| Laravel RCE | CVE-2024-52301 | FriendsOfPHP |
| Symfony HTTP foundation bypass | various | FriendsOfPHP |
| Twig sandbox escape | CVE-2022-23614 | FriendsOfPHP |
| Guzzle cookie-jar issues | various | FriendsOfPHP |

## Vulnerability database: FriendsOfPHP

The authoritative PHP advisory DB: https://github.com/FriendsOfPHP/security-advisories

Maintained as YAML files keyed by package. Composer's built-in `audit` and `local-php-security-checker` both consume this feed. OSV also mirrors it.

## Gotchas

- `composer.json` `"scripts"` run during install/update — audit before enabling a new dep (equivalent to npm postinstall).
- Private Packagist / Satis repos defined in `composer.json` `"repositories"` bypass default registry trust. Audit URL + auth.
- Composer has no built-in package-signing; rely on HTTPS + vendor trust. Sigstore integration is not mainstream yet.
- `replace` keyword in `composer.json` claims to provide another package — supply chain risk if misused to shadow legit packages.

## Dependency confusion

PHP is especially exposed because:
- `composer.json` `repositories` can include internal Satis URLs.
- Resolver picks highest version across repos unless constrained.
- Pin with:

```json
{
  "repositories": [
    {"type": "composer", "url": "https://satis.internal.example.com"},
    {"packagist.org": false}
  ]
}
```

Disabling packagist.org ensures internal-only.

## Tool minimums (2026-04)

- PHP >= 8.2
- Composer >= 2.7
- local-php-security-checker >= 2.0
- cyclonedx/cyclonedx-php-composer >= 5.0
