# Brakeman Reference (Ruby on Rails)

Rails-aware, AST-based scanner. Understands ActiveRecord, routes, controllers, views. Highest signal-to-noise for Rails apps.

## Install

```bash
gem install brakeman
# Verify: brakeman --version (target >= 6.0)
```

## Invocation

```bash
# Scan current Rails app
brakeman

# Explicit app path
brakeman /path/to/rails/app

# Output formats
brakeman -f json   -o brakeman.json
brakeman -f sarif  -o brakeman.sarif
brakeman -f html   -o brakeman.html
brakeman -f markdown -o brakeman.md

# Severity / confidence
brakeman -w 1   # warn level (1=high, 2=medium, 3=weak)
brakeman --confidence-level 2   # 1=high, 2=medium, 3=weak

# Skip / include checks
brakeman --skip-checks CheckCrossSiteScripting,CheckSQL
brakeman -t SQL,CrossSiteScripting

# Diff mode (PR/CI)
brakeman --only-files app/controllers/users_controller.rb
brakeman --compare old_report.json > diff.json
```

## High-value checks

| Check | CWE | Note |
|-------|-----|------|
| SQL | CWE-89 | `where("name = #{params[:name]}")` |
| CrossSiteScripting | CWE-79 | Unescaped output in ERB |
| Redirect | CWE-601 | `redirect_to params[:url]` |
| MassAssignment | CWE-915 | Missing `strong_parameters` |
| SessionSettings | CWE-614 | Cookies without secure/httponly |
| DefaultRoutes | — | Wildcard `match ':controller(/:action(/:id))'` |
| UnsafeReflection | CWE-470 | `params[:klass].constantize` |
| CommandInjection | CWE-78 | backticks / `system` with user input |
| FileAccess | CWE-22 | `File.open(params[:path])` |
| Deserialize | CWE-502 | `YAML.load` / `Marshal.load` on user data |
| RegexDoS | CWE-1333 | Catastrophic backtracking |
| CSRFTokenSkipped | CWE-352 | `skip_before_action :verify_authenticity_token` |

## Config (`config/brakeman.yml`)

```yaml
:skip_checks:
  - CheckForceSSL
:exclude_paths:
  - vendor/
  - node_modules/
:run_all_checks: true
:confidence_level: 2
```

## Suppression

Inline comment above the flagged line:
```ruby
# brakeman:ignore:SQL -- validated by strong_parameters on controller #create
User.where("name = #{params[:name]}")
```

Or in `config/brakeman.ignore` (JSON fingerprint file generated via `brakeman -I`).

## Known FP patterns

- ActiveRecord `where("...", value)` (2-arg form) flagged identically to string interp — verify arg count.
- `raw` in helpers marked safe after sanitization: suppress with justification.
- Redirect check fires on any `redirect_to` with variable even when allowlisted.

## Pair with

- bundler-audit (dependency vulns) — not SAST; see sca-security skill.
- Semgrep `p/ruby` for non-Rails Ruby code.
- CodeQL Ruby suite for inter-procedural taint.
