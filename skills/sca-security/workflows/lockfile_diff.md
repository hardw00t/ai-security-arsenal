# Lockfile Diff Workflow — PR Review

**This is a frontier-model-favored workflow.** Long context lets one agent read the full base + head lockfiles, reason about the full dependency delta, and surface new vulns, license changes, and supply-chain risks introduced by a single PR.

## When to use

- Reviewing a PR that modifies `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `requirements.txt` with hashes.
- Any PR where `package.json` / `pyproject.toml` / `pom.xml` / `go.mod` / `Cargo.toml` / `Gemfile` / `composer.json` changes.

Skip for PRs that only touch application code (no manifest or lockfile changes).

## Step 1 — Collect base + head

```bash
gh pr checkout $PR_NUMBER
git fetch origin $BASE_BRANCH
# Work in a tmp dir so both versions survive
mkdir -p /tmp/lockdiff/{base,head}
git show "origin/$BASE_BRANCH:package-lock.json" > /tmp/lockdiff/base/package-lock.json
cp package-lock.json /tmp/lockdiff/head/
```

## Step 2 — Normalize + diff

Prefer tool-native diffs — plain `git diff` is noisy for lockfiles.

```bash
# npm — official
npm-lockfile-diff /tmp/lockdiff/base/package-lock.json /tmp/lockdiff/head/package-lock.json

# yarn
yarn-deduplicate --list /tmp/lockdiff/head/yarn.lock

# Python
pip-compile --dry-run --upgrade  # shows delta against existing
# Or structural:
poetry show --tree  # before + after, diff the outputs
```

General-purpose: parse both lockfiles to a normalized `(name, version, integrity)` set and set-diff.

## Step 3 — Classify each change

For every `(pkg, old_ver, new_ver)` tuple, classify:

| Class | Signal | Action |
|-------|--------|--------|
| New direct | appears in manifest diff | full SCA + supply-chain check |
| New transitive | appears only in lockfile | vuln + license check, flag if unexpected parent |
| Version bump | same pkg, different ver | vuln delta, license delta, changelog scan |
| Version downgrade | semver decrease | ALWAYS flag — unusual in a healthy upgrade |
| Removed | gone in head | usually benign; confirm nothing imports it |
| Integrity hash change w/o version change | same ver, diff hash | CRITICAL — possible registry compromise |

## Step 4 — Run scans on the *delta* only

For each new or bumped package, query OSV directly:

```bash
# Batch API
curl -s https://api.osv.dev/v1/querybatch \
  -d '{"queries":[{"package":{"name":"left-pad","ecosystem":"npm"},"version":"1.3.0"},...]}'
```

Compare results against the same batch for base versions. A vuln that existed in both base and head is not a PR regression; a vuln present in head only IS.

## Step 5 — Supply chain signals on new packages

For every package appearing for the first time in head, apply `supply_chain_review.md` checks:
- Package age (first publish < 30 days → flag)
- Maintainer count
- Download volume vs similarly-named popular packages (typosquat?)
- Install scripts present? (npm `scripts.preinstall|install|postinstall`)
- For internal-namespace packages: does a public package with the same name exist? (dependency confusion)

## Step 6 — License delta

Re-run `license_audit.md` on just the diff:
- Any new package with a denied or review-required license → block PR.
- Any license change on the same package (rare but real: `faker.js` relicensing) → flag.

## Step 7 — Emit PR comment

One comment summarizing:
- N new direct deps, M new transitive deps
- K new vulnerabilities introduced (table: pkg → CVE → severity → fixed version)
- L license changes (table: pkg → old → new → policy)
- S supply-chain risks (table: pkg → indicator → evidence)

For each new vuln, emit a finding with `finding_type: "vulnerability"` and set `evidence.lockfile` + `evidence.lockfile_lines` to the exact PR diff hunk.

## Parallelism hint

- Step 4 (OSV batch), Step 5 (supply chain), Step 6 (license): fully parallel per package; batch where the API supports it.
- Consider spawning one sub-agent per lockfile in polyglot monorepos (one per ecosystem).

## Reasoning budget

- Medium — classify changes correctly, resolve dep paths, distinguish regression vs pre-existing.
- High for integrity hash changes without version changes (registry compromise scenario).
- Low for simple version bumps with only additive vulns.

## Frontier-model advantage

Claude Opus 4.7 / GPT-5.4 can hold the full base + head lockfiles (often 10k+ lines each) in context and produce a holistic diff review in one pass — something fragment-at-a-time older models cannot. Use this capability: read whole files, don't grep.
