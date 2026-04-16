# Severity Normalization Across IaC Scanners

Each tool ships its own severity scale. To aggregate findings across Checkov + tfsec + Terrascan + kubesec + others, map to the 5-level normalized scale used in `schemas/finding.json`.

## Normalized scale
`critical` → `high` → `medium` → `low` → `info`

## Per-tool mapping

| Tool        | Native scale                                       | → critical | → high   | → medium | → low    | → info  |
|-------------|----------------------------------------------------|-----------|----------|----------|----------|---------|
| Checkov     | Derived from BC policy metadata (severity string)  | CRITICAL  | HIGH     | MEDIUM   | LOW      | INFO    |
| Checkov (no severity) | Many built-in rules ship without severity | —         | default  | —        | —        | —       |
| tfsec       | CRITICAL / HIGH / MEDIUM / LOW                     | CRITICAL  | HIGH     | MEDIUM   | LOW      | —       |
| Terrascan   | HIGH / MEDIUM / LOW                                | —         | HIGH     | MEDIUM   | LOW      | —       |
| KICS        | HIGH / MEDIUM / LOW / INFO / TRACE                 | —         | HIGH     | MEDIUM   | LOW      | INFO/TRACE |
| kubesec     | Score (-∞ … +∞) — use advise/critical tags         | critical advise | negative score | score = 0 | positive score | — |
| kube-linter | Severity absent; use check category + own policy   | Policy-defined | Policy-defined | Policy-defined | Policy-defined | — |
| Polaris     | danger / warning / ignore                          | —         | danger   | warning  | —        | ignore  |
| cfn-nag     | FAIL / WARN                                        | —         | FAIL     | WARN     | —        | —       |
| cfn-lint    | E (error) / W (warning) / I (info)                 | —         | E (sec-related) | W (sec-related) | W (non-sec) | I     |
| Trivy config| CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN           | CRITICAL  | HIGH     | MEDIUM   | LOW      | UNKNOWN |

## Rules of thumb

1. **Checkov rules without native severity** — default to `high` only when the rule name clearly implies unauthenticated exposure / secret leakage / broad IAM; otherwise `medium`.
2. **kubesec scores** — any rule tagged `critical` → `critical`; negative total score with no `critical` rule → `high`; positive score but failing advice → `low`.
3. **Terrascan has no `CRITICAL`** — re-rank Terrascan `HIGH` to `critical` only when the same check fires in Checkov/tfsec as CRITICAL. Otherwise keep `high`.
4. **cfn-nag `FAIL`** — treat as `high` unless the rule text describes public exposure (then `critical`).
5. **kube-linter / Polaris** — severity is policy-defined; the team's `.kube-linter.yaml` / Polaris config must pin severities or dedup will be noisy.

## Cross-tool dedup key

When the same resource is flagged by multiple scanners, prefer:
```
(iac_file, resource_type, resource_name, rule_category)
```
Keep the HIGHEST normalized severity. Retain per-tool `rule_id`s in a `duplicates[]` array so remediation can cite all applicable fixes.

## Category buckets (for dedup / reporting)

- `encryption` — at-rest / in-transit
- `iam` — policies, roles, trust, wildcards
- `network` — SGs, NACLs, NSGs, public IPs, ingress/egress
- `logging` — CloudTrail, flow logs, diagnostic settings, audit logs
- `secrets` — hardcoded creds, key rotation, Key Vault
- `resource_hygiene` — tagging, versioning, lifecycle, backup
- `supply_chain` — image pins, provenance, dependency sources
- `runtime_hardening` — pod security context, readOnlyRootFilesystem, privileged
