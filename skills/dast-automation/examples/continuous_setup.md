# Example: Continuous weekly scan setup

**User:** "Set up automated weekly security scanning for production.example.com."

## Tool-call blueprint

1. Confirm authorization to run recurring scans in production (different from one-shot).
2. Discuss blackbox-only vs greybox with service account; greybox in prod requires stable test tenant.
3. Run one **baseline** scan now: invoke `workflows/blackbox_single_domain.md` and save output as `baseline.json`.
4. `Write` → cron or GitHub Actions config. For GitHub, copy `examples/github_actions_dast.yml` into the target repo.
5. `Write` → alerting config: where to page on new Critical/High (email, Slack webhook, PagerDuty integration key).
6. Return to operator:
   - Baseline summary (severity counts).
   - Schedule configured.
   - Location of baseline artifact.
   - Who will receive alerts.

## Baseline artifact

```
results/continuous/production.example.com/
  baseline.json           # schemas/finding.json array
  baseline.date.txt       # ISO-8601 timestamp
  baseline.commit.txt     # git SHA of scan config
```

## Diff rules

See `workflows/continuous_scanning.md` → "Diff rules" table. Only new Critical/High page; new Medium is digested weekly.

## Operator questions to ask up front

- Production or staging?
- Preferred alert channel and recipients?
- Weekly, nightly, or post-deploy cadence?
- Scope changes per release (new subdomains, new API versions)?
- Who owns baseline-bump reviews?
