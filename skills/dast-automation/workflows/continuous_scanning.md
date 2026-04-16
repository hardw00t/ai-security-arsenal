# Workflow: Continuous DAST scanning

**Trigger:** "Schedule weekly DAST on <domain>" / "set up continuous security scanning".

## Pattern

Baseline once; diff every subsequent run against the baseline; alert only on **new** Critical/High.

```
┌──────────────────────────────┐
│ Run 0 (baseline)             │
│  → results/baseline.json     │
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────┐
│ Run N (cron / CI scheduled)  │
│  → results/<YYYY-MM-DD>.json │
│  → diff vs baseline.json     │
│  → alert if Δ = new Crit/High│
│  → update rolling baseline   │
└──────────────────────────────┘
```

## Scheduling options

### cron

```bash
# /etc/cron.d/dast-target
0 2 * * 1 dast /opt/dast/run.sh target.com --mode blackbox --baseline /opt/dast/baseline.json --notify sec@corp.com
```

### GitHub Actions

See `examples/github_actions_dast.yml`.

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: dast-weekly }
spec:
  schedule: "0 2 * * 1"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: dast
              image: corp/dast-runner:latest
              args: ["--target", "https://target.com",
                     "--mode", "blackbox",
                     "--baseline", "/data/baseline.json"]
```

## Baseline management

- Commit `baseline.json` to a versioned store (git, S3 with object-lock).
- Bump baseline only after human review of the diff.
- Rotate baseline on major release of the target application.

## Diff rules

A "new" entry = same `(affected.url, affected.parameter, cwe)` absent from baseline.

| Δ severity | Action |
|------------|--------|
| New Critical | Page on-call immediately. |
| New High | Ticket within 24h. |
| New Medium | Weekly digest. |
| Fixed Critical/High | Note in digest, auto-close linked ticket. |
| No change | Silent success. |

## Drift alerts

- Scan duration >2× baseline → infra anomaly or coverage regression.
- Endpoint count <0.8× baseline → crawl regression (maybe auth broke).
- Nuclei template count mismatch → update templates and re-baseline.

## Related

- Single scan: `workflows/blackbox_single_domain.md`
- CI integration: `examples/github_actions_dast.yml`
