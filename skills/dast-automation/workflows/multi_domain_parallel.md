# Workflow: Multi-domain parallel DAST

**Trigger:** "Scan these domains: a.com, b.com, c.com" / "run DAST across our fleet".

## Parallelization model

**One sub-agent per domain.** Each sub-agent independently runs `workflows/blackbox_single_domain.md` (or `greybox_authenticated.md`) against its assigned host. The parent agent aggregates.

```
             ┌─── sub-agent A ──→ workflows/blackbox_single_domain.md (a.com)
orchestrator─┼─── sub-agent B ──→ workflows/blackbox_single_domain.md (b.com)
             ├─── sub-agent C ──→ workflows/greybox_authenticated.md  (c.com)
             └─── sub-agent N ──→ ...
```

Default concurrency cap: **5 sub-agents**. Raise only if:

- Each target is on a separate origin (no shared WAF).
- Operator confirms infrastructure can absorb aggregate load.

## Dispatch pattern

```python
# Pseudocode — the parent agent emits this by spawning sub-agents via the Task tool
for domain in domains:
    spawn_subagent(
        workflow="blackbox_single_domain",
        target=domain,
        output_dir=f"results/{domain}/",
        cap_rps=5,
    )
# Wait for all; aggregate
merged = aggregate_finding_jsons("results/*/output.json")
write("results/aggregate.json", merged)
```

## Per-sub-agent contract

Each sub-agent MUST:

1. Confine writes to `results/<its-domain>/`.
2. Emit `output.json` conforming to `schemas/finding.json`.
3. Never read another sub-agent's output mid-run.
4. Honor per-host rate limits independently.

## Aggregation

The parent composes:

- `results/aggregate.json` — union of all per-domain `output.json`.
- `results/aggregate.html` — sorted by severity then domain.
- `results/cross_domain.md` — patterns recurring across >1 domain (candidate for systemic fix).

## Safety

- Mixed blackbox+greybox fleet: run **all blackbox first** so a misbehaving auth scan doesn't poison unrelated hosts with shared credentials.
- Shared WAF/CDN: sequence domains behind the same WAF to avoid collective rate-limit block.
- Prod + staging in the same run: quarantine prod outputs from staging outputs.

## Resource tuning

| Domains | Concurrent sub-agents | Per-target RPS | Total RPS |
|---------|-----------------------|----------------|-----------|
| 1–3     | N                     | 10             | ≤30       |
| 4–10    | 5                     | 5              | ≤25       |
| 10+     | 5 (queue rest)        | 3              | ≤15       |

## Related

- Single domain: `workflows/blackbox_single_domain.md`
- Scheduled: `workflows/continuous_scanning.md`
