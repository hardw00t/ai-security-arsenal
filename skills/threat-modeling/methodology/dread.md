# DREAD Risk Scoring

DREAD is a simple five-factor scoring scheme. It is **deprecated by Microsoft** and widely criticized for subjectivity, but it remains in common use for quick prioritization when organizations lack a mature risk framework.

## Factors (each 0-10)

| Letter | Factor | Question |
|--------|--------|----------|
| D | Damage | How bad if the attack succeeds? |
| R | Reproducibility | How easy to reproduce? |
| E | Exploitability | How easy to launch? |
| A | Affected users | How many users impacted? |
| D | Discoverability | How easy to find? |

### Scoring Guidance

**Damage (0-10)**
- 0: Nothing
- 5: Individual user data, limited scope
- 10: Complete system compromise, brand-level harm

**Reproducibility (0-10)**
- 0: Very hard, rare conditions
- 5: Requires specific configuration
- 10: Always reproducible

**Exploitability (0-10)**
- 0: Requires advanced knowledge + custom tools
- 5: Requires some expertise
- 10: Novice can exploit with public tools

**Affected Users (0-10)**
- 0: None
- 5: Some users / specific roles
- 10: All users / all tenants

**Discoverability (0-10)**
- 0: Very difficult to find (requires source code + specialized research)
- 5: Can be found with focused effort
- 10: Already public or easily visible

## Calculation

```
Risk Score = (D + R + E + A + D) / 5
```

### Rating Scale

| Score | Rating |
|-------|--------|
| 8-10 | Critical |
| 6-8 | High |
| 4-6 | Medium |
| 2-4 | Low |
| 0-2 | Informational |

### Worked Example: SQL Injection in Login

- Damage: 10 (Full database access)
- Reproducibility: 10 (Always works once found)
- Exploitability: 6 (Requires SQLi skill, well-known tools exist)
- Affected Users: 10 (All users)
- Discoverability: 6 (Found by testing)

Score = (10+10+6+10+6)/5 = **8.4 → Critical**

## Known Critiques

1. **Subjective scoring** — different analysts produce wildly different scores.
2. **Discoverability rewards obscurity** — a high-damage hidden bug scores lower than a trivial visible one. Many orgs drop the second D.
3. **Linear averaging** masks critical factors — a 10 Damage + 0 Exploitability averages the same as 5/5.
4. **No attacker-capability model** — treats script kiddie and nation-state the same.

## Recommended Alternatives

- **CVSS 4.0** — standardized, base/threat/environmental metrics; widely tooled.
- **OWASP Risk Rating Methodology** — similar factor style but better-calibrated.
- **FAIR (Factor Analysis of Information Risk)** — quantitative / monetary.
- **Likelihood × Impact matrix** — simplest for qualitative rankings.

## Where DREAD Still Earns Its Keep

- Fast triage in a workshop setting
- Converting a flat list of threats into a rough rank order
- Environments with no existing risk taxonomy

If using DREAD, record each factor separately in the finding (see `schemas/finding.json`, field `dread_score`) so the score can be recomputed or superseded by a better methodology later.
