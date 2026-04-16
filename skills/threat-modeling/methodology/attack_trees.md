# Attack Trees

Attack trees decompose an attacker's ultimate goal into sub-goals via AND/OR logic. Each leaf is an atomic attack step that can be evaluated for cost, skill, probability, and detectability.

## Structure

```
ROOT: Ultimate attack goal
├── OR: Alternative methods (any one succeeds)
│   ├── AND: Required steps (all must succeed)
│   │   ├── Leaf: Atomic attack step
│   │   └── Leaf: Atomic attack step
│   └── Leaf: Alternative atomic attack
└── OR: Another path to goal
    └── AND: Required combination
        ├── Leaf: Step 1
        └── Leaf: Step 2
```

- **OR nodes**: default. Child probability combines as `1 - Π(1 - p_child)`.
- **AND nodes**: all children required. Child probability combines as `Π p_child`.
- **Leaf nodes**: atomic, evaluable attacker actions.

## Construction Workflow

1. **Define the root** — one concrete attacker goal. "Compromise customer PII" is too vague; "Exfiltrate user password hashes" is better.
2. **First-level decomposition** — enumerate high-level strategies (supply chain, credential theft, insider, network, direct exploit). These become OR children.
3. **Expand each strategy** — recursively break into required prerequisites (AND) or alternatives (OR).
4. **Stop at atomic leaves** — a leaf is atomic when you can assign numeric costs/skills/probabilities to it.
5. **Annotate leaves** (see below).
6. **Propagate** values up the tree.
7. **Prioritize pruning paths** — cheapest / highest-probability paths are where defenders invest first.

Rule of thumb: trees deeper than 5 levels become unmanageable. Refactor into sub-trees.

## Leaf Annotations

| Dimension | Low | Medium | High |
|-----------|-----|--------|------|
| Probability (P) | Unlikely | Possible | Likely |
| Cost (C) | < $1k or free | $1k–$100k | > $100k |
| Skill (S) | Novice | Intermediate | Expert |
| Time (T) | Hours | Days | Weeks+ |
| Detectability (D) | Stealthy | Some telemetry | Obvious |

Each leaf: `ThreatScore = f(P, C, S, T, D)` — typical formulation is `P / (C × S × T)` with detectability as an adjustment. Use the model that matches the defender's risk appetite.

## Propagation Rules

- **OR**: pick the minimum-cost / highest-probability child (attacker picks easiest path).
- **AND**: sum costs; multiply probabilities; max skill; sum time; detectability = max of children (if any leg is loud, the whole leg is loud).

## Boolean Attributes (special case)

For yes/no annotations like "requires physical access":
- OR: value = any child true
- AND: value = all children true

Useful for "can this be done remotely?" or "does this require insider access?".

## Example

See `examples/attack_tree_banking.md` for a fully worked banking attack tree.

## Automation

Sub-trees are independent — parallelize their construction across sub-agents. See parent `SKILL.md` Sub-Agent Delegation section.

For machine-readable trees, use:
- ADTool / ADTree-maker (academic)
- AttackTree (Amenaza) — commercial
- Custom: YAML + graphviz (Threagile produces similar structures)

## When to Build One

Use attack trees when:
- A specific high-consequence threat is identified and needs deeper analysis
- Defenders need to compare mitigations on cost vs. attacker friction
- Communicating risk to non-technical stakeholders (visual)

Do NOT use attack trees as your primary threat-identification tool — they're exhaustive per-goal but don't enumerate goals. Start with STRIDE to identify goals, then build trees for the top N.

See `workflows/attack_tree_from_threat.md` for the runbook.
