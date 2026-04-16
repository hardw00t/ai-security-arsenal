# Workflow: Attack Tree from a High-Level Threat

Given a high-level threat (e.g. "Attacker exfiltrates customer PII"), construct a concrete attack tree to drive defensive prioritization.

## Inputs
- A single, clearly-defined attacker goal (the root)
- System context (DFD, component list, tech stack)
- Threat intelligence (MITRE ATT&CK, known exploits for the stack)

## Outputs
- Attack tree (Markdown outline + Mermaid)
- Leaf annotations (cost, skill, probability, detectability)
- Ranked paths by attacker cost
- Mitigation recommendations by path

## Steps

### 1. Sharpen the root
Rewrite vague goals into concrete, testable ones:
- "Compromise the system" → "Obtain read access to the `users` table"
- "Steal data" → "Exfiltrate 10k+ customer records undetected"
- "Break authentication" → "Authenticate as any customer given only their email"

### 2. Generate first-level branches (OR)
Use these categories as a checklist:
- **Credential theft**: phishing, brute force, credential stuffing, password-reset abuse
- **Vulnerability exploit**: app, framework, OS, library CVEs
- **Supply chain**: dependency, build system, CI/CD, update channel
- **Insider**: malicious employee, compromised employee
- **Physical**: device theft, lost backups, shoulder surfing
- **Social engineering**: pretexting, business email compromise
- **Indirect**: compromise a dependent service, pivot from a weaker tenant

### 3. Expand each branch
Recursively decompose using AND (all-required) and OR (alternatives). Reference MITRE ATT&CK techniques for realistic sub-steps. Stop at atomic leaves — actions a single attacker can execute with defined tools.

### 4. Annotate leaves
For each leaf record:
- Probability (H/M/L)
- Cost (H/M/L) — dollars + time
- Skill (Novice/Intermediate/Expert)
- Detectability (H/M/L) — likelihood of triggering existing telemetry

### 5. Propagate
- **AND**: sum costs; multiply probabilities; take max skill; take max detectability
- **OR**: attacker chooses cheapest/highest-prob path; for the tree's overall probability, use `1 - Π(1 - p_i)`

### 6. Identify the cheapest path
Walk the tree from root, choosing min-cost child at each OR. This is the attacker's rational path. Defenders prioritize breaking this path.

### 7. Suggest mitigations per leaf
A mitigation either raises cost/skill/detectability, or eliminates the leaf. Aim for controls that break multiple paths simultaneously — these have the best ROI.

### 8. Reassess
After mitigations are applied, recompute the cheapest path. Iterate until residual risk is acceptable.

## Parallelism

Sub-trees are independent. Spawn one sub-agent per first-level branch to recursively expand. Join results back to the root.

## Extended Thinking

Extended thinking is high-value at:
- Step 2 (enumerating first-level branches — adversarial creativity)
- Step 4 (accurate probability/cost estimation)
- Step 6 (identifying non-obvious attacker paths)

Skip extended thinking for mechanical steps (5, 7 propagation/templating).

## Example

See `examples/attack_tree_banking.md` for a fully worked tree on "Transfer money from a victim's account".

## Output Format

```markdown
# Attack Tree: <Root>

## Root
<Concrete attacker goal>

## Tree
- OR Branch 1: <name>
  - AND
    - Leaf: <atomic step> [P=H, C=L, S=Novice, D=L]
    - Leaf: <atomic step> [P=M, C=M, S=Intermediate, D=M]
- OR Branch 2: <name>
  - Leaf: <atomic step> [...]

## Cheapest Path
Branch X → ... → leaves summed cost $5k, skill Intermediate, detectability L

## Mitigations
| Target | Control | Effect |
|--------|---------|--------|
| Leaf L1 | MFA | raises cost H, skill Expert |
```

## When to Use vs. Not

Use attack trees when:
- A specific high-impact threat needs deep analysis
- Comparing mitigation options on cost basis
- Communicating attacker economics to leadership

Don't use attack trees as the primary enumeration method — use STRIDE for that.
