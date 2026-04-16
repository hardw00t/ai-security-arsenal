# SARIF Reference

Static Analysis Results Interchange Format (OASIS SARIF 2.1.0). The lingua franca for SAST tool output — every major tool emits it, GitHub code scanning ingests it, and it's the right intermediate for multi-tool aggregation.

## Minimal schema

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep",
          "version": "1.60.0",
          "informationUri": "https://semgrep.dev",
          "rules": [
            {
              "id": "python.lang.security.audit.dangerous-system-call",
              "name": "dangerous-system-call",
              "shortDescription": {"text": "Subprocess with shell=True"},
              "fullDescription": {"text": "..."},
              "helpUri": "https://semgrep.dev/r/...",
              "properties": {
                "security-severity": "8.8",
                "tags": ["security", "CWE-78"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.dangerous-system-call",
          "level": "error",
          "message": {"text": "Subprocess with shell=True is dangerous"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 42, "startColumn": 5, "endLine": 42, "endColumn": 40}
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "abc123..."
          }
        }
      ]
    }
  ]
}
```

## Key objects

| Object | Purpose |
|--------|---------|
| `run.tool.driver` | Which tool produced the run |
| `run.tool.driver.rules[]` | Rule definitions, referenced by `ruleId` |
| `run.results[]` | Actual findings |
| `result.ruleId` | Links to rule definition |
| `result.level` | `none` / `note` / `warning` / `error` |
| `result.locations[].physicalLocation` | File + region |
| `result.codeFlows[]` | Taint path (source → intermediate → sink) |
| `result.partialFingerprints` | Stable ID for dedup across runs |
| `result.suppressions[]` | Explicit suppression with justification |
| `result.properties.security-severity` | CVSS-like numeric 0.0-10.0 |

## Taint paths (`codeFlows`)

```json
"codeFlows": [{
  "threadFlows": [{
    "locations": [
      {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/routes.py"}, "region": {"startLine": 10}}}, "message": {"text": "user input read"}},
      {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/utils.py"}, "region": {"startLine": 25}}}, "message": {"text": "passed to helper"}},
      {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/db.py"},    "region": {"startLine": 77}}}, "message": {"text": "reaches SQL sink"}}
    ]
  }]
}]
```

CodeQL path-problem queries emit codeFlows; Semgrep taint mode emits them with `--sarif`; Bandit does not.

## Level → severity mapping (for aggregation)

| SARIF `level` | Normalized severity |
|---------------|---------------------|
| error | high / critical |
| warning | medium |
| note | low |
| none | info |

Use `properties.security-severity` when present for finer ranking (CVSS-style 0.0-10.0).

## Fingerprinting for dedup

Prefer `partialFingerprints.primaryLocationLineHash` when tools provide it. Fallback: hash of `(ruleId, file_path, line, snippet)`. Across tools, match on `(cwe, file_path, ±3 lines)` to merge duplicates.

## Tool emission commands

| Tool | Flag |
|------|------|
| Semgrep | `--sarif -o out.sarif` |
| CodeQL | `--format=sarif-latest --output=out.sarif` |
| Bandit | `-f sarif -o out.sarif` (with `bandit[sarif]`) |
| gosec | `-fmt=sarif -out=out.sarif` |
| Brakeman | `-f sarif -o out.sarif` |
| SpotBugs | `sarifOutput=true` in plugin config |
| ESLint | `--format @microsoft/eslint-formatter-sarif` |

## Upload

- GitHub: `github/codeql-action/upload-sarif@v3`
- GitLab: native SAST report artifact (converts SARIF subset)
- Defect Dojo / Dradis: direct SARIF import

## Tools for manipulation

- `jq` for quick queries: `jq '.runs[0].results | length' out.sarif`
- Microsoft `sarif-multitool` (dotnet): `sarif rewrite`, `sarif page`
- Python: `sarif-om`, `jschema-to-python`
