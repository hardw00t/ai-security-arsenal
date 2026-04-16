# OWASP API Security Top 10 (2023)

Canonical reference list of the OWASP API Top 10 2023 edition. Use the `API#:2023`
identifiers in the `owasp_api_id` field of `schemas/finding.json`.

| Rank | ID         | Name                                                  | Typical Severity | Detection          |
|------|------------|-------------------------------------------------------|------------------|--------------------|
| 1    | API1:2023  | Broken Object Level Authorization (BOLA)              | Critical         | Manual + Automated |
| 2    | API2:2023  | Broken Authentication                                 | Critical         | Manual + Tools     |
| 3    | API3:2023  | Broken Object Property Level Authorization (BOPLA)    | High             | Manual             |
| 4    | API4:2023  | Unrestricted Resource Consumption                     | High             | Automated          |
| 5    | API5:2023  | Broken Function Level Authorization (BFLA)            | High             | Manual             |
| 6    | API6:2023  | Unrestricted Access to Sensitive Business Flows       | High             | Manual             |
| 7    | API7:2023  | Server-Side Request Forgery (SSRF)                    | High             | Manual + Automated |
| 8    | API8:2023  | Security Misconfiguration                             | Medium           | Automated          |
| 9    | API9:2023  | Improper Inventory Management                         | Medium           | Discovery          |
| 10   | API10:2023 | Unsafe Consumption of APIs                            | Medium           | Code Review        |

## Per-category pointers into this skill

- **API1 BOLA** -> `methodology/bola_bfla_matrix.md` (BOLA section) + `payloads/bola_idor.txt`
- **API2 Broken Auth** -> `workflows/jwt_attack_chooser.md`
- **API3 BOPLA** -> `methodology/bola_bfla_matrix.md` (BOPLA section) + `payloads/mass_assignment.txt`
- **API4 Resource Consumption** -> `workflows/graphql_testing.md` (DoS section), `workflows/rest_testing.md` (Phase 6)
- **API5 BFLA** -> `methodology/bola_bfla_matrix.md` (BFLA section) + `payloads/bfla_privilege.txt`
- **API6 Business Flows** -> manual; model refund / loyalty / invite flows and abuse rate/state.
- **API7 SSRF** -> `payloads/injection.txt` (SSRF section)
- **API8 Misconfig** -> `workflows/rest_testing.md` (Phase 7), nuclei templates
- **API9 Inventory** -> `methodology/api_recon.md` (Environment inventory)
- **API10 Unsafe Consumption** -> source-review territory; delegate to `sast-orchestration`

## Canonical URL

`https://owasp.org/API-Security/editions/2023/en/0x00-header/`
