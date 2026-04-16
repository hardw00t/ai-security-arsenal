# OWASP Top 10 for LLM Applications (2025)

Source: OWASP GenAI Security Project, 2025 release.
Last validated against this skill: **2026-04**. The 2025 list is still the
active reference at that time; monitor https://genai.owasp.org for updates.

---

## Priority matrix (validated for frontier-model systems, 2026-04)

| ID | Title | 2026 relevance | Primary detection | Workflow |
|---|---|---|---|---|
| LLM01 | Prompt Injection | Critical — still #1 risk; indirect + multimodal dominate | Manual + automated | `workflows/direct_injection_testing.md`, `workflows/indirect_injection_testing.md` |
| LLM02 | Sensitive Information Disclosure | High — PII, training-data, tool-schema leak | Manual, partial auto | `workflows/system_prompt_extraction.md` |
| LLM03 | Supply Chain Vulnerabilities | High — MCP servers, model weights, fine-tune data, deps | Automated + manual | `workflows/mcp_server_injection.md`, `workflows/skill_file_injection.md` |
| LLM04 | Data and Model Poisoning | High — training, RAG, memory | Data-provenance analysis | `workflows/rag_poisoning.md`, `workflows/memory_poisoning.md` |
| LLM05 | Improper Output Handling | High — agent tool output, XSS, SSRF in downstream | Manual | `workflows/agentic_tool_misuse.md` |
| LLM06 | Excessive Agency | Critical — agentic era amplifies impact | Manual | `workflows/excessive_agency_testing.md`, `workflows/agentic_tool_misuse.md` |
| LLM07 | System Prompt Leakage | Medium — but trivially amplified into LLM01/LLM06 | Manual | `workflows/system_prompt_extraction.md` |
| LLM08 | Vector and Embedding Weaknesses | Medium–High — RAG dominance in 2026 raises impact | Manual | `workflows/rag_poisoning.md` |
| LLM09 | Misinformation | Medium — agent autonomy increases downstream harm | Manual | Out of scope for core sweep; treat per-deployment |
| LLM10 | Unbounded Consumption | High — cost + DoS vector for hosted services | Automated | Cross-cutting; see excessive-agency workflow |

---

## Coverage checklist (per engagement)

Mark each as one of: **tested-vulnerable**, **tested-clean**, **partial**,
**not-tested**.

- [ ] LLM01 Direct prompt injection
- [ ] LLM01 Indirect prompt injection (per channel: RAG, web, email, tools, MCP)
- [ ] LLM01 Multimodal injection (image/audio/video/screen)
- [ ] LLM02 Training-data disclosure
- [ ] LLM02 Tool-schema / credential leak
- [ ] LLM03 MCP server supply-chain
- [ ] LLM03 Model-weight / checkpoint integrity (if self-hosted)
- [ ] LLM03 Skill-file / CLAUDE.md supply-chain
- [ ] LLM04 RAG corpus poisoning
- [ ] LLM04 Memory poisoning
- [ ] LLM04 Fine-tune data poisoning (if applicable)
- [ ] LLM05 Tool-output injection to downstream (XSS, SQLi, SSRF)
- [ ] LLM06 Tool inventory & least-privilege
- [ ] LLM06 HITL quality
- [ ] LLM06 Privilege-escalation within agent
- [ ] LLM07 System-prompt full dump
- [ ] LLM07 Partial-leak accumulation
- [ ] LLM08 Retrieval hijacking
- [ ] LLM08 Embedding-space adversarial
- [ ] LLM08 Cross-tenant retrieval (ACL)
- [ ] LLM09 Misinformation / grounding failure (if applicable)
- [ ] LLM10 Prompt-length exhaustion
- [ ] LLM10 Tool-loop cost explosion
- [ ] LLM10 Per-user rate / quota limits

---

## 2026 notes

- **Agentic systems** radically change LLM06 and LLM05 impact.
  Single-turn-chat threat models are insufficient.
- **MCP** is a new supply-chain entry under LLM03; see separate workflow.
- **Multimodal** injection (LLM01) is a first-class concern now that
  frontier models natively process images/audio/screens.
- **Memory** (per-user & shared) raises persistent-poisoning severity
  under LLM04.
- OWASP 2025 list does not have a dedicated "agentic" category; treat
  agent-specific findings across LLM01, LLM05, LLM06.
