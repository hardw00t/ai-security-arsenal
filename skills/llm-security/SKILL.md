---
name: llm-security
description: "LLM and AI application security testing skill for prompt injection (direct, indirect, multimodal), system-prompt extraction, RAG poisoning, memory poisoning, MCP server injection, skill-file injection, agentic tool misuse, computer-use UI injection, and excessive agency. Authorization required — this skill tests AI systems you are explicitly permitted to assess. Triggers on requests to test LLM / AI-agent / RAG / MCP / computer-use security, perform prompt injection, extract system prompts, poison RAG or memory, audit agent tool use, or evaluate AI guardrails."
---

# LLM Security Testing

Thin router skill for security testing of LLM applications and AI agents.
Covers the OWASP LLM Top 10 (2025) with a 2026-grade threat model for
frontier-model agentic systems: indirect injection, multimodal injection,
MCP supply chain, memory poisoning, skill-file injection, computer-use UI
injection, and agentic tool misuse.

**Defensive / educational framing.** Every workflow here assumes written
authorization to test the target. Canary strings, throwaway accounts, and
controlled endpoints are preferred over real-data exploitation at every
step.

## When to Use

- Testing an LLM application for prompt-injection vulnerabilities (direct or indirect)
- Assessing RAG pipeline security (poisoning, retrieval hijack, ACL)
- Red-teaming an agentic system (Claude Code, Cursor, Copilot-agent, Operator, Computer Use)
- Auditing an MCP server configuration or a new MCP server before trusting it
- Testing long-term memory / persistent-context poisoning
- Evaluating guardrails, refusal behavior, and safety classifiers
- Checking for system-prompt / tool-schema leakage
- Scoping excessive-agency / tool-misuse blast radius
- Testing multimodal injection (image, audio, video, screenshot)
- Validating skill-file / CLAUDE.md / .cursor/rules supply-chain hygiene

### Trigger Phrases

"test this LLM for prompt injection", "jailbreak this model" (authorized),
"test AI guardrails", "assess RAG security", "poison this RAG corpus",
"test MCP server injection", "red-team this agent", "extract system prompt",
"test agent tool misuse", "test computer use UI injection", "audit LLM
application security", "test multimodal injection", "test memory poisoning",
"audit CLAUDE.md for injection".

## When NOT to Use This Skill

- **LLM API endpoint hardening** (auth, rate-limiting, quota abuse on
  standard REST surface) → use `api-security`.
- **Source-code review of an LLM application** (SAST for Python/TS/Go
  serving the model) → use `sast-orchestration`.
- **Cloud infrastructure hosting the model** (IAM, S3, secrets) → use
  `cloud-security` / `iac-security`.
- **Classical web bugs in an LLM chatbot UI** (XSS, CSRF, IDOR) → use
  `web-security`.
- **Privacy / compliance assessment of training data** → out of scope;
  requires DPIA tooling.

Many engagements need multiple skills; call them in parallel when scopes
don't overlap.

## Decision Tree

```
Is the target an agent with tools? ─ yes ─▶ excessive_agency_testing.md
                │                         └─▶ agentic_tool_misuse.md
                no
                ▼
Does it ingest external content (RAG/web/email)? ─ yes ─▶ indirect_injection_testing.md
                │                                      └─▶ rag_poisoning.md (if RAG)
                no
                ▼
Multimodal input accepted? ─ yes ─▶ payloads/multimodal_injection.md
                │              └─▶ computer_use_abuse.md (if screen-controller)
                no
                ▼
MCP servers attached? ─ yes ─▶ mcp_server_injection.md
                no
                ▼
Persistent memory / cross-session state? ─ yes ─▶ memory_poisoning.md
                no
                ▼
Project loads CLAUDE.md / skills / rules? ─ yes ─▶ skill_file_injection.md
                no
                ▼
Always run last: direct_injection_testing.md + system_prompt_extraction.md
```

## Parallelism Hints

**Parallelizable (fire concurrently, per rate limits):**
- Direct-injection payload sweep (one worker per payload)
- Encoding-obfuscation variant sweep
- Per-tool abuse probes in `agentic_tool_misuse.md`
- OWASP LLM category coverage via sub-agent fan-out
- Independent payload authoring for multimodal / skill-file / MCP tests

**Sequential (must observe one at a time):**
- RAG poisoning (retrieval observation must follow each upload)
- Memory poisoning (cross-session persistence testing needs strict turn ordering)
- Multi-turn stepwise-escalation jailbreaks
- Computer-use navigation chains
- MCP trust-building across turns

## Sub-Agent Delegation

Two clean partitions — pick whichever matches the engagement:

**By OWASP category** (one sub-agent each) for comprehensive coverage:
- LLM01 prompt injection (direct + indirect + multimodal)
- LLM02 sensitive-info disclosure
- LLM03 supply chain (MCP, skill-files, dependencies)
- LLM04 data/model poisoning (RAG + memory)
- LLM05 improper output handling
- LLM06 excessive agency
- LLM07 system-prompt leakage
- LLM08 vector/embedding weaknesses
- LLM10 unbounded consumption

**By attack surface** for deep-dive on one class:
- Direct-prompt surface
- Indirect-content surface (RAG, web, email, tool outputs)
- Agentic tool surface (all tools × all coercion vectors)
- Multimodal surface (image, audio, screen)
- Persistence surface (memory, skill-files, MCP config)

Parent agent aggregates findings (`schemas/finding.json`), de-dupes, and
cross-references overlapping findings (e.g. an MCP injection that enables
tool misuse).

## Reasoning Budget

**Use extended thinking** for:
- Crafting novel bypasses tuned to a specific defense stack
  (which spotlighting variant? which classifier version?)
- Analyzing whether an injection actually succeeded (subtle signals:
  behavior delta vs. baseline, refusal-template absence)
- Planning multi-step exploit chains (MCP → tool-misuse → file-write)
- Designing memory payloads that survive summarization
- Computer-use UI layouts that exploit agent heuristics

**Minimal thinking** for:
- Running fixed payload sets (encoding_obfuscation.txt, injection_2026.txt)
- Direct-extraction probes from a canned list
- Per-tool abuse sweeps with standard patterns
- Baseline / negative-control runs

## Multimodal Hooks

- **Image**: OCR-visible overlays, EXIF metadata, low-contrast adversarial
  text, QR codes. See `payloads/multimodal_injection.md`.
- **Audio**: spoken instructions in transcription workflows, ultrasonic
  carriers (deprecated but test), voice-clone authority spoof.
- **Video**: single-frame flash, subtitle-channel payloads, scene-change
  instruction cards.
- **Screen / computer-use**: fake dialogs, spoofed chrome, fake dev-tools,
  clipboard bait. See `workflows/computer_use_abuse.md`.
- **Evidence**: save screenshots (`evidence.screenshot`) for every
  multimodal finding — visual proof is essential.

Frontier models are also useful *as testing tools*: use a separate
vision-capable model to generate candidate adversarial images and to
judge whether OCR extraction succeeded.

## Structured Output

All findings use `schemas/finding.json`. Required fields:
`id`, `title`, `severity`, `attack_class`, `evidence`, `reproduction`,
`remediation`. Skill-specific fields include `attack_class`,
`target_model`, `target_agent`, `payload` (with modality and delivery
vector), `success_indicator`, `owasp_llm_id`, `defense_bypassed`.

## Workflow Index

| Workflow | When |
|---|---|
| `workflows/direct_injection_testing.md` | Text prompts directly in user channel |
| `workflows/indirect_injection_testing.md` | Content arrives via retrieval / tools / email |
| `workflows/system_prompt_extraction.md` | Recover system prompt / tool schemas |
| `workflows/rag_poisoning.md` | RAG corpus + retrieval-layer attacks |
| `workflows/agentic_tool_misuse.md` | Coerce agent to misuse file/http/shell tools |
| `workflows/memory_poisoning.md` | Persistent cross-session memory attacks |
| `workflows/mcp_server_injection.md` | Malicious MCP server → host agent |
| `workflows/skill_file_injection.md` | CLAUDE.md / .cursor/rules / SKILL.md as vector |
| `workflows/computer_use_abuse.md` | Screenshot/UI-based injection for computer-use agents |
| `workflows/excessive_agency_testing.md` | Blast-radius assessment (OWASP LLM06) |

## Payloads Index

| File | Contents |
|---|---|
| `payloads/injection_2026.txt` | Modern direct/indirect injection patterns (trust-boundary, authority spoof, tool-result spoof, CoT injection) |
| `payloads/system_prompt_extraction.txt` | Full-dump + partial-leak + tool-schema extraction |
| `payloads/encoding_obfuscation.txt` | Base64, ROT, hex, unicode homoglyph, zero-width, emoji smuggle, tag-char |
| `payloads/multimodal_injection.md` | Image / audio / video / screenshot payload descriptions |
| `payloads/legacy_jailbreaks.txt` | DAN / STAN / DUDE / roleplay — regression only |

## References Index

| File | Contents |
|---|---|
| `references/owasp_llm_top10_2025.md` | OWASP LLM Top 10 table + 2026 coverage checklist |
| `references/defense_patterns_2026.md` | Constitutional, classifiers, spotlighting, HITL, allowlisting — with known bypass hints |
| `references/threat_model_agents.md` | Actors, assets, surfaces, T1-T10 scenarios for agentic systems |

## Examples

| File | Contents |
|---|---|
| `examples/indirect_injection_doc.md` | Ready-to-deploy injection doc for RAG / shared drive |
| `examples/malicious_mcp_response.json` | Malicious MCP tool-response body |
| `examples/poisoned_rag_chunk.md` | Retrieval-optimized poisoning chunk |

## Tools

| Tool | Purpose | Install |
|---|---|---|
| `promptfoo` | Automated prompt-injection sweeps and eval | `npm i -g promptfoo` |
| `garak` | LLM vulnerability scanner (NVIDIA) | `pip install garak` |
| `giskard` | LLM testing & evaluation | `pip install giskard` |
| `pyrit` | Microsoft's AI red-team toolkit | `pip install pyrit` |
| `@modelcontextprotocol/sdk` | Build controlled test MCP servers | `npm i @modelcontextprotocol/sdk` |
| custom HTTP server | Attacker-endpoint for exfil signal | any language |
| `anthropic`, `openai`, `google-genai` SDKs | Drive target APIs | per-SDK |

Use your own logging endpoint for exfil-signal tests so you can
unambiguously confirm tool invocation.

## Authorization Reminder

Every engagement MUST have:
- Written scope document signed by target owner
- Named contact for incident escalation
- Canary strategy so tests don't require handling real sensitive data
- Rate-limit plan that respects ToS

Populate `authorization.scope_document` and `authorization.contact` on
every finding record.

## Last Validated

**2026-04.** Minimum tool versions tested:
- promptfoo ≥ 0.110
- garak ≥ 0.12
- pyrit ≥ 0.9
- MCP SDK ≥ 1.4
OWASP LLM Top 10 reference: 2025 edition (current at validation time).
