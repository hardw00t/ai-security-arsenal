# Threat Model: Agentic LLM Systems (2026)

A structured threat model specifically for tool-using, possibly-autonomous
LLM agents. Single-turn chat threat models are insufficient. Use this as a
checklist when scoping an engagement or designing defenses.

---

## Actors

| Actor | Capabilities |
|---|---|
| **Legitimate user** | Issues prompts through sanctioned channels |
| **External content author** | Writes web pages, emails, docs the agent may ingest |
| **Compromised service** | Attacker-controlled upstream (MCP server, API, webhook) |
| **Malicious insider** | Has limited write to corpus / memory / repo |
| **Dependency author** | Ships code/config/skills that the agent auto-loads |
| **Network attacker** | TLS MITM, DNS hijack (often out of scope but note) |

## Assets

- Model weights (if self-hosted)
- System prompts, tool schemas, internal workflows (IP)
- Training & fine-tune data
- RAG corpus (business-sensitive documents)
- User & session data in context window
- Persistent memory (per-user, per-team)
- Tool-accessible downstream systems (filesystem, DB, email, cloud APIs, Git)
- Long-term reputation / trust of the service

## Attack surfaces

### Prompt channel
- User input → OWASP LLM01 direct
- System-prompt-placement if configurable → LLM07, LLM01
- Developer-message channel in multi-role APIs → privilege confusion

### Retrieval channel
- RAG corpus content → LLM01 indirect, LLM04, LLM08
- Metadata fields (title, tags, source) that propagate to context
- Cross-tenant retrieval (ACL failures)

### Tool-output channel
- Any tool return that is placed in context
- Especially: web-browse (attacker-controlled), email (inbound), code
  execution output

### MCP channel
- Tool descriptions, input schemas, response bodies, resources, prompts
- See `workflows/mcp_server_injection.md`

### Multimodal channel
- Images, audio, video, screenshots
- See `payloads/multimodal_injection.md`, `workflows/computer_use_abuse.md`

### Memory channel
- Explicit or implicit long-term memory
- See `workflows/memory_poisoning.md`

### File-load channel
- `CLAUDE.md`, `.cursor/rules`, `skills/*`, `.mcp.json`
- See `workflows/skill_file_injection.md`

### Identity / auth channel
- API keys, OAuth tokens, session cookies reachable by tools
- Agent's own identity within the org (what can "the agent" do?)

## Trust boundaries

A useful mental model: classify every byte entering the model context as
either **trusted** (sanctioned-user input, vetted system prompt) or
**untrusted** (everything else, especially everything an external party
could influence). The core invariant:

> **Untrusted content must be data, never instructions.**

Most LLM-app bugs in 2026 stem from violations of that invariant.

## Threat scenarios (rank-ordered by typical impact)

### T1. Indirect injection via RAG / web / email → exfil
Most common high-impact bug. Attacker plants instructions in retrieved
content; agent exfiltrates user context via tool call.

### T2. MCP server supply-chain compromise
Upstream MCP package compromised or malicious from the start.

### T3. Skill-file / config supply-chain
Dependency ships `.cursor/rules/` or `CLAUDE.md` that instructs the agent
in the developer's IDE.

### T4. Memory poisoning (persistent)
Cross-session attack via long-term memory writes.

### T5. Tool-chain confused deputy
Agent has broad permissions; attacker coerces via indirect injection;
agent uses its own creds to act on attacker's behalf.

### T6. Computer-use UI injection
Agent clicks/types in response to rendered attacker content.

### T7. System-prompt / tool-schema leak
Enables more targeted follow-up attacks; sometimes directly leaks
credentials embedded in prompts.

### T8. Direct jailbreak → harmful content generation
Still present but lower relative priority vs. agentic threats.

### T9. Unbounded consumption / cost DoS
Economic impact; prompt-loops, retrieval recursion, tool storms.

### T10. Training-data extraction
Specialized; primarily concern for self-hosted or fine-tuned models.

## Trust decisions a well-designed agent makes

1. Is this byte stream trusted (user/system) or untrusted (retrieved/tool)?
2. Before executing a tool call, does the call originate from a trust-boundary
   violation? (Instructions from untrusted content must not drive tool calls.)
3. Does the user see, understand, and approve each sensitive action?
4. Is the identity under which the tool runs narrower than the agent itself?
5. Is there an audit trail that can be reviewed after compromise?

Grade a deployment by how many of these it answers explicitly.
