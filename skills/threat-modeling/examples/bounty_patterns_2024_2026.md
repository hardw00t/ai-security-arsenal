# Bug Bounty Patterns 2024-2026 — threat-modeling addendum

## Overview

STRIDE-per-element extension of the existing `stride_threat_library.md`, digesting the
38 post-2023 bug-bounty patterns from the other skills into system-modelling language.
This file is an addendum — not a replacement — and mirrors the existing library's
`## <Element> / ### <STRIDE letter>` shape so consumers can merge it in directly.

Source patterns (by ID) are numbered identically to the per-skill reference files; see
`../../<skill>/references/bounty_patterns_2024_2026.md` for operational detail.

---

## External Entity

### Spoofing
- Malicious mobile app registers same URL scheme / Android intent filter as legitimate app, spoofing the OAuth callback receiver (iOS P35, Android P34).
- Attacker-controlled Terraform Cloud workspace spoofs the organization principal accepted by an AWS OIDC trust (IaC P26).
- Attacker AI tool description spoofs a trusted MCP tool to pull instructions into a coding agent (LLM P8 / SAST P8).

### Repudiation
- Refresh tokens continue minting access tokens after password reset, breaking the "user revoked access" audit narrative (API P4).
- Key-cycling makes "per-user anomalous usage" metrics unreliable (API P5).

---

## Process

### Spoofing
- JWT `request_uri` JAR injection swaps an attacker's identity claims into the IdP's flow (API P2).
- Unauthenticated kube-apiserver admits any caller as `system:anonymous` (IaC P28).

### Tampering
- Prototype pollution overrides `Object.prototype` and tampers with library-internal allow-lists (DAST PA / SAST PA).
- Mass assignment rewrites `role`/`permissions` via ordinary PATCH endpoints (API P6).
- Helm chart drift tampers dev securityContext into prod (IaC P27).
- Malicious npm preinstall tampers with source tree during install (SCA P30).
- Git arbitrary file write via `.gitmodules` tampers with arbitrary paths (SCA P32).

### Repudiation
- Adaptive LLM defense evasion defeats the very "judge" log meant to provide forensics (LLM P10).

### Information Disclosure
- Indirect prompt injection via retrieved docs exfiltrates session data via tool calls (LLM P7).
- Multimodal injection extracts text the user never saw (LLM P9).
- ORM filter DSLs leak adjacent tenant data through boolean-timing oracles (API PB / SAST PB).
- SSRF via DNS rebinding leaks IMDS credentials (Cloud P15).
- HTTP request smuggling reveals internal vhosts and cross-user bodies (DAST P21 / Network P21).
- Cache deception serves prior user's authenticated payload to anonymous callers (DAST PC).
- Unprotected broadcast receivers leak auth tokens to any installed app (Android P37).

### Denial of Service
- Cycling API keys bypasses per-key throttles, enabling distributed DoS (API P5).
- Shai-Hulud 2.0 payload wipes `$HOME`, a targeted DoS on developer machines (SCA P30).

### Elevation of Privilege
- OAuth non-happy-path flow → account takeover (API P1).
- JWT forgery via leaked `.env` secret → admin ATO (API P3).
- ConfusedFunction → project-wide GCP privesc (Cloud P11).
- `AWSMarketplaceFullAccess` → full AWS admin via EC2 role (Cloud P14).
- Compute-SA-reassignment + network-tag chain → lateral to admin VM (Cloud P13).
- runC escape → container breakout + host compromise (Container P17).
- NVIDIA Container Toolkit LD_PRELOAD escape (Container P18).
- K8s RoleBinding creation → cluster-admin (Container P20).
- SA token theft → lateral pivot + API-server admin ops (Container P19 / Network P19).
- GitHub Action `tj-actions` tag retargeting → stolen CI secrets → downstream privesc (SCA P31).

---

## Data Store

### Tampering
- RAG vector / doc store poisoning embeds instructions into the knowledge base (LLM P7).
- Keychain / Keystore items with loose ACL allow on-device modification (iOS P38).

### Information Disclosure
- Exposed `.env` / `.git` / backup files reveal JWT secrets, AWS keys, etc. (API P3).
- iOS backup + Keychain accessibility = off-device credential leak (iOS P38).
- Oracle EBS SSRF chain reads IMDS / internal services, disclosing secrets (Cloud P16).

### Denial of Service
- Transitive dependency CVE in data-layer code (e.g., protobuf parser) reachable from network input → DoS (SCA P33).

---

## Data Flow

### Tampering
- HTTP request smuggling mutates requests between front-end and back-end (DAST P21 / Network P21).
- HTTP/2 CONNECT punches an unsanctioned data flow into internal ranges (DAST P22 / Network P22).
- WAF parser-discrepancy lets malicious bodies reach the app unmutated (DAST P23).
- Base64-encoded SSRF in headers evades WAF inspection (DAST P25).

### Information Disclosure
- Blind-SSRF redirect-loop oracle turns invisible flows into measurable ones (Cloud PD).
- Cache deception splits a single authenticated flow into many anonymous ones (DAST PC).

---

## Cross-cutting (maps to any element)

### Supply-chain meta-threats
- Shai-Hulud 2.0 worm (SCA P30), `tj-actions` compromise (SCA P31), Git CVE-2025-48384 (SCA P32), and MCP-server tampering (LLM P8) jointly represent the "compromised upstream artefact" class — should appear on every DFD as an External-Entity-Tampering arrow into any Process that executes third-party code.

### Governance / shift-left
- IaC shift-left correlation (IaC P29) is a control-maturity finding; include in every threat model as a pre-condition for mitigation credibility.

---

## Using this addendum

1. Merge entries into your existing DFD's element table; the `STRIDE` letter and element type
   are the natural join key.
2. Cross-reference each row with `../../<skill>/references/bounty_patterns_2024_2026.md`
   for detection/mitigation detail.
3. For DREAD scoring, assume severity ratings from the source pattern index (Critical ≥ 8,
   High ≥ 6) unless contextual factors warrant re-scoring.
4. Include "Supply-chain meta-threats" as a standalone section of every threat model that
   involves third-party libraries, AI agents, or GitOps pipelines.
