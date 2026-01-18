# AI Security Arsenal

A comprehensive collection of skills for automated security testing, penetration testing, and security assessment workflows with coding agents like Claude Code, Codex, OpenCode, and others.

## Skills Overview

| Category | Skill | Description |
|----------|-------|-------------|
| **Mobile** | [android-pentest](#android-pentest) | Android app pentesting with Frida, objection, ADB |
| **Mobile** | [ios-pentest](#ios-pentest) | iOS app security testing with Frida, Cycript, objection |
| **Web** | [dast-automation](#dast-automation) | Dynamic testing with ZAP, Burp, Nuclei, Playwright |
| **Web** | [api-security](#api-security) | REST/GraphQL API security, OWASP API Top 10 |
| **Cloud** | [cloud-security](#cloud-security) | AWS/GCP/Azure security assessment |
| **Cloud** | [iac-security](#iac-security) | Infrastructure as Code security scanning |
| **Cloud** | [container-security](#container-security) | Docker/Kubernetes security assessment |
| **Network** | [network-pentest](#network-pentest) | Internal network/AD penetration testing |
| **Code** | [sast-orchestration](#sast-orchestration) | Static analysis with Semgrep, CodeQL, Bandit |
| **Code** | [sca-security](#sca-security) | Software Composition Analysis, SBOM, dependencies |
| **AI/ML** | [llm-security](#llm-security) | LLM security, prompt injection, OWASP LLM Top 10 |
| **Process** | [threat-modeling](#threat-modeling) | STRIDE, PASTA, Attack Trees, threat analysis |

---

## Mobile Security

### Android Pentest

Comprehensive Android mobile application penetration testing with full ADB shell access to rooted devices.

**Capabilities:**
- Static & dynamic analysis of Android applications
- Runtime manipulation with Frida (SSL pinning bypass, root detection bypass, crypto hooks)
- OWASP MASTG compliance testing
- Data extraction (databases, SharedPreferences, storage)
- Component fuzzing (activities, services, content providers, broadcast receivers)

**Trigger phrases:** `pentest this Android app`, `bypass SSL pinning`, `extract data from app`, `MASTG testing`

**Tools:** ADB, Frida, objection, apktool, jadx, Burp Suite

---

### iOS Pentest

iOS mobile application security testing with runtime manipulation and binary analysis.

**Capabilities:**
- Static analysis with class-dump, otool, Hopper
- Runtime manipulation with Frida and Cycript
- SSL pinning and jailbreak detection bypass
- Keychain extraction and data protection analysis
- OWASP MASTG compliance testing
- IPA decryption and binary patching

**Trigger phrases:** `pentest this iOS app`, `bypass jailbreak detection`, `extract keychain`, `iOS security assessment`

**Tools:** Frida, objection, Cycript, class-dump, otool, Clutch/bfdecrypt

---

### Mobile MCP for Device Interaction

Both mobile pentesting skills support **[Mobile MCP](https://github.com/mobile-next/mobile-mcp)** for advanced device, emulator, and simulator interactions:

- Screen capture and UI inspection
- Touch automation and gesture simulation
- App lifecycle management
- Complements Frida/Objection for scenarios requiring direct UI interaction

```json
// Add to ~/.claude/mcp.json
{
  "mcpServers": {
    "mobile-mcp": {
      "command": "npx",
      "args": ["-y", "@anthropic/mobile-mcp", "--android"]  // or "--ios"
    }
  }
}
```

---

## Web Security

### DAST Automation

Automated Dynamic Application Security Testing using browser-based scanning and traditional tools.

**Capabilities:**
- Blackbox and greybox (authenticated) testing
- Intelligent browser-based crawling with JavaScript execution
- Multi-domain parallel scanning
- XSS, CSRF, SQLi, SSRF, IDOR, auth bypass detection
- Integration with Nuclei, ZAP, Burp Suite, SQLMap

**Trigger phrases:** `scan domain for vulnerabilities`, `run DAST on`, `automated security scan`, `web penetration test`

**Tools:** Playwright MCP, Nuclei, OWASP ZAP, Burp Suite, SQLMap

---

### API Security

REST and GraphQL API security testing based on OWASP API Security Top 10.

**Capabilities:**
- Authentication/authorization testing (BOLA, BFLA, broken auth)
- Injection testing (SQLi, NoSQLi, command injection)
- Mass assignment and SSRF detection
- Rate limiting and resource exhaustion testing
- GraphQL introspection and query depth attacks
- JWT and OAuth vulnerability testing

**Trigger phrases:** `test API security`, `scan REST API`, `GraphQL security assessment`, `OWASP API Top 10`

**Tools:** Burp Suite, Postman, graphql-cop, jwt_tool, Nuclei

---

## Cloud Security

### Cloud Security

Multi-cloud security assessment for AWS, GCP, and Azure environments.

**Capabilities:**
- IAM policy analysis and privilege escalation paths
- Storage security (S3, GCS, Azure Blob misconfigurations)
- Network security (VPC, security groups, firewall rules)
- Secrets management and key rotation assessment
- Compliance checking (CIS benchmarks, SOC2, PCI-DSS)
- Serverless security (Lambda, Cloud Functions)

**Trigger phrases:** `assess AWS security`, `audit GCP permissions`, `Azure security review`, `cloud misconfiguration scan`

**Tools:** ScoutSuite, Prowler, CloudSploit, Steampipe, cloud-nuke

---

### IaC Security

Infrastructure as Code security scanning for Terraform, CloudFormation, Kubernetes, and Helm.

**Capabilities:**
- Terraform security with Checkov, tfsec, Terrascan
- CloudFormation scanning with cfn-lint, cfn-nag
- Kubernetes manifest security with kubesec, kube-linter
- Helm chart security analysis
- ARM template scanning for Azure
- Policy-as-code with OPA/Conftest

**Trigger phrases:** `scan Terraform for security issues`, `check CloudFormation template`, `Kubernetes manifest security`, `IaC security audit`

**Tools:** Checkov, tfsec, Terrascan, KICS, kubesec, OPA/Conftest

---

### Container Security

Docker and Kubernetes security assessment including image scanning and cluster hardening.

**Capabilities:**
- Container image vulnerability scanning with Trivy, Grype
- SBOM generation with Syft
- Kubernetes cluster security with Kubescape, kube-bench
- Runtime threat detection with Falco
- Container escape and privilege escalation testing
- Network policy and RBAC analysis

**Trigger phrases:** `scan container image`, `Kubernetes security audit`, `check Docker security`, `cluster hardening assessment`

**Tools:** Trivy, Grype, Syft, Kubescape, kube-bench, kube-hunter, Falco

---

## Network Security

### Network Pentest

Internal network and Active Directory penetration testing.

**Capabilities:**
- Network reconnaissance with Nmap, Masscan
- Active Directory enumeration with BloodHound
- Credential attacks (Kerberoasting, AS-REP roasting, password spraying)
- Lateral movement (Pass-the-Hash, Pass-the-Ticket, DCOM, WMI)
- Privilege escalation (DCSync, delegation abuse, GPO attacks)
- Domain dominance (Golden/Silver tickets, skeleton key)

**Trigger phrases:** `internal network pentest`, `Active Directory assessment`, `enumerate domain`, `lateral movement testing`

**Tools:** Nmap, BloodHound, Impacket, CrackMapExec, Responder, Mimikatz, Rubeus

---

## Code Security

### SAST Orchestration

Static Application Security Testing orchestration with custom rule development.

**Capabilities:**
- Multi-tool scanning with Semgrep, CodeQL, Bandit
- Custom rule development (Semgrep YAML, CodeQL queries)
- Finding triage and false positive reduction
- CI/CD integration (GitHub Actions, GitLab CI)
- Language-specific scanning (gosec, Brakeman, ESLint security)
- SARIF output and result aggregation

**Trigger phrases:** `scan code for vulnerabilities`, `write Semgrep rule`, `triage SAST findings`, `static analysis setup`

**Tools:** Semgrep, CodeQL, Bandit, gosec, Brakeman, SpotBugs, ESLint

---

### SCA Security

Software Composition Analysis for dependency vulnerabilities and supply chain security.

**Capabilities:**
- SBOM generation (CycloneDX, SPDX formats)
- Multi-ecosystem scanning (npm, pip, Maven, Cargo, Go, Ruby, PHP)
- Vulnerability database correlation (NVD, OSV, GitHub Advisory)
- License compliance checking
- Dependency graph analysis and transitive vulnerability detection
- Supply chain attack detection

**Trigger phrases:** `scan dependencies`, `generate SBOM`, `check for vulnerable packages`, `license compliance audit`

**Tools:** Syft, Grype, Trivy, OWASP Dependency-Check, npm audit, pip-audit, Snyk

---

## AI/ML Security

### LLM Security

LLM and AI application security testing including prompt injection and guardrail testing.

**Capabilities:**
- Prompt injection testing (direct and indirect)
- Jailbreaking and guardrail bypass techniques
- System prompt extraction attacks
- RAG pipeline security assessment
- AI agent excessive agency testing
- OWASP LLM Top 10 coverage

**Trigger phrases:** `test LLM for prompt injection`, `jailbreak AI system`, `test AI guardrails`, `RAG security assessment`

**Tools:** Custom scripts, Garak, AI security testing frameworks

---

## Security Process

### Threat Modeling

Systematic threat identification using industry frameworks and methodologies.

**Capabilities:**
- STRIDE threat analysis (per element and per interaction)
- PASTA 7-stage methodology
- Attack Tree construction with AND/OR gates
- DREAD risk scoring
- Data Flow Diagram (DFD) creation
- Threat library and mitigation mapping

**Trigger phrases:** `threat model this system`, `STRIDE analysis`, `create attack tree`, `security architecture review`

**Tools:** Microsoft Threat Modeling Tool, OWASP Threat Dragon, draw.io

---

## Directory Structure

```
ai-security-arsenal/
├── skills/
│   ├── android-pentest/      # Mobile - Android security
│   ├── ios-pentest/          # Mobile - iOS security
│   ├── dast-automation/      # Web - Dynamic testing
│   ├── api-security/         # Web - API security
│   ├── cloud-security/       # Cloud - Multi-cloud assessment
│   ├── iac-security/         # Cloud - Infrastructure as Code
│   ├── container-security/   # Cloud - Docker/Kubernetes
│   ├── network-pentest/      # Network - Internal/AD testing
│   ├── sast-orchestration/   # Code - Static analysis
│   ├── sca-security/         # Code - Dependency scanning
│   ├── llm-security/         # AI/ML - LLM security
│   └── threat-modeling/      # Process - Threat analysis
└── README.md
```

## Quick Start

### Mobile Testing

```bash
# Android - Connect rooted device and start Frida
adb devices
adb shell "su -c '/data/local/tmp/frida-server -D &'"
# "pentest com.example.app"

# iOS - Connect jailbroken device
iproxy 2222 22
ssh -p 2222 root@localhost
# "pentest com.example.app"
```

### Web Testing

```bash
# DAST with Playwright MCP
# "scan https://target.com for vulnerabilities"

# API Security
# "test API security for https://api.target.com"
```

### Cloud/Infrastructure

```bash
# Cloud Security
aws configure  # or gcloud auth login
# "assess AWS security for account 123456789"

# IaC Security
# "scan Terraform in ./infrastructure for security issues"

# Container Security
# "scan container image nginx:latest"
```

### Code Analysis

```bash
# SAST
# "scan this codebase for vulnerabilities"

# SCA
# "check dependencies for vulnerabilities"
```

## Requirements

| Category | Skill | Key Requirements |
|----------|-------|------------------|
| Mobile | android-pentest | ADB, Frida, objection, rooted device, [Mobile MCP](https://github.com/mobile-next/mobile-mcp) (optional) |
| Mobile | ios-pentest | Frida, objection, jailbroken device, iproxy, [Mobile MCP](https://github.com/mobile-next/mobile-mcp) (optional) |
| Web | dast-automation | Playwright MCP, Nuclei, Python 3.8+ |
| Web | api-security | Burp Suite, Postman, jwt_tool |
| Cloud | cloud-security | Cloud CLI tools (aws, gcloud, az), ScoutSuite |
| Cloud | iac-security | Checkov, tfsec, Terrascan |
| Cloud | container-security | Trivy, Kubescape, kubectl |
| Network | network-pentest | Nmap, BloodHound, Impacket, CrackMapExec |
| Code | sast-orchestration | Semgrep, Bandit, CodeQL CLI |
| Code | sca-security | Syft, Grype, language package managers |
| AI/ML | llm-security | Python 3.8+, target LLM API access |
| Process | threat-modeling | Draw.io or Threat Dragon (optional) |

## Usage with Coding Agents

These skills are designed to work with AI coding agents that support skill/instruction systems. Invoke via natural language:

```
You: pentest the banking app com.megabank.mobile
Agent: [Executes android-pentest - spawns with Frida, bypasses SSL, extracts data...]

You: scan our AWS account for security misconfigurations
Agent: [Executes cloud-security - runs ScoutSuite, analyzes IAM, checks S3...]

You: check this codebase for vulnerabilities
Agent: [Executes sast-orchestration - runs Semgrep, Bandit, aggregates findings...]

You: threat model the payment processing system
Agent: [Executes threat-modeling - creates DFD, applies STRIDE, generates report...]
```

**Compatible with:** Claude Code, Codex CLI, OpenCode, Aider, and other agents supporting markdown-based skill definitions.

## License

For authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only. Always obtain proper authorization before testing.
