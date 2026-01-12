# AI Security Arsenal

A collection of Claude Code skills for automated security testing and penetration testing workflows.

## Skills

### [Android Pentest](skills/android-pentest/SKILL.md)

Comprehensive Android mobile application penetration testing with full ADB shell access to rooted devices.

**Capabilities:**
- Static & dynamic analysis of Android applications
- Runtime manipulation with Frida (SSL pinning bypass, root detection bypass, crypto hooks)
- OWASP MASTG compliance testing
- Data extraction (databases, SharedPreferences, storage)
- Component fuzzing (activities, services, content providers, broadcast receivers)
- Automated reporting with customizable templates

**Trigger phrases:**
- "pentest this Android app"
- "bypass SSL pinning on [app]"
- "extract data from [app]"
- "MASTG testing for [app]"

**Prerequisites:** ADB, Frida, rooted device/emulator, Burp Suite

---

### [DAST Automation](skills/dast-automation/SKILL.md)

Automated Dynamic Application Security Testing using Playwright MCP for browser-based security scanning.

**Capabilities:**
- Blackbox testing (unauthenticated) and Greybox testing (authenticated)
- Intelligent browser-based crawling with JavaScript execution
- Multi-domain parallel scanning
- Vulnerability testing: XSS, CSRF, SQLi, SSRF, IDOR, auth bypass, business logic flaws
- Integration with Nuclei, Nikto, SQLMap, and other tools
- Comprehensive HTML/JSON/PDF reporting
- CI/CD integration support

**Trigger phrases:**
- "scan this domain for vulnerabilities"
- "run DAST on example.com"
- "perform blackbox/greybox security scan"
- "automated penetration test"

**Prerequisites:** Playwright MCP, Python 3, Nuclei (optional), SQLMap (optional)

---

## Directory Structure

```
ai-security-arsenal/
├── skills/
│   ├── android-pentest/
│   │   ├── SKILL.md              # Main skill documentation
│   │   ├── scripts/              # Frida scripts, Python tools
│   │   ├── methodology/          # Testing methodology guides
│   │   ├── checklists/           # OWASP MASTG checklists
│   │   ├── templates/            # Report templates
│   │   ├── payloads/             # Injection payloads
│   │   ├── workflows/            # Automated assessment workflows
│   │   ├── reporting/            # Report generation tools
│   │   └── setup/                # Environment setup (Docker, Magisk, etc.)
│   │
│   └── dast-automation/
│       ├── SKILL.md              # Main skill documentation
│       ├── scripts/              # Scanner, orchestrator, crawler
│       ├── references/           # Methodology, attack patterns
│       └── assets/               # Config, payloads, templates
│
└── README.md
```

## Quick Start

### Android Pentest

```bash
# 1. Connect rooted device
adb devices

# 2. Start Frida server on device
adb shell "su -c '/data/local/tmp/frida-server -D &'"

# 3. Use skill in Claude Code
# "pentest com.example.app"
```

### DAST Automation

```bash
# 1. Ensure Playwright MCP is configured
# 2. Use skill in Claude Code
# "scan https://target.com for vulnerabilities"
```

## Usage with Claude Code

These skills are designed to work with Claude Code's skill system. Reference them in your Claude configuration or invoke directly via natural language.

**Example interactions:**

```
You: pentest the banking app com.megabank.mobile
Claude: [Executes android-pentest skill - spawns app with Frida, bypasses SSL, extracts data...]

You: run DAST on staging.example.com with credentials admin / password123
Claude: [Executes dast-automation skill - authenticated crawl, vulnerability testing, report generation...]
```

## Requirements

| Skill | Requirements |
|-------|--------------|
| android-pentest | ADB, Frida, Objection, apktool, jadx, rooted device/emulator |
| dast-automation | Playwright MCP, Python 3.8+, Nuclei (optional), nmap (optional) |

## License

For authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only.
