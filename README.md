# Lui

**Agentic Security Auditor for Developers**

Lui is a security auditing CLI that inspects software projects, web applications, APIs, dependencies, configuration, authentication/authorization implementation, source code, infrastructure files, containers, CI/CD configuration, and optionally an explicitly authorized running application.

Lui identifies security risks, vulnerabilities, security misconfigurations, exposed secrets, dependency problems, insecure coding patterns, authentication problems, authorization problems, API problems, and other security weaknesses. It presents findings in a professional cybersecurity-report style directly in the terminal.

---

## Dynamic by Design

Lui is **not** a static regex scanner. It combines pattern-based detection with a dynamic analysis engine that adapts to *your* project:

### Dynamic Detection Layers

```
Static foundation (fast, always on)
├── Regex pattern rules (60+ across 10 scanners)
├── Hardcoded vulnerability database (50+ known CVEs)
└── Endpoint discovery across 5 frameworks

Dynamic adaptation layer (context-aware)
├── Technology-adaptive rules
│   ├── React detected → elevate XSS severity
│   ├── Express/Node detected → elevate SQLi + SSRF confidence
│   ├── Django/Flask detected → elevate command injection rules
│   ├── Vue/Angular/Svelte detected → add dangerous HTML binding rules
│   └── Mobile detected → add insecure storage rules 
├── Deep-scan dynamic rules
│   ├── SAST-DYN-001  Insecure deserialization
│   ├── SAST-DYN-002  Open redirect
│   ├── SAST-DYN-003  Template injection
│   └── SAST-DYN-004  Dangerous HTML binding
├── Context-aware secret confidence
│   ├── Surrounding code signals (real usage vs examples)
│   ├── Sanitization proximity detection
│   └── Environment-variable reference recognition

Live intelligence layer (opt-in, LLM-powered)
├── LLM finding validation → confirms or flags false positives
├── LLM confidence adjustment → upgrades/downgrades finding confidence
├── LLM enriched descriptions → plain-language exploit scenarios
├── LLM remediation steps → concrete code-level fixes
├── LLM contextual "lui ask" → conversational security assistance
└── NVD real-time CVE lookup → fresh vulnerabilities beyond local DB
```

The key difference: Lui *understands what it scans* — it detects the technology stack, adapts its rules, traces data flows, validates its own findings, and explains the *why* behind every detection.

---

## Features

- **Agentic analysis** - discards the project, detects the technology stack, then runs only relevant security checks
- **Dynamic rule adaptation** - rules are elevated/downgraded/modified based on detected frameworks and languages
- **LLM-powered validation** - when AI is enabled, every finding is validated, enriched, and explained by an LLM (never falsifies real issues)
- **Real-time CVE intelligence** - optional NVD API integration fetches vulnerabilities beyond the local database
- **Comprehensive scanning** - secrets, dependencies, SAST, authentication, authorization, APIs, configuration, Docker, CI/CD
- **Confidence-based findings** - distinguishes confirmed vulnerabilities from potential and heuristic detections
- **Evidence engine** - explains *why* each finding was raised with data-flow visualization and sanitization analysis
- **Security context graph** - connects inputs, endpoints, storage, and outputs to reveal attack paths
- **Attack surface mapping** - `lui map` shows public, authenticated, and admin endpoints plus external services
- **Risk prioritization** - P0-P3 priorities based on severity, confidence, exposure, reachability, and exploitability
- **API endpoint discovery** - automatically discovers and catalogs API routes with a security matrix
- **Dependency graph** - `lui deps` visualizes dependency relationships and vulnerable paths
- **Security regression detection** - score-aware `lui diff` catches security regressions between scans
- **Secret rotation guidance** - `lui fix` includes step-by-step credential rotation playbooks
- **Security incident indicators** - `lui investigate` looks for signs of suspicious activity (never claims compromise)
- **Regression test generation** - `lui test <id>` generates safe security regression tests
- **Fix verification** - `lui verify <id>` re-scans and confirms whether a fix worked
- **Vulnerability lifecycle** - track findings through NEW → CONFIRMED → FIXED → VERIFIED states
- **Security profiles** - presets for startup, webapp, api, enterprise, ci, mobile, docker
- **Policy engine** - `.lui-policy.yml` for customizable fail/warn rules
- **Plugin architecture** - `LuiPlugin` and `PluginRegistry` for scanner and hook extensions
- **"Ask Lui" assistant** - `lui ask` answers security questions conversationally, powered by LLM when enabled
- **Developer-friendly output** - `lui scan --developer` shows unsafe code with suggested fixes
- **Incremental scanning** - `lui scan --incremental` only scans files changed since the last commit
- **Security dashboard** - `lui-report.html` is a full dashboard with trends, risk areas, and matrices
- **MCP integration** - ready-to-use MCP server tools for AI assistant integration
- **Deterministic scoring** - a documented, reproducible security score from 0-100
- **Attack-chain correlation** - identifies combinations of weaknesses that form exploit chains
- **Professional reports** - terminal, JSON, Markdown, and HTML output
- **CI/CD integration** - baseline and diff support with configurable exit codes
- **Privacy-first** - local-only mode, secret redaction, no source code sent to AI without explicit consent
- **False-positive control** - context-aware analysis to reduce noise

## Installation

```bash
npm install -g lui-security
```

Or for development:

```bash
git clone <repository>
cd lui
npm install
npm run build
npm link
```

## Quick Start

```bash
cd my-project
lui scan
```

## Commands

| Command | Description |
|---------|-------------|
| `lui scan [path]` | Scan a project for security vulnerabilities |
| `lui scan --quick` | Quick scan (secrets, dependencies, basic SAST) |
| `lui scan --deep` | Deep scan (all scanners + dynamic rules + data flow analysis) |
| `lui scan --category <cat>` | Scan a specific category |
| `lui scan --url <url>` | Scan a running web application (requires authorization) |
| `lui scan --format json` | Output results as JSON |
| `lui explain <id>` | Explain a specific security finding (with data flow + AI analysis when enabled) |
| `lui fix <id>` | Show remediation guidance (including secret rotation playbooks) |
| `lui report` | Generate a report |
| `lui baseline` | Save current results as a baseline |
| `lui diff` | Compare current scan with baseline |
| `lui ignore <id>` | Suppress a finding |
| `lui config` | Show configuration |
| `lui map` | Show attack surface map |
| `lui investigate` | Check for security incident indicators |
| `lui verify <id>` | Re-scan and verify a fix |
| `lui test <id>` | Generate a security regression test |
| `lui deps` | Show dependency graph with vulnerable paths |
| `lui lifecycle <id> <status>` | Update finding lifecycle status |
| `lui ask [question]` | Ask Lui security questions (LLM-powered when enabled) |
| `lui profiles` | List security profiles |
| `lui secrets history` | Guidance for checking git history |
| `lui --version` | Show version |
| `lui --help` | Show help |

## Scan Categories

```bash
lui scan --category secrets
lui scan --category dependencies
lui scan --category code
lui scan --category auth
lui scan --category authorization
lui scan --category api
lui scan --category configuration
lui scan --category docker
lui scan --category cicd
lui scan --category web
lui scan --category api-discovery
```

## Configuration

Create a `.lui.yml` file in your project root:

```yaml
project:
  name: my-project

scan:
  depth: deep

exclude:
  - node_modules
  - vendor
  - dist
  - build

security:
  secrets: true
  dependencies: true
  sast: true
  auth: true
  authorization: true
  api: true
  docker: true
  cicd: true
  dynamic_cve: true        # fetch fresh CVEs from NVD API (opt-in)

privacy:
  local_only: true
  redact_secrets: true

policy:
  fail_on: high
```

### Enabling Dynamic (LLM) Analysis

```yaml
ai:
  enabled: true
  provider: openai        # openai | anthropic | ollama | openai-compatible
  model: gpt-4o-mini
  apiKey: sk-...          # optional for local ollama

privacy:
  redact_secrets: true
  send_source_to_ai: false
```

When AI is enabled, Lui adds a **dynamic analysis phase** to the pipeline:

1. **LLM validation** — each finding is analyzed to determine if it's a real vulnerability
2. **Confidence adjustment** — LLM can upgrade or downgrade finding confidence
3. **Enriched explanations** — plain-language descriptions of the exploit scenario
4. **Code-level fixes** — concrete remediation suggestions based on the actual source
5. **Contextual answers** — `lui ask` becomes conversational

The LLM layer *never* removes real findings and *never* invents new ones. It runs strictly as a validation/enrichment layer on top of the deterministic scanners.

### Enabling Real-Time CVE Lookup

```yaml
security:
  dynamic_cve: true
```

This queries the NVD API for fresh vulnerability data beyond the bundled database. Results are cached locally for 24 hours. If the NVD API is unreachable, Lui falls back to the bundled database without error.

## Dynamic Rule Adaptation

Lui's SAST scanner doesn't just run a fixed rule table. It adapts rules based on the detected technology stack:

| Detected Technology | Dynamic Behavior |
|---------------------|------------------|
| React | `dangerouslySetInnerHTML` elevated to HIGH |
| Express / Node.js | SQL injection + SSRF confidence upgraded |
| Django / Flask | Command injection rules elevated |
| Vue / Angular / Svelte | Added HTML binding XSS rules |
| React Native / Flutter | Added insecure storage rules |
| Deep scan mode | Adds deserialization, open redirect, template injection rules |

Deep scans (`lui scan --deep`) also inject dynamic cross-cutting rules that aren't in the static table.

## Scanner Architecture

```
Scanner
 ├── name
 ├── category
 ├── description
 ├── supported technologies
 └── scan(context)
```

Every scanner implements a common interface. The agent pipeline is:

```
Discovery → Planning → Scanning → Correlation → Risk Assessment → Dynamic Validation → Remediation → Reporting
```

### Scanners

| Scanner | Category | Detects |
|---------|----------|---------|
| SecretScanner | secrets | API keys, tokens, private keys, credentials (context-aware confidence) |
| DependencyScanner | dependencies | Known vulnerable packages (local DB + optional NVD), unpinned dependencies |
| SASTScanner | sast | SQL injection, XSS, command injection, path traversal, weak crypto (technology-adaptive) |
| AuthScanner | auth | Weak password hashing, insecure token storage, JWT issues |
| AuthorizationScanner | authorization | IDOR/BOLA, missing authorization, admin route exposure |
| APIScanner | api | CORS issues, missing rate limiting, verbose errors |
| ConfigScanner | configuration | Exposed secrets in env files, missing gitignore, debug mode |
| DockerScanner | docker | Root containers, privileged mode, secrets in images |
| CICDScanner | cicd | Unsafe workflows, excessive permissions, unpinned actions |
| ActiveWebScanner | web | Security headers, cookie flags, CORS exposure on a running app |

## Active Web Scanning

Scan a running application (requires explicit authorization):

```bash
lui scan --url https://your-app.example.com
lui scan ./project --url http://localhost:3000 --category web
```

The active scanner only issues safe, read-only `GET` requests and checks:

- Missing security headers (HSTS, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, CSP, `Referrer-Policy`)
- Cookie security attributes (`HttpOnly`, `Secure`, `SameSite`)
- Permissive or reflective CORS configuration
- Server/technology header disclosure

## LLM/AI Correlation

Opt-in correlation is disabled by default and never blocks or alters real findings. Enable it in `.lui.yml`:

```yaml
ai:
  enabled: true
  provider: openai        # openai | anthropic | ollama | openai-compatible
  model: gpt-4o-mini
  apiKey: sk-...          # optional for local ollama

privacy:
  redact_secrets: true
  send_source_to_ai: false
```

The summarized analysis (remediation plan, root-cause, attack-chain correlations) is stored in the scan result under `metadata.aiAnalysis`. If the provider is unreachable or misconfigured the scan continues normally.

## Severity System

| Severity | Meaning |
|----------|---------|
| CRITICAL | Immediate action required |
| HIGH | Serious vulnerability, fix as soon as possible |
| MEDIUM | Moderate risk, should be reviewed |
| LOW | Minor issue, consider addressing |
| INFO | Informational, best practices |

Every finding also has a **confidence** level:

| Confidence | Meaning |
|------------|---------|
| HIGH | Strong evidence for the finding |
| MEDIUM | Likely but requires review |
| LOW | Heuristic detection, manual review recommended |

Confidence is **dynamic** — it starts from the rule's base value and is adjusted by:
- Nearby user-input sources (`req.body`, `req.query`, etc.)
- Nearby sanitization (`sanitize`, `escape`, `validate`)
- Confirmed tainted data flows (source → sink)
- LLM validation (when enabled)
- Surrounding code context in secret detection

## Security Score

| Score | Rating |
|-------|--------|
| 85-100 | Strong |
| 70-84 | Good |
| 50-69 | Needs Improvement |
| 30-49 | Poor |
| 0-29 | Critical |

The score is calculated deterministically: each finding deducts points based on severity and confidence.

## Privacy

Lui is designed with privacy in mind:

- Never uploads source code without explicit user configuration
- Never sends secrets to an LLM
- Redacts secrets before any external analysis
- Provides local-only mode
- Clearly indicates when external AI is being used (`metadata.aiAnalysis.enabled`)
- Never stores credentials in logs
- Never prints complete secrets

## Safe Use Policy

Lui is designed for systems you own or are explicitly authorized to assess.

- Scans local projects freely
- Requires explicit authorization for active scans on external targets
- Avoids destructive testing, brute force, credential attacks, persistence, stealth, and exploitation of third-party systems

## CI/CD Integration

```yaml
# .lui.yml
policy:
  fail_on: high
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No blocking security issues |
| 1 | Security policy violation |
| 2 | Scanner or runtime error |

Example GitHub Action:

```yaml
- name: Security Scan
  run: |
    npm install -g lui-security
    lui scan . --format json
```

## Development Setup

```bash
npm install
npm run build
npm test
npm link
lui --version
```

## Testing

```bash
npm test
```

The test suite covers all major scanners including positive, negative, and false-positive tests using synthetic fixtures.

## Working with Findings

```bash
lui scan                          # run an initial scan
lui explain LUI-SEC-001           # why a finding was raised (data flow + AI analysis)
lui fix LUI-SEC-001               # how to remediate it (rotation playbooks)
lui baseline                      # save current state as baseline
lui diff                          # compare against the baseline
lui verify LUI-CODE-001           # re-scan and verify a fix
lui test LUI-CODE-001             # generate a regression test
lui ask "What should I fix first?"  # conversational Q&A (LLM-powered when enabled)
lui ignore LUI-API-301            # suppress a finding (requires a reason)
lui report --format html          # generate a report
```

## Reports

```bash
lui report --format html         # writes lui-report.html
lui report --format json         # writes lui-report.json
lui report --format markdown     # writes SECURITY-REPORT.md
```

### Generated files and `.luiignore`

- `.luiignore` — JSON map of ignored finding IDs to reasons (created via `lui ignore <id>`)
- `lui-report.html` / `lui-report.json` / `SECURITY-REPORT.md` — generated reports
- `.lui-last-scan.json` — cache of the most recent scan (used by `explain`, `report`, `diff`, `baseline`)
- `.lui-baseline.json` — baseline snapshot for `lui diff`

Add these to your project's `.gitignore`:

```gitignore
.lui-last-scan.json
.lui-baseline.json
.luiignore
lui-report.html
lui-report.json
SECURITY-REPORT.md
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `lui: command not found` | Re-run `npm link` (or reinstall with `npm install -g lui-security`) |
| Build errors | Ensure `npm install` completed; run `npm run build` |
| Scan too slow | Use `lui scan --quick` or expand `exclude` in `.lui.yml` |
| `lui` not running after source edits | Rebuild with `npm run build` |
| `lui ask` gives static answers | Enable AI in `.lui.yml` (`ai.enabled: true`) for dynamic responses |
| Dependency scan detecting too little | Enable `security.dynamic_cve: true` for NVD API lookups |

## Roadmap

- [x] Core scanner engine
- [x] Secret detection (context-aware)
- [x] Dependency scanning (local DB + NVD API)
- [x] SAST checks (technology-adaptive)
- [x] Authentication analysis
- [x] Authorization analysis
- [x] API security
- [x] Docker security
- [x] CI/CD security
- [x] Config scanning
- [x] Terminal, JSON, Markdown, HTML reports
- [x] LLM/AI correlation (opt-in, privacy-aware)
- [x] LLM finding validation and enrichment
- [x] LLM-powered `lui ask`
- [x] Active web scanning
- [x] Data flow analysis
- [x] Header/cookie scanning of running apps
- [x] Expanded vulnerability database
- [x] Dynamic technology-adaptive rule selection
- [x] Real-time NVD CVE lookup (opt-in)

## License

MIT
