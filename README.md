# Lui

**Agentic Security Auditor for Developers**

Lui is a security auditing CLI that inspects software projects, web applications, APIs, dependencies, configuration, authentication/authorization implementation, source code, infrastructure files, containers, CI/CD configuration, and optionally an explicitly authorized running application.

Lui identifies security risks, vulnerabilities, security misconfigurations, exposed secrets, dependency problems, insecure coding patterns, authentication problems, authorization problems, API problems, and other security weaknesses. It presents findings in a professional cybersecurity-report style directly in the terminal.

---

## Features

- **Agentic analysis** - discards the project, detects the technology stack, then runs only relevant security checks
- **Comprehensive scanning** - secrets, dependencies, SAST, authentication, authorization, APIs, configuration, Docker, CI/CD
- **Confidence-based findings** - distinguishes confirmed vulnerabilities from potential and heuristic detections
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
| `lui scan --deep` | Deep scan (all scanners) |
| `lui scan --category <cat>` | Scan a specific category |
| `lui scan --url <url>` | Scan a running web application (requires authorization) |
| `lui scan --format json` | Output results as JSON |
| `lui explain <id>` | Explain a specific security finding |
| `lui fix <id>` | Show remediation guidance |
| `lui report` | Generate a report |
| `lui baseline` | Save current results as a baseline |
| `lui diff` | Compare current scan with baseline |
| `lui ignore <id>` | Suppress a finding |
| `lui config` | Show configuration |
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

privacy:
  local_only: true
  redact_secrets: true

policy:
  fail_on: high
```

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
Discovery → Planning → Scanning → Correlation → Risk Assessment → Remediation → Reporting
```

### Scanners

| Scanner | Category | Detects |
|---------|----------|---------|
| SecretScanner | secrets | API keys, tokens, private keys, credentials |
| DependencyScanner | dependencies | Known vulnerable packages, unpinned dependencies |
| SASTScanner | sast | SQL injection, XSS, command injection, path traversal, weak crypto |
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
lui explain LUI-SEC-001           # why a finding was raised
lui fix LUI-SEC-001               # how to remediate it
lui baseline                      # save current state as baseline
lui diff                          # compare against the baseline
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

## Roadmap

- [x] Core scanner engine
- [x] Secret detection
- [x] Dependency scanning
- [x] SAST checks
- [x] Authentication analysis
- [x] Authorization analysis
- [x] API security
- [x] Docker security
- [x] CI/CD security
- [x] Config scanning
- [x] Terminal, JSON, Markdown, HTML reports
- [x] LLM/AI correlation (opt-in, privacy-aware)
- [x] Active web scanning
- [x] Data flow analysis
- [x] Header/cookie scanning of running apps
- [x] Expanded vulnerability database

## License

MIT