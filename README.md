# autonomous-soc

**An open-source Autonomous Security Operations Center for software supply chains.**

One GitHub Action. Six security layers. AI-powered triage. Plug and play.

```yaml
# Add to .github/workflows/soc.yml
- uses: himanshuramchandani/autonomous-soc@v1
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Why This Exists

In March 2026, one stolen token cascaded through five package ecosystems in 12 days, compromising Trivy, LiteLLM (95M downloads/month), Axios (83M downloads/week), OpenAI Codex, and Claude Code. Every attack had a defense that would have caught it. Nobody was running those defenses together.

This project integrates six open-source security tools into a single CI/CD pipeline with AI-powered signal correlation and automated response.

## What It Does

On every push and pull request:

| Layer | Tool | What It Catches |
|---|---|---|
| **SBOM Diff** | [Syft](https://github.com/anchore/syft) | Unexpected dependency additions or changes |
| **Provenance** | `npm audit signatures` | Packages published without Sigstore provenance |
| **Runtime Monitoring** | [Harden-Runner](https://github.com/step-security/harden-runner) | Anomalous network calls, file modifications |
| **Vulnerability Scan** | [Grype](https://github.com/anchore/grype) | Known CVEs in your dependency tree |
| **Secret Scan** | [Gitleaks](https://github.com/gitleaks/gitleaks) | Leaked API keys, tokens, credentials |
| **AI Triage** | Claude API | Correlates all signals, determines severity, auto-remediates |

## Quick Start

### Option 1: GitHub Action (Recommended)

Create `.github/workflows/soc.yml`:

```yaml
name: Supply Chain SOC
on: [push, pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  soc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci --ignore-scripts
      - uses: himanshuramchandani/autonomous-soc@v1
        with:
          policy: moderate
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Option 2: Local Scan

```bash
git clone https://github.com/himanshuramchandani/autonomous-soc.git
cd autonomous-soc
pip install -r tools/requirements.txt
python tools/soc-scan.py /path/to/your/project
```

## Architecture

```
DETECT            →  ANALYZE         →  DECIDE        →  RESPOND
Syft (SBOM diff)     Grype (CVEs)      AI Agent         Block build
Harden-Runner        Signal             Policy           Pin version
npm audit sig        correlation        engine           Rotate keys
Gitleaks                                Human-loop       Alert team
```

All signals feed into `tools/ai-triage.py` which correlates them and outputs a verdict.

## AI provider (optional)

LLM triage uses **Anthropic** if `ANTHROPIC_API_KEY` is set; otherwise **Groq** if `GROQ_API_KEY` is set ([Groq console](https://console.groq.com) — free tier for development). If neither is set, the **policy engine** runs (no API cost).

Override order with `SOC_AI_PROVIDER`: `auto` (default), `anthropic`, or `groq`. Optional: `GROQ_MODEL` (default `llama-3.1-8b-instant`), `ANTHROPIC_MODEL`.

```yaml
env:
  GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
  # SOC_AI_PROVIDER: groq   # optional if you also set ANTHROPIC_API_KEY
```

## Policy Modes

| Mode | Auto-block | Alert | Use Case |
|---|---|---|---|
| `strict` | 2+ high signals | 1+ high | Production, regulated |
| `moderate` | 3+ high signals | 2+ high | Default |
| `audit` | Never | Never | Initial rollout |

## Demo Scenarios

```bash
# Clean (should pass)
python tools/soc-scan.py demo/app/

# Malicious dependency (simulates Axios attack)
cp demo/scenarios/malicious-dep/package.json demo/app/
python tools/soc-scan.py demo/app/

# Leaked secrets
cp demo/scenarios/leaked-secret/.env demo/app/
python tools/soc-scan.py demo/app/

# Vulnerable dependencies
cp demo/scenarios/vuln-dep/package.json demo/app/
python tools/soc-scan.py demo/app/
```

## How It Would Have Caught March 2026 Attacks

| Attack | Signals | SOC Verdict |
|---|---|---|
| **LiteLLM** | SBOM: `.pth` file, Grype: malicious payload | AUTO_BLOCK |
| **Axios** | SBOM: new dep, Provenance: missing, Runtime: C2 call | AUTO_BLOCK |
| **Claude Code** | SBOM: `.map` file in package | ALERT_HUMAN |

## References

- Article: "This Week Broke the Software Supply Chain"
- [Architecture docs](docs/architecture.md)
- DevOps Days Tokyo 2026 talk

## License

Apache 2.0
