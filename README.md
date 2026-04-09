# autonomous-soc

**An open-source Autonomous Security Operations Center for software supply chains in CI/CD.**

This repository ships a **composite GitHub Action** that runs multiple detection tools, merges their output into one **signal list**, and applies **AI-assisted triage** (with a **rule-based fallback** when no LLM API is available). It also writes **Markdown and JSON reports** and can optionally run **`npm audit fix`** for npm-based projects.

**Maintainer:** Himanshu Sangshetti · Related talk: **DevOps Days Tokyo 2026** (*The Autonomous SOC: AI-Driven Supply Chain Security and SBOM Remediation*).

---

## Why this exists

### The problem

Modern **AI and developer tools** (CLI agents, scanners in CI, dependency proxies) often hold **elevated credentials by design**: API keys, registry tokens, OAuth to source control. That is usually intentional, not a misconfiguration.

The industry has invested heavily in **“AI for the SOC”** (assistants that help analysts monitor production). There has been much less focus on the inverse: **treating the CI/CD pipeline and those tools themselves** with SOC-style discipline: continuous detection, correlation, and a clear **allow / escalate / block** decision.

### What March 2026 illustrated

In a short window, several high-impact **supply chain** incidents (including compromised tooling, hijacked packages, and leaked or abused credentials) showed that **individual defenses already existed** (runtime egress visibility, SBOM drift, provenance signals, CVE data, secret scanning). The practical gap for many teams is **running them together** and **making sense of the combined output** under time pressure.

### What we are building

**autonomous-soc** is an **integration layer**: one workflow hook that runs a **consistent stack** (Syft, Grype, Gitleaks, npm provenance checks, plus your own **SBOM diff** and **signal collector**), then **one triage step** that outputs:

- **`AUTO_BLOCK`** – fail the job (configurable)
- **`ALERT_HUMAN`** – escalate for review (configurable failure)
- **`ALLOW`** – no blocking signals under policy

It is **Apache 2.0** and intended as an alternative to stitching six separate vendors or scripts yourself, or to enterprise-only “agentic” products that are not open source.

---

## What you get (the six layers)

Place **StepSecurity Harden-Runner** in your workflow **before** checkout if you want **runtime / egress** monitoring; the composite action itself installs and runs the tools below against your repository (configure **`working-directory`** when your app is not the repo root).

| Layer | Mechanism | What it answers |
| --- | --- | --- |
| 1. Runtime (workflow step) | [Harden-Runner](https://github.com/step-security/harden-runner) | What is this job doing on the network and the runner? |
| 2. SBOM + diff | [Syft](https://github.com/anchore/syft) + `tools/sbom-diff.py` | What packages are present, and **what changed** vs a baseline? |
| 3. Provenance | `npm audit signatures` | Do installs report **signature / provenance** issues for npm packages? |
| 4. Vulnerabilities | [Grype](https://github.com/anchore/grype) on the SBOM | Which components match **known CVEs / advisories**? |
| 5. Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | Are there **tokens or keys** in the scanned tree? |
| 6. Triage | `tools/ai-triage.py` (Anthropic **or** Groq **or** policy only) | Given **all signals**, what is the **single verdict** and **recommended next steps**? |

**Signal flow:** scanners write or append **JSON signals**; `tools/collect-signals.sh` normalizes Grype, Gitleaks, and provenance text into **`/tmp/soc-signals.json`**. Triage reads that file and writes **`/tmp/soc-verdict.json`** plus **SOC reports** (see below).

---

## How to use it (GitHub Actions)

Replace **`OWNER`** with your GitHub user or organization name (the account that publishes the action).

```yaml
name: Supply chain SOC
on: [push, pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  soc:
    runs-on: ubuntu-latest
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@5ef0c079ce82195b2a36a210272d6b661572d83e
        with:
          egress-policy: audit

      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies (example)
        run: npm ci --ignore-scripts
        working-directory: .

      - uses: OWNER/autonomous-soc@v1
        with:
          policy: moderate
          fail-on-block: 'true'
          working-directory: .
          apply-npm-audit-fix: 'false'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
```

**Secrets:** set **`ANTHROPIC_API_KEY`** and/or **`GROQ_API_KEY`** in the repository secrets. If neither is set, triage uses the **built-in policy engine** only (no LLM cost).

**Inputs (composite action):** see `action.yml` for full list. Common ones: `policy` (`strict` | `moderate` | `audit`), `skip-ai`, `sbom-format`, `fail-on-block`, `working-directory`, `apply-npm-audit-fix`.

---

## Reports and optional npm remediation

After triage, the action writes:

- **`/tmp/soc-report.md`** – human-readable verdict, correlation, remediation bullets, signal table, capped **Grype HIGH/CRITICAL** table (default **75** rows; set **`SOC_REPORT_GRYPE_MAX`** to change).
- **`/tmp/soc-report.json`** – same content in structured form for automation.

On GitHub Actions, the Markdown is also **appended to the job summary** (`GITHUB_STEP_SUMMARY`). Override output paths with **`SOC_REPORT_MD`** and **`SOC_REPORT_JSON`** if needed.

**Optional `npm audit fix`:** set **`apply-npm-audit-fix: 'true'`** and **`working-directory`** to your Node app. This runs **`npm audit fix --ignore-scripts`** after triage (even when triage fails the job), with **`continue-on-error`**. It only fixes what npm can fix automatically; large CVE backlogs still need **policy, prioritization, Dependabot/Renovate, and manual review**.

This repository’s **Autonomous SOC Pipeline** workflow uploads **`soc-report.md`** and **`soc-report.json`** as **workflow artifacts** on every run (`if: always()`).

---

## AI providers

- **`auto` (default):** use Anthropic if **`ANTHROPIC_API_KEY`** is set, else Groq if **`GROQ_API_KEY`** is set, else policy engine.
- Override with **`SOC_AI_PROVIDER`:** `anthropic` | `groq` | `auto`.
- Optional: **`GROQ_MODEL`** (default `llama-3.1-8b-instant`), **`ANTHROPIC_MODEL`**.

Groq keys: [console.groq.com](https://console.groq.com) (useful for development tiers).

---

## Policy modes

| Mode | Auto-block | Alert | Typical use |
| --- | --- | --- | --- |
| `strict` | 2+ high signals | 1+ high | Production, regulated |
| `moderate` | 3+ high signals | 2+ high | Default |
| `audit` | Never | Never | Rollout: observe only |

In **`strict`**, the LLM cannot **ALLOW** when HIGH/CRITICAL signals remain (enforced in code).

---

## Local scan (optional)

Requires **Syft**, **Grype**, and **Gitleaks** on your `PATH`.

```bash
git clone https://github.com/OWNER/autonomous-soc.git
cd autonomous-soc
pip install -r tools/requirements.txt
python tools/soc-scan.py /path/to/your/project
```

Use **`--skip-ai`** to force policy-only triage.

---

## Workflows in this repository

| Workflow | Purpose |
| --- | --- |
| **Autonomous SOC Pipeline** | Full demo: Harden-Runner, Node, optional **scenarios**, safe install, composite action, **artifact reports**. |
| **Naked Pipeline (Zero Protection)** | Baseline: checkout, Node, **`npm install`** (scripts allowed), test — no SOC (for before/after talks). |
| **Layer 1 … Layer 6** | Progressive demos: add one defense at a time (runtime only through full triage). |

**Manual runs:** **Actions** → choose workflow → **Run workflow**. Scenario dropdown (where present): `clean`, `malicious-dep`, `leaked-secret`, `vuln-dep`.

---

## Demo scenarios (local)

```bash
python tools/soc-scan.py demo/app/

cp demo/scenarios/malicious-dep/package.json demo/app/package.json
python tools/soc-scan.py demo/app/

cp demo/scenarios/leaked-secret/.env demo/app/
python tools/soc-scan.py demo/app/

cp demo/scenarios/vuln-dep/package.json demo/app/package.json
python tools/soc-scan.py demo/app/
```

Reset with `git checkout demo/app/` when finished.

---

## How this maps to known attack patterns (illustrative)

| Scenario | Example signals | Typical verdict |
| --- | --- | --- |
| Unexpected dependency + provenance/runtime context | SBOM diff, provenance text, optional egress | **AUTO_BLOCK** / **ALERT_HUMAN** |
| Known-malicious or suspicious artifacts | SBOM flags (e.g. suspicious extensions) | **AUTO_BLOCK** |
| CVE concentration on one package | Multiple Grype HIGH/CRITICAL on same component | **ALERT_HUMAN** or **AUTO_BLOCK** (policy) |
| Secrets in tree | Gitleaks | **ALERT_HUMAN** / **AUTO_BLOCK** |

Exact outcomes depend on **policy** and **signal set**.

---

## Roadmap (short)

- PR comments with verdict, SARIF for the Security tab, container image scanning, multi-CI adapters, stronger automation (e.g. Dependabot-style PRs) where safe.

---

## Primary references (March 2026 supply chain context)

- Wiz (Trivy / TeamPCP): [wiz.io blog](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)  
- Snyk (LiteLLM): [snyk.io articles](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)  
- StepSecurity (Axios): [stepsecurity.io blog](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)  
- Socket (Axios): [socket.dev blog](https://socket.dev/blog/axios-npm-package-compromised)  
- GitGuardian (secrets / incident response): [blog.gitguardian.com](https://blog.gitguardian.com/)  

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2026 Himanshu Sangshetti.
