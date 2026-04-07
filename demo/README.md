# Demo Scenarios

## Clean App
```bash
cd demo/app && npm install
python tools/soc-scan.py demo/app/
# Expected: All green, no signals
```

## Scenario 1: Malicious Dependency Injection
Simulates the March 2026 Axios attack (unexpected dependency added).
```bash
cp demo/scenarios/malicious-dep/package.json demo/app/package.json
python tools/soc-scan.py demo/app/
# Expected: SBOM diff flags plain-crypto-js, AI triage says AUTO_BLOCK
```

## Scenario 2: Leaked Secrets
Simulates leaked API keys in code and MCP configs.
```bash
cp demo/scenarios/leaked-secret/.env demo/app/.env
cp demo/scenarios/leaked-secret/mcp-config.json demo/app/mcp-config.json
python tools/soc-scan.py demo/app/
# Expected: Gitleaks flags all planted secrets, AI triage says ALERT_HUMAN
```

## Scenario 3: Vulnerable Dependencies
Simulates known CVEs in dependency tree.
```bash
cp demo/scenarios/vuln-dep/package.json demo/app/package.json
python tools/soc-scan.py demo/app/
# Expected: Grype flags lodash CVE, AI triage says ALERT_HUMAN
```

## Reset
```bash
git checkout demo/app/
```
