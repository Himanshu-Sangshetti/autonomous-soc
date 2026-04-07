#!/usr/bin/env bash
# autonomous-soc: Signal Collector
# Normalizes outputs from Grype, Gitleaks, npm audit signatures into shared signal format.
set -euo pipefail

SIGNALS_FILE="${SIGNALS_FILE:-/tmp/soc-signals.json}"
[ ! -f "$SIGNALS_FILE" ] && echo "[]" > "$SIGNALS_FILE"

append_signal() {
    python3 -c "
import json, sys
sig = {'source':'$4','type':'$1','severity':'$2','package':'$3','detail':'''$5''','timestamp':'$(date -u +%Y-%m-%dT%H:%M:%SZ)'}
with open('$SIGNALS_FILE') as f: sigs = json.load(f)
sigs.append(sig)
with open('$SIGNALS_FILE','w') as f: json.dump(sigs, f, indent=2)
" 2>/dev/null || true
}

# Grype
GRYPE_OUT="${GRYPE_OUTPUT:-/tmp/grype-output.json}"
if [ -f "$GRYPE_OUT" ]; then
    echo "[COLLECT] Processing Grype..."
    python3 -c "
import json
with open('$GRYPE_OUT') as f: data = json.load(f)
for m in data.get('matches',[]):
    v = m.get('vulnerability',{})
    a = m.get('artifact',{})
    sev = v.get('severity','').upper()
    if sev in ('HIGH','CRITICAL'):
        vid = v.get('id','?')
        pkg = f\"{a.get('name','?')}@{a.get('version','?')}\"
        fixed = ', '.join(x.get('version','') for x in v.get('fix',{}).get('versions',[]))
        detail = f'{vid} in {pkg}' + (f' (fix: {fixed})' if fixed else '')
        print(f'{sev}|{pkg}|{detail}')
" 2>/dev/null | while IFS='|' read -r sev pkg detail; do
        append_signal "vulnerability" "$sev" "$pkg" "grype" "$detail"
    done
fi

# Gitleaks
GL_OUT="${GITLEAKS_OUTPUT:-/tmp/gitleaks-output.json}"
if [ -f "$GL_OUT" ]; then
    echo "[COLLECT] Processing Gitleaks..."
    python3 -c "
import json
with open('$GL_OUT') as f: findings = json.load(f)
for f in (findings or []):
    rule = f.get('RuleID','unknown')
    desc = f.get('Description','Secret detected')
    file = f.get('File','?')
    line = f.get('StartLine',0)
    print(f'{rule}|{desc} in {file}:{line}')
" 2>/dev/null | while IFS='|' read -r rule detail; do
        append_signal "secret_detected" "HIGH" "$rule" "gitleaks" "$detail"
    done
fi

# Provenance
PROV_OUT="${PROVENANCE_OUTPUT:-/tmp/provenance-output.txt}"
if [ -f "$PROV_OUT" ]; then
    echo "[COLLECT] Processing provenance..."
    if grep -qi "missing\|invalid\|no signature\|failed" "$PROV_OUT" 2>/dev/null; then
        append_signal "provenance_missing" "HIGH" "npm-packages" "npm-audit-signatures" \
            "One or more packages missing Sigstore provenance"
    fi
fi

COUNT=$(python3 -c "import json; print(len(json.load(open('$SIGNALS_FILE'))))" 2>/dev/null || echo "?")
echo "[COLLECT] Total signals: $COUNT"
