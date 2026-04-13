#!/usr/bin/env python3
"""autonomous-soc: SBOM Diff Engine
Compares CycloneDX SBOMs between builds to detect supply chain changes."""

import json, sys, os, argparse, shutil
from datetime import datetime, timezone

SUSPICIOUS_PATTERNS = ['.pth', '.map', '.exe', '.dll', '.ps1']
KNOWN_MALICIOUS = {
    'plain-crypto-js': 'Known malicious (Axios March 2026 attack)',
    'plain-crypto': 'Potential typosquat of crypto-js',
}

def load_sbom(path):
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)

def extract_components(sbom):
    result = {}
    for c in sbom.get('components', []):
        name = c.get('name', '')
        if not name:
            continue
        # Skip path-based entries Syft generates for file: local deps and lockfiles
        # e.g. "../mock-packages/plain-crypto-js", "/home/runner/.../package-lock.json"
        if name.startswith('.') or name.startswith('/') or name.endswith('.json'):
            continue
        result[name] = {'version': c.get('version', 'unknown'), 'purl': c.get('purl', '')}
    return result

def diff_components(baseline, current):
    b, c = set(baseline), set(current)
    added = {n: current[n] for n in (c - b)}
    removed = {n: baseline[n] for n in (b - c)}
    changed = {n: {'from': baseline[n]['version'], 'to': current[n]['version']}
               for n in (b & c) if baseline[n]['version'] != current[n]['version']}
    return added, removed, changed

def check_suspicious(sbom):
    return [{'file': c.get('name',''), 'pattern': p}
            for c in sbom.get('components',[])
            for p in SUSPICIOUS_PATTERNS
            if c.get('name','').endswith(p)]

def create_signal(stype, severity, package, detail, meta=None):
    sig = {'source': 'sbom-diff', 'type': stype, 'severity': severity,
           'package': package, 'detail': detail,
           'timestamp': datetime.now(timezone.utc).isoformat()}
    if meta: sig['metadata'] = meta
    return sig

def write_signals(signals, path):
    existing = []
    if os.path.exists(path):
        try:
            with open(path) as f: existing = json.load(f)
        except: pass
    existing.extend(signals)
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f: json.dump(existing, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='SBOM Diff Engine')
    parser.add_argument('current_sbom')
    parser.add_argument('--baseline', default=None)
    parser.add_argument('--signals-file', default=None)
    parser.add_argument('--store-baseline', action='store_true')
    args = parser.parse_args()

    baseline_path = args.baseline or os.environ.get('SBOM_BASELINE', 'sbom-baseline.json')
    signals_path = args.signals_file or os.environ.get('SIGNALS_FILE', '/tmp/soc-signals.json')

    current_sbom = load_sbom(args.current_sbom)
    current = extract_components(current_sbom)
    suspicious = check_suspicious(current_sbom)
    print(f'[SBOM-DIFF] Current: {len(current)} components')

    if not os.path.exists(baseline_path) or args.store_baseline:
        os.makedirs(os.path.dirname(baseline_path) or '.', exist_ok=True)
        shutil.copy(args.current_sbom, baseline_path)
        print(f'[SBOM-DIFF] Baseline created ({len(current)} components)')
        signals = [create_signal('sbom_suspicious_file', 'HIGH', f['file'],
                   f"Suspicious file pattern '{f['pattern']}': {f['file']}") for f in suspicious]
        if signals:
            write_signals(signals, signals_path)
            sys.exit(1)
        return

    baseline_sbom = load_sbom(baseline_path)
    baseline = extract_components(baseline_sbom)
    print(f'[SBOM-DIFF] Baseline: {len(baseline)} components')

    added, removed, changed = diff_components(baseline, current)
    signals = []

    if added:
        print(f'\n[SBOM-DIFF] NEW DEPENDENCIES ({len(added)}):')
        for name, info in added.items():
            known = KNOWN_MALICIOUS.get(name, '')
            flag = f' <- KNOWN MALICIOUS: {known}' if known else ''
            print(f'  + {name}@{info["version"]}{flag}')
            sev = 'CRITICAL' if name in KNOWN_MALICIOUS else 'HIGH'
            detail = f'New dependency {name}@{info["version"]} not in baseline'
            if known: detail += f'. WARNING: {known}'
            signals.append(create_signal('sbom_new_dependency', sev, name, detail,
                          {'version': info['version']}))

    if changed:
        print(f'\n[SBOM-DIFF] VERSION CHANGES ({len(changed)}):')
        for name, info in changed.items():
            print(f'  ~ {name}: {info["from"]} -> {info["to"]}')
            signals.append(create_signal('sbom_version_change', 'MEDIUM', name,
                          f'Version changed: {info["from"]} -> {info["to"]}',
                          {'from_version': info['from'], 'to_version': info['to']}))

    if suspicious:
        print(f'\n[SBOM-DIFF] SUSPICIOUS FILES ({len(suspicious)}):')
        for f in suspicious:
            print(f'  ! {f["file"]} (pattern: {f["pattern"]})')
            signals.append(create_signal('sbom_suspicious_file', 'HIGH', f['file'],
                          f"Suspicious file pattern '{f['pattern']}': {f['file']}"))

    if not added and not removed and not changed and not suspicious:
        print('[SBOM-DIFF] No changes. SBOM matches baseline.')

    if signals:
        write_signals(signals, signals_path)
        print(f'\n[SBOM-DIFF] {len(signals)} signal(s) written')

    shutil.copy(args.current_sbom, baseline_path)
    if signals: sys.exit(1)

if __name__ == '__main__':
    main()
