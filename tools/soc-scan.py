#!/usr/bin/env python3
"""autonomous-soc: Local Scanner
Run the full Autonomous SOC pipeline on any local project directory.
Usage: python soc-scan.py /path/to/project [--policy moderate] [--skip-ai]"""

import argparse, json, os, subprocess, sys
from pathlib import Path

TOOLS = Path(__file__).parent
SIG = "/tmp/soc-signals.json"

def has(name, cmd):
    try: subprocess.run(cmd, capture_output=True, timeout=10); return True
    except: return False

def run(cmd, desc, env=None):
    print(f"\n  -> {desc}")
    e = {**os.environ, **(env or {})}
    r = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=120)
    if r.returncode != 0 and r.stderr:
        for l in r.stderr.strip().split("\n")[:3]: print(f"     {l}")
    return r

def main():
    p = argparse.ArgumentParser(description="Run autonomous-soc locally")
    p.add_argument("project_dir")
    p.add_argument("--policy", default="moderate", choices=["strict","moderate","audit"])
    p.add_argument("--skip-ai", action="store_true")
    a = p.parse_args()

    proj = Path(a.project_dir).resolve()
    if not proj.is_dir():
        print(f"Error: {proj} not a directory"); sys.exit(2)

    print(f"\n{'='*60}")
    print(f"  AUTONOMOUS SOC — LOCAL SCAN")
    print(f"{'='*60}")
    print(f"  Target: {proj}")
    print(f"  Policy: {a.policy}")

    missing = []
    for n, c in {"syft":["syft","version"],"grype":["grype","version"],"gitleaks":["gitleaks","version"]}.items():
        ok = has(n, c)
        print(f"  {'OK' if ok else 'MISSING'}: {n}")
        if not ok: missing.append(n)
    if missing:
        print(f"\n  Install missing: {', '.join(missing)}")
        print(f"  See README.md for install commands"); sys.exit(2)

    with open(SIG, "w") as f: json.dump([], f)

    # SBOM
    sbom = "/tmp/soc-sbom-current.json"
    run(["syft","packages",f"dir:{proj}","-o","cyclonedx-json",f"--file={sbom}"], "Generating SBOM...")
    if os.path.exists(sbom):
        with open(sbom) as f: cc = len(json.load(f).get("components",[]))
        print(f"     {cc} components")

    # SBOM Diff
    bl = str(proj / "sbom-baseline.json")
    run([sys.executable, str(TOOLS/"sbom-diff.py"), sbom, "--baseline", bl, "--signals-file", SIG],
        "SBOM diff...")

    # Grype
    grype_out = "/tmp/grype-output.json"
    run(["grype", f"sbom:{sbom}", "-o", "json", f"--file={grype_out}"], "Vulnerability scan...")

    # Gitleaks
    gl_out = "/tmp/gitleaks-output.json"
    run(["gitleaks","detect","--source",str(proj),"--no-git","--report-format","json","--report-path",gl_out],
        "Secret scan...")

    # Collect
    run(["bash", str(TOOLS/"collect-signals.sh")], "Collecting signals...",
        {"SIGNALS_FILE": SIG, "GRYPE_OUTPUT": grype_out, "GITLEAKS_OUTPUT": gl_out})

    # AI Triage
    triage_env = {"SIGNALS_FILE": SIG}
    if a.skip_ai:
        triage_env["ANTHROPIC_API_KEY"] = ""
        triage_env["GROQ_API_KEY"] = ""
    r = run([sys.executable, str(TOOLS/"ai-triage.py"), "--signals-file", SIG, "--policy", a.policy],
            "AI triage...", triage_env)
    if r.stdout: print(r.stdout)
    sys.exit(r.returncode)

if __name__ == "__main__":
    main()
