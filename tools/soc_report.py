#!/usr/bin/env python3
"""
Write Autonomous SOC run reports for humans and automation.

Outputs:
  - Markdown (SOC_REPORT_MD, default /tmp/soc-report.md)
  - JSON bundle (SOC_REPORT_JSON, default /tmp/soc-report.json)
  - Appends to GITHUB_STEP_SUMMARY when set (GitHub Actions job summary)

Grype matches in the report are capped (SOC_REPORT_GRYPE_MAX, default 75) so large
monorepos get a useful summary without megabyte logs.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_json(path: str | None, default: Any) -> Any:
    if not path or not os.path.isfile(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _grype_high_critical_rows(grype_data: dict, limit: int) -> tuple[list[list[str]], int]:
    rows: list[list[str]] = []
    total = 0
    for m in grype_data.get("matches") or []:
        v = m.get("vulnerability") or {}
        sev = (v.get("severity") or "").upper()
        if sev not in ("HIGH", "CRITICAL"):
            continue
        total += 1
        if len(rows) >= limit:
            continue
        a = m.get("artifact") or {}
        pkg = f"{a.get('name', '?')}@{a.get('version', '?')}"
        rows.append([v.get("id", "?"), sev, pkg, (v.get("description") or "")[:120]])
    return rows, total


def build_markdown(
    signals: list[dict],
    verdict: dict,
    grype_path: str | None,
    grype_max: int,
) -> str:
    lines: list[str] = []
    lines.append("# Autonomous SOC report")
    lines.append("")
    lines.append(f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Triage verdict")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Decision | `{verdict.get('decision', '?')}` |")
    lines.append(f"| Confidence | {verdict.get('confidence', 'n/a')} |")
    lines.append(f"| Engine | {verdict.get('engine', 'n/a')} |")
    if verdict.get("llm"):
        lines.append(f"| LLM | {verdict.get('llm')} |")
    lines.append("")
    if verdict.get("correlation"):
        lines.append("### Correlation")
        lines.append(verdict["correlation"])
        lines.append("")
    if verdict.get("risk_summary"):
        lines.append("### Risk summary")
        lines.append(verdict["risk_summary"])
        lines.append("")
    rem = verdict.get("remediation") or []
    if rem:
        lines.append("### Recommended remediation (manual or tracked as work items)")
        lines.append("")
        lines.append(
            "These are recommendations. Automated `npm audit fix` (optional action input) "
            "only addresses a subset of npm advisories; review lockfile and tests."
        )
        lines.append("")
        for i, step in enumerate(rem, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    lines.append("## Signals (normalized)")
    lines.append("")
    if not signals:
        lines.append("No signals.")
    else:
        lines.append("| # | Severity | Source | Type | Package | Detail |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for i, s in enumerate(signals, 1):
            det = (s.get("detail") or "").replace("|", "\\|")[:200]
            lines.append(
                f"| {i} | {s.get('severity', '')} | {s.get('source', '')} | "
                f"{s.get('type', '')} | {s.get('package', '')} | {det} |"
            )
    lines.append("")

    data = _load_json(grype_path, {})
    if isinstance(data, dict) and data.get("matches"):
        rows, total = _grype_high_critical_rows(data, grype_max)
        lines.append("## Vulnerability scan (Grype, HIGH/CRITICAL)")
        lines.append("")
        lines.append(
            f"Showing up to {grype_max} of **{total}** HIGH/CRITICAL matches "
            "(see full SBOM scan in workflow logs or attach Grype JSON as artifact separately)."
        )
        lines.append("")
        if rows:
            lines.append("| CVE/ID | Severity | Package | Description (trimmed) |")
            lines.append("| --- | --- | --- | --- |")
            for r in rows:
                lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} |")
        lines.append("")

    lines.append("## Operational notes")
    lines.append("")
    lines.append(
        "- Large projects: triage by severity, reachability, and exploitability; "
        "use this report as the shared reference for security and engineering."
    )
    lines.append(
        "- Optional: enable Dependabot or Renovate for ongoing dependency PRs; "
        "this action does not open PRs by default."
    )
    lines.append("")
    return "\n".join(lines)


def build_json_bundle(
    signals: list[dict],
    verdict: dict,
    grype_path: str | None,
    grype_max: int,
) -> dict:
    data = _load_json(grype_path, {})
    rows, total = _grype_high_critical_rows(data, grype_max) if isinstance(data, dict) else ([], 0)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "signal_count": len(signals),
        "signals": signals,
        "grype_high_critical_total": total,
        "grype_high_critical_sample": [
            {"id": r[0], "severity": r[1], "package": r[2], "description_trimmed": r[3]} for r in rows
        ],
    }


def write_soc_reports(
    signals: list[dict],
    verdict: dict,
    *,
    grype_path: str | None = None,
    out_md: str | None = None,
    out_json: str | None = None,
) -> None:
    grype_path = grype_path or os.environ.get("GRYPE_OUTPUT", "/tmp/grype-output.json")
    out_md = out_md or os.environ.get("SOC_REPORT_MD", "/tmp/soc-report.md")
    out_json = out_json or os.environ.get("SOC_REPORT_JSON", "/tmp/soc-report.json")
    try:
        grype_max = int(os.environ.get("SOC_REPORT_GRYPE_MAX", "75"))
    except ValueError:
        grype_max = 75

    md = build_markdown(signals, verdict, grype_path, grype_max)
    bundle = build_json_bundle(signals, verdict, grype_path, grype_max)

    Path(out_md).parent.mkdir(parents=True, exist_ok=True)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as f:
                f.write("\n")
                f.write(md)
                f.write("\n")
        except OSError:
            pass


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="Generate SOC markdown/JSON report from verdict + signals")
    p.add_argument("--signals-file", default=os.environ.get("SIGNALS_FILE", "/tmp/soc-signals.json"))
    p.add_argument("--verdict-file", default=os.environ.get("SOC_VERDICT_JSON", "/tmp/soc-verdict.json"))
    args = p.parse_args()

    signals = _load_json(args.signals_file, [])
    if not isinstance(signals, list):
        signals = []
    verdict = _load_json(args.verdict_file, {"decision": "UNKNOWN", "engine": "none"})
    if not isinstance(verdict, dict):
        verdict = {"decision": "UNKNOWN", "engine": "none"}
    write_soc_reports(signals, verdict)


if __name__ == "__main__":
    main()
