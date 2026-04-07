#!/usr/bin/env python3
"""autonomous-soc: AI Triage Agent
Correlates signals from all detection layers, determines threat level, recommends action."""

import json, os, sys, argparse
from datetime import datetime, timezone

THRESHOLDS = {
    "strict": {"auto_block": 2, "alert": 1},
    "moderate": {"auto_block": 3, "alert": 2},
    "audit": {"auto_block": 999, "alert": 999},
}

TRIAGE_PROMPT = """You are an AI supply chain security analyst in an Autonomous SOC pipeline.
Signals detected during a CI/CD build:

{signals}

Respond ONLY with valid JSON (no markdown, no backticks):
{{
  "decision": "AUTO_BLOCK" or "ALERT_HUMAN" or "ALLOW",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "correlation": "How signals relate to each other",
  "risk_summary": "One paragraph on the risk",
  "remediation": ["Step 1", "Step 2", "Step 3"],
  "evidence": {{
    "signal_count": <int>,
    "high_severity_count": <int>,
    "critical_count": <int>,
    "packages_involved": ["pkg1"],
    "attack_pattern": "description or null"
  }}
}}

Rules:
- CRITICAL or 3+ correlated HIGH = AUTO_BLOCK
- 2+ HIGH or known attack pattern = AUTO_BLOCK
- 1 HIGH or 2+ MEDIUM = ALERT_HUMAN
- Only LOW = ALLOW
Known patterns: unexpected dep + missing provenance = account takeover (Axios 2026),
new .pth file = interpreter persistence (LiteLLM), anomalous egress = C2 (TeamPCP)."""

# Groq: free-tier dev keys — https://console.groq.com (OpenAI-compatible API)
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "llama-3.1-8b-instant"


def load_signals(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except:
        return []


def policy_decision(signals, policy):
    t = THRESHOLDS.get(policy, THRESHOLDS["moderate"])
    crit = sum(1 for s in signals if s.get("severity") == "CRITICAL")
    high = sum(1 for s in signals if s.get("severity") == "HIGH")
    med = sum(1 for s in signals if s.get("severity") == "MEDIUM")
    total = crit + high
    pkgs = list(set(s.get("package", "unknown") for s in signals if s.get("package")))

    if crit > 0 or total >= t["auto_block"]:
        decision, conf = "AUTO_BLOCK", "HIGH" if total >= 3 else "MEDIUM"
    elif total >= t["alert"] or med >= 2:
        decision, conf = "ALERT_HUMAN", "MEDIUM"
    else:
        decision, conf = "ALLOW", "HIGH"

    remed = []
    for s in signals:
        pkg = s.get("package", "?")
        st = s.get("type", "")
        if "new_dependency" in st: remed.append(f"Remove unexpected dependency: {pkg}")
        elif "version_change" in st: remed.append(f"Review version change for {pkg}")
        elif "provenance" in st: remed.append(f"Verify provenance for {pkg}")
        elif "vulnerability" in st: remed.append(f"Update {pkg} to patched version")
        elif "secret" in st: remed.append(f"Rotate exposed credential in {pkg}")
        elif "runtime" in st: remed.append(f"Investigate anomalous call: {s.get('detail','')}")
    if not remed: remed = ["Review detected signals manually"]

    return {
        "decision": decision, "confidence": conf, "engine": "policy",
        "correlation": f"{len(signals)} signal(s). Policy-based decision ({policy}).",
        "risk_summary": f"{crit} critical, {high} high, {med} medium across {len(pkgs)} package(s).",
        "remediation": remed,
        "evidence": {"signal_count": len(signals), "high_severity_count": high,
                     "critical_count": crit, "packages_involved": pkgs, "attack_pattern": None},
    }


def _parse_llm_json(text: str) -> dict:
    text = text.strip()
    if "```" in text:
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return json.loads(text)


def _apply_strict_policy(result: dict, signals: list, policy: str) -> dict:
    if policy == "strict":
        hc = sum(1 for s in signals if s.get("severity") in ("HIGH", "CRITICAL"))
        if result.get("decision") == "ALLOW" and hc > 0:
            result["decision"] = "ALERT_HUMAN"
            result["correlation"] = (result.get("correlation") or "") + (
                " (Overridden: strict policy, HIGH signals present.)"
            )
    return result


def _triage_anthropic(signals: list, policy: str, api_key: str) -> dict:
    from anthropic import Anthropic

    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    client = Anthropic(api_key=api_key)
    prompt = TRIAGE_PROMPT.format(signals=json.dumps(signals, indent=2))
    resp = client.messages.create(
        model=model,
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.content[0].text.strip()
    result = _parse_llm_json(text)
    result["engine"] = "ai"
    result["llm"] = "anthropic"
    return _apply_strict_policy(result, signals, policy)


def _triage_groq(signals: list, policy: str, api_key: str) -> dict:
    from openai import OpenAI

    model = os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL)
    client = OpenAI(api_key=api_key, base_url=GROQ_BASE_URL)
    prompt = TRIAGE_PROMPT.format(signals=json.dumps(signals, indent=2))
    resp = client.chat.completions.create(
        model=model,
        max_tokens=1500,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.choices[0].message.content.strip()
    result = _parse_llm_json(text)
    result["engine"] = "ai"
    result["llm"] = "groq"
    return _apply_strict_policy(result, signals, policy)


def ai_triage(signals, policy):
    """Use Anthropic, Groq (free-tier friendly), or policy fallback.

    SOC_AI_PROVIDER: auto | anthropic | groq
      auto — ANTHROPIC_API_KEY if set, else GROQ_API_KEY, else policy engine.
    """
    anthropic_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    groq_key = (os.environ.get("GROQ_API_KEY") or "").strip()
    provider = (os.environ.get("SOC_AI_PROVIDER") or "auto").strip().lower()

    use_anthropic = provider == "anthropic" or (provider == "auto" and anthropic_key)
    use_groq = provider == "groq" or (provider == "auto" and not anthropic_key and groq_key)

    if provider == "anthropic" and not anthropic_key:
        print("[AI-TRIAGE] SOC_AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is empty. Using policy engine.")
        return policy_decision(signals, policy)
    if provider == "groq" and not groq_key:
        print("[AI-TRIAGE] SOC_AI_PROVIDER=groq but GROQ_API_KEY is empty. Using policy engine.")
        return policy_decision(signals, policy)

    if use_anthropic and anthropic_key:
        try:
            return _triage_anthropic(signals, policy, anthropic_key)
        except Exception as e:
            print(f"[AI-TRIAGE] Anthropic error: {e}. Using policy engine.")
            return policy_decision(signals, policy)

    if use_groq and groq_key:
        try:
            return _triage_groq(signals, policy, groq_key)
        except Exception as e:
            print(f"[AI-TRIAGE] Groq error: {e}. Using policy engine.")
            return policy_decision(signals, policy)

    print("[AI-TRIAGE] No ANTHROPIC_API_KEY or GROQ_API_KEY. Using policy engine.")
    return policy_decision(signals, policy)


def print_verdict(result, signals):
    d = result.get("decision", "?")
    icons = {"AUTO_BLOCK": "\U0001f6d1", "ALERT_HUMAN": "\u26a0\ufe0f", "ALLOW": "\u2705"}
    if result.get("engine") == "ai":
        label = {"anthropic": "Claude", "groq": "Groq"}.get(result.get("llm"), "LLM")
        eng = f"AI ({label})"
    else:
        eng = "Policy Engine"

    print(f"\n{'='*60}")
    print(f"  AUTONOMOUS SOC — TRIAGE VERDICT")
    print(f"{'='*60}")
    print(f"\n  Engine: {eng}")
    print(f"  Signals: {len(signals)}")
    print(f"\n  {icons.get(d,'?')} DECISION: {d} (Confidence: {result.get('confidence','?')})")
    if result.get("correlation"): print(f"\n  Correlation: {result['correlation']}")
    if result.get("risk_summary"): print(f"\n  Risk: {result['risk_summary']}")
    ev = result.get("evidence", {})
    if ev:
        print(f"\n  Evidence:")
        print(f"    Signals: {ev.get('signal_count', '?')}, Critical: {ev.get('critical_count', 0)}, High: {ev.get('high_severity_count', 0)}")
        pkgs = ev.get("packages_involved", [])
        if pkgs: print(f"    Packages: {', '.join(pkgs)}")
        if ev.get("attack_pattern"): print(f"    Pattern: {ev['attack_pattern']}")
    remed = result.get("remediation", [])
    if remed:
        print(f"\n  Remediation:")
        for i, s in enumerate(remed, 1): print(f"    {i}. {s}")
    print(f"\n{'='*60}")
    if d == "AUTO_BLOCK": print(f"\n  \U0001f6d1 BUILD BLOCKED.\n")
    elif d == "ALERT_HUMAN": print(f"\n  \u26a0\ufe0f Human review required.\n")
    else: print(f"\n  \u2705 Pipeline clean.\n")


def main():
    parser = argparse.ArgumentParser(description="AI Triage Agent")
    parser.add_argument("--signals-file", default=None)
    parser.add_argument("--policy", default=None, choices=["strict", "moderate", "audit"])
    parser.add_argument("--output", default="/tmp/soc-verdict.json")
    args = parser.parse_args()

    sig_path = args.signals_file or os.environ.get("SIGNALS_FILE", "/tmp/soc-signals.json")
    policy = args.policy or os.environ.get("SOC_POLICY", "moderate")
    signals = load_signals(sig_path)

    print(f"\n{'='*60}")
    print(f"  AUTONOMOUS SOC — AI TRIAGE AGENT")
    print(f"{'='*60}")
    print(f"  Policy: {policy} | Signals: {len(signals)}")

    if not signals:
        print(f"\n  \u2705 No signals. Pipeline clean.\n")
        with open(args.output, "w") as f:
            json.dump({"decision": "ALLOW", "engine": "none"}, f, indent=2)
        return

    for i, s in enumerate(signals, 1):
        sev = s.get("severity", "?")
        ic = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f534", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}.get(sev, "\u26aa")
        print(f"  {ic} [{sev}] {s.get('source','?')}: {s.get('type','?')}")
        print(f"     Pkg: {s.get('package','N/A')} | {s.get('detail','')}")

    print(f"\n  Triaging {len(signals)} signal(s)...")
    result = ai_triage(signals, policy)
    print_verdict(result, signals)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    fail = os.environ.get("FAIL_ON_BLOCK", "true").lower() == "true"
    if result.get("decision") in ("AUTO_BLOCK", "ALERT_HUMAN") and fail:
        sys.exit(1)

if __name__ == "__main__":
    main()
