#!/usr/bin/env python3
"""Compare two anon_probe result files (before / after a fix) and emit per-probe verdicts.

Verdicts per probe id:
  FIXED            LEAK before, BLOCKED-* after
  STILL-LEAKING    LEAK before and after
  NEWLY-LEAKING    not LEAK before, LEAK after
  REGRESSION       a legitimate flow (expect=ALLOW) is no longer allowed after the change
  STILL-ALLOWED    legitimate flow still works (regression check passed)
  UNCHANGED-BLOCKED  blocked before and after
  UNVERIFIED       INCONCLUSIVE on either side (no claim possible)
  MISSING          probe present on only one side

Overall status:
  VERIFIED         at least one FIXED, nothing leaking or regressing, a regression probe
                   (expect=ALLOW, STILL-ALLOWED) exists, and no probe on the fixed targets is UNVERIFIED
  FIX-APPLIED-NOT-VERIFIED   anything else that is not a failure
  FAILED           STILL-LEAKING, NEWLY-LEAKING or REGRESSION present
Exit code: 0 for VERIFIED/FIX-APPLIED-NOT-VERIFIED, 1 for FAILED, 2 for usage errors.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BLOCKED = {"BLOCKED-RLS", "BLOCKED-GRANT"}


def verdict(before, after):
    if before is None or after is None:
        return "MISSING"
    b, a = before["classification"], after["classification"]
    if a == "REGRESSION":
        return "REGRESSION"
    if before.get("expect") == "ALLOW" or after.get("expect") == "ALLOW":
        if a == "ALLOWED":
            return "STILL-ALLOWED"
        return "UNVERIFIED" if a == "INCONCLUSIVE" else "REGRESSION"
    if b == "LEAK" and a == "LEAK":
        return "STILL-LEAKING"
    if b == "LEAK" and a in BLOCKED:
        return "FIXED"
    if a == "LEAK":
        return "NEWLY-LEAKING"
    if "INCONCLUSIVE" in (a, b):
        return "UNVERIFIED"
    if a in BLOCKED and b in BLOCKED:
        return "UNCHANGED-BLOCKED"
    return "UNVERIFIED"


def compare(before_doc, after_doc):
    warnings = []
    bm, am = before_doc.get("meta", {}), after_doc.get("meta", {})
    if bm.get("host") != am.get("host"):
        warnings.append("Runs target different hosts; the comparison is not like-for-like.")
    if bm.get("mode") != am.get("mode"):
        warnings.append("Runs used different verification modes (A/B).")
    if bm.get("role") != am.get("role") and bm.get("role") and am.get("role"):
        warnings.append("Runs used different roles; compare anon with anon.")
    b = {r["id"]: r for r in before_doc["results"]}
    a = {r["id"]: r for r in after_doc["results"]}
    rows = [{"id": pid, "before": (b.get(pid) or {}).get("classification"),
             "after": (a.get(pid) or {}).get("classification"), "verdict": verdict(b.get(pid), a.get(pid))}
            for pid in sorted(set(b) | set(a))]
    verdicts = {r["verdict"] for r in rows}
    failed = bool(verdicts & {"STILL-LEAKING", "NEWLY-LEAKING", "REGRESSION"})
    regression_probe = "STILL-ALLOWED" in verdicts
    fixed_ids = {r["id"] for r in rows if r["verdict"] == "FIXED"}
    unverified_fixed = [r["id"] for r in rows if r["verdict"] == "UNVERIFIED" and r["id"] in fixed_ids]
    if failed:
        status = "FAILED"
    elif "FIXED" in verdicts and regression_probe and not unverified_fixed and not warnings:
        status = "VERIFIED"
    else:
        status = "FIX-APPLIED-NOT-VERIFIED"
    reasons = []
    if status == "FIX-APPLIED-NOT-VERIFIED":
        if "FIXED" not in verdicts:
            reasons.append("no probe moved from LEAK to BLOCKED")
        if not regression_probe:
            reasons.append("no regression probe (expect=ALLOW, role authenticated) confirmed the legitimate flow")
        if warnings:
            reasons.append("runs are not like-for-like")
    return {"status": status, "reasons": reasons, "warnings": warnings, "rows": rows}


def render_markdown(result) -> str:
    out = [f"**Overall: {result['status']}**", ""]
    for r in result["reasons"]:
        out.append(f"- not verified because: {r}")
    for w in result["warnings"]:
        out.append(f"- warning: {w}")
    out += ["", "| Probe | Before | After | Verdict |", "|---|---|---|---|"]
    for r in result["rows"]:
        out.append(f"| {r['id']} | {r['before'] or '-'} | {r['after'] or '-'} | {r['verdict']} |")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    try:
        before = json.loads(Path(a.before).read_text())
        after = json.loads(Path(a.after).read_text())
    except (OSError, ValueError) as e:
        print(f"ERROR: cannot read inputs: {e}", file=sys.stderr)
        return 2
    result = compare(before, after)
    text = json.dumps(result, indent=2) if a.format == "json" else render_markdown(result)
    if a.out:
        Path(a.out).write_text(text + "\n")
    else:
        print(text)
    return 1 if result["status"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
