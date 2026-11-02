#!/usr/bin/env python3
"""Probe a Supabase project's Data API as `anon` (or a test user) and classify the results.

SAFETY CONTRACT
  * Uses only a publishable key or a legacy anon JWT. Secret / service_role keys are refused.
  * Refuses to send any request unless --mode and --confirm-authorized are given. The agent must
    obtain that choice from the user first (see SKILL.md). The flags are a mechanical backstop,
    not a substitute for asking.
  * Never stores or prints row values or credentials: only status, counts, column names, verdicts.
  * --dry-run prints the planned requests and sends nothing (no consent flags needed).

MODES (chosen by the user)
  A  local or staging environment. Persisting write probes allowed only with --allow-persisting-writes.
  B  any URL, including production. Reads, GET-only RPC and Storage listing. Write probes are
     opt-in via --include-unverified-write-probes and are designed not to persist data.

Classification: LEAK | BLOCKED-RLS | BLOCKED-GRANT | INCONCLUSIVE (expect=DENY, the default)
                ALLOWED | REGRESSION                                (expect=ALLOW)
A `200 []` is never reported as safe unless the config says a row is known to exist
(seed_expected: true): an empty table and an RLS filter look identical.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import TOOL_VERSION, classify_key, is_probe_key_allowed, redact  # noqa: E402

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal", "kong"}
MAX_BODY = 1_000_000


# --------------------------------------------------------------------------- classification (pure)
def parse_error(body: bytes):
    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return "", body.decode("utf-8", errors="ignore")[:200]
    if isinstance(data, dict):
        return str(data.get("code") or data.get("error") or ""), str(data.get("message") or data.get("error") or "")
    return "", ""


def _denied_kind(status, code, message):
    """'rls' | 'grant' | 'auth' | None for an error response."""
    low = (message or "").lower()
    if "row-level security" in low or "row level security" in low:
        return "rls"
    if code == "42501" or "permission denied" in low:
        return "grant"
    if status in (401, 403):
        return "auth"
    return None


def classify_read(status, rows, code, message, seed_expected, expect="DENY"):
    """Return (classification, outcome, reason)."""
    if status is None:
        return "INCONCLUSIVE", "ERROR", "network error or timeout"
    if status in (200, 206):
        n = len(rows) if isinstance(rows, list) else 0
        if n > 0:
            return ("ALLOWED", "ROWS", "rows returned as expected") if expect == "ALLOW" else \
                   ("LEAK", "ROWS", "rows readable by this role")
        if expect == "ALLOW":
            if seed_expected:
                return "REGRESSION", "EMPTY", "empty result although a visible row was expected"
            return "INCONCLUSIVE", "EMPTY", "empty result; cannot tell empty table from RLS filter"
        if seed_expected:
            return "BLOCKED-RLS", "EMPTY", "empty result while a row is known to exist"
        return "INCONCLUSIVE", "EMPTY", "empty result; cannot tell empty table from RLS filter (seed a row or compare with a privileged count)"
    kind = _denied_kind(status, code, message)
    if kind in ("rls", "grant"):
        if expect == "ALLOW":
            return "REGRESSION", "DENIED", "access denied but expected to be allowed"
        return ("BLOCKED-RLS" if kind == "rls" else "BLOCKED-GRANT"), "DENIED", f"{kind} denial (HTTP {status})"
    if status == 404:
        return "INCONCLUSIVE", "NOT_FOUND", "table not found or not exposed; check name/schema"
    if kind == "auth":
        return "INCONCLUSIVE", "AUTH", "credential or gateway rejected the request; not a grant decision"
    return "INCONCLUSIVE", "ERROR", f"unexpected HTTP {status}"


def classify_write(kind, status, rows, code, message, seed_expected, expect="DENY"):
    """kind: insert | update | delete | insert_invalid | impossible_update | impossible_delete."""
    if status is None:
        return "INCONCLUSIVE", "ERROR", "network error or timeout"
    denied = _denied_kind(status, code, message)
    if denied in ("rls", "grant"):
        if expect == "ALLOW":
            return "REGRESSION", "DENIED", "write denied but expected to be allowed"
        return ("BLOCKED-RLS" if denied == "rls" else "BLOCKED-GRANT"), "DENIED", f"{denied} denial (HTTP {status})"
    if denied == "auth":
        return "INCONCLUSIVE", "AUTH", "credential or gateway rejected the request; not a grant decision"
    if kind == "insert":
        if status in (200, 201, 204):
            return ("ALLOWED", "WRITTEN", "insert succeeded as expected") if expect == "ALLOW" else \
                   ("LEAK", "WRITTEN", "insert persisted for this role (clean up the marked row)")
    if kind in ("update", "delete"):
        if status in (200, 201, 204):
            n = len(rows) if isinstance(rows, list) else 0
            if n > 0:
                return ("ALLOWED", "WRITTEN", "rows affected as expected") if expect == "ALLOW" else \
                       ("LEAK", "WRITTEN", f"{kind} affected rows for this role")
            if seed_expected:
                return ("REGRESSION", "NO_ROWS", "no rows affected although a target row exists") if expect == "ALLOW" else \
                       ("BLOCKED-RLS", "NO_ROWS", "no rows affected while a target row is known to exist")
            return "INCONCLUSIVE", "NO_ROWS", "no rows affected; cannot tell missing row from RLS filter"
    if kind == "insert_invalid":
        if status in (400, 409, 422):
            return "INCONCLUSIVE", "CONSTRAINT", ("reached constraint validation without a policy/grant error; "
                                                  "possible gap (UNVERIFIED hypothesis: confirm in mode A)")
    if kind in ("impossible_update", "impossible_delete") and status in (200, 204):
        return "INCONCLUSIVE", "GRANT_OPEN", "grants allow this operation; RLS layer not verified (use mode A)"
    return "INCONCLUSIVE", "ERROR", f"unexpected HTTP {status}"


def classify_rpc(status, code, message, expect="DENY"):
    if status is None:
        return "INCONCLUSIVE", "ERROR", "network error or timeout"
    if 200 <= status < 300:
        return ("ALLOWED", "EXECUTED", "function executed as expected") if expect == "ALLOW" else \
               ("LEAK", "EXECUTED", "function executable by this role")
    denied = _denied_kind(status, code, message)
    if denied in ("rls", "grant"):
        if expect == "ALLOW":
            return "REGRESSION", "DENIED", "function denied but expected to be allowed"
        return "BLOCKED-GRANT", "DENIED", "execute permission denied"
    if denied == "auth":
        return "INCONCLUSIVE", "AUTH", "credential or gateway rejected the request; not a grant decision"
    if status == 404:
        return "INCONCLUSIVE", "NOT_FOUND", "function not found or signature mismatch"
    return "INCONCLUSIVE", "ERROR", f"unexpected HTTP {status}"


def classify_storage_list(status, items, message, seed_expected, expect="DENY"):
    """UNVERIFIED against a real Storage API in this release (see references/probe-methodology.md)."""
    if status is None:
        return "INCONCLUSIVE", "ERROR", "network error or timeout"
    if 200 <= status < 300:
        n = len(items) if isinstance(items, list) else 0
        if n > 0:
            return ("ALLOWED", "ROWS", "objects listed as expected") if expect == "ALLOW" else \
                   ("LEAK", "ROWS", "objects listable by this role")
        if seed_expected:
            return ("REGRESSION", "EMPTY", "empty listing although objects expected") if expect == "ALLOW" else \
                   ("BLOCKED-RLS", "EMPTY", "empty listing while objects are known to exist")
        return "INCONCLUSIVE", "EMPTY", "empty listing; cannot tell empty bucket from policy filter"
    low = (message or "").lower()
    if status in (400, 401, 403) and any(w in low for w in ("row-level security", "unauthorized", "not authorized", "permission")):
        return ("REGRESSION", "DENIED", "listing denied but expected to be allowed") if expect == "ALLOW" else \
               ("BLOCKED-RLS", "DENIED", "storage policy denied listing")
    if status == 404:
        return "INCONCLUSIVE", "NOT_FOUND", "bucket not found"
    return "INCONCLUSIVE", "ERROR", f"unexpected HTTP {status}"


# --------------------------------------------------------------------------- HTTP
def _opener_for(url: str):
    host = urllib.parse.urlparse(url).hostname or ""
    if host in LOCAL_HOSTS:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


def http_request(method, url, headers, body=None, timeout=10):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _opener_for(url).open(req, timeout=timeout) as r:
            return r.status, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_BODY)
    except Exception as e:  # URLError, timeout, ...
        return None, redact(str(e)).encode()


def _json_or_none(body: bytes):
    try:
        return json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return None


# --------------------------------------------------------------------------- planning
def build_plan(config, mode, allow_persisting, include_unverified_writes, role="anon"):
    """Return a list of probe dicts (no network). Pure function.

    Entries run only in a run whose --role matches their `role` field (default "anon").
    Raises ValueError on duplicate probe ids within one run."""
    plan = []
    for t in config.get("tables", []):
        if t.get("role", "anon") != role:
            continue
        name, expect = t["name"], t.get("expect", "DENY")
        seed = t.get("seed_expected")
        base = {"target": f"{t.get('schema', 'public')}.{name}", "table": t, "expect": expect, "seed": seed}
        plan.append({**base, "id": f"read:{name}", "kind": "read"})
        if mode == "A" and allow_persisting:
            if t.get("insert_payload") is not None:
                plan.append({**base, "id": f"insert:{name}", "kind": "insert"})
            if t.get("update"):
                plan.append({**base, "id": f"update:{name}", "kind": "update"})
            if t.get("delete"):
                plan.append({**base, "id": f"delete:{name}", "kind": "delete"})
        if include_unverified_writes:
            if t.get("insert_invalid_payload") is not None:
                plan.append({**base, "id": f"insert_invalid:{name}", "kind": "insert_invalid"})
            if t.get("impossible_filter") and t.get("noop_payload") is not None:
                plan.append({**base, "id": f"impossible_update:{name}", "kind": "impossible_update"})
            if t.get("impossible_filter"):
                plan.append({**base, "id": f"impossible_delete:{name}", "kind": "impossible_delete"})
    for r in config.get("rpc", []):
        if r.get("role", "anon") != role:
            continue
        plan.append({"id": f"rpc:{r['name']}", "kind": "rpc", "target": f"rpc/{r['name']}", "rpc": r,
                     "expect": r.get("expect", "DENY"), "seed": None})
    for s in config.get("storage", []):
        if s.get("role", "anon") != role:
            continue
        plan.append({"id": f"storage:{s['bucket']}", "kind": "storage", "target": f"storage/{s['bucket']}",
                     "storage": s, "expect": s.get("expect", "DENY"), "seed": s.get("seed_expected")})
    ids = [x["id"] for x in plan]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise ValueError(f"duplicate probe ids in one run: {dup}. Give each entry a distinct role or remove the duplicate.")
    return plan


def describe(probe, mode):
    k = probe["kind"]
    if k == "read":
        return f"GET   {probe['target']}?select=…&limit=1"
    if k == "rpc":
        return f"{'POST' if mode == 'A' else 'GET '}  {probe['target']}"
    if k == "storage":
        return f"POST  {probe['target']} (list, limit 1)"
    verb = {"insert": "POST", "update": "PATCH", "delete": "DELETE", "insert_invalid": "POST",
            "impossible_update": "PATCH", "impossible_delete": "DELETE"}[k]
    note = " [PERSISTS DATA]" if k in ("insert", "update", "delete") else " [designed not to persist]"
    return f"{verb:5} {probe['target']} ({k}){note}"


# --------------------------------------------------------------------------- execution
def run_probe(probe, base_url, headers, mode, timeout):
    k, t = probe["kind"], probe.get("table", {})
    h = dict(headers)
    expect, seed = probe["expect"], probe["seed"]
    if k in ("read", "insert", "update", "delete", "insert_invalid", "impossible_update", "impossible_delete"):
        name = urllib.parse.quote(t["name"], safe="")
        base = f"{base_url}/rest/v1/{name}"
        schema = t.get("schema")
        if schema and schema != "public":
            h["Accept-Profile"] = schema
            h["Content-Profile"] = schema
    if k == "read":
        url = f"{base}?select={urllib.parse.quote(t.get('select', '*'), safe='*,')}&limit=1"
        status, body = http_request("GET", url, h, timeout=timeout)
        data = _json_or_none(body)
        code, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_read(status, data if status in (200, 206) else None, code, msg, seed, expect)
        res = {"rows_count": len(data) if isinstance(data, list) else None}
        if isinstance(data, list) and data and isinstance(data[0], dict):
            res["columns"] = sorted(data[0].keys())
    elif k in ("insert", "insert_invalid"):
        payload = t["insert_payload"] if k == "insert" else t["insert_invalid_payload"]
        h.update({"Content-Type": "application/json", "Prefer": "return=representation"})
        status, body = http_request("POST", base, h, json.dumps(payload).encode(), timeout)
        code, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_write(k, status, None, code, msg, seed, expect)
        res = {}
    elif k in ("update", "impossible_update"):
        spec = t["update"] if k == "update" else {"filter": t["impossible_filter"], "payload": t["noop_payload"]}
        h.update({"Content-Type": "application/json", "Prefer": "return=representation"})
        status, body = http_request("PATCH", f"{base}?{spec['filter']}", h, json.dumps(spec["payload"]).encode(), timeout)
        data = _json_or_none(body)
        code, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_write(k, status, data if status and status < 300 else None, code, msg, seed, expect)
        res = {"rows_count": len(data) if isinstance(data, list) else None}
    elif k in ("delete", "impossible_delete"):
        flt = t["delete"]["filter"] if k == "delete" else t["impossible_filter"]
        h.update({"Prefer": "return=representation"})
        status, body = http_request("DELETE", f"{base}?{flt}", h, timeout=timeout)
        data = _json_or_none(body)
        code, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_write(k, status, data if status and status < 300 else None, code, msg, seed, expect)
        res = {"rows_count": len(data) if isinstance(data, list) else None}
    elif k == "rpc":
        r = probe["rpc"]
        fn = urllib.parse.quote(r["name"], safe="")
        if mode == "A":
            h["Content-Type"] = "application/json"
            status, body = http_request("POST", f"{base_url}/rest/v1/rpc/{fn}", h,
                                        json.dumps(r.get("args", {})).encode(), timeout)
        else:  # GET only: PostgREST should refuse volatile functions over GET (UNVERIFIED here)
            qs = urllib.parse.urlencode({k2: str(v) for k2, v in r.get("args", {}).items()})
            status, body = http_request("GET", f"{base_url}/rest/v1/rpc/{fn}" + (f"?{qs}" if qs else ""), h, timeout=timeout)
        code, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_rpc(status, code, msg, expect)
        res = {}
    else:  # storage list
        s = probe["storage"]
        h["Content-Type"] = "application/json"
        bucket = urllib.parse.quote(s["bucket"], safe="")
        status, body = http_request("POST", f"{base_url}/storage/v1/object/list/{bucket}", h,
                                    json.dumps({"prefix": s.get("prefix", ""), "limit": 1, "offset": 0}).encode(), timeout)
        data = _json_or_none(body)
        _, msg = parse_error(body) if status and status >= 400 else ("", "")
        cls, outcome, reason = classify_storage_list(status, data if status and status < 300 else None, msg, seed, expect)
        res = {"rows_count": len(data) if isinstance(data, list) else None}
    return {"id": probe["id"], "kind": k, "target": probe["target"], "expect": expect, "http_status": status,
            "outcome": outcome, "classification": cls, "reason": reason, **res}


# --------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="probe plan JSON (see references/probe-methodology.md)")
    ap.add_argument("--mode", choices=["A", "B"], help="verification mode chosen by the user")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="the user confirmed they own/are authorized for this project and accept responsibility")
    ap.add_argument("--staging-ack", action="store_true",
                    help="mode A against a non-local host: the user attests it is a staging/branch project")
    ap.add_argument("--url", help="project URL (or env SUPABASE_URL)")
    ap.add_argument("--key-env", help="env var holding the publishable/anon key (default: tries "
                                       "SUPABASE_PUBLISHABLE_KEY then SUPABASE_ANON_KEY)")
    ap.add_argument("--role", choices=["anon", "authenticated"], default="anon")
    ap.add_argument("--user-jwt-env", default="SUPABASE_USER_JWT",
                    help="env var with a TEST user's JWT (role=authenticated only)")
    ap.add_argument("--allow-persisting-writes", action="store_true", help="mode A only")
    ap.add_argument("--include-unverified-write-probes", action="store_true",
                    help="mode B only: non-persisting write probes whose interpretation is partly UNVERIFIED")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, send nothing")
    ap.add_argument("--out")
    ap.add_argument("--delay", type=float, default=0.2)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-requests", type=int, default=100)
    ap.add_argument("--fail-on-leak", action="store_true")
    a = ap.parse_args(argv)

    config = json.loads(Path(a.config).read_text())
    mode = a.mode or "B"
    if a.allow_persisting_writes and a.mode != "A":
        print("ERROR: --allow-persisting-writes is only valid with --mode A", file=sys.stderr)
        return 2
    if a.include_unverified_write_probes and a.mode != "B":
        print("ERROR: --include-unverified-write-probes is only valid with --mode B", file=sys.stderr)
        return 2
    try:
        plan = build_plan(config, mode, a.allow_persisting_writes, a.include_unverified_write_probes, a.role)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if len(plan) > a.max_requests:
        print(f"ERROR: plan has {len(plan)} requests, above --max-requests {a.max_requests}", file=sys.stderr)
        return 2

    if a.dry_run:
        print(f"DRY RUN (mode {a.mode or 'unselected'}): {len(plan)} planned requests, nothing sent")
        for p in plan:
            print("  -", p["id"], "|", describe(p, mode), "| expect", p["expect"])
        return 0

    if not a.mode or not a.confirm_authorized:
        print("REFUSING TO RUN: ask the user to choose mode A (local/staging) or B (URL, incl. production) and to "
              "confirm authorization and responsibility, then pass --mode and --confirm-authorized.", file=sys.stderr)
        return 2
    url = (a.url or os.environ.get("SUPABASE_URL") or "").rstrip("/")
    if not url.startswith(("http://", "https://")):
        print("ERROR: provide --url or SUPABASE_URL (http/https)", file=sys.stderr)
        return 2
    host = urllib.parse.urlparse(url).hostname or ""
    if a.mode == "A" and host not in LOCAL_HOSTS and not a.staging_ack:
        print("ERROR: mode A targets local/staging. For a remote host the user must attest it is staging "
              "(--staging-ack); otherwise choose mode B.", file=sys.stderr)
        return 2

    key = ""
    names = [a.key_env] if a.key_env else ["SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY"]
    for nme in names:
        if nme and os.environ.get(nme):
            key = os.environ[nme].strip()
            break
    kind = classify_key(key) if key else "missing"
    if not key or not is_probe_key_allowed(key):
        print(f"ERROR: probe key must be a publishable key or anon JWT (found: {kind}). "
              "Secret and service_role keys are never used for probing.", file=sys.stderr)
        return 2
    headers = {"apikey": key, "Accept": "application/json"}
    if kind == "anon":
        headers["Authorization"] = f"Bearer {key}"
    role_label = "anon"
    if a.role == "authenticated":
        jwt = os.environ.get(a.user_jwt_env, "").strip()
        if classify_key(jwt) != "authenticated":
            print("ERROR: --role authenticated needs a TEST user JWT with role=authenticated "
                  f"in ${a.user_jwt_env}", file=sys.stderr)
            return 2
        headers["Authorization"] = f"Bearer {jwt}"
        role_label = "authenticated"

    results = []
    for p in plan:
        results.append(run_probe(p, url, headers, mode, a.timeout))
        time.sleep(a.delay)
    report = {
        "meta": {"tool": "anon_probe", "version": TOOL_VERSION, "mode": a.mode, "role": role_label,
                 "host": host, "key_kind": kind, "started": datetime.now(timezone.utc).isoformat(),
                 "consent": {"confirmed_authorized": True, "mode_selected_by_user": a.mode,
                             "persisting_writes": bool(a.allow_persisting_writes),
                             "unverified_write_probes": bool(a.include_unverified_write_probes)}},
        "results": results,
    }
    text = json.dumps(report, indent=2)
    if a.out:
        Path(a.out).write_text(text + "\n")
    for r in results:
        print(f"{r['classification']:<14} {r['id']:<34} HTTP {r['http_status']} - {r['reason']}")
    if a.fail_on_leak and any(r["classification"] == "LEAK" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
