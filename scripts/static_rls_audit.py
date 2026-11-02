#!/usr/bin/env python3
"""Heuristic static audit of Supabase SQL migrations (RLS, policies, grants, views, functions).

Read-only. Results are STATIC HEURISTICS: tables may be secured outside the files you give
it (dashboard, other migrations). Confirm with scripts/catalog_audit.sql and the anon probe.

Usage:
  python3 static_rls_audit.py PATH [PATH...] [--format json|text] [--out FILE] [--fail-on high]
PATH may be a .sql file or a directory (searched recursively, files processed in sorted order,
which matches timestamp-named Supabase migrations).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import TOOL_VERSION  # noqa: E402

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
QNAME = IDENT + r'(?:\s*\.\s*' + IDENT + r')*'
WRITE_CMDS = {"insert", "update", "delete", "all"}


# --------------------------------------------------------------------------- parsing helpers
def split_statements(sql: str):
    """Split SQL into (start_line, statement) honoring comments, quotes and dollar quoting."""
    stmts, buf = [], []
    i, n, line, start_line = 0, len(sql), 1, 1

    def flush():
        nonlocal buf
        text = "".join(buf).strip()
        if text:
            stmts.append((start_line, " ".join(text.split())))
        buf = []

    def append(seg):
        nonlocal start_line, line
        if not buf:
            if not seg.strip():          # leading whitespace: count lines, keep buffer empty
                line += seg.count("\n")
                return
            start_line = line
        buf.append(seg)
        line += seg.count("\n")

    while i < n:
        c = sql[i]
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += sql.count("\n", i, j)
            i = j
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            append(sql[i:j + 1])
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$(?:[A-Za-z_]\w*)?\$", sql[i:i + 64])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                append(sql[i:j])
                i = j
                continue
        if c == ";":
            flush()
            i += 1
            continue
        append(c)
        i += 1
    flush()
    return stmts


def norm_name(raw: str, default_schema: str = "public") -> str:
    parts = [p.strip() for p in re.split(r'\.(?=(?:[^"]*"[^"]*")*[^"]*$)', raw)]
    cleaned = [p[1:-1] if p.startswith('"') and p.endswith('"') else p.lower() for p in parts]
    if len(cleaned) == 1:
        cleaned.insert(0, default_schema)
    return ".".join(cleaned[-2:])


def extract_paren(text: str, keyword_regex: str):
    """Return the balanced (...) content following keyword_regex, or None."""
    m = re.search(keyword_regex + r"\s*\(", text, re.I)
    if not m:
        return None
    depth, start = 1, m.end()
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:idx]
    return None


def is_true_expr(expr) -> bool:
    if expr is None:
        return False
    e = re.sub(r"\s+", "", expr.lower())
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1]
    return e in ("true", "1=1", "'t'::boolean", "true::boolean")


def parse_policy(stmt: str):
    m = re.match(r'create\s+policy\s+(' + IDENT + r')\s+on\s+(' + QNAME + r')(.*)$', stmt, re.I)
    if not m:
        return None
    name, table, rest = m.group(1).strip('"'), norm_name(m.group(2)), m.group(3)
    head = re.split(r"\b(?:using|with\s+check)\b", rest, maxsplit=1, flags=re.I)[0]
    restrictive = bool(re.search(r"\bas\s+restrictive\b", head, re.I))
    cmd_m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", head, re.I)
    cmd = cmd_m.group(1).lower() if cmd_m else "all"
    roles_m = re.search(r"\bto\s+(.+)$", head, re.I)
    roles = [r.strip().strip('"').lower() for r in roles_m.group(1).split(",") if r.strip()] if roles_m else []
    using = extract_paren(rest, r"\busing")
    check = extract_paren(rest, r"\bwith\s+check")
    return {"name": name, "table": table, "restrictive": restrictive, "cmd": cmd,
            "roles": roles, "using": using, "check": check}


def targets_anon(roles) -> bool:
    return (not roles) or "anon" in roles or "public" in roles


# --------------------------------------------------------------------------- auditing
def f(rule, severity, file, line, obj, message, confidence="static-heuristic"):
    return {"rule": rule, "severity": severity, "file": file, "line": line,
            "object": obj, "message": message, "confidence": confidence}


def audit_files(paths):
    tables, policies, views, functions = {}, [], {}, {}
    revoked_fn, findings, anon_grants, public_buckets = set(), [], {}, {}
    revoked_all_functions = False
    for path in paths:
        file = str(path)
        try:
            sql = path.read_text(errors="ignore")
        except OSError:
            continue
        for line, stmt in split_statements(sql):
            s = stmt
            low = s.lower()
            m = re.match(r'create\s+(temp(?:orary)?\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(' + QNAME + r')',
                         s, re.I)
            if m:
                if not (m.group(1) and m.group(1).lower().startswith("temp")):
                    key = norm_name(m.group(2))
                    if key.startswith("public."):
                        tables[key] = {"file": file, "line": line, "rls": False, "disabled_at": None}
                continue
            m = re.match(r'drop\s+table\s+(?:if\s+exists\s+)?(' + QNAME + r')', s, re.I)
            if m:
                tables.pop(norm_name(m.group(1)), None)
                continue
            m = re.match(r'alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(' + QNAME +
                         r')\s+(enable|disable|force|no\s+force)\s+row\s+level\s+security', s, re.I)
            if m:
                key, action = norm_name(m.group(1)), m.group(2).lower()
                if key in tables and action == "enable":
                    tables[key]["rls"] = True
                    tables[key]["disabled_at"] = None
                elif key in tables and action == "disable":
                    tables[key]["rls"] = False
                    tables[key]["disabled_at"] = f"{file}:{line}"
                continue
            if low.startswith("create policy"):
                p = parse_policy(s)
                if p:
                    p.update({"file": file, "line": line})
                    policies.append(p)
                continue
            m = re.match(r'drop\s+policy\s+(?:if\s+exists\s+)?(' + IDENT + r')\s+on\s+(' + QNAME + r')', s, re.I)
            if m:
                pname, tname = m.group(1).strip('"'), norm_name(m.group(2))
                policies = [p for p in policies if not (p["name"] == pname and p["table"] == tname)]
                continue
            m = re.match(r'create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?view\s+(' + QNAME + r')(.*)$',
                         s, re.I)
            if m:
                key = norm_name(m.group(1))
                head = re.split(r"\bas\b", m.group(2), maxsplit=1, flags=re.I)[0]
                inv = bool(re.search(r"security_invoker\s*=\s*(true|on|1|'true'|'on')", head, re.I))
                views[key] = {"file": file, "line": line, "invoker": inv}
                continue
            m = re.match(r'alter\s+view\s+(?:if\s+exists\s+)?(' + QNAME + r')\s+set\s*\((.*)\)', s, re.I)
            if m:
                key = norm_name(m.group(1))
                if key in views and re.search(r"security_invoker\s*=\s*(true|on|1)", m.group(2), re.I):
                    views[key]["invoker"] = True
                continue
            m = re.match(r'create\s+(?:or\s+replace\s+)?function\s+(' + QNAME + r')\s*\(', s, re.I)
            if m:
                key = norm_name(m.group(1))
                functions[key] = {"file": file, "line": line,
                                  "definer": bool(re.search(r"\bsecurity\s+definer\b", s, re.I)),
                                  "search_path": bool(re.search(r"\bset\s+search_path\b", s, re.I))}
                continue
            m = re.match(r'revoke\s+(?:all|execute)(?:\s+privileges)?\s+on\s+(function\s+(' + QNAME +
                         r')\s*(?:\([^)]*\))?|all\s+functions\s+in\s+schema\s+(\w+))\s+from\s+(.+)$', s, re.I)
            if m and re.search(r"\b(anon|public)\b", m.group(4), re.I):
                if m.group(2):
                    revoked_fn.add(norm_name(m.group(2)))
                elif (m.group(3) or "").lower() == "public":
                    revoked_all_functions = True
                continue
            m = re.match(r'grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+)$', s, re.I)
            if m and not low.startswith("grant usage"):
                privs, target, roles = m.group(1).lower(), m.group(2), m.group(3).lower()
                if re.search(r"\b(anon|public)\b", roles) and re.search(r"\b(all|insert|update|delete|truncate)\b", privs):
                    if "function" not in target.lower():
                        anon_grants[re.sub(r"^table\s+", "", target.strip().lower())] = (file, line)
                continue
            m = re.match(r'revoke\s+(.+?)\s+on\s+(.+?)\s+from\s+(.+)$', s, re.I)
            if m and re.search(r"\b(anon|public)\b", m.group(3), re.I) and "function" not in m.group(2).lower():
                anon_grants.pop(re.sub(r"^table\s+", "", m.group(2).strip().lower()), None)
                continue
            if low.startswith("alter default privileges") and re.search(r"\bgrant\b.*\bto\b.*\banon\b", low):
                findings.append(f("DEFAULT_PRIVS_TO_ANON", "MEDIUM", file, line, "default privileges",
                                  "Default privileges grant access to anon for future objects."))
                continue
            if "storage.buckets" in low and low.startswith("insert") and re.search(r"\btrue\b", low):
                idm = re.search(r"values\s*\(\s*'([^']+)'", s, re.I)   # Supabase convention: (id, name, public)
                public_buckets[idm.group(1) if idm else f"?{file}:{line}"] = (file, line)
                continue
            if low.startswith("update storage.buckets") and re.search(r"set\s+public\s*=\s*(false|'f'|0)", low):
                idm = re.search(r"\bid\s*=\s*'([^']+)'", s, re.I)
                if idm:
                    public_buckets.pop(idm.group(1), None)
                else:
                    public_buckets.clear()
                continue

    for bucket, (bfile, bline) in public_buckets.items():
        findings.append(f("PUBLIC_BUCKET_CANDIDATE", "MEDIUM", bfile, bline, f"storage.buckets:{bucket}",
                          "A bucket is created as public: any object URL is readable without auth. "
                          "Acceptable only for intentionally public assets."))
    for target, (gfile, gline) in anon_grants.items():
        findings.append(f("GRANT_WRITE_TO_ANON", "HIGH", gfile, gline, target,
                          "Write/ALL privileges granted to anon/public; RLS becomes the only barrier."))

    by_table = {}
    for p in policies:
        by_table.setdefault(p["table"], []).append(p)

    for key, t in tables.items():
        if not t["rls"]:
            extra = f" (explicitly disabled at {t['disabled_at']})" if t["disabled_at"] else ""
            findings.append(f("RLS_NOT_ENABLED", "HIGH", t["file"], t["line"], key,
                              "No ENABLE ROW LEVEL SECURITY found for a table in the public schema" + extra +
                              ". It may be enabled outside these files: confirm with catalog_audit.sql."))
        elif key not in by_table:
            findings.append(f("RLS_ENABLED_NO_POLICY", "INFO", t["file"], t["line"], key,
                              "RLS enabled with no policy: API access is denied for non-bypass roles "
                              "(safe, but check the app is not broken)."))

    for p in policies:
        obj = f"{p['table']}.{p['name']}"
        anon = targets_anon(p["roles"])
        exprs = [e for e in (p["using"], p["check"]) if e is not None]
        if not p["restrictive"]:
            if any(is_true_expr(e) for e in exprs):
                if anon and p["cmd"] in WRITE_CMDS:
                    findings.append(f("POLICY_TRUE_WRITE", "HIGH", p["file"], p["line"], obj,
                                      "Unconditional (true) write policy reachable by anon/public."))
                elif anon:
                    findings.append(f("POLICY_TRUE_SELECT", "MEDIUM", p["file"], p["line"], obj,
                                      "Unconditional (true) read policy reachable by anon/public. "
                                      "Only acceptable for intentionally public data."))
                elif p["cmd"] in ("update", "delete", "all"):
                    findings.append(f("POLICY_TRUE_WRITE", "HIGH", p["file"], p["line"], obj,
                                      "Unconditional (true) update/delete policy: any signed-in user can modify any row."))
                elif p["cmd"] == "insert":
                    findings.append(f("POLICY_TRUE_WRITE", "MEDIUM", p["file"], p["line"], obj,
                                      "Unconditional (true) insert check for signed-in users: confirm this is intended."))
                else:
                    findings.append(f("POLICY_TRUE_SELECT", "LOW", p["file"], p["line"], obj,
                                      "Every signed-in user can read every row: confirm this is intended."))
            elif anon and p["cmd"] in WRITE_CMDS and any(re.sub(r"\s+", "", e.lower()) != "false" for e in exprs):
                findings.append(f("POLICY_ANON_WRITE", "MEDIUM", p["file"], p["line"], obj,
                                  "Write policy applies to anon/public; review that the predicate really excludes anonymous callers."))
        if any(re.search(r"user_metadata|raw_user_meta_data", e, re.I) for e in exprs):
            findings.append(f("POLICY_USER_METADATA", "HIGH", p["file"], p["line"], obj,
                              "Policy relies on user_metadata, which users can edit. Use app_metadata or a server-managed table."))
        if not p["roles"]:
            findings.append(f("POLICY_NO_ROLE_CLAUSE", "LOW", p["file"], p["line"], obj,
                              "No TO clause: policy applies to every role including anon. Prefer an explicit TO."))
        for e in exprs:
            if re.search(r"auth\.uid\(\)", e, re.I) and not re.search(r"\(\s*select\s+auth\.uid\(\)\s*\)", e, re.I):
                findings.append(f("POLICY_AUTH_UID_NOT_WRAPPED", "INFO", p["file"], p["line"], obj,
                                  "Prefer (select auth.uid()) so Postgres evaluates it once per statement (performance)."))
                break

    for table, plist in by_table.items():
        has_select = any(p["cmd"] in ("select", "all") for p in plist)
        for p in plist:
            if p["cmd"] == "update" and not has_select:
                findings.append(f("UPDATE_WITHOUT_SELECT_POLICY", "LOW", p["file"], p["line"], f"{table}.{p['name']}",
                                  "UPDATE needs a matching SELECT policy to see rows; updates may silently affect 0 rows."))

    for key, v in views.items():
        if key.startswith("public.") and not v["invoker"]:
            findings.append(f("VIEW_NO_SECURITY_INVOKER", "MEDIUM", v["file"], v["line"], key,
                              "View runs with its owner's privileges and bypasses RLS of underlying tables "
                              "(Postgres 15+: WITH (security_invoker = true))."))

    for key, fn in functions.items():
        if key.startswith("public.") and fn["definer"]:
            if not fn["search_path"]:
                findings.append(f("DEFINER_NO_SEARCH_PATH", "MEDIUM", fn["file"], fn["line"], key,
                                  "SECURITY DEFINER function without SET search_path."))
            if key not in revoked_fn and not revoked_all_functions:
                findings.append(f("DEFINER_FUNCTION_EXPOSED", "MEDIUM", fn["file"], fn["line"], key,
                                  "SECURITY DEFINER function in an exposed schema with no REVOKE EXECUTE from anon/public "
                                  "in these files. It bypasses RLS if callable: confirm with catalog_audit.sql."))
    findings.sort(key=lambda x: (-SEVERITY_ORDER[x["severity"]], x["file"], x["line"]))
    return findings


def collect_sql(paths):
    out = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            out.extend(sorted(x for x in p.rglob("*.sql") if "node_modules" not in x.parts))
        elif p.is_file():
            out.append(p)
    return out


def render_text(report) -> str:
    lines = [f"supabase-rls-secrets-audit static_rls_audit v{TOOL_VERSION}",
             f"files: {report['files_scanned']}  findings: {len(report['findings'])}  (STATIC HEURISTICS)"]
    for x in report["findings"]:
        lines.append(f"[{x['severity']}] {x['rule']} {x['file']}:{x['line']} {x['object']} - {x['message']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--format", choices=["json", "text"], default="text")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default=None)
    a = ap.parse_args(argv)
    files = collect_sql(a.paths)
    findings = audit_files(files)
    report = {"tool": "static_rls_audit", "version": TOOL_VERSION, "files_scanned": len(files), "findings": findings}
    text = json.dumps(report, indent=2) if a.format == "json" else render_text(report)
    if a.out:
        Path(a.out).write_text(text + "\n")
    else:
        print(text)
    if a.fail_on:
        limit = SEVERITY_ORDER[a.fail_on.upper()]
        if any(SEVERITY_ORDER[x["severity"]] >= limit for x in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
