#!/usr/bin/env python3
"""Scan a working tree (and optionally Git history) for exposed Supabase credentials.

Read-only. Never prints or stores a raw secret: findings carry a masked form only.
Usage:
  python3 scan_secrets.py [PATH] [--format json|text] [--out FILE] [--fail-on high]
                          [--history] [--max-file-mb 10]
Inline allow marker: add `supabase-audit:ignore` on the same line to skip a line.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    JWT_RE, SB_PUBLISHABLE_RE, SB_SECRET_RE, TOOL_VERSION,
    decode_jwt_payload, mask, mask_full,
)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
             ".pytest_cache", ".turbo", ".cache"}
BUILD_DIRS = {".next", "dist", "build", "out", ".output", ".svelte-kit", ".nuxt", ".vercel"}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
IGNORE_MARKER = "supabase-audit:ignore"

PUBLIC_PREFIXES = r"(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC|GATSBY|PLASMO_PUBLIC)"
SECRET_MARKERS = r"(?:SERVICE_ROLE|SERVICE_KEY|SECRET|JWT_SECRET|DATABASE_URL|DB_URL|DB_PASSWORD)"
# Name only counts when it is an assignment or an env access, not prose in documentation.
ENV_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(" + PUBLIC_PREFIXES + r"_[A-Z0-9_]*" + SECRET_MARKERS + r"[A-Z0-9_]*)\s*[=:]")
ENV_ACCESS_RE = re.compile(
    r"(?:process\.env|import\.meta\.env)\.(" + PUBLIC_PREFIXES + r"_[A-Z0-9_]*" + SECRET_MARKERS + r"[A-Z0-9_]*)")
PG_URL_RE = re.compile(r"postgres(?:ql)?://([^:\s/@'\"]+):([^@\s'\"]+)@([^\s/'\"]+)", re.I)
PLACEHOLDER_PW_RE = re.compile(
    r"^\[?(your[-_ ]?password|password|pass|xxx+|\*+|changeme|<.*>|\$\{.*\}|\{.*\}|%s)\]?$", re.I)
LOCAL_HOST_RE = re.compile(r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)(:\d+)?$", re.I)
ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")
ENV_TEMPLATE_RE = re.compile(r"(example|sample|template|dist)$", re.I)
USE_CLIENT_RE = re.compile(r"""^\s*['"]use client['"]""", re.M)


def _looks_random(tail: str) -> bool:
    """Heuristic: a real key tail mixes digits/uppercase; a snake_case identifier does not.
    The exact key format is not verified by the author, so this may miss an unusual all-lowercase key."""
    return bool(re.search(r"[0-9A-Z]", tail))


def _finding(rule, severity, file, line, kind, masked, note):
    return {"rule": rule, "severity": severity, "file": file, "line": line,
            "kind": kind, "masked": masked, "note": note}


def scan_text(text: str, relpath: str, in_build: bool = False, max_findings: int = 200):
    """Scan text; return findings. Raw values are masked before leaving this function."""
    findings = []
    build_note = " Found inside a build artifact: treat as publicly exposed if deployed." if in_build else ""
    if USE_CLIENT_RE.search(text) and re.search(r"SERVICE_ROLE", text):
        findings.append(_finding(
            "SB009", "MEDIUM", relpath, 1, "service-role-reference-in-client-file", "",
            "File has a 'use client' directive and mentions SERVICE_ROLE (heuristic; verify)."))
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        for m in JWT_RE.finditer(line):
            payload = decode_jwt_payload(m.group(0))
            role = payload.get("role") if payload else None
            if role == "service_role":
                findings.append(_finding("SB001", "CRITICAL", relpath, lineno, "service_role-jwt",
                                         mask(m.group(0)),
                                         "Bypasses RLS. Rotate first, then remove from code." + build_note))
            elif role == "authenticated":
                findings.append(_finding("SB003", "MEDIUM", relpath, lineno, "user-session-jwt",
                                         mask(m.group(0)), "A user session token is committed; revoke the session."))
            elif role == "anon":
                findings.append(_finding("SB004", "INFO", relpath, lineno, "anon-jwt",
                                         mask(m.group(0)), "Public by design; its safety depends on RLS and grants."))
        for m in SB_SECRET_RE.finditer(line):
            if not _looks_random(m.group(0)[len("sb_secret_"):]):
                continue  # e.g. an identifier like sb_secret_loader_function, not a key
            findings.append(_finding("SB002", "CRITICAL", relpath, lineno, "sb_secret-key",
                                     mask(m.group(0)),
                                     "Secret key (bypasses RLS). Rotate first, then remove from code." + build_note))
        for m in SB_PUBLISHABLE_RE.finditer(line):
            if not _looks_random(m.group(0)[len("sb_publishable_"):]):
                continue
            findings.append(_finding("SB005", "INFO", relpath, lineno, "publishable-key",
                                     mask(m.group(0)), "Public by design."))
        for m in PG_URL_RE.finditer(line):
            user, pw, host = m.groups()
            if PLACEHOLDER_PW_RE.match(pw) or LOCAL_HOST_RE.match(host):
                continue
            sev = "HIGH" if "supabase" in host.lower() else "MEDIUM"
            findings.append(_finding("SB006", sev, relpath, lineno, "database-url-with-password",
                                     f"postgresql://{user}:{mask_full(pw)}@{host}",
                                     "Direct DB credentials bypass RLS. Rotate the database password." + build_note))
        for rx in (ENV_ASSIGN_RE, ENV_ACCESS_RE):
            m = rx.search(line)
            if m:
                findings.append(_finding("SB007", "HIGH", relpath, lineno, "secret-named-public-variable",
                                         m.group(1),
                                         "Variables with a public prefix are bundled into client code."))
                break
        if len(findings) >= max_findings:
            break
    return findings


def _gitignore_covers(root: Path, name: str) -> bool:
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    for raw in gi.read_text(errors="ignore").splitlines():
        pat = raw.strip().lstrip("/")
        if not pat or pat.startswith("#") or pat.startswith("!"):
            continue
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(name, pat.rstrip("/")):
            return True
    return False


def _git_tracked(root: Path, rel: str):
    """True/False if git can tell (read-only `git ls-files`), None if unavailable."""
    if not (root / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", "--", rel],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return None


def scan_tree(root: Path, max_file_bytes: int):
    findings, scanned = [], 0
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts) or not path.is_file():
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="ignore")
        rel = "/".join(rel_parts)
        in_build = any(p in BUILD_DIRS for p in rel_parts)
        file_findings = scan_text(text, rel, in_build)
        findings.extend(file_findings)
        scanned += 1
        if ENV_FILE_RE.match(path.name) and not ENV_TEMPLATE_RE.search(path.name):
            has_assignment = any(re.match(r"\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S", ln)
                                 for ln in text.splitlines() if not ln.lstrip().startswith("#"))
            if has_assignment:
                tracked = _git_tracked(root, rel)
                if tracked:
                    findings.append(_finding("SB008", "HIGH", rel, 1, "env-file-tracked-by-git", "",
                                             "Env file is tracked by Git; credentials may be in history."))
                elif not _gitignore_covers(root, path.name):
                    findings.append(_finding("SB008", "MEDIUM", rel, 1, "env-file-not-ignored", "",
                                             "Env file is not covered by .gitignore."))
    return findings, scanned


def scan_diff_lines(lines, max_findings=500):
    """Scan added lines of a `git log -p` stream. Pure function (testable without Git)."""
    findings, commit, path = [], "?", "?"
    for raw in lines:
        if raw.startswith("commit "):
            commit = raw.split()[1][:8] if len(raw.split()) > 1 else "?"
        elif raw.startswith("+++ b/"):
            path = raw[6:].strip()
        elif raw.startswith("+") and not raw.startswith("+++"):
            for f in scan_text(raw[1:], f"{path}@{commit}"):
                f["line"] = 0
                f["note"] += " (found in Git history)"
                findings.append(f)
        if len(findings) >= max_findings:
            break
    return findings


def scan_history(root: Path, max_bytes: int = 200_000_000):
    """OPTIONAL. Read-only `git log -p`; bounded by max_bytes."""
    if not (root / ".git").exists():
        return [], "no .git directory"
    proc = subprocess.Popen(["git", "-C", str(root), "log", "--all", "-p", "--no-color", "-U0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="ignore")
    total = 0

    def limited():
        nonlocal total
        for ln in proc.stdout:
            total += len(ln)
            if total > max_bytes:
                proc.kill()
                return
            yield ln.rstrip("\n")

    findings = scan_diff_lines(limited())
    proc.wait()
    note = "history scan truncated at max bytes" if total > max_bytes else "ok"
    return findings, note


def render_text(report) -> str:
    out = [f"supabase-rls-secrets-audit scan_secrets v{TOOL_VERSION}",
           f"files scanned: {report['files_scanned']}  findings: {len(report['findings'])}"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for f in [x for x in report["findings"] if x["severity"] == sev]:
            out.append(f"[{sev}] {f['rule']} {f['file']}:{f['line']} {f['kind']} {f['masked']} - {f['note']}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--format", choices=["json", "text"], default="text")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default=None)
    ap.add_argument("--history", action="store_true", help="also scan Git history (read-only, optional)")
    ap.add_argument("--max-file-mb", type=float, default=10.0)
    a = ap.parse_args(argv)
    root = Path(a.path).resolve()
    findings, scanned = scan_tree(root, int(a.max_file_mb * 1024 * 1024))
    history_note = None
    if a.history:
        hf, history_note = scan_history(root)
        findings.extend(hf)
    findings.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])
    report = {"tool": "scan_secrets", "version": TOOL_VERSION, "files_scanned": scanned,
              "history": history_note, "findings": findings}
    text = json.dumps(report, indent=2) if a.format == "json" else render_text(report)
    if a.out:
        Path(a.out).write_text(text + "\n")
    else:
        print(text)
    if a.fail_on:
        limit = SEVERITY_ORDER[a.fail_on.upper()]
        if any(SEVERITY_ORDER[f["severity"]] >= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
