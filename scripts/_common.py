#!/usr/bin/env python3
"""Shared helpers for supabase-rls-secrets-audit (Python 3 standard library only).

Responsibilities:
  * mask secrets so raw values never reach reports, logs or terminals
  * classify Supabase keys (secret / publishable / service_role / anon / ...)
  * decide which keys are acceptable for probing (publishable or anon ONLY)
"""
from __future__ import annotations

import base64
import json
import re

TOOL_VERSION = "0.1.0"

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}")
SB_SECRET_RE = re.compile(r"sb_secret_[A-Za-z0-9_-]{10,}")
SB_PUBLISHABLE_RE = re.compile(r"sb_publishable_[A-Za-z0-9_-]{10,}")


def mask(value: str) -> str:
    """Return a safe, non-reversible description of a credential."""
    n = len(value)
    for prefix in ("sb_secret_", "sb_publishable_"):
        if value.startswith(prefix):
            return f"{prefix}…(len={n})"
    if n < 12:
        return f"***(len={n})"
    return f"{value[:4]}…(len={n})"


def mask_full(value: str) -> str:
    """Mask a value completely (used for passwords)."""
    return f"***(len={len(value)})"


def redact(text: str) -> str:
    """Replace any key-shaped substring in free text (errors, logs) by its mask."""
    text = JWT_RE.sub(lambda m: mask(m.group(0)), text)
    text = SB_SECRET_RE.sub(lambda m: mask(m.group(0)), text)
    text = SB_PUBLISHABLE_RE.sub(lambda m: mask(m.group(0)), text)
    return text


def _b64url_decode(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def decode_jwt_payload(token: str):
    """Decode (WITHOUT verifying) a JWT payload. Classification only, never auth."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def classify_key(value: str) -> str:
    """One of: secret, publishable, service_role, anon, authenticated, other_jwt, unknown."""
    v = value.strip()
    if v.startswith("sb_secret_"):
        return "secret"
    if v.startswith("sb_publishable_"):
        return "publishable"
    if v.startswith("eyJ"):
        payload = decode_jwt_payload(v)
        if payload is None:
            return "unknown"
        role = payload.get("role")
        if role in ("service_role", "anon", "authenticated"):
            return role
        return "other_jwt"
    return "unknown"


def is_probe_key_allowed(value: str) -> bool:
    """Probes may only use public-by-design keys."""
    return classify_key(value) in ("publishable", "anon")
