"""Test helpers. Tokens are generated at runtime so the repository never contains key-like strings."""
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(role: str, **extra) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"iss": "supabase", "role": role, **extra}).encode())
    return f"{header}.{payload}.{_b64(b'fake-signature-for-tests-only-0123456789')}"


def make_sb_secret() -> str:
    return "sb_" + "secret_" + "A1b2C3d4E5f6G7h8I9j0"


def make_sb_publishable() -> str:
    return "sb_" + "publishable_" + "K1l2M3n4O5p6Q7r8S9t0"
