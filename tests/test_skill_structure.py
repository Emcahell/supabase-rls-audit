#!/usr/bin/env python3
"""Static validation of the skill package (stdlib only).

Run:  python3 -m unittest discover -s tests     (or this file alone with python3)
This is NOT the official `skills-ref validate` tool (not available offline). It re-checks the
rules documented in the Agent Skills specification as the author understands them.
"""
import py_compile
import re
import sys
import unittest
from pathlib import Path

from _helpers import ROOT
import scan_secrets

ALLOWED_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")


def parse_frontmatter(text):
    """Minimal parser for the subset used here: scalar `key: value` plus one nested `metadata:` map."""
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with '---'")
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("frontmatter is not closed")
    data, current = {}, None
    for raw in text[4:end].splitlines():
        if not raw.strip():
            continue
        if raw.startswith((" ", "\t")):
            if current is None:
                raise ValueError(f"unexpected indentation: {raw!r}")
            k, _, v = raw.strip().partition(":")
            data[current][k.strip()] = v.strip().strip('"')
            continue
        k, _, v = raw.partition(":")
        k, v = k.strip(), v.strip()
        if v == "":
            data[k] = {}
            current = k
        else:
            data[k] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v
            current = None
    body = text[end + 4:].lstrip("\n")
    return data, body


class SkillStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "SKILL.md").read_text()
        cls.meta, cls.body = parse_frontmatter(cls.text)

    def test_required_files_exist(self):
        for rel in ("SKILL.md", "README.md", "LICENSE", "SOURCES.md", "CHANGELOG.md"):
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_frontmatter_fields(self):
        self.assertTrue(set(self.meta) <= ALLOWED_KEYS, set(self.meta) - ALLOWED_KEYS)
        name = self.meta["name"]
        self.assertTrue(NAME_RE.match(name) and len(name) <= 64, name)
        self.assertTrue(0 < len(self.meta["description"]) <= 1024, len(self.meta["description"]))
        self.assertLessEqual(len(self.meta.get("compatibility", "")), 500)

    def test_name_matches_directory_when_installed(self):
        # Only enforce inside an installed-skills folder; a cloned repo may have any folder name.
        if ROOT.parent.name in ("skills",):
            self.assertEqual(ROOT.name, self.meta["name"])

    def test_skill_md_is_short_enough(self):
        self.assertLessEqual(len(self.text.splitlines()), 500)

    def test_description_mentions_trigger_and_gate(self):
        d = self.meta["description"].lower()
        for word in ("supabase", "rls", "secret", "anonymous", "mode"):
            self.assertIn(word, d)

    def test_relative_links_resolve(self):
        for md in ROOT.rglob("*.md"):
            for target in LINK_RE.findall(md.read_text()):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                path = target.split("#")[0]
                if path:
                    self.assertTrue((md.parent / path).exists(), f"{md.relative_to(ROOT)} -> {target}")

    def test_every_bundled_file_is_referenced_by_skill_or_readme(self):
        docs = (ROOT / "SKILL.md").read_text() + (ROOT / "README.md").read_text()
        for folder in ("references", "checklists", "examples", "scripts"):
            for f in (ROOT / folder).iterdir():
                if f.is_file() and not f.name.startswith("__") and not f.name.startswith("_"):
                    self.assertIn(f.name, docs, f"{folder}/{f.name} is not referenced")

    def test_paths_mentioned_in_skill_md_exist(self):
        for rel in set(re.findall(r"`((?:scripts|references|checklists|examples)/[\w./-]+)`", self.text)):
            self.assertTrue((ROOT / rel.rstrip("/")).exists(), rel)

    def test_python_files_compile(self):
        for py in list((ROOT / "scripts").glob("*.py")) + list((ROOT / "tests").glob("*.py")):
            py_compile.compile(str(py), doraise=True)

    def test_no_directories_are_empty(self):
        for d in ROOT.rglob("*"):
            if d.is_dir() and d.name != "__pycache__":
                self.assertTrue(any(d.iterdir()), f"empty directory: {d.relative_to(ROOT)}")

    def test_package_contains_no_credentials(self):
        """Dogfooding: the skill's own repository must be clean of real-looking secrets."""
        findings, scanned = scan_secrets.scan_tree(ROOT, 10 * 1024 * 1024)
        serious = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        self.assertGreater(scanned, 10)
        self.assertEqual(serious, [], serious)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], "-v"])
