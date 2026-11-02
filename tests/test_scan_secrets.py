import json
import tempfile
import unittest
from pathlib import Path

from _helpers import make_jwt, make_sb_publishable, make_sb_secret  # noqa: F401  (also sets sys.path)
import scan_secrets as ss


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def scan(root: Path):
    findings, _ = ss.scan_tree(root, 10 * 1024 * 1024)
    return findings


def rules(findings):
    return {f["rule"] for f in findings}


class ScanSecretsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_service_role_jwt_is_critical_and_masked(self):
        tok = make_jwt("service_role")
        write(self.root, "src/server.ts", f"const key = '{tok}'\n")
        fs = scan(self.root)
        crit = [f for f in fs if f["rule"] == "SB001"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "CRITICAL")
        self.assertNotIn(tok, json.dumps(fs))
        self.assertIn("len=", crit[0]["masked"])

    def test_anon_and_publishable_are_info_only(self):
        write(self.root, "a.ts", f"k='{make_jwt('anon')}'\nj='{make_sb_publishable()}'\n")
        fs = scan(self.root)
        self.assertEqual(rules(fs), {"SB004", "SB005"})
        self.assertTrue(all(f["severity"] == "INFO" for f in fs))

    def test_sb_secret_is_critical_and_never_printed(self):
        tok = make_sb_secret()
        write(self.root, "x.env.txt", f"KEY={tok}\n")
        fs = scan(self.root)
        self.assertIn("SB002", rules(fs))
        self.assertNotIn(tok, json.dumps(fs))
        self.assertNotIn(tok, ss.render_text({"files_scanned": 1, "findings": fs}))

    def test_identifiers_that_merely_start_with_the_prefix_are_not_keys(self):
        write(self.root, "a.py", "def sb_" + "secret_loader_function_name(): pass\n"
                                   "x = sb_" + "publishable_client_factory_name\n")
        self.assertEqual(scan(self.root), [])

    def test_build_artifact_is_flagged_as_publicly_exposed(self):
        write(self.root, ".next/static/chunk.js", f"var k=\"{make_jwt('service_role')}\";")
        f = [x for x in scan(self.root) if x["rule"] == "SB001"][0]
        self.assertIn("build artifact", f["note"])

    def test_public_prefixed_secret_variable_names(self):
        write(self.root, ".env.example", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=placeholder\n")
        write(self.root, "src/a.ts", "const a = process.env." + "VITE_SECRET_THING;\n")
        write(self.root, "ok.env.txt", "NEXT_PUBLIC_SUPABASE_ANON_KEY=abc\n")
        fs = [f for f in scan(self.root) if f["rule"] == "SB007"]
        files = {f["file"] for f in fs}
        self.assertIn(".env.example", files)       # name alone is the problem, even in an example file
        self.assertIn("src/a.ts", files)
        self.assertNotIn("ok.env.txt", files)

    def test_database_url(self):
        pw = "hunter2-real-password"
        remote = "postgres" + "ql://postgres:" + pw + "@db.abcdefgh.supabase.co:5432/postgres"
        placeholder = "postgres" + "ql://postgres:[YOUR-PASSWORD]@db.abcdefgh.supabase.co:5432/postgres"
        local = "postgres" + "ql://postgres:postgres@127.0.0.1:54322/postgres"
        write(self.root, "a.txt", remote + "\n")
        write(self.root, "b.txt", placeholder + "\n")
        write(self.root, "c.txt", local + "\n")
        fs = [f for f in scan(self.root) if f["rule"] == "SB006"]
        self.assertEqual({f["file"] for f in fs}, {"a.txt"})
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertNotIn(pw, json.dumps(fs))

    def test_ignore_marker(self):
        write(self.root, "a.ts", f"k='{make_jwt('service_role')}' // supabase-audit:ignore\n")
        self.assertEqual(scan(self.root), [])

    def test_env_file_not_ignored_and_ignored(self):
        write(self.root, ".env.local", "FOO=bar\n")
        self.assertIn("SB008", rules(scan(self.root)))
        write(self.root, ".gitignore", ".env*\n")
        self.assertNotIn("SB008", rules(scan(self.root)))

    def test_env_template_files_are_not_reported_as_env_files(self):
        write(self.root, ".env.example", "FOO=bar\n")
        self.assertNotIn("SB008", rules(scan(self.root)))

    def test_use_client_with_service_role_reference(self):
        write(self.root, "app/page.tsx", "'use client'\nconst x = SERVICE_ROLE_THING\n")
        self.assertIn("SB009", rules(scan(self.root)))

    def test_non_supabase_jwt_like_text_is_ignored(self):
        write(self.root, "a.txt", "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.c2lnbmF0dXJlLXZhbHVl\n")
        self.assertEqual(scan(self.root), [])

    def test_binary_files_skipped(self):
        p = self.root / "bin.dat"
        p.write_bytes(b"\x00\x01" + make_jwt("service_role").encode())
        self.assertEqual(scan(self.root), [])

    def test_git_history_diff_scanning_is_pure_and_masked(self):
        tok = make_jwt("service_role")
        diff = ["commit abcdef1234567890", "+++ b/config.ts", f"+const k = '{tok}'", "-removed line"]
        fs = ss.scan_diff_lines(diff)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["rule"], "SB001")
        self.assertIn("config.ts@abcdef12", fs[0]["file"])
        self.assertNotIn(tok, json.dumps(fs))

    def test_cli_json_and_exit_codes(self):
        write(self.root, "a.ts", f"k='{make_jwt('service_role')}'\n")
        out = self.root / "report.json"
        rc = ss.main([str(self.root), "--format", "json", "--out", str(out), "--fail-on", "high"])
        self.assertEqual(rc, 1)
        data = json.loads(out.read_text())
        self.assertEqual(data["findings"][0]["rule"], "SB001")
        clean = tempfile.TemporaryDirectory()
        try:
            write(Path(clean.name), "ok.txt", "nothing here\n")
            self.assertEqual(ss.main([clean.name, "--fail-on", "high"]), 0)
        finally:
            clean.cleanup()


if __name__ == "__main__":
    unittest.main()
