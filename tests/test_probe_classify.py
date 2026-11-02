"""Tests for scripts/anon_probe.py.

IMPORTANT: the end-to-end tests run against a local SIMULATION of PostgREST/Storage responses
(tests/_helpers + the handler below). They verify the probe's logic, not Supabase itself.
"""
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from _helpers import make_jwt, make_sb_publishable, make_sb_secret
import anon_probe as ap
from _common import classify_key, is_probe_key_allowed, redact

SECRET_ROW_VALUE = "TOP-SECRET-ROW-VALUE-123"
RLS_MSG = 'new row violates row-level security policy for table "x"'


class SimHandler(BaseHTTPRequestHandler):
    log = []
    user_jwt = ""

    def log_message(self, *a):
        pass

    def _send(self, status, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        SimHandler.log.append((method, self.path, {k.lower(): v for k, v in self.headers.items()}))
        path = self.path.split("?")[0]
        name = path.rsplit("/", 1)[-1]
        denied_grant = {"code": "42501", "message": f"permission denied for table {name}"}
        if path.startswith("/rest/v1/rpc/"):
            if name == "open_fn":
                return self._send(200, None)
            if name == "closed_fn":
                return self._send(401, {"code": "42501", "message": f"permission denied for function {name}"})
            return self._send(404, {"code": "PGRST202", "message": "Could not find the function"})
        if path.startswith("/storage/v1/object/list/"):
            if name == "pub":
                return self._send(200, [{"name": "a.png"}])
            if name == "priv":
                return self._send(400, {"statusCode": "403", "error": "Unauthorized", "message": RLS_MSG})
            return self._send(404, {"message": "Bucket not found"})
        if method == "GET":
            routes = {
                "leaky": (200, [{"id": 1, "secret_col": SECRET_ROW_VALUE}]),
                "rls_empty": (200, []),
                "nogrant": (401, denied_grant),
                "missing": (404, {"code": "PGRST205", "message": "Could not find the table"}),
                "badkey": (401, {"message": "Invalid API key"}),
                "boom": (500, {"message": "oops"}),
            }
            if name == "mine":
                ok = self.headers.get("Authorization") == f"Bearer {SimHandler.user_jwt}"
                return self._send(200, [{"id": 7}] if ok else [])
            return self._send(*routes.get(name, (404, {"code": "PGRST205", "message": "nf"})))
        if method == "POST":
            routes = {
                "open_insert": (201, [{"id": 9}]),
                "rls_insert": (403, {"code": "42501", "message": RLS_MSG}),
                "nogrant_insert": (401, denied_grant),
                "strict_insert": (400, {"code": "23502", "message": "null value in column violates not-null"}),
            }
            return self._send(*routes.get(name, (404, {"code": "PGRST205", "message": "nf"})))
        if method == "PATCH":
            if name == "leaky":
                return self._send(200, [{"id": 1}])
            if name == "nogrant":
                return self._send(401, denied_grant)
            return self._send(200, [])
        if method == "DELETE":
            if name == "nogrant":
                return self._send(401, denied_grant)
            return self._send(200, [])
        return self._send(405, {"message": "method not allowed"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")


class ClassifierTests(unittest.TestCase):
    def test_read_matrix(self):
        c = ap.classify_read
        self.assertEqual(c(200, [{"id": 1}], "", "", None)[0], "LEAK")
        self.assertEqual(c(200, [], "", "", None)[0], "INCONCLUSIVE")          # never "safe" from 200 []
        self.assertEqual(c(200, [], "", "", False)[0], "INCONCLUSIVE")
        self.assertEqual(c(200, [], "", "", True)[0], "BLOCKED-RLS")
        self.assertEqual(c(401, None, "42501", "permission denied for table t", None)[0], "BLOCKED-GRANT")
        self.assertEqual(c(403, None, "", "permission denied for table t", None)[0], "BLOCKED-GRANT")
        self.assertEqual(c(401, None, "", "Invalid API key", None), ("INCONCLUSIVE", "AUTH",
                         "credential or gateway rejected the request; not a grant decision"))
        self.assertEqual(c(404, None, "PGRST205", "nf", None)[0], "INCONCLUSIVE")
        self.assertEqual(c(500, None, "", "", None)[0], "INCONCLUSIVE")
        self.assertEqual(c(None, None, "", "", None)[0], "INCONCLUSIVE")

    def test_read_expect_allow(self):
        c = ap.classify_read
        self.assertEqual(c(200, [{"id": 1}], "", "", True, "ALLOW")[0], "ALLOWED")
        self.assertEqual(c(200, [], "", "", True, "ALLOW")[0], "REGRESSION")
        self.assertEqual(c(200, [], "", "", None, "ALLOW")[0], "INCONCLUSIVE")
        self.assertEqual(c(401, None, "42501", "permission denied", None, "ALLOW")[0], "REGRESSION")

    def test_write_matrix(self):
        w = ap.classify_write
        self.assertEqual(w("insert", 201, [{"id": 1}], "", "", None)[0], "LEAK")
        self.assertEqual(w("insert", 403, None, "42501", RLS_MSG, None)[0], "BLOCKED-RLS")
        self.assertEqual(w("insert", 401, None, "42501", "permission denied for table t", None)[0], "BLOCKED-GRANT")
        self.assertEqual(w("update", 200, [{"id": 1}], "", "", None)[0], "LEAK")
        self.assertEqual(w("update", 200, [], "", "", True)[0], "BLOCKED-RLS")
        self.assertEqual(w("update", 200, [], "", "", None)[0], "INCONCLUSIVE")
        self.assertEqual(w("delete", 200, [], "", "", None)[0], "INCONCLUSIVE")
        cls, outcome, reason = w("insert_invalid", 400, None, "23502", "not-null", None)
        self.assertEqual((cls, outcome), ("INCONCLUSIVE", "CONSTRAINT"))
        self.assertIn("UNVERIFIED", reason)
        self.assertEqual(w("impossible_delete", 200, [], "", "", None)[1], "GRANT_OPEN")
        self.assertEqual(w("insert", 401, None, "", "Invalid API key", None)[0], "INCONCLUSIVE")

    def test_rpc_and_storage(self):
        self.assertEqual(ap.classify_rpc(200, "", "")[0], "LEAK")
        self.assertEqual(ap.classify_rpc(401, "42501", "permission denied for function f")[0], "BLOCKED-GRANT")
        self.assertEqual(ap.classify_rpc(404, "PGRST202", "nf")[0], "INCONCLUSIVE")
        self.assertEqual(ap.classify_storage_list(200, [{"name": "a"}], "", None)[0], "LEAK")
        self.assertEqual(ap.classify_storage_list(200, [], "", None)[0], "INCONCLUSIVE")
        self.assertEqual(ap.classify_storage_list(400, None, RLS_MSG, None)[0], "BLOCKED-RLS")

    def test_only_public_keys_are_allowed_for_probing(self):
        self.assertTrue(is_probe_key_allowed(make_jwt("anon")))
        self.assertTrue(is_probe_key_allowed(make_sb_publishable()))
        for bad in (make_jwt("service_role"), make_jwt("authenticated"), make_jwt("supabase_admin"),
                    make_sb_secret(), "plain-text", ""):
            self.assertFalse(is_probe_key_allowed(bad), bad[:8])
        self.assertEqual(classify_key(make_jwt("service_role")), "service_role")

    def test_redact_hides_key_shaped_text(self):
        tok = make_jwt("service_role")
        self.assertNotIn(tok, redact(f"connection failed for {tok}"))
        sec = make_sb_secret()
        self.assertNotIn(sec, redact(f"bad {sec}"))


class PlanTests(unittest.TestCase):
    CFG = {"tables": [{"name": "t", "insert_payload": {"a": 1}, "update": {"filter": "id=eq.1", "payload": {"a": 2}},
                       "delete": {"filter": "id=eq.1"}, "insert_invalid_payload": {}, "impossible_filter": "id=eq.0",
                       "noop_payload": {"a": 1}}],
           "rpc": [{"name": "f"}], "storage": [{"bucket": "b"}]}

    def kinds(self, mode, persist, unverified):
        return {p["kind"] for p in ap.build_plan(self.CFG, mode, persist, unverified)}

    def test_mode_b_default_is_read_only(self):
        self.assertEqual(self.kinds("B", False, False), {"read", "rpc", "storage"})

    def test_mode_b_unverified_writes_are_non_persisting_kinds_only(self):
        ks = self.kinds("B", False, True)
        self.assertTrue(ks <= {"read", "rpc", "storage", "insert_invalid", "impossible_update", "impossible_delete"})
        self.assertFalse(ks & {"insert", "update", "delete"})

    def test_persisting_writes_only_in_mode_a_with_flag(self):
        self.assertFalse(self.kinds("A", False, False) & {"insert", "update", "delete"})
        self.assertTrue({"insert", "update", "delete"} <= self.kinds("A", True, False))


class RolePlanTests(unittest.TestCase):
    CFG = {"tables": [{"name": "notes"},
                      {"name": "notes", "role": "authenticated", "expect": "ALLOW"}]}

    def test_entries_run_only_for_their_role(self):
        anon = ap.build_plan(self.CFG, "B", False, False, "anon")
        auth = ap.build_plan(self.CFG, "B", False, False, "authenticated")
        self.assertEqual([(p["id"], p["expect"]) for p in anon], [("read:notes", "DENY")])
        self.assertEqual([(p["id"], p["expect"]) for p in auth], [("read:notes", "ALLOW")])

    def test_duplicate_ids_in_one_run_are_rejected(self):
        with self.assertRaises(ValueError):
            ap.build_plan({"tables": [{"name": "t"}, {"name": "t"}]}, "B", False, False)

    def test_shipped_example_config_is_valid_for_both_roles(self):
        import json
        from _helpers import ROOT
        cfg = json.loads((ROOT / "examples" / "probe-config.example.json").read_text())
        for role in ("anon", "authenticated"):
            ids = [p["id"] for p in ap.build_plan(cfg, "B", False, False, role)]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(ids)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), SimHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        SimHandler.log = []
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.anon = make_jwt("anon")
        SimHandler.user_jwt = make_jwt("authenticated", sub="test-user")
        self._env = dict(os.environ)
        for k in ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_USER_JWT"):
            os.environ.pop(k, None)
        os.environ["SUPABASE_ANON_KEY"] = self.anon

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def cfg(self, data):
        p = self.dir / "probe.json"
        p.write_text(json.dumps(data))
        return str(p)

    def run_probe(self, config, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ap.main(["--config", self.cfg(config), *args])
        return rc, out.getvalue(), err.getvalue()

    def results(self):
        return {r["id"]: r for r in json.loads((self.dir / "out.json").read_text())["results"]}

    READ_CFG = {"tables": [{"name": n} for n in ("leaky", "rls_empty", "nogrant", "missing", "badkey", "boom")]}

    # ---- consent gate
    def test_refuses_without_mode_or_confirmation_and_sends_nothing(self):
        for extra in ([], ["--mode", "B"], ["--confirm-authorized"]):
            rc, _, err = self.run_probe(self.READ_CFG, "--url", self.url, *extra)
            self.assertEqual(rc, 2)
            self.assertIn("REFUSING", err)
        self.assertEqual(SimHandler.log, [])

    def test_dry_run_needs_no_consent_and_sends_nothing(self):
        rc, out, _ = self.run_probe(self.READ_CFG, "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("nothing sent", out)
        self.assertEqual(SimHandler.log, [])

    def test_mode_a_remote_host_needs_staging_attestation(self):
        rc, _, err = self.run_probe(self.READ_CFG, "--mode", "A", "--confirm-authorized",
                                    "--url", "https://example-project.supabase.co")
        self.assertEqual(rc, 2)
        self.assertIn("staging", err)
        self.assertEqual(SimHandler.log, [])

    def test_flag_combinations_are_validated(self):
        rc, _, _ = self.run_probe(self.READ_CFG, "--mode", "B", "--allow-persisting-writes")
        self.assertEqual(rc, 2)
        rc, _, _ = self.run_probe(self.READ_CFG, "--mode", "A", "--include-unverified-write-probes")
        self.assertEqual(rc, 2)

    # ---- key restrictions
    def test_privileged_keys_are_refused_before_any_request(self):
        for bad in (make_jwt("service_role"), make_sb_secret(), make_jwt("supabase_admin"), "not-a-key"):
            os.environ["SUPABASE_ANON_KEY"] = bad
            rc, out, err = self.run_probe(self.READ_CFG, "--mode", "B", "--confirm-authorized", "--url", self.url)
            self.assertEqual(rc, 2, bad[:6])
            self.assertNotIn(bad, out + err)
        self.assertEqual(SimHandler.log, [])

    def test_publishable_key_sends_apikey_only_and_anon_jwt_sends_bearer(self):
        os.environ.pop("SUPABASE_ANON_KEY")
        pub = make_sb_publishable()
        os.environ["SUPABASE_PUBLISHABLE_KEY"] = pub
        self.run_probe({"tables": [{"name": "rls_empty"}]}, "--mode", "B", "--confirm-authorized",
                       "--url", self.url, "--out", str(self.dir / "out.json"), "--delay", "0")
        h = SimHandler.log[0][2]
        self.assertEqual(h.get("apikey"), pub)
        self.assertNotIn("authorization", h)
        os.environ.pop("SUPABASE_PUBLISHABLE_KEY")
        os.environ["SUPABASE_ANON_KEY"] = self.anon
        SimHandler.log = []
        self.run_probe({"tables": [{"name": "rls_empty"}]}, "--mode", "B", "--confirm-authorized",
                       "--url", self.url, "--out", str(self.dir / "out.json"), "--delay", "0")
        self.assertEqual(SimHandler.log[0][2].get("authorization"), f"Bearer {self.anon}")

    # ---- end to end
    def test_mode_b_read_probes_classification_and_no_data_leak_in_output(self):
        rc, out, _ = self.run_probe(self.READ_CFG, "--mode", "B", "--confirm-authorized", "--url", self.url,
                                    "--out", str(self.dir / "out.json"), "--delay", "0")
        self.assertEqual(rc, 0)
        res = self.results()
        self.assertEqual(res["read:leaky"]["classification"], "LEAK")
        self.assertEqual(res["read:leaky"]["columns"], ["id", "secret_col"])
        self.assertEqual(res["read:rls_empty"]["classification"], "INCONCLUSIVE")
        self.assertEqual(res["read:nogrant"]["classification"], "BLOCKED-GRANT")
        self.assertEqual(res["read:missing"]["classification"], "INCONCLUSIVE")
        self.assertEqual(res["read:badkey"]["classification"], "INCONCLUSIVE")
        self.assertEqual(res["read:boom"]["classification"], "INCONCLUSIVE")
        blob = (self.dir / "out.json").read_text() + out
        self.assertNotIn(SECRET_ROW_VALUE, blob)
        self.assertNotIn(self.anon, blob)
        meta = json.loads((self.dir / "out.json").read_text())["meta"]
        self.assertEqual(meta["mode"], "B")
        self.assertTrue(meta["consent"]["confirmed_authorized"])

    def test_mode_b_default_sends_no_writes_to_tables(self):
        cfg = {"tables": [{"name": "leaky", "insert_payload": {"a": 1}, "update": {"filter": "id=eq.1", "payload": {}},
                           "delete": {"filter": "id=eq.1"}}], "rpc": [{"name": "open_fn"}]}
        self.run_probe(cfg, "--mode", "B", "--confirm-authorized", "--url", self.url,
                       "--out", str(self.dir / "out.json"), "--delay", "0")
        methods = {(m, p.split("?")[0]) for m, p, _ in SimHandler.log}
        self.assertEqual(methods, {("GET", "/rest/v1/leaky"), ("GET", "/rest/v1/rpc/open_fn")})

    def test_mode_a_persisting_write_probes(self):
        cfg = {"tables": [
            {"name": "open_insert", "insert_payload": {"marker": "audit-probe"}},
            {"name": "rls_insert", "insert_payload": {"marker": "audit-probe"}},
            {"name": "nogrant_insert", "insert_payload": {"marker": "audit-probe"}},
            {"name": "leaky", "seed_expected": True, "update": {"filter": "id=eq.1", "payload": {"x": 1}}},
            {"name": "rls_empty", "seed_expected": True, "update": {"filter": "id=eq.1", "payload": {"x": 1}},
             "delete": {"filter": "id=eq.1"}},
            {"name": "nogrant", "delete": {"filter": "id=eq.1"}}]}
        self.run_probe(cfg, "--mode", "A", "--confirm-authorized", "--allow-persisting-writes",
                       "--url", self.url, "--out", str(self.dir / "out.json"), "--delay", "0")
        r = self.results()
        self.assertEqual(r["insert:open_insert"]["classification"], "LEAK")
        self.assertEqual(r["insert:rls_insert"]["classification"], "BLOCKED-RLS")
        self.assertEqual(r["insert:nogrant_insert"]["classification"], "BLOCKED-GRANT")
        self.assertEqual(r["update:leaky"]["classification"], "LEAK")
        self.assertEqual(r["update:rls_empty"]["classification"], "BLOCKED-RLS")
        self.assertEqual(r["delete:rls_empty"]["classification"], "BLOCKED-RLS")
        self.assertEqual(r["delete:nogrant"]["classification"], "BLOCKED-GRANT")

    def test_mode_b_unverified_write_probes(self):
        cfg = {"tables": [{"name": "strict_insert", "insert_invalid_payload": {"a": None}},
                          {"name": "rls_empty", "impossible_filter": "id=eq.0", "noop_payload": {"a": 1}},
                          {"name": "nogrant", "impossible_filter": "id=eq.0"}]}
        self.run_probe(cfg, "--mode", "B", "--include-unverified-write-probes", "--confirm-authorized",
                       "--url", self.url, "--out", str(self.dir / "out.json"), "--delay", "0")
        r = self.results()
        self.assertEqual(r["insert_invalid:strict_insert"]["classification"], "INCONCLUSIVE")
        self.assertIn("UNVERIFIED", r["insert_invalid:strict_insert"]["reason"])
        self.assertEqual(r["impossible_update:rls_empty"]["outcome"], "GRANT_OPEN")
        self.assertEqual(r["impossible_delete:nogrant"]["classification"], "BLOCKED-GRANT")

    def test_rpc_and_storage_probes(self):
        cfg = {"rpc": [{"name": "open_fn"}, {"name": "closed_fn"}],
               "storage": [{"bucket": "pub"}, {"bucket": "priv"}]}
        self.run_probe(cfg, "--mode", "B", "--confirm-authorized", "--url", self.url,
                       "--out", str(self.dir / "out.json"), "--delay", "0")
        r = self.results()
        self.assertEqual(r["rpc:open_fn"]["classification"], "LEAK")
        self.assertEqual(r["rpc:closed_fn"]["classification"], "BLOCKED-GRANT")
        self.assertEqual(r["storage:pub"]["classification"], "LEAK")
        self.assertEqual(r["storage:priv"]["classification"], "BLOCKED-RLS")

    def test_authenticated_regression_probe(self):
        os.environ["SUPABASE_USER_JWT"] = SimHandler.user_jwt
        cfg = {"tables": [{"name": "mine", "role": "authenticated", "expect": "ALLOW", "seed_expected": True}]}
        self.run_probe(cfg, "--mode", "B", "--confirm-authorized", "--role", "authenticated", "--url", self.url,
                       "--out", str(self.dir / "out.json"), "--delay", "0")
        self.assertEqual(self.results()["read:mine"]["classification"], "ALLOWED")
        # a signed-in flow whose token stops working (here: an anon-style call) is reported as a regression
        os.environ.pop("SUPABASE_USER_JWT")
        cfg_anon = {"tables": [{"name": "mine", "expect": "ALLOW", "seed_expected": True}]}
        self.run_probe(cfg_anon, "--mode", "B", "--confirm-authorized", "--url", self.url,
                       "--out", str(self.dir / "out.json"), "--delay", "0")
        self.assertEqual(self.results()["read:mine"]["classification"], "REGRESSION")

    def test_authenticated_role_refuses_privileged_jwt(self):
        os.environ["SUPABASE_USER_JWT"] = make_jwt("service_role")
        rc, _, err = self.run_probe(self.READ_CFG, "--mode", "B", "--confirm-authorized", "--role", "authenticated",
                                    "--url", self.url)
        self.assertEqual(rc, 2)
        self.assertEqual(SimHandler.log, [])

    def test_max_requests_cap(self):
        rc, _, err = self.run_probe(self.READ_CFG, "--mode", "B", "--confirm-authorized", "--url", self.url,
                                    "--max-requests", "2")
        self.assertEqual(rc, 2)
        self.assertEqual(SimHandler.log, [])

    def test_fail_on_leak_exit_code(self):
        rc, _, _ = self.run_probe({"tables": [{"name": "leaky"}]}, "--mode", "B", "--confirm-authorized",
                                  "--url", self.url, "--delay", "0", "--fail-on-leak")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
