import tempfile
import unittest
from pathlib import Path

from _helpers import ROOT
import static_rls_audit as sa


def audit_sql(*chunks):
    d = tempfile.TemporaryDirectory()
    files = []
    for i, sql in enumerate(chunks):
        p = Path(d.name) / f"{i:03d}.sql"
        p.write_text(sql)
        files.append(p)
    try:
        return sa.audit_files(files)
    finally:
        d.cleanup()


def rules(findings):
    return {f["rule"] for f in findings}


def sev(findings, rule):
    return [f["severity"] for f in findings if f["rule"] == rule]


class SplitterTests(unittest.TestCase):
    def test_comments_quotes_and_dollar_quoting(self):
        sql = """-- a; comment
        select 'a;b'; /* x; y */
        create function f() returns int as $$ begin return 1; end; $$ language plpgsql;
        select 2;"""
        stmts = [s for _, s in sa.split_statements(sql)]
        self.assertEqual(len(stmts), 3)
        self.assertIn("$$ begin return 1; end; $$", stmts[1])

    def test_line_numbers(self):
        sql = "\n\nselect 1;\n\nselect 2;"
        self.assertEqual([l for l, _ in sa.split_statements(sql)], [3, 5])


class RuleTests(unittest.TestCase):
    def test_table_without_rls(self):
        fs = audit_sql("create table public.t (id int);")
        self.assertEqual(sev(fs, "RLS_NOT_ENABLED"), ["HIGH"])

    def test_rls_enabled_without_policy_is_info(self):
        fs = audit_sql("create table public.t (id int); alter table public.t enable row level security;")
        self.assertEqual(rules(fs), {"RLS_ENABLED_NO_POLICY"})

    def test_explicit_disable_is_reported(self):
        fs = audit_sql("create table t (id int); alter table t enable row level security;"
                       "alter table t disable row level security;")
        self.assertIn("explicitly disabled", [f for f in fs if f["rule"] == "RLS_NOT_ENABLED"][0]["message"])

    def test_true_policies_by_target(self):
        base = "create table public.t (id int); alter table public.t enable row level security;"
        self.assertEqual(sev(audit_sql(base + "create policy p on public.t for insert with check (true);"),
                             "POLICY_TRUE_WRITE"), ["HIGH"])
        self.assertEqual(sev(audit_sql(base + "create policy p on public.t for select using (true);"),
                             "POLICY_TRUE_SELECT"), ["MEDIUM"])
        self.assertEqual(sev(audit_sql(base + "create policy p on public.t for delete to authenticated using (true);"),
                             "POLICY_TRUE_WRITE"), ["HIGH"])
        self.assertEqual(sev(audit_sql(base + "create policy p on public.t for insert to authenticated with check (true);"),
                             "POLICY_TRUE_WRITE"), ["MEDIUM"])
        self.assertEqual(sev(audit_sql(base + "create policy p on public.t for select to authenticated using (true);"),
                             "POLICY_TRUE_SELECT"), ["LOW"])

    def test_restrictive_true_is_not_flagged(self):
        fs = audit_sql("create table public.t (id int); alter table public.t enable row level security;"
                       "create policy p on public.t as restrictive for all using (true);")
        self.assertNotIn("POLICY_TRUE_WRITE", rules(fs))

    def test_to_inside_expression_does_not_change_roles(self):
        fs = audit_sql("create table public.t (id int, note text); alter table public.t enable row level security;"
                       "create policy p on public.t for select to authenticated using (note = 'sent to everyone');")
        self.assertNotIn("POLICY_NO_ROLE_CLAUSE", rules(fs))

    def test_user_metadata(self):
        fs = audit_sql("create table public.t (id int); alter table public.t enable row level security;"
                       "create policy p on public.t for select to authenticated "
                       "using ((auth.jwt() -> 'user_metadata' ->> 'r') = 'x');")
        self.assertEqual(sev(fs, "POLICY_USER_METADATA"), ["HIGH"])

    def test_auth_uid_wrapped_vs_not(self):
        pre = "create table public.t (id int, o uuid); alter table public.t enable row level security;"
        bad = audit_sql(pre + "create policy p on public.t for select to authenticated using (auth.uid() = o);")
        good = audit_sql(pre + "create policy p on public.t for select to authenticated using ((select auth.uid()) = o);")
        self.assertIn("POLICY_AUTH_UID_NOT_WRAPPED", rules(bad))
        self.assertNotIn("POLICY_AUTH_UID_NOT_WRAPPED", rules(good))

    def test_view_invoker(self):
        bad = audit_sql("create view public.v as select 1;")
        good = audit_sql("create view public.v with (security_invoker = true) as select 1;")
        later = audit_sql("create view public.v as select 1; alter view public.v set (security_invoker = true);")
        self.assertIn("VIEW_NO_SECURITY_INVOKER", rules(bad))
        self.assertNotIn("VIEW_NO_SECURITY_INVOKER", rules(good))
        self.assertNotIn("VIEW_NO_SECURITY_INVOKER", rules(later))

    def test_definer_function_revoke(self):
        fn = ("create function public.f(a uuid) returns void language sql security definer "
              "set search_path = '' as $$ select 1 $$;")
        self.assertIn("DEFINER_FUNCTION_EXPOSED", rules(audit_sql(fn)))
        self.assertNotIn("DEFINER_NO_SEARCH_PATH", rules(audit_sql(fn)))
        revoked = fn + "revoke execute on function public.f(uuid) from public, anon;"
        self.assertNotIn("DEFINER_FUNCTION_EXPOSED", rules(audit_sql(revoked)))

    def test_grant_then_revoke_to_anon(self):
        t = "create table public.t (id int); alter table public.t enable row level security;"
        self.assertEqual(sev(audit_sql(t + "grant all on public.t to anon;"), "GRANT_WRITE_TO_ANON"), ["HIGH"])
        self.assertNotIn("GRANT_WRITE_TO_ANON", rules(audit_sql(t + "grant all on public.t to anon; revoke all on public.t from anon;")))
        self.assertNotIn("GRANT_WRITE_TO_ANON", rules(audit_sql(t + "grant select on public.t to anon;")))

    def test_public_bucket_then_private(self):
        ins = "insert into storage.buckets (id, name, public) values ('b', 'b', true);"
        self.assertIn("PUBLIC_BUCKET_CANDIDATE", rules(audit_sql(ins)))
        self.assertNotIn("PUBLIC_BUCKET_CANDIDATE",
                         rules(audit_sql(ins + "update storage.buckets set public = false where id = 'b';")))

    def test_update_without_select_policy(self):
        fs = audit_sql("create table public.t (id int); alter table public.t enable row level security;"
                       "create policy p on public.t for update to authenticated using (true);")
        self.assertIn("UPDATE_WITHOUT_SELECT_POLICY", rules(fs))


class ExampleFixtureTests(unittest.TestCase):
    def test_vulnerable_fixture_has_every_seeded_flaw(self):
        fs = sa.audit_files([ROOT / "examples" / "vulnerable-schema.sql"])
        expected = {"RLS_NOT_ENABLED", "GRANT_WRITE_TO_ANON", "POLICY_TRUE_WRITE", "POLICY_USER_METADATA",
                    "VIEW_NO_SECURITY_INVOKER", "DEFINER_NO_SEARCH_PATH", "DEFINER_FUNCTION_EXPOSED",
                    "PUBLIC_BUCKET_CANDIDATE"}
        self.assertTrue(expected <= rules(fs), expected - rules(fs))
        rls = [f for f in fs if f["rule"] == "RLS_NOT_ENABLED"][0]
        self.assertEqual(rls["line"], 3)

    def test_fixed_migration_clears_everything_when_applied_in_order(self):
        fs = sa.audit_files([ROOT / "examples" / "vulnerable-schema.sql", ROOT / "examples" / "fixed-migration.sql"])
        self.assertEqual(fs, [])


if __name__ == "__main__":
    unittest.main()
