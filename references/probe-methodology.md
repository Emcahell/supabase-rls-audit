# Probe methodology

How `scripts/anon_probe.py` tests a project, how to read it, and what it cannot tell you.
Read this before building a `probe.json`.

## Contents
1. Modes A and B
2. Config format
3. What each probe sends
4. Classification
5. Why empty results are not proof
6. Cleaning up after mode A
7. Unverified points and known gaps

## 1. Modes A and B

The user chooses the mode (see SKILL.md, Step 0). The script refuses to send anything without
`--mode` and `--confirm-authorized`.

| | Mode A: local or staging | Mode B: project URL (incl. production) |
|---|---|---|
| Reads | yes | yes |
| RPC | `POST` with the given args | `GET` only (read-only intent) |
| Storage listing | yes | yes |
| Writes that persist data | only with `--allow-persisting-writes` and disposable rows | never |
| Non-persisting write probes | n/a | only with `--include-unverified-write-probes` (partly conclusive) |
| Host check | local hosts, or remote with `--staging-ack` | any |

Mode B cannot confirm that writes are blocked by RLS. Report write protection as `NOT-VERIFIED`
for mode B runs, and rely on the static audit plus the catalog audit (`anon_insert`,
`anon_update`, `anon_delete` privileges) until a mode A run is possible.

Every mode keeps these limits: publishable or anon key only, no row values or credentials in
output, `--max-requests` (default 100) and a delay between requests (default 0.2 s).

## 2. Config format

```json
{
  "tables": [
    {
      "name": "notes",
      "schema": "public",
      "expect": "DENY",
      "seed_expected": true,
      "select": "id",
      "insert_payload": {"body": "audit-probe-marker"},
      "update": {"filter": "id=eq.1", "payload": {"body": "audit-probe-marker"}},
      "delete": {"filter": "id=eq.1"},
      "insert_invalid_payload": {"body": null},
      "impossible_filter": "id=eq.-1",
      "noop_payload": {"body": "x"}
    }
  ],
  "rpc": [{"name": "promote_user", "args": {}, "expect": "DENY"}],
  "storage": [{"bucket": "avatars", "expect": "DENY", "seed_expected": null}]
}
```

- `role`: `anon` (default) or `authenticated`. An entry runs only in a run with the same `--role`, so the same
  table can appear twice (once per role) without clashing. Probe ids must be unique within a run; duplicates are rejected.
  Run and compare each role separately (anon before/after, authenticated before/after).
- `expect`: `DENY` (default) for data the role should not see; `ALLOW` for a legitimate flow
  (use `role: authenticated`, run with `--role authenticated` and a **test** user's JWT) so regressions are caught.
- `seed_expected`: `true` only when a row is known to exist **and** the role under test should not
  see it. Leave it out when unknown; an empty result is then `INCONCLUSIVE`.
- `insert_payload`, `update`, `delete`: used only in mode A with `--allow-persisting-writes`.
  Put a recognizable marker in the payload so rows can be found and removed.
- `insert_invalid_payload`: valid types, but violating a NOT NULL or CHECK constraint. A type error
  (wrong type for a column) is rejected before any policy runs and tells you nothing.
- `impossible_filter` and `noop_payload`: used only by the optional mode B probes. The filter must
  match no row in any state of the table.
- `--dry-run` prints the exact plan and sends nothing.

## 3. What each probe sends

- Read: `GET /rest/v1/<table>?select=<cols>&limit=1`. Only the row count and column names are kept.
- Insert / update / delete (mode A): `POST` / `PATCH` / `DELETE` with `Prefer: return=representation`
  so the number of affected rows is visible.
- RPC: mode A `POST /rest/v1/rpc/<fn>`; mode B `GET` with args as query parameters.
- Storage: `POST /storage/v1/object/list/<bucket>` with `{"prefix": "", "limit": 1}`.
- Headers: `apikey: <key>`; `Authorization: Bearer <jwt>` for a legacy anon JWT or a test user JWT.

## 4. Classification

| Situation (role under test) | Result |
|---|---|
| Rows returned | `LEAK` (`ALLOWED` when `expect: ALLOW`) |
| `200 []` and `seed_expected: true` | `BLOCKED-RLS` |
| `200 []` and `seed_expected` unknown or false | `INCONCLUSIVE` |
| Error 42501 "permission denied" | `BLOCKED-GRANT` |
| Error mentioning row-level security | `BLOCKED-RLS` |
| `401`/`403` without a permission error (bad key, gateway) | `INCONCLUSIVE` (credential problem, not a grant decision) |
| `404` (not found / not exposed) | `INCONCLUSIVE` (check name and schema) |
| Timeout, 5xx, other | `INCONCLUSIVE` |
| Write succeeded | `LEAK` |
| Update/delete with no affected rows, row known to exist | `BLOCKED-RLS`; otherwise `INCONCLUSIVE` |
| `ALLOW` probe denied or empty with a known row | `REGRESSION` |

## 5. Why empty results are not proof

- A `SELECT` that RLS filters returns `200` with `[]`, exactly like an empty table.
- An `UPDATE` or `DELETE` that RLS filters returns success with no rows (or `204`), not an error.
- So a `200` alone proves nothing in either direction. To turn `INCONCLUSIVE` into evidence:
  seed a disposable row (mode A), or compare with a privileged row count on a local/staging
  database (`scripts/catalog_audit.sql`, section 7). Never use a privileged key for the probe itself.

## 6. Cleaning up after mode A

The probe has no privileged key, so it cannot clean up. Rows created by `insert` probes carry your
marker. Remove them with a privileged connection to the **local/staging** database, or reset the
local database (`supabase db reset`). Never run persisting probes against data you cannot recreate.

## 7. Unverified points and known gaps

These were not executed against a real Supabase project by the author. Confirm them before relying on them.

1. **Invalid-insert ordering (mode B optional probe).** The idea assumes the RLS `WITH CHECK` runs
   before constraint validation. A policy or grant error is conclusive; a constraint error is reported
   only as `INCONCLUSIVE` with a possible-gap hint.
2. **GET on RPC.** Mode B relies on PostgREST rejecting GET calls to volatile functions. Verify in
   the PostgREST documentation for your version before treating mode B RPC probes as side-effect free.
3. **Storage API shape.** The listing request and its error messages follow the documented Storage
   API as the author understands it; whether a publishable key alone is accepted there is unconfirmed.
4. **Status mapping.** Permission errors are recognized by code 42501 and message text, not by HTTP
   status alone, because the status for anon versus authenticated differs.
5. **Not covered in v0.1:** Realtime, Edge Functions, GraphQL, custom schemas beyond the `schema`
   field, and the OpenAPI document exposure.
