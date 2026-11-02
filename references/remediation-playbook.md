# Remediation playbook

## Contents
1. Ground rules
2. Order of operations
3. Writing the migration
4. Typical breakages
5. Rollback
6. Verification

## 1. Ground rules
- New migration file; never edit one that was already applied.
- Fix grants and RLS together in the same migration.
- Local or staging first. Production only after the user sees the exact statements and says yes.
- Do not weaken a control to unblock a feature. If a legitimate flow breaks, change the policy that blocks it.

## 2. Order of operations
1. Exposed privileged key: rotate (see `secrets-and-keys.md`).
2. Stop the bleeding: `enable row level security` on exposed tables; revoke write grants from `anon`.
3. Replace permissive policies with scoped ones.
4. Views (`security_invoker`), functions (`search_path`, `revoke execute`), buckets.
5. Re-probe, then run the regression probe for legitimate flows.

## 3. Writing the migration
- One statement per concern, commented with the finding it closes.
- Name policies descriptively and per command.
- Use `(select auth.uid())`, explicit `TO` roles, and add indexes for policy columns.
- Ask when intent is unclear (for example, is this table public?). Do not guess.
- See `examples/fixed-migration.sql`.

## 4. Typical breakages
| Symptom after the fix | Likely cause |
|---|---|
| Insert works but returns an error or nothing | `INSERT ... RETURNING` needs a `SELECT` policy too |
| Update returns success but nothing changes | No matching `SELECT` policy, or the `USING` predicate excludes the row |
| Everything is empty for signed-in users | Policy `TO` role mismatch, or the app calls with the anon role (user not signed in) |
| A view shows no rows | `security_invoker` now applies the caller's RLS to the underlying tables |
| A server job stopped working | It relied on anon access it should never have had: give it a server-side credential |
| A cross-table policy is slow | Missing index; wrap `auth.uid()` in `select` |

## 5. Rollback
Keep the inverse statements next to the migration for the user (re-disable RLS only as an emergency
measure and say so in the report, since it re-opens the exposure).

## 6. Verification
Follow SKILL.md Step 8. Status is `VERIFIED` only with the before/after probe, a regression probe, and
no `INCONCLUSIVE` on the fixed targets. Otherwise report `FIX-APPLIED` or `NOT-VERIFIED` and say why.
