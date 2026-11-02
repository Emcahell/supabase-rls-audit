# RLS, grants and related rules

Rules use four levels: **REQUIRED** (unless a justified exception), **PREFERRED** (default choice),
**OPTIONAL** (situational), **FORBIDDEN** (reject).

## Contents
1. The two-layer model
2. Policy rules
3. Patterns
4. Views
5. Functions
6. Storage
7. Roles and anonymous users
8. Not covered

## 1. The two-layer model

- Access through the Data API needs a **grant** to the role and, when RLS is on, a **policy**.
- RLS enabled with no policy means no access for non-bypass roles. RLS disabled plus a grant means
  full access for that role.
- Newer Supabase projects are moving to explicit exposure of objects, while older projects were granted
  access automatically to objects created in `public`. Check the current documentation for the
  project's behavior, and use `scripts/catalog_audit.sql` section 1 to see the real privileges.
- As the author understands it, tables created in the Dashboard Table Editor have RLS enabled by default and tables created with raw SQL do not. Verify for the project; do not rely on it.

| Level | Rule | Justification / exception |
|---|---|---|
| REQUIRED | RLS enabled on every table in an exposed schema | Exception: a table that is deliberately not exposed (no grants, or schema not exposed) |
| REQUIRED | No write grant to `anon` unless a policy deliberately allows it | RLS would be the only barrier |
| REQUIRED | Revoke default access when objects must not be public | Future objects inherit default privileges |

## 2. Policy rules

| Level | Rule | Why |
|---|---|---|
| REQUIRED | No `USING (true)` / `WITH CHECK (true)` for write commands reachable by `anon` or `public` | Anyone can modify data |
| REQUIRED | Do not authorize with `user_metadata` | Users can edit it. Use `app_metadata` or a server-managed table |
| REQUIRED | `UPDATE` policies need a matching `SELECT` policy | Without it, updates silently affect 0 rows |
| PREFERRED | Explicit `TO authenticated` (or the exact role) | A policy with no `TO` applies to every role including `anon` |
| PREFERRED | `(select auth.uid())` instead of bare `auth.uid()` | Evaluated once per statement (performance) |
| PREFERRED | Index columns used in policies | Avoids sequential scans per row check |
| PREFERRED | Separate policies per command | Clearer; avoids accidental `FOR ALL` breadth |
| OPTIONAL | `RESTRICTIVE` policies for cross-cutting rules (for example, MFA) | Combine with permissive ones deliberately |
| FORBIDDEN | Disabling RLS to make a feature work | Find and fix the blocking policy |

Exception for `true`: a `SELECT` policy on deliberately public data (a catalog, public posts) is
legitimate. Scope it to `SELECT` and ask the user to confirm the table is public.

## 3. Patterns

Own rows:
```sql
alter table public.notes enable row level security;
create policy "notes select own" on public.notes for select to authenticated
  using ((select auth.uid()) = owner);
create policy "notes insert own" on public.notes for insert to authenticated
  with check ((select auth.uid()) = owner);
create policy "notes update own" on public.notes for update to authenticated
  using ((select auth.uid()) = owner) with check ((select auth.uid()) = owner);
create policy "notes delete own" on public.notes for delete to authenticated
  using ((select auth.uid()) = owner);
```

Role from a trusted claim: `((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin'`.

Columns users must not change (for example `is_admin`): policies work on rows, not columns. Use column
privileges (`revoke update on ... ; grant update (col1, col2) on ...`) or keep such data in a table users
cannot write.

## 4. Views

A view runs with its owner's privileges and bypasses the RLS of its tables unless it is created with
`security_invoker = true` (PostgreSQL 15+). On older versions, do not expose such views to the API, or
put the filter inside the view. Materialized views are not subject to RLS: keep them out of exposed schemas.

## 5. Functions

| Level | Rule |
|---|---|
| REQUIRED | `SECURITY DEFINER` functions set `search_path` (for example `set search_path = ''`) and schema-qualify objects |
| REQUIRED | `REVOKE EXECUTE ... FROM public, anon` (and `authenticated` if not needed) for definer functions that must not be called from the API |
| PREFERRED | Put definer helpers in a schema that is not exposed through the API |

A definer function runs with its owner's rights, so an exposed one acts like a `service_role` call.
Supabase's own lints cover functions executable by `anon`/`authenticated`; use them as the base check.

## 6. Storage

- Access to objects is governed by policies on `storage.objects`; buckets can be public or private.
- A public bucket makes every object URL readable without auth: acceptable only for intentionally public assets.
- Policies should check `bucket_id` and, for user files, ownership (for example a folder named after the user id).
- The probe lists objects only; write protection for Storage is not covered in v0.1.

## 7. Roles and anonymous users

- `anon` is the role for requests without a signed-in user; `authenticated` for signed-in users.
- Supabase also offers anonymous sign-ins. As the author understands it, those users are `authenticated`
  with an `is_anonymous` claim, so `TO authenticated` policies reach them. **Verify in the current Auth
  documentation**, and check it before relying on `TO authenticated` as a "real account" barrier.
- `service_role` and secret keys bypass RLS by design: they belong only on trusted servers.

## 8. Not covered

Realtime authorization, Edge Function auth, GraphQL exposure, Auth provider settings, and database
extension risks. Mention them as out of scope in the report instead of implying they were checked.
