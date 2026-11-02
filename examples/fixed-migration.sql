-- ILLUSTRATIVE FIX for examples/vulnerable-schema.sql, written as a NEW migration.
-- Review every statement against your real data model before applying; apply to local/staging first.

-- profiles: enable RLS, remove the broad grant, allow users to read/update only their own row
alter table public.profiles enable row level security;
revoke all on public.profiles from anon;
create policy "profiles read own" on public.profiles for select to authenticated
  using ((select auth.uid()) = id);
create policy "profiles update own" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
-- NOTE: is_admin must not be user-writable. Revoke column-level update or move it to a server-only table.

-- notes: replace the open policy with owner-scoped policies
drop policy "notes open" on public.notes;
revoke all on public.notes from anon;
create policy "notes select own" on public.notes for select to authenticated
  using ((select auth.uid()) = owner);
create policy "notes insert own" on public.notes for insert to authenticated
  with check ((select auth.uid()) = owner);
create policy "notes update own" on public.notes for update to authenticated
  using ((select auth.uid()) = owner) with check ((select auth.uid()) = owner);
create policy "notes delete own" on public.notes for delete to authenticated
  using ((select auth.uid()) = owner);

-- invoices: authorize with app_metadata (not user-editable) instead of user_metadata
drop policy "tenant admin" on public.invoices;
create policy "tenant admin" on public.invoices for select to authenticated
  using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');

-- view: evaluate underlying RLS as the caller (PostgreSQL 15+)
alter view public.invoice_totals set (security_invoker = true);

-- function: pin search_path and remove default execute rights
create or replace function public.promote_user(target uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.profiles set is_admin = true where id = target;
end;
$$;
revoke execute on function public.promote_user(uuid) from public, anon, authenticated;

-- bucket: private unless the assets are intentionally public
update storage.buckets set public = false where id = 'avatars';
