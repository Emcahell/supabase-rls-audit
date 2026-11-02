-- ILLUSTRATIVE AND INTENTIONALLY VULNERABLE. Fixture for docs and tests. Never deploy.

create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text,
  is_admin boolean not null default false
);
-- (1) no ENABLE ROW LEVEL SECURITY and (2) broad grant below.
grant all on public.profiles to anon;

create table public.notes (
  id bigint generated always as identity primary key,
  owner uuid not null,
  body text
);
alter table public.notes enable row level security;
-- (3) unconditional policy for every role, including anon
create policy "notes open" on public.notes for all using (true) with check (true);

create table public.invoices (
  id bigint generated always as identity primary key,
  tenant text not null,
  amount numeric not null
);
alter table public.invoices enable row level security;
-- (4) authorization based on user-editable metadata
create policy "tenant admin" on public.invoices for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- (5) view without security_invoker
create view public.invoice_totals as
  select tenant, sum(amount) as total from public.invoices group by tenant;

-- (6) SECURITY DEFINER function, no search_path, no REVOKE
create function public.promote_user(target uuid) returns void
language plpgsql security definer as $$
begin
  update public.profiles set is_admin = true where id = target;
end;
$$;

-- (7) public bucket
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
