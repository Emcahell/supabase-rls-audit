-- supabase-rls-secrets-audit :: catalog_audit.sql
-- READ-ONLY catalog queries. Run with psql against a database YOU own:
--   psql "$DATABASE_URL" -f scripts/catalog_audit.sql
-- STATUS: written against documented PostgreSQL catalogs but NOT EXECUTED in the build
-- environment (no PostgreSQL available there). Review the output critically.
-- Complements, and does not replace, the official Supabase Security Advisor / splinter lints.
-- Edit the schema lists below if your project exposes schemas other than public.

begin read only;

-- 1) Tables and views in the exposed schema: RLS state and API-role privileges.
--    Look for: rls_enabled = false with any anon_* / authenticated_* privilege = true.
select n.nspname                                   as schema,
       c.relname                                   as name,
       case c.relkind when 'r' then 'table' when 'p' then 'partitioned table'
                      when 'v' then 'view'  when 'm' then 'materialized view'
                      when 'f' then 'foreign table' end as kind,
       c.relrowsecurity                            as rls_enabled,
       c.relforcerowsecurity                       as rls_forced,
       has_table_privilege('anon', c.oid, 'SELECT')          as anon_select,
       has_table_privilege('anon', c.oid, 'INSERT')          as anon_insert,
       has_table_privilege('anon', c.oid, 'UPDATE')          as anon_update,
       has_table_privilege('anon', c.oid, 'DELETE')          as anon_delete,
       has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select,
       has_table_privilege('authenticated', c.oid, 'INSERT') as auth_insert,
       has_table_privilege('authenticated', c.oid, 'UPDATE') as auth_update,
       has_table_privilege('authenticated', c.oid, 'DELETE') as auth_delete
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname in ('public')
  and c.relkind in ('r', 'p', 'v', 'm', 'f')
order by n.nspname, c.relname;

-- 2) Policies, with quick flags for the usual mistakes.
select p.schemaname, p.tablename, p.policyname, p.permissive, p.roles, p.cmd,
       p.qual, p.with_check,
       (lower(coalesce(p.qual, ''))       in ('true', '(true)')
        or lower(coalesce(p.with_check, '')) in ('true', '(true)'))           as is_unconditional,
       ((coalesce(p.qual, '') || ' ' || coalesce(p.with_check, '')) ilike '%user_metadata%') as uses_user_metadata,
       (p.roles @> array['anon']::name[] or p.roles @> array['public']::name[]) as targets_anon
from pg_policies p
where p.schemaname in ('public', 'storage')
order by p.schemaname, p.tablename, p.policyname;

-- 3) Views: Postgres 15+ honours security_invoker; without it a view bypasses the RLS of its tables.
select n.nspname as schema, c.relname as view_name,
       exists (select 1 from unnest(coalesce(c.reloptions, '{}'::text[])) as o
               where o in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1')) as security_invoker
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v' and n.nspname in ('public')
order by 1, 2;

-- 4) Functions in the exposed schema (extension-owned functions excluded).
--    Look for: security_definer = true AND anon_can_execute = true, or config without search_path.
select n.nspname as schema, p.proname as function_name,
       pg_get_function_identity_arguments(p.oid) as args,
       p.prosecdef as security_definer,
       p.proconfig as config,
       has_function_privilege('anon', p.oid, 'EXECUTE')          as anon_can_execute,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated_can_execute
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('public')
  and p.prokind = 'f'
  and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
order by p.prosecdef desc, n.nspname, p.proname;

-- 5) Default privileges: what future objects will be granted automatically.
select pg_get_userbyid(d.defaclrole) as grantor, n.nspname as schema,
       d.defaclobjtype as object_type, d.defaclacl as acl
from pg_default_acl d
left join pg_namespace n on n.oid = d.defaclnamespace
order by 1, 2, 3;

-- 6) Storage buckets (requires the Supabase storage schema).
select id, name, public from storage.buckets order by name;

-- 7) To turn an INCONCLUSIVE empty probe result into evidence, count rows with a privileged
--    connection in LOCAL/STAGING only, e.g.:   select count(*) from public.<table>;

rollback;
