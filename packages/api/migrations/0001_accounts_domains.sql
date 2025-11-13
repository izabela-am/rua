-- Roles. Passwords are set out of band (see README). Neither role bypasses RLS.
do $$
begin
  if not exists (select from pg_roles where rolname = 'rua_app') then
    create role rua_app login nobypassrls;
  end if;
  if not exists (select from pg_roles where rolname = 'rua_worker') then
    create role rua_worker login nobypassrls;
  end if;
end $$;

grant usage on schema public to rua_app, rua_worker;
alter default privileges in schema public grant select, insert, update, delete on tables to rua_app, rua_worker;
alter default privileges in schema public grant usage, select on sequences to rua_app, rua_worker;

-- The tenant predicate. current_setting returns '' rather than null once a
-- pooled connection has run a transaction that set the value locally, and
-- ''::uuid raises; nullif turns both cases into "no tenant", which matches no row.
create or replace function rua_account_id() returns uuid
  language sql stable
  as $$ select nullif(current_setting('app.account_id', true), '')::uuid $$;

-- Enables RLS on a tenant table: rua_app sees its own rows, rua_worker sees all.
create or replace function rua_protect(t regclass, col text default 'account_id') returns void
  language plpgsql
  as $$
begin
  execute format('alter table %s enable row level security', t);
  execute format('alter table %s force row level security', t);
  execute format(
    'create policy tenant_isolation on %s using (%I = rua_account_id()) with check (%I = rua_account_id())',
    t, col, col);
  execute format('create policy worker_all on %s to rua_worker using (true) with check (true)', t);
end $$;

create table accounts (
  id uuid primary key,
  created_at timestamptz not null default now()
);

create table domains (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id),
  name text not null,
  rua_local_part text not null unique,
  verify_token text not null,
  verified_at timestamptz,
  last_verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (account_id, name)
);

grant select, insert, update, delete on accounts, domains to rua_app, rua_worker;

select rua_protect('accounts', 'id');
select rua_protect('domains');

-- On Supabase, PostgREST exposes public tables to these roles. Rua does not use
-- PostgREST; revoke so RLS is not the only thing standing in the way.
do $$
begin
  if exists (select from pg_roles where rolname = 'anon') then
    revoke all on all tables in schema public from anon, authenticated;
    alter default privileges in schema public revoke all on tables from anon, authenticated;
  end if;
end $$;
