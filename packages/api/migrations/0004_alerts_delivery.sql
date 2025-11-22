-- Alert emails need an address. Copied from the JWT on each sign-in.
alter table accounts add column email text;

create table alerts (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  kind text not null check (kind in ('new_source', 'spoofing_source', 'policy_ready', 'ownership_lost', 'audit_finding')),
  dedup_key text not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  emailed_at timestamptz,
  webhook_delivered_at timestamptz,
  unique (domain_id, dedup_key)
);

create index alerts_domain_created on alerts (domain_id, created_at desc);

create table alert_webhooks (
  account_id uuid primary key references accounts(id) on delete cascade,
  url text not null,
  secret_enc bytea not null,
  key_id text not null,
  created_at timestamptz not null default now()
);

create table resend_connections (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  signing_secret_enc bytea not null,
  key_id text not null,
  created_at timestamptz not null default now()
);

create table delivery_stats (
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  day date not null,
  delivered int not null default 0,
  bounced int not null default 0,
  complained int not null default 0,
  primary key (domain_id, day)
);

grant select, insert, update, delete on alerts, alert_webhooks, resend_connections, delivery_stats to rua_app, rua_worker;

select rua_protect('alerts');
select rua_protect('alert_webhooks');
select rua_protect('resend_connections');
select rua_protect('delivery_stats');
