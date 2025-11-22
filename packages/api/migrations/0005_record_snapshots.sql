create table record_snapshots (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  taken_at timestamptz not null default now(),
  records jsonb not null,
  findings jsonb not null
);

create index record_snapshots_domain_taken on record_snapshots (domain_id, taken_at desc);

grant select, insert, update, delete on record_snapshots to rua_app, rua_worker;
select rua_protect('record_snapshots');

create index reports_received_raw on reports (received_at) where raw_object_key is not null;
