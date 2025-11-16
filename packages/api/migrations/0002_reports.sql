alter table domains drop constraint domains_account_id_fkey,
  add constraint domains_account_id_fkey foreign key (account_id) references accounts(id) on delete cascade;

create table reports (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  reporter_org text not null,
  report_id text not null,
  begin_at timestamptz not null,
  end_at timestamptz not null,
  policy_published jsonb not null,
  raw_object_key text,
  received_at timestamptz not null default now(),
  unique (domain_id, reporter_org, report_id)
);

create index reports_domain_begin on reports (domain_id, begin_at desc);

create table report_records (
  id bigint generated always as identity primary key,
  account_id uuid not null references accounts(id) on delete cascade,
  report_id uuid not null references reports(id) on delete cascade,
  source_ip inet not null,
  count int not null,
  disposition text not null,
  dkim_aligned boolean not null,
  spf_aligned boolean not null,
  header_from text not null,
  envelope_from text,
  auth_results jsonb not null
);

create index report_records_report on report_records (report_id);
create index report_records_source on report_records (source_ip);

grant select, insert, update, delete on reports, report_records to rua_app, rua_worker;

select rua_protect('reports');
select rua_protect('report_records');
