-- Global cache: a PTR does not depend on who asks. No account_id, no RLS.
create table ip_intel (
  ip inet primary key,
  ptr text,
  ptr_confirmed boolean not null default false,
  asn int,
  as_name text,
  provider text,
  refreshed_at timestamptz not null
);

grant select on ip_intel to rua_app;
grant select, insert, update, delete on ip_intel to rua_worker;

-- Per domain: the same IP is an aligned sender for one tenant and a spoofer for another.
create table domain_sources (
  account_id uuid not null references accounts(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  source_ip inet not null,
  classification text not null check (classification in ('aligned_sender', 'known_forwarder', 'unknown')),
  first_seen timestamptz not null,
  last_seen timestamptz not null,
  primary key (domain_id, source_ip)
);

grant select, insert, update, delete on domain_sources to rua_app, rua_worker;
select rua_protect('domain_sources');

create index report_records_report_source on report_records (report_id, source_ip);
