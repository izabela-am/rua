import { and, desc, eq, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { recordSnapshots, type Finding, type Records } from "../db/schema.js";
import type { Resolver } from "../lib/dns.js";
import { auditDkim } from "./dkim.js";
import { auditDmarc, parseDmarc } from "./dmarc.js";
import { auditExtras, type FetchText } from "./extras.js";
import { auditSpf } from "./spf.js";

export type AuditDeps = { workerDb: Db; resolver: Resolver; fetchText: FetchText };

const since = (now: Date) => new Date(now.getTime() - 30 * 86_400_000).toISOString();

/** What reports tell the auditor about a domain: DKIM selectors, subdomains, relaxed-only alignment. */
export async function reportContext(db: Db, domainId: string, name: string, now: Date) {
  const selectors = await db.execute<{ selector: string }>(sql`
    select distinct a->>'selector' as selector
      from report_records rr
      join reports r on r.id = rr.report_id,
           jsonb_array_elements(rr.auth_results) a
     where r.domain_id = ${domainId} and r.end_at >= ${since(now)}::timestamptz
       and a->>'type' = 'dkim' and a->>'domain' = ${name} and a->>'selector' is not null
     limit 20`);
  const subs = await db.execute<{ header_from: string }>(sql`
    select distinct rr.header_from
      from report_records rr join reports r on r.id = rr.report_id
     where r.domain_id = ${domainId} and r.end_at >= ${since(now)}::timestamptz
       and rr.header_from like ${"%." + name}
     limit 20`);
  const [relaxed] = await db.execute<{ found: boolean }>(sql`
    select exists (
      select 1
        from report_records rr join reports r on r.id = rr.report_id
       where r.domain_id = ${domainId} and r.end_at >= ${since(now)}::timestamptz
         and (rr.dkim_aligned or rr.spf_aligned)
         and not exists (
           select 1 from jsonb_array_elements(rr.auth_results) a
            where a->>'result' = 'pass' and a->>'domain' = rr.header_from)
    ) as found`);
  return {
    selectors: selectors.map((r) => r.selector),
    subdomainsSeen: subs.map((r) => r.header_from),
    relaxedOnlySenders: relaxed?.found ?? false,
  };
}

export async function runAudit(
  deps: AuditDeps,
  domain: { id: string; name: string; rua: string },
  now: Date,
): Promise<{ records: Records; findings: Finding[] }> {
  const ctx = await reportContext(deps.workerDb, domain.id, domain.name, now);
  const spf = await auditSpf(deps.resolver, domain.name);
  const dmarc = await auditDmarc(deps.resolver, domain.name, { ruaAddress: domain.rua, ...ctx });
  const dkim = await auditDkim(deps.resolver, domain.name, ctx.selectors);
  const policy = dmarc.record ? (parseDmarc(dmarc.record)?.p ?? null) : null;
  const extras = await auditExtras(deps.resolver, deps.fetchText, domain.name, policy);
  return {
    records: { spf: spf.record, dmarc: dmarc.record, dkim: dkim.records, mtaSts: extras.mtaSts, tlsRpt: extras.tlsRpt, bimi: extras.bimi },
    findings: [...spf.findings, ...dmarc.findings, ...dkim.findings, ...extras.findings],
  };
}

export const findingKey = (f: Pick<Finding, "code" | "selector">) => `${f.code}:${f.selector ?? ""}`;

/** Stores a snapshot and returns the findings that were not in the previous one. */
export async function saveSnapshot(
  db: Db,
  domain: { id: string; accountId: string },
  audit: { records: Records; findings: Finding[] },
  now: Date,
) {
  const [previous] = await db
    .select({ findings: recordSnapshots.findings })
    .from(recordSnapshots)
    .where(and(eq(recordSnapshots.domainId, domain.id)))
    .orderBy(desc(recordSnapshots.takenAt))
    .limit(1);
  const [row] = await db
    .insert(recordSnapshots)
    .values({ accountId: domain.accountId, domainId: domain.id, takenAt: now, records: audit.records, findings: audit.findings })
    .returning({ id: recordSnapshots.id });
  const before = new Set((previous?.findings ?? []).map(findingKey));
  return { snapshotId: row!.id, newFindings: audit.findings.filter((f) => !before.has(findingKey(f))), first: !previous };
}

/** Walks snapshots oldest first and lists when each finding appeared and cleared. */
export function findingHistory(snapshots: Array<{ takenAt: Date; findings: Finding[] }>) {
  const events: Array<{ code: string; selector?: string; change: "appeared" | "cleared"; at: Date }> = [];
  let open = new Map<string, Finding>();
  for (const s of [...snapshots].sort((a, b) => a.takenAt.getTime() - b.takenAt.getTime())) {
    const now = new Map(s.findings.map((f) => [findingKey(f), f]));
    for (const [k, f] of now) {
      if (!open.has(k)) events.push({ code: f.code, ...(f.selector ? { selector: f.selector } : {}), change: "appeared", at: s.takenAt });
    }
    for (const [k, f] of open) {
      if (!now.has(k)) events.push({ code: f.code, ...(f.selector ? { selector: f.selector } : {}), change: "cleared", at: s.takenAt });
    }
    open = now;
  }
  return events.reverse();
}
