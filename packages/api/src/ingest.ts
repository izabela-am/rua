import { decompress, parseAggregateReport, type AggregateReport } from "@rua/dmarc-parser";
import { and, eq } from "drizzle-orm";
import type { Db } from "./db/client.js";
import { domains, reportRecords, reports } from "./db/schema.js";
import type { InboundMail } from "./lib/inbound.js";
import type { RawStore } from "./lib/storage.js";

export type IngestDeps = { workerDb: Db; mail: InboundMail; store: RawStore };

/** Maps a recipient list to the domain that owns the report address. */
export async function domainForRecipients(db: Db, recipients: string[], reportsDomain: string) {
  const suffix = `@${reportsDomain.toLowerCase()}`;
  for (const r of recipients) {
    const addr = r.toLowerCase().replace(/^.*</, "").replace(/>.*$/, "").trim();
    if (!addr.endsWith(suffix)) continue;
    const local = addr.slice(0, -suffix.length).split("+")[0]!;
    const [row] = await db
      .select({ id: domains.id, accountId: domains.accountId })
      .from(domains)
      .where(eq(domains.ruaLocalPart, local));
    if (row) return row;
  }
  return null;
}

/** Downloads the report attachment and keeps the raw bytes. Returns the object key, or null if the email has none. */
export async function storeAttachment(deps: IngestDeps, ev: { domainId: string; emailId: string }) {
  const att = await deps.mail.reportAttachment(ev.emailId);
  if (!att) return null;
  const key = `${ev.domainId}/${ev.emailId}/${att.id}`;
  await deps.store.put(key, att.bytes);
  return key;
}

/**
 * Parses a stored report and writes it. A report already seen for the same
 * (domain, reporter, report id) is a no-op, so redelivery and replay are safe.
 */
export async function ingestStored(deps: IngestDeps, ev: { domainId: string; accountId: string; key: string }) {
  const raw = await deps.store.get(ev.key);
  const report = parseAggregateReport(decompress(raw));
  return upsertReport(deps.workerDb, ev, report);
}

export async function upsertReport(
  db: Db,
  ev: { domainId: string; accountId: string; key: string | null },
  report: AggregateReport,
): Promise<{ duplicate: true } | { duplicate: false; reportId: string }> {
  return db.transaction(async (tx) => {
    // The tenant comes from the domain row, never from the report body.
    const [domain] = await tx
      .select({ id: domains.id })
      .from(domains)
      .where(and(eq(domains.id, ev.domainId), eq(domains.accountId, ev.accountId)));
    if (!domain) return { duplicate: true };

    const pp = report.policyPublished;
    const [row] = await tx
      .insert(reports)
      .values({
        accountId: ev.accountId,
        domainId: ev.domainId,
        reporterOrg: report.reporter.orgName,
        reportId: report.reporter.reportId,
        beginAt: report.dateRange.begin,
        endAt: report.dateRange.end,
        policyPublished: { p: pp.p, ...(pp.sp ? { sp: pp.sp } : {}), pct: pp.pct, adkim: pp.adkim, aspf: pp.aspf },
        rawObjectKey: ev.key,
      })
      .onConflictDoNothing({ target: [reports.domainId, reports.reporterOrg, reports.reportId] })
      .returning({ id: reports.id });
    if (!row) return { duplicate: true };

    const rows = report.records.map((r) => ({
      accountId: ev.accountId,
      reportId: row.id,
      sourceIp: r.sourceIp,
      count: r.count,
      disposition: r.disposition,
      dkimAligned: r.dkim === "pass",
      spfAligned: r.spf === "pass",
      headerFrom: r.headerFrom,
      envelopeFrom: r.envelopeFrom ?? null,
      authResults: r.authResults,
    }));
    // Postgres caps bind parameters at 65535; 10 columns per row.
    for (let i = 0; i < rows.length; i += 5000) {
      await tx.insert(reportRecords).values(rows.slice(i, i + 5000));
    }
    return { duplicate: false, reportId: row.id };
  });
}
