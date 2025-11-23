import { and, eq, gte, sql } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { domainSources, reportRecords, reports, type Classification } from "../db/schema.js";
import { classify, isSpoofing, type AlignmentStats } from "./classify.js";
import { intelFor, type EnrichDeps } from "./enrich.js";

export const WINDOW_DAYS = 30;

export type SourceChange = {
  ip: string;
  classification: Classification;
  previous: Classification | null;
  isNew: boolean;
  spoofing: boolean;
  provider: string | null;
  ptr: string | null;
  asn: number | null;
  messages: number;
  aligned: number;
};

/** End of a report's period. Classification looks back from here, not from the wall clock, so a late or replayed report is judged on its own window. */
export async function reportEnd(db: Db, reportId: string): Promise<Date> {
  const [row] = await db.select({ endAt: reports.endAt }).from(reports).where(eq(reports.id, reportId));
  if (!row) throw new Error(`report ${reportId} not found`);
  return row.endAt;
}

export async function distinctSourceIps(db: Db, reportId: string): Promise<string[]> {
  const rows = await db
    .selectDistinct({ ip: reportRecords.sourceIp })
    .from(reportRecords)
    .where(eq(reportRecords.reportId, reportId));
  return rows.map((r) => r.ip);
}

export async function alignmentStats(db: Db, domainId: string, ip: string, since: Date) {
  const [row] = await db
    .select({
      messages: sql<number>`coalesce(sum(${reportRecords.count}), 0)::int`,
      aligned: sql<number>`coalesce(sum(${reportRecords.count}) filter (where ${reportRecords.dkimAligned} or ${reportRecords.spfAligned}), 0)::int`,
      failingBoth: sql<number>`coalesce(sum(${reportRecords.count}) filter (where not ${reportRecords.dkimAligned} and not ${reportRecords.spfAligned}), 0)::int`,
      firstSeen: sql<Date>`min(${reports.beginAt})`,
      lastSeen: sql<Date>`max(${reports.endAt})`,
    })
    .from(reportRecords)
    .innerJoin(reports, eq(reports.id, reportRecords.reportId))
    .where(and(eq(reports.domainId, domainId), eq(reportRecords.sourceIp, ip), gte(reports.endAt, since)));
  return row!;
}

/**
 * Enriches and labels one source IP of a domain and records what changed.
 * asOf is the end of the report being processed; the 30-day window ends there.
 */
export async function classifySource(
  deps: EnrichDeps,
  ev: { domainId: string; accountId: string },
  ip: string,
  asOf: Date,
): Promise<SourceChange> {
  const now = new Date();
  const intel = await intelFor(deps, ip, now);
  const since = new Date(asOf.getTime() - WINDOW_DAYS * 86_400_000);
  const s = await alignmentStats(deps.workerDb, ev.domainId, ip, since);
  const stats: AlignmentStats = { messages: s.messages, aligned: s.aligned, failingBoth: s.failingBoth };
  const label = classify(stats, intel.provider, deps.providers);

  return deps.workerDb.transaction(async (tx) => {
    const [prev] = await tx
      .select({ classification: domainSources.classification })
      .from(domainSources)
      .where(and(eq(domainSources.domainId, ev.domainId), eq(domainSources.sourceIp, ip)))
      .for("update");
    const firstSeen = new Date(s.firstSeen ?? asOf);
    const lastSeen = new Date(s.lastSeen ?? asOf);
    await tx
      .insert(domainSources)
      .values({ accountId: ev.accountId, domainId: ev.domainId, sourceIp: ip, classification: label, firstSeen, lastSeen })
      .onConflictDoUpdate({
        target: [domainSources.domainId, domainSources.sourceIp],
        set: {
          classification: label,
          lastSeen: sql`greatest(${domainSources.lastSeen}, ${lastSeen.toISOString()}::timestamptz)`,
        },
      });
    return {
      ip,
      classification: label,
      previous: prev?.classification ?? null,
      isNew: !prev,
      spoofing: isSpoofing(label, stats),
      provider: intel.provider,
      ptr: intel.ptrConfirmed ? intel.ptr : null,
      asn: intel.asn,
      messages: stats.messages,
      aligned: stats.aligned,
    };
  });
}
