import { and, desc, eq, sql } from "drizzle-orm";
import type { Db, Tx } from "./db/client.js";
import { reports } from "./db/schema.js";

/** Thresholds for the policy recommendation. One place to change them. */
export const READINESS = {
  windowDays: 30,
  quarantineSurvival: 0.99,
  rejectSurvival: 0.995,
  /** An unknown source failing both checks this recently blocks reject. */
  unknownFailingBlockDays: 14,
};

export type Policy = "none" | "quarantine" | "reject";
const RANK: Record<Policy, number> = { none: 0, quarantine: 1, reject: 2 };
export const stricter = (a: Policy, b: Policy) => RANK[a] > RANK[b];

export type Blocker = { ip: string; classification: string; messages: number; lastSeen: Date };

export type ClassifiedVolume = {
  total: number;
  aligned: number;
  knownForwarder: number;
  unknown: number;
  unknownFailing: Blocker[];
};

export type Readiness = {
  survival: { quarantine: number; reject: number } | null;
  recommended: Policy;
  blockers: Blocker[];
};

/** Pure: 30 days of classified volume in, a recommendation out. */
export function readiness(volume: ClassifiedVolume, now: Date): Readiness {
  if (volume.total === 0) return { survival: null, recommended: "none", blockers: [] };
  const legit = volume.aligned + volume.knownForwarder;
  // The same share survives both policies; reject is gated harder below.
  const share = legit / volume.total;
  const survival = { quarantine: share, reject: share };
  const cutoff = now.getTime() - READINESS.unknownFailingBlockDays * 86_400_000;
  const recentUnknownFail = volume.unknownFailing.some((s) => new Date(s.lastSeen).getTime() > cutoff);
  const recommended: Policy =
    share >= READINESS.rejectSurvival && !recentUnknownFail
      ? "reject"
      : share >= READINESS.quarantineSurvival
        ? "quarantine"
        : "none";
  return { survival, recommended, blockers: volume.unknownFailing };
}

export async function classifiedVolume(db: Db | Tx, domainId: string, now: Date): Promise<ClassifiedVolume> {
  const since = new Date(now.getTime() - READINESS.windowDays * 86_400_000).toISOString();
  const rows = await db.execute<{ ip: string; classification: string; messages: number; failing_both: number; last_seen: Date }>(sql`
    select host(rr.source_ip) as ip,
           coalesce(ds.classification, 'unknown') as classification,
           sum(rr.count)::int as messages,
           coalesce(sum(rr.count) filter (where not rr.dkim_aligned and not rr.spf_aligned), 0)::int as failing_both,
           max(r.end_at) as last_seen
      from report_records rr
      join reports r on r.id = rr.report_id
      left join domain_sources ds on ds.domain_id = r.domain_id and ds.source_ip = rr.source_ip
     where r.domain_id = ${domainId} and r.end_at >= ${since}::timestamptz
     group by rr.source_ip, ds.classification`);

  const v: ClassifiedVolume = { total: 0, aligned: 0, knownForwarder: 0, unknown: 0, unknownFailing: [] };
  for (const r of rows) {
    v.total += r.messages;
    if (r.classification === "aligned_sender") v.aligned += r.messages;
    else if (r.classification === "known_forwarder") v.knownForwarder += r.messages;
    else {
      v.unknown += r.messages;
      if (r.failing_both > 0) {
        v.unknownFailing.push({ ip: r.ip, classification: r.classification, messages: r.messages, lastSeen: new Date(r.last_seen) });
      }
    }
  }
  v.unknownFailing.sort((a, b) => b.messages - a.messages);
  return v;
}

/** The policy receivers last reported, from the newest report. */
export async function publishedPolicy(db: Db | Tx, domainId: string) {
  const [row] = await db
    .select({ policy: reports.policyPublished })
    .from(reports)
    .where(and(eq(reports.domainId, domainId)))
    .orderBy(desc(reports.endAt))
    .limit(1);
  return row?.policy ?? null;
}

export function recordFor(p: Policy, rua: string, published: { adkim?: string; aspf?: string } | null) {
  return `v=DMARC1; p=${p}; pct=100; rua=mailto:${rua}; adkim=${published?.adkim ?? "r"}; aspf=${published?.aspf ?? "r"}`;
}
