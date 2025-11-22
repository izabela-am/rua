import { and, eq, inArray, isNotNull, lt } from "drizzle-orm";
import type { AlertRequest } from "./alerts.js";
import type { AuditDeps } from "./audit/domain.js";
import { runAudit, saveSnapshot } from "./audit/domain.js";
import type { Db } from "./db/client.js";
import { domains, reports } from "./db/schema.js";
import type { Resolver } from "./lib/dns.js";
import type { RawStore } from "./lib/storage.js";
import { classifiedVolume, publishedPolicy, readiness, stricter, type Policy } from "./readiness.js";
import { txtMatches } from "./routes/domains.js";

export const RAW_RETENTION_DAYS = 30;

type DomainRow = typeof domains.$inferSelect;
const day = (d: Date) => d.toISOString().slice(0, 10);

/**
 * Re-checks the ownership TXT. A domain whose record is gone loses its
 * verified status, so its data is hidden until the owner proves it again.
 */
export async function checkOwnership(deps: { workerDb: Db; resolver: Resolver }, d: DomainRow, now: Date) {
  const { found } = await txtMatches(deps, d.name, d.verifyToken);
  if (found) {
    await deps.workerDb.update(domains).set({ lastVerifiedAt: now }).where(eq(domains.id, d.id));
    return { verified: true as const };
  }
  await deps.workerDb.update(domains).set({ verifiedAt: null }).where(eq(domains.id, d.id));
  const alert: AlertRequest = {
    domainId: d.id,
    accountId: d.accountId,
    kind: "ownership_lost",
    dedupKey: `ownership_lost:${day(now)}`,
    payload: { message: `_rua.${d.name} no longer holds the verification token.`, txt: `_rua.${d.name}` },
  };
  return { verified: false as const, alert };
}

/** Audits one domain, stores a snapshot, and returns alerts for new findings and a newly reachable policy. */
export async function auditDomain(deps: AuditDeps, d: DomainRow, reportsDomain: string, now: Date) {
  const rua = `${d.ruaLocalPart}@${reportsDomain}`;
  const audit = await runAudit(deps, { id: d.id, name: d.name, rua }, now);
  const { snapshotId, newFindings, first } = await saveSnapshot(deps.workerDb, d, audit, now);

  const alerts: AlertRequest[] = [];
  // The first snapshot is the baseline; alerting on all of it would be noise.
  if (!first) {
    for (const f of newFindings.filter((f) => f.severity === "high" || f.severity === "medium")) {
      alerts.push({
        domainId: d.id,
        accountId: d.accountId,
        kind: "audit_finding",
        dedupKey: `audit_finding:${f.code}:${f.selector ?? ""}:${snapshotId}`,
        payload: { ...f },
      });
    }
  }

  const published = await publishedPolicy(deps.workerDb, d.id);
  const r = readiness(await classifiedVolume(deps.workerDb, d.id, now), now);
  const current = (published?.p ?? "none") as Policy;
  if (stricter(r.recommended, current)) {
    alerts.push({
      domainId: d.id,
      accountId: d.accountId,
      kind: "policy_ready",
      dedupKey: `policy_ready:${r.recommended}`,
      payload: { published: current, recommended: r.recommended, survival: r.survival },
    });
  }
  return { snapshotId, findings: audit.findings.length, alerts };
}

/** Deletes raw report objects past retention. Parsed rows stay. */
export async function expireRaw(deps: { workerDb: Db; store: RawStore }, now: Date, batch = 500) {
  const cutoff = new Date(now.getTime() - RAW_RETENTION_DAYS * 86_400_000);
  const rows = await deps.workerDb
    .select({ id: reports.id, key: reports.rawObjectKey })
    .from(reports)
    .where(and(isNotNull(reports.rawObjectKey), lt(reports.receivedAt, cutoff)))
    .limit(batch);
  if (rows.length === 0) return 0;
  await deps.store.remove(rows.map((r) => r.key!));
  await deps.workerDb.update(reports).set({ rawObjectKey: null }).where(inArray(reports.id, rows.map((r) => r.id)));
  return rows.length;
}
