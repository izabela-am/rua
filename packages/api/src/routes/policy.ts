import { desc, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthVars } from "../auth.js";
import { findingHistory } from "../audit/domain.js";
import { recordSnapshots } from "../db/schema.js";
import { withTenant } from "../db/tenant.js";
import type { Deps } from "../deps.js";
import { classifiedVolume, publishedPolicy, readiness, recordFor } from "../readiness.js";
import { fail, verifiedDomain } from "./reports.js";

export function policyRoutes(deps: Deps) {
  const app = new Hono<{ Variables: AuthVars }>();

  app.get("/domains/:id/readiness", async (c) =>
    withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const now = deps.now();
      const volume = await classifiedVolume(tx, d.domain.id, now);
      const published = await publishedPolicy(tx, d.domain.id);
      const r = readiness(volume, now);
      const rua = `${d.domain.ruaLocalPart}@${deps.reportsDomain}`;
      return c.json({
        published: published?.p ?? null,
        recommended: r.recommended,
        survival: r.survival,
        volume: { total: volume.total, aligned: volume.aligned, knownForwarder: volume.knownForwarder, unknown: volume.unknown },
        blockers: r.blockers,
        record: recordFor(r.recommended, rua, published),
      });
    }),
  );

  app.get("/domains/:id/audit", async (c) =>
    withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const snaps = await tx
        .select({ takenAt: recordSnapshots.takenAt, records: recordSnapshots.records, findings: recordSnapshots.findings })
        .from(recordSnapshots)
        .where(eq(recordSnapshots.domainId, d.domain.id))
        .orderBy(desc(recordSnapshots.takenAt))
        .limit(90);
      const latest = snaps[0];
      return c.json({
        takenAt: latest?.takenAt ?? null,
        records: latest?.records ?? null,
        findings: latest?.findings ?? [],
        history: findingHistory(snaps),
      });
    }),
  );

  return app;
}
