import { and, desc, eq, gte, lte, sql } from "drizzle-orm";
import { Hono, type Context } from "hono";
import { z } from "zod";
import type { AuthVars } from "../auth.js";
import type { Tx } from "../db/client.js";
import { reportRecords, reports } from "../db/schema.js";
import { withTenant } from "../db/tenant.js";
import type { Deps } from "../deps.js";
import { getDomain } from "./domains.js";

/** Loads a domain the caller owns and has verified; data stays hidden until the TXT check passes. */
export async function verifiedDomain(tx: Tx, id: string) {
  const d = await getDomain(tx, id);
  if (!d) return { ok: false as const, error: "not_found", status: 404 as const };
  if (!d.verifiedAt) return { ok: false as const, error: "domain_unverified", status: 403 as const };
  return { ok: true as const, domain: d };
}

export function fail(c: Context, r: { error: string; status: 403 | 404 }) {
  return c.json({ error: r.error }, r.status);
}

const range = z.object({
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

export function reportRoutes(deps: Deps) {
  const app = new Hono<{ Variables: AuthVars }>();

  app.get("/domains/:id/reports", async (c) => {
    const q = range.safeParse(c.req.query());
    if (!q.success) return c.json({ error: "invalid_query" }, 400);

    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx
        .select({
          id: reports.id,
          reporterOrg: reports.reporterOrg,
          reportId: reports.reportId,
          beginAt: reports.beginAt,
          endAt: reports.endAt,
          policyPublished: reports.policyPublished,
          receivedAt: reports.receivedAt,
          messages: sql<number>`coalesce(sum(${reportRecords.count}), 0)::int`,
        })
        .from(reports)
        .leftJoin(reportRecords, eq(reportRecords.reportId, reports.id))
        .where(
          and(
            eq(reports.domainId, d.domain.id),
            q.data.from ? gte(reports.beginAt, q.data.from) : undefined,
            q.data.to ? lte(reports.beginAt, q.data.to) : undefined,
          ),
        )
        .groupBy(reports.id)
        .orderBy(desc(reports.beginAt))
        .limit(q.data.limit);
      return c.json({ reports: rows });
    });
  });

  app.get("/reports/:id/records", async (c) => {
    const id = c.req.param("id");
    if (!z.uuid().safeParse(id).success) return c.json({ error: "not_found" }, 404);

    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const [report] = await tx.select({ domainId: reports.domainId }).from(reports).where(eq(reports.id, id));
      if (!report) return c.json({ error: "not_found" }, 404);
      const d = await verifiedDomain(tx, report.domainId);
      if (!d.ok) return fail(c, d);
      const records = await tx
        .select({
          sourceIp: reportRecords.sourceIp,
          count: reportRecords.count,
          disposition: reportRecords.disposition,
          dkimAligned: reportRecords.dkimAligned,
          spfAligned: reportRecords.spfAligned,
          headerFrom: reportRecords.headerFrom,
          envelopeFrom: reportRecords.envelopeFrom,
          authResults: reportRecords.authResults,
        })
        .from(reportRecords)
        .where(eq(reportRecords.reportId, id))
        .orderBy(desc(reportRecords.count));
      return c.json({ records });
    });
  });

  return app;
}
