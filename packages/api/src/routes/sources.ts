import { sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import type { AuthVars } from "../auth.js";
import { withTenant } from "../db/tenant.js";
import type { Deps } from "../deps.js";
import { fail, verifiedDomain } from "./reports.js";

const window = z.object({ days: z.coerce.number().int().min(1).max(90).default(30) });

const since = (now: Date, days: number) => new Date(now.getTime() - days * 86_400_000).toISOString();

export function sourceRoutes(deps: Deps) {
  const app = new Hono<{ Variables: AuthVars }>();

  app.get("/domains/:id/sources", async (c) => {
    const q = window.safeParse(c.req.query());
    if (!q.success) return c.json({ error: "invalid_query" }, 400);

    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx.execute<{
        ip: string;
        classification: string;
        first_seen: Date;
        last_seen: Date;
        ptr: string | null;
        ptr_confirmed: boolean | null;
        asn: number | null;
        as_name: string | null;
        provider: string | null;
        messages: number;
        aligned: number;
        failing_both: number;
      }>(sql`
        with stats as (
          select rr.source_ip,
                 sum(rr.count)::int as messages,
                 coalesce(sum(rr.count) filter (where rr.dkim_aligned or rr.spf_aligned), 0)::int as aligned,
                 coalesce(sum(rr.count) filter (where not rr.dkim_aligned and not rr.spf_aligned), 0)::int as failing_both
            from report_records rr
            join reports r on r.id = rr.report_id
           where r.domain_id = ${d.domain.id} and r.end_at >= ${since(deps.now(), q.data.days)}::timestamptz
           group by rr.source_ip
        )
        select host(ds.source_ip) as ip, ds.classification, ds.first_seen, ds.last_seen,
               ii.ptr, ii.ptr_confirmed, ii.asn, ii.as_name, ii.provider,
               coalesce(s.messages, 0) as messages, coalesce(s.aligned, 0) as aligned,
               coalesce(s.failing_both, 0) as failing_both
          from domain_sources ds
          left join ip_intel ii on ii.ip = ds.source_ip
          left join stats s on s.source_ip = ds.source_ip
         where ds.domain_id = ${d.domain.id}
         order by messages desc, ds.last_seen desc`);

      return c.json({
        sources: rows.map((r) => ({
          ip: r.ip,
          ptr: r.ptr,
          ptrConfirmed: r.ptr_confirmed ?? false,
          asn: r.asn,
          asName: r.as_name,
          provider: r.provider,
          classification: r.classification,
          spoofing: r.classification === "unknown" && r.failing_both > 0,
          messages: r.messages,
          aligned: r.aligned,
          failingBoth: r.failing_both,
          firstSeen: r.first_seen,
          lastSeen: r.last_seen,
        })),
      });
    });
  });

  /** Daily volume by label and the aligned share, for the two Sources charts. */
  app.get("/domains/:id/charts", async (c) => {
    const q = window.safeParse(c.req.query());
    if (!q.success) return c.json({ error: "invalid_query" }, 400);

    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx.execute<{ day: string; label: string; messages: number; aligned: number }>(sql`
        select to_char(date_trunc('day', r.begin_at at time zone 'UTC'), 'YYYY-MM-DD') as day,
               coalesce(ds.classification, 'unknown') as label,
               sum(rr.count)::int as messages,
               coalesce(sum(rr.count) filter (where rr.dkim_aligned or rr.spf_aligned), 0)::int as aligned
          from report_records rr
          join reports r on r.id = rr.report_id
          left join domain_sources ds on ds.domain_id = r.domain_id and ds.source_ip = rr.source_ip
         where r.domain_id = ${d.domain.id} and r.begin_at >= ${since(deps.now(), q.data.days)}::timestamptz
         group by 1, 2
         order by 1`);

      const days = new Map<string, { day: string; aligned_sender: number; known_forwarder: number; unknown: number; total: number; aligned: number }>();
      for (const r of rows) {
        const e = days.get(r.day) ?? { day: r.day, aligned_sender: 0, known_forwarder: 0, unknown: 0, total: 0, aligned: 0 };
        e[r.label as "aligned_sender" | "known_forwarder" | "unknown"] += r.messages;
        e.total += r.messages;
        e.aligned += r.aligned;
        days.set(r.day, e);
      }
      return c.json({
        days: [...days.values()].map((e) => ({ ...e, alignedRate: e.total ? e.aligned / e.total : null })),
      });
    });
  });

  return app;
}
