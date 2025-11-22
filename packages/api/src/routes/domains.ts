import { createHash, timingSafeEqual } from "node:crypto";
import { and, count, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import type { AuthVars } from "../auth.js";
import type { Tx } from "../db/client.js";
import { accounts, domains } from "../db/schema.js";
import { withTenant } from "../db/tenant.js";
import type { Deps } from "../deps.js";
import { orEmpty } from "../lib/dns.js";
import { newRuaLocalPart, newVerifyToken, normalizeDomain } from "../lib/ids.js";

export const MAX_DOMAINS_PER_ACCOUNT = 10;

type DomainRow = typeof domains.$inferSelect;

export function present(d: DomainRow, reportsDomain: string) {
  return {
    id: d.id,
    name: d.name,
    verified: d.verifiedAt !== null,
    verifiedAt: d.verifiedAt,
    txt: { host: `_rua.${d.name}`, value: `rua-verify=${d.verifyToken}` },
    rua: `${d.ruaLocalPart}@${reportsDomain}`,
    createdAt: d.createdAt,
  };
}

/** Creates the account row on first use and keeps its email current for alert mail. */
export async function ensureAccount(tx: Tx, accountId: string, email?: string) {
  await tx
    .insert(accounts)
    .values({ id: accountId, email: email ?? null })
    .onConflictDoUpdate({ target: accounts.id, set: email ? { email } : { id: accountId } });
}

export async function getDomain(tx: Tx, id: string) {
  if (!z.uuid().safeParse(id).success) return undefined;
  const [row] = await tx.select().from(domains).where(eq(domains.id, id));
  return row;
}

function sameSecret(a: string, b: string) {
  // Hash first so the comparison is constant time regardless of length.
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

export async function txtMatches(deps: Pick<Deps, "resolver">, name: string, token: string) {
  const answers = (await orEmpty(deps.resolver.resolveTxt(`_rua.${name}`))).map((chunks) => chunks.join(""));
  const expected = `rua-verify=${token}`;
  return { found: answers.some((a) => sameSecret(a, expected)), observed: answers };
}

const createBody = z.object({ name: z.string().min(1).max(253) });

export function domainRoutes(deps: Deps) {
  const app = new Hono<{ Variables: AuthVars }>();

  app.get("/", async (c) => {
    const rows = await withTenant(deps.appDb, c.var.accountId, (tx) =>
      tx.select().from(domains).orderBy(domains.createdAt),
    );
    return c.json({ domains: rows.map((d) => present(d, deps.reportsDomain)) });
  });

  app.post("/", async (c) => {
    const body = createBody.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: "invalid_body" }, 400);
    const name = normalizeDomain(body.data.name);
    if (!name) return c.json({ error: "invalid_domain" }, 400);

    const result = await withTenant(deps.appDb, c.var.accountId, async (tx) => {
      await ensureAccount(tx, c.var.accountId, c.var.email);
      const [{ n } = { n: 0 }] = await tx.select({ n: count() }).from(domains);
      if (n >= MAX_DOMAINS_PER_ACCOUNT) return "limit" as const;
      const [row] = await tx
        .insert(domains)
        .values({
          accountId: c.var.accountId,
          name,
          ruaLocalPart: newRuaLocalPart(),
          verifyToken: newVerifyToken(),
        })
        .onConflictDoNothing({ target: [domains.accountId, domains.name] })
        .returning();
      return row ?? ("exists" as const);
    });

    if (result === "limit") return c.json({ error: "domain_limit", limit: MAX_DOMAINS_PER_ACCOUNT }, 409);
    if (result === "exists") return c.json({ error: "domain_exists" }, 409);
    return c.json(present(result, deps.reportsDomain), 201);
  });

  app.get("/:id", async (c) => {
    const row = await withTenant(deps.appDb, c.var.accountId, (tx) => getDomain(tx, c.req.param("id")));
    if (!row) return c.json({ error: "not_found" }, 404);
    return c.json(present(row, deps.reportsDomain));
  });

  app.post("/:id/verify", async (c) => {
    const id = c.req.param("id");
    const row = await withTenant(deps.appDb, c.var.accountId, (tx) => getDomain(tx, id));
    if (!row) return c.json({ error: "not_found" }, 404);

    // DNS runs outside the transaction so a slow resolver does not hold a connection.
    const { found, observed } = await txtMatches(deps, row.name, row.verifyToken);
    if (!found) return c.json({ error: "txt_not_found", observed }, 409);

    const now = new Date();
    await withTenant(deps.appDb, c.var.accountId, (tx) =>
      tx
        .update(domains)
        .set({ verifiedAt: row.verifiedAt ?? now, lastVerifiedAt: now })
        .where(and(eq(domains.id, id), eq(domains.accountId, c.var.accountId))),
    );
    return c.json({ verified: true, verifiedAt: row.verifiedAt ?? now });
  });

  app.delete("/:id", async (c) => {
    const deleted = await withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const row = await getDomain(tx, c.req.param("id"));
      if (!row) return false;
      await tx.delete(domains).where(eq(domains.id, row.id));
      return true;
    });
    return deleted ? c.body(null, 204) : c.json({ error: "not_found" }, 404);
  });

  return app;
}
