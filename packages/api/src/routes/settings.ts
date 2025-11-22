import { and, desc, eq, gte } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { newWebhookSecret } from "../alerts.js";
import type { AuthVars } from "../auth.js";
import { alerts, alertWebhooks, deliveryStats, resendConnections } from "../db/schema.js";
import { withTenant } from "../db/tenant.js";
import type { Deps } from "../deps.js";
import { encrypt } from "../lib/crypto.js";
import { resolveSafeUrl, UnsafeUrl } from "../lib/safe-url.js";
import { ensureAccount } from "./domains.js";
import { fail, verifiedDomain } from "./reports.js";

const webhookBody = z.object({ url: z.string().max(2048) });
const connectionBody = z.object({ signingSecret: z.string().regex(/^whsec_[A-Za-z0-9+/=_-]{16,}$/) });

export function settingsRoutes(deps: Deps) {
  const app = new Hono<{ Variables: AuthVars }>();
  const endpoint = (id: string) => `${deps.publicUrl}/hooks/resend/tenant/${id}`;

  app.get("/settings/alert-webhook", async (c) => {
    const [hook] = await withTenant(deps.appDb, c.var.accountId, (tx) =>
      tx.select({ url: alertWebhooks.url, createdAt: alertWebhooks.createdAt }).from(alertWebhooks),
    );
    return c.json(hook ?? { url: null });
  });

  // Saving replaces the URL and the secret. The secret is shown once.
  app.post("/settings/alert-webhook", async (c) => {
    const body = webhookBody.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: "invalid_body" }, 400);
    try {
      await resolveSafeUrl(deps.resolver, body.data.url);
    } catch (e) {
      if (e instanceof UnsafeUrl) return c.json({ error: "unsafe_url", reason: e.message }, 400);
      throw e;
    }

    const secret = newWebhookSecret();
    const { blob, keyId } = encrypt(deps.keyring, secret);
    await withTenant(deps.appDb, c.var.accountId, async (tx) => {
      await ensureAccount(tx, c.var.accountId, c.var.email);
      const values = { accountId: c.var.accountId, url: body.data.url, secretEnc: blob, keyId };
      await tx.insert(alertWebhooks).values(values).onConflictDoUpdate({ target: alertWebhooks.accountId, set: values });
    });
    return c.json({ url: body.data.url, secret }, 201);
  });

  app.delete("/settings/alert-webhook", async (c) => {
    await withTenant(deps.appDb, c.var.accountId, (tx) => tx.delete(alertWebhooks));
    return c.body(null, 204);
  });

  app.get("/domains/:id/resend-connections", async (c) =>
    withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx
        .select({ id: resendConnections.id, createdAt: resendConnections.createdAt })
        .from(resendConnections)
        .where(eq(resendConnections.domainId, d.domain.id));
      return c.json({ connections: rows.map((r) => ({ ...r, endpoint: endpoint(r.id) })) });
    }),
  );

  app.post("/domains/:id/resend-connections", async (c) => {
    const body = connectionBody.safeParse(await c.req.json().catch(() => null));
    if (!body.success) return c.json({ error: "invalid_signing_secret" }, 400);
    const { blob, keyId } = encrypt(deps.keyring, body.data.signingSecret);

    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const [row] = await tx
        .insert(resendConnections)
        .values({ accountId: c.var.accountId, domainId: d.domain.id, signingSecretEnc: blob, keyId })
        .returning({ id: resendConnections.id });
      return c.json({ id: row!.id, endpoint: endpoint(row!.id) }, 201);
    });
  });

  app.delete("/domains/:id/resend-connections/:cid", async (c) => {
    const cid = c.req.param("cid");
    if (!z.uuid().safeParse(cid).success) return c.json({ error: "not_found" }, 404);
    const gone = await withTenant(deps.appDb, c.var.accountId, (tx) =>
      tx
        .delete(resendConnections)
        .where(and(eq(resendConnections.id, cid), eq(resendConnections.domainId, c.req.param("id"))))
        .returning({ id: resendConnections.id }),
    );
    return gone.length ? c.body(null, 204) : c.json({ error: "not_found" }, 404);
  });

  app.get("/domains/:id/alerts", async (c) =>
    withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx
        .select({
          id: alerts.id,
          kind: alerts.kind,
          payload: alerts.payload,
          createdAt: alerts.createdAt,
          emailedAt: alerts.emailedAt,
          webhookDeliveredAt: alerts.webhookDeliveredAt,
        })
        .from(alerts)
        .where(eq(alerts.domainId, d.domain.id))
        .orderBy(desc(alerts.createdAt))
        .limit(200);
      return c.json({ alerts: rows });
    }),
  );

  app.get("/domains/:id/delivery", async (c) => {
    const days = z.coerce.number().int().min(1).max(90).catch(30).parse(c.req.query("days"));
    const since = new Date(deps.now().getTime() - days * 86_400_000).toISOString().slice(0, 10);
    return withTenant(deps.appDb, c.var.accountId, async (tx) => {
      const d = await verifiedDomain(tx, c.req.param("id"));
      if (!d.ok) return fail(c, d);
      const rows = await tx
        .select({
          day: deliveryStats.day,
          delivered: deliveryStats.delivered,
          bounced: deliveryStats.bounced,
          complained: deliveryStats.complained,
        })
        .from(deliveryStats)
        .where(and(eq(deliveryStats.domainId, d.domain.id), gte(deliveryStats.day, since)))
        .orderBy(deliveryStats.day);
      return c.json({ days: rows });
    });
  });

  return app;
}
