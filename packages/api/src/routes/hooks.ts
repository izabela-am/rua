import { Hono } from "hono";
import type { Deps } from "../deps.js";
import { ingestTenantEvent } from "../delivery.js";
import { domainForRecipients } from "../ingest.js";
import { log } from "../log.js";

export type VerifyWebhook = (payload: string, headers: { id: string; timestamp: string; signature: string }) => unknown;

let dropped = 0;
export const droppedReports = () => dropped;

function svixHeaders(h: (name: string) => string | undefined) {
  return { id: h("svix-id") ?? "", timestamp: h("svix-timestamp") ?? "", signature: h("svix-signature") ?? "" };
}

type Received = { type: string; data?: { email_id?: string; to?: string[]; received_for?: string[] } };

/** Webhooks from Resend. No session; each hook verifies its own signature. */
export function hookRoutes(deps: Deps) {
  const app = new Hono();

  // Verify, resolve the domain, emit, return. Anything slow happens in Inngest.
  app.post("/resend/inbound", async (c) => {
    const body = await c.req.text();
    let event: Received;
    try {
      event = deps.verifyInbound(body, svixHeaders((n) => c.req.header(n))) as Received;
    } catch {
      return c.json({ error: "invalid_signature" }, 400);
    }
    if (event.type !== "email.received" || !event.data?.email_id) return c.body(null, 204);

    const recipients = [...(event.data.received_for ?? []), ...(event.data.to ?? [])];
    const domain = await domainForRecipients(deps.workerDb, recipients, deps.reportsDomain);
    if (!domain) {
      // Unknown address. The sender gets a 200 so Resend does not retry; nothing is stored.
      dropped++;
      log.info("inbound for unknown report address", { dropped });
      return c.json({ ok: true });
    }

    await deps.events.send({
      name: "report/received",
      // Same email id, same event id: Inngest drops a redelivered webhook.
      id: `received-${event.data.email_id}`,
      data: { emailId: event.data.email_id, domainId: domain.id, accountId: domain.accountId },
    });
    return c.json({ ok: true });
  });

  // Delivery events from a tenant's own Resend account.
  app.post("/resend/tenant/:id", async (c) => {
    const id = c.req.param("id");
    if (!/^[0-9a-f-]{36}$/i.test(id)) return c.json({ error: "not_found" }, 404);
    const result = await ingestTenantEvent(
      { workerDb: deps.workerDb, keyring: deps.keyring, verify: deps.verifyTenant },
      id,
      await c.req.text(),
      svixHeaders((n) => c.req.header(n)),
    );
    if (result.status === 404) return c.json({ error: "not_found" }, 404);
    if (result.status === 400) return c.json({ error: "invalid_signature" }, 400);
    return c.body(null, 204);
  });

  return app;
}
