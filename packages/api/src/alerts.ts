import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Db } from "./db/client.js";
import { accounts, alerts, alertWebhooks, domains, type AlertKind } from "./db/schema.js";
import { decrypt, type Keyring } from "./lib/crypto.js";
import type { Mailer } from "./lib/mailer.js";
import type { PostWebhook } from "./lib/safe-url.js";
import { signAlert } from "./lib/sign.js";
import type { SourceChange } from "./intel/sources.js";

export type AlertDeps = { workerDb: Db; mailer: Mailer; postWebhook: PostWebhook; keyring: Keyring; publicUrl: string };

export type AlertRequest = {
  domainId: string;
  accountId: string;
  kind: AlertKind;
  /** Same key, same alert: unique per domain in the database and per event in Inngest. */
  dedupKey: string;
  payload: Record<string, unknown>;
};

const day = (d: Date) => d.toISOString().slice(0, 10);

/** Turns classification results into alerts: a source seen for the first time, or a source that starts spoofing. */
export function alertsFromChanges(ev: { domainId: string; accountId: string }, changes: SourceChange[], now = new Date()): AlertRequest[] {
  const out: AlertRequest[] = [];
  for (const c of changes) {
    const payload = {
      ip: c.ip,
      provider: c.provider,
      ptr: c.ptr,
      asn: c.asn,
      classification: c.classification,
      messages: c.messages,
      aligned: c.aligned,
    };
    if (c.isNew) {
      const kind = c.spoofing ? "spoofing_source" : "new_source";
      out.push({ ...ev, kind, dedupKey: `${kind}:${c.ip}`, payload });
    } else if (c.spoofing && c.previous !== "unknown") {
      out.push({ ...ev, kind: "spoofing_source", dedupKey: `spoofing_source:${c.ip}:${day(now)}`, payload });
    }
  }
  return out;
}

/** Stores the alert. Returns its id, or null when this dedup key was already raised. */
export async function storeAlert(db: Db, a: AlertRequest): Promise<string | null> {
  const [row] = await db
    .insert(alerts)
    .values({ accountId: a.accountId, domainId: a.domainId, kind: a.kind, dedupKey: a.dedupKey, payload: a.payload })
    .onConflictDoNothing({ target: [alerts.domainId, alerts.dedupKey] })
    .returning({ id: alerts.id });
  return row?.id ?? null;
}

async function loadAlert(db: Db, alertId: string) {
  const [row] = await db
    .select({ alert: alerts, domain: domains.name, email: accounts.email })
    .from(alerts)
    .innerJoin(domains, eq(domains.id, alerts.domainId))
    .innerJoin(accounts, eq(accounts.id, alerts.accountId))
    .where(eq(alerts.id, alertId));
  if (!row) throw new Error(`alert ${alertId} not found`);
  return row;
}

export function describe(kind: AlertKind, domain: string, p: Record<string, unknown>) {
  const who = [p.provider, p.ptr, p.ip].filter(Boolean).join(" / ");
  switch (kind) {
    case "new_source":
      return `New source sending as ${domain}: ${who}`;
    case "spoofing_source":
      return `Possible spoofing of ${domain}: ${who} fails SPF and DKIM`;
    case "policy_ready":
      return `${domain} is ready for p=${p.recommended}`;
    case "ownership_lost":
      return `Ownership TXT record for ${domain} is gone`;
    case "audit_finding":
      return `DNS audit for ${domain}: ${p.message ?? p.code}`;
  }
}

export function webhookBody(row: Awaited<ReturnType<typeof loadAlert>>) {
  return JSON.stringify({
    id: row.alert.id,
    kind: row.alert.kind,
    domain: row.domain,
    createdAt: row.alert.createdAt,
    summary: describe(row.alert.kind, row.domain, row.alert.payload),
    data: row.alert.payload,
  });
}

export async function emailAlert(deps: AlertDeps, alertId: string) {
  const row = await loadAlert(deps.workerDb, alertId);
  if (row.alert.emailedAt) return { skipped: "already_emailed" };
  if (!row.email) return { skipped: "no_email" };

  const p = row.alert.payload;
  const lines = [
    describe(row.alert.kind, row.domain, p),
    "",
    ...Object.entries(p)
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`),
    "",
    `${deps.publicUrl}/domains/${row.alert.domainId}${p.ip ? `#ip-${p.ip}` : ""}`,
  ];
  await deps.mailer.send({ to: row.email, subject: describe(row.alert.kind, row.domain, p), text: lines.join("\n") });
  await deps.workerDb.update(alerts).set({ emailedAt: new Date() }).where(eq(alerts.id, alertId));
  return { emailed: row.email };
}

export class WebhookFailed extends Error {}

export async function deliverWebhook(deps: AlertDeps, alertId: string, now = Date.now()) {
  const row = await loadAlert(deps.workerDb, alertId);
  if (row.alert.webhookDeliveredAt) return { skipped: "already_delivered" };
  const [hook] = await deps.workerDb.select().from(alertWebhooks).where(eq(alertWebhooks.accountId, row.alert.accountId));
  if (!hook) return { skipped: "no_webhook" };

  const secret = decrypt(deps.keyring, hook.secretEnc, hook.keyId);
  const body = webhookBody(row);
  const res = await deps.postWebhook(hook.url, body, { "x-rua-signature": signAlert(secret, body, now) });
  // Non-2xx throws so Inngest retries the step with backoff.
  if (res.status < 200 || res.status >= 300) throw new WebhookFailed(`webhook returned ${res.status}`);
  await deps.workerDb.update(alerts).set({ webhookDeliveredAt: new Date() }).where(eq(alerts.id, alertId));
  return { delivered: res.status };
}

export const newWebhookSecret = () => `whsec_${randomBytes(24).toString("base64url")}`;
