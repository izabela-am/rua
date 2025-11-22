import { eq } from "drizzle-orm";
import { afterAll, beforeAll, expect, test } from "vitest";
import { alertsFromChanges, deliverWebhook, emailAlert, storeAlert } from "../src/alerts.js";
import { alerts, deliveryStats } from "../src/db/schema.js";
import type { Deps } from "../src/deps.js";
import type { SourceChange } from "../src/intel/sources.js";
import { verifyAlert } from "../src/lib/sign.js";
import { signStandardWebhook } from "../src/lib/webhook-sign.js";
import {
  fakeResolver,
  mailRecorder,
  newAccount,
  setupDb,
  testClient,
  testDeps,
  verifiedDomainFor,
  webhookRecorder,
} from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
let deps: Deps;
let client: ReturnType<typeof testClient>;
const mailer = mailRecorder();
const hooks = webhookRecorder();
const resolver = fakeResolver({ a: { "ops.example.com": ["93.184.216.34"], "internal.example.com": ["10.0.0.5"] } });

beforeAll(async () => {
  db = await setupDb();
  deps = testDeps(db, { mailer, resolver, postWebhook: hooks.post.bind(hooks) });
  client = testClient(deps);
});
afterAll(() => db.close());

const change = (over: Partial<SourceChange>): SourceChange => ({
  ip: "45.33.12.9",
  classification: "unknown",
  previous: null,
  isNew: true,
  spoofing: true,
  provider: null,
  ptr: null,
  asn: 63949,
  messages: 7,
  aligned: 0,
  ...over,
});

test("alert requests come from new and newly spoofing sources", () => {
  const ev = { domainId: "d", accountId: "a" };
  const now = new Date("2025-11-11T00:00:00Z");
  const out = alertsFromChanges(
    ev,
    [
      change({}),
      change({ ip: "1.1.1.1", spoofing: false, classification: "aligned_sender", provider: "Google Workspace" }),
      change({ ip: "2.2.2.2", isNew: false, previous: "known_forwarder" }),
      change({ ip: "3.3.3.3", isNew: false, previous: "unknown" }),
    ],
    now,
  );
  expect(out.map((a) => [a.kind, a.dedupKey])).toEqual([
    ["spoofing_source", "spoofing_source:45.33.12.9"],
    ["new_source", "new_source:1.1.1.1"],
    ["spoofing_source", "spoofing_source:2.2.2.2:2025-11-11"],
  ]);
});

test("the alert webhook URL is checked and its secret shown once", async () => {
  const me = newAccount();
  const bad = await client.call(me, "POST", "/api/settings/alert-webhook", { url: "https://internal.example.com/hook" });
  expect(bad).toEqual({ status: 400, body: { error: "unsafe_url", reason: "hostname resolves to a non-public address" } });

  const ok = await client.call(me, "POST", "/api/settings/alert-webhook", { url: "https://ops.example.com/hooks/rua" });
  expect(ok.status).toBe(201);
  expect(ok.body.secret).toMatch(/^whsec_/);
  const read = await client.call(me, "GET", "/api/settings/alert-webhook");
  expect(read.body).toMatchObject({ url: "https://ops.example.com/hooks/rua" });
  expect(read.body.secret).toBeUndefined();
});

test("an alert is stored once, emailed, and posted with a signature", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "alerts.test");
  const { body: hook } = await client.call(me, "POST", "/api/settings/alert-webhook", { url: "https://ops.example.com/hooks/rua" });

  const [req] = alertsFromChanges({ domainId: domain.id, accountId: me }, [change({})]);
  const id = await storeAlert(db.workerDb, req!);
  expect(id).toBeTruthy();
  expect(await storeAlert(db.workerDb, req!)).toBeNull();

  expect(await emailAlert(deps, id!)).toEqual({ emailed: expect.stringContaining("@example.test") });
  expect(mailer.sent.at(-1)!.subject).toBe("Possible spoofing of alerts.test: 45.33.12.9 fails SPF and DKIM");
  expect(mailer.sent.at(-1)!.text).toContain(`https://rua.test/domains/${domain.id}#ip-45.33.12.9`);
  expect(await emailAlert(deps, id!)).toEqual({ skipped: "already_emailed" });

  hooks.status = 503;
  await expect(deliverWebhook(deps, id!)).rejects.toThrow(/503/);
  hooks.status = 200;
  expect(await deliverWebhook(deps, id!)).toEqual({ delivered: 200 });

  const post = hooks.posts.at(-1)!;
  expect(post.url).toBe("https://ops.example.com/hooks/rua");
  expect(verifyAlert(hook.secret, post.body, post.headers["x-rua-signature"]!)).toBe(true);
  expect(JSON.parse(post.body)).toMatchObject({ kind: "spoofing_source", domain: "alerts.test", data: { ip: "45.33.12.9" } });

  const list = await client.call(me, "GET", `/api/domains/${domain.id}/alerts`);
  expect(list.body.alerts).toHaveLength(1);
  expect(list.body.alerts[0].webhookDeliveredAt).toBeTruthy();
  expect((await client.call(newAccount(), "GET", `/api/domains/${domain.id}/alerts`)).status).toBe(404);
});

test("no webhook configured is a skip, not a failure", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "quiet.test");
  const [req] = alertsFromChanges({ domainId: domain.id, accountId: me }, [change({})]);
  const id = await storeAlert(db.workerDb, req!);
  expect(await deliverWebhook(deps, id!)).toEqual({ skipped: "no_webhook" });
  const [row] = await db.workerDb.select().from(alerts).where(eq(alerts.id, id!));
  expect(row!.webhookDeliveredAt).toBeNull();
});

test("tenant Resend events become daily delivery counts", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "sends.test");
  const secret = `whsec_${Buffer.from("tenant-resend-signing-secret").toString("base64")}`;
  const conn = await client.call(me, "POST", `/api/domains/${domain.id}/resend-connections`, { signingSecret: secret });
  expect(conn.status).toBe(201);
  expect(conn.body.endpoint).toBe(`https://rua.test/hooks/resend/tenant/${conn.body.id}`);

  const post = (type: string, from: string, s = secret, id = conn.body.id) => {
    const body = JSON.stringify({ type, created_at: "2025-11-10T15:00:00Z", data: { from, to: ["x@y.test"], email_id: "e" } });
    return client.app.request(`/hooks/resend/tenant/${id}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...signStandardWebhook(s, body) },
      body,
    });
  };

  expect((await post("email.delivered", "Team <hi@sends.test>")).status).toBe(204);
  expect((await post("email.delivered", "hi@sends.test")).status).toBe(204);
  expect((await post("email.bounced", "hi@sends.test")).status).toBe(204);
  expect((await post("email.complained", "hi@sends.test")).status).toBe(204);
  // Not counted: another sender domain, an event type Rua ignores.
  expect((await post("email.delivered", "hi@other.test")).status).toBe(204);
  expect((await post("email.opened", "hi@sends.test")).status).toBe(204);
  // Rejected: wrong secret, unknown connection.
  const wrong = `whsec_${Buffer.from("someone-else").toString("base64")}`;
  expect((await post("email.delivered", "hi@sends.test", wrong)).status).toBe(400);
  expect((await post("email.delivered", "hi@sends.test", secret, "00000000-0000-0000-0000-000000000000")).status).toBe(404);

  const rows = await db.workerDb.select().from(deliveryStats).where(eq(deliveryStats.domainId, domain.id));
  expect(rows).toEqual([expect.objectContaining({ day: "2025-11-10", delivered: 2, bounced: 1, complained: 1 })]);
  const api = await client.call(me, "GET", `/api/domains/${domain.id}/delivery`);
  expect(api.body.days).toEqual([{ day: "2025-11-10", delivered: 2, bounced: 1, complained: 1 }]);
});

test("bad signing secrets are refused", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "badsecret.test");
  const res = await client.call(me, "POST", `/api/domains/${domain.id}/resend-connections`, { signingSecret: "hunter2" });
  expect(res.status).toBe(400);
});
