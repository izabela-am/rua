import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, expect, test } from "vitest";
import type { Deps } from "../src/deps.js";
import { ingestStored, storeAttachment } from "../src/ingest.js";
import { signStandardWebhook } from "../src/lib/webhook-sign.js";
import {
  eventRecorder,
  fakeMail,
  fixture,
  INBOUND_SECRET,
  newAccount,
  REPORTS_DOMAIN,
  setupDb,
  testClient,
  testDeps,
  verifiedDomainFor,
} from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
let deps: Deps;
let client: ReturnType<typeof testClient>;
let events: ReturnType<typeof eventRecorder>;
let mail: ReturnType<typeof fakeMail>;

beforeAll(async () => {
  db = await setupDb();
  events = eventRecorder();
  mail = fakeMail();
  deps = testDeps(db, { events, mail });
  client = testClient(deps);
});
afterAll(() => db.close());

function inbound(to: string[], emailId = `em_${Math.random().toString(36).slice(2)}`, secret = INBOUND_SECRET) {
  const body = JSON.stringify({
    type: "email.received",
    created_at: new Date().toISOString(),
    data: { email_id: emailId, to, received_for: [], from: "noreply-dmarc-support@google.com", attachments: [] },
  });
  return client.app.request("/hooks/resend/inbound", {
    method: "POST",
    headers: { "content-type": "application/json", ...signStandardWebhook(secret, body) },
    body,
  });
}

test("inbound hook rejects a forged signature", async () => {
  const forged = `whsec_${Buffer.from("not-the-secret").toString("base64")}`;
  expect((await inbound([`d-x@${REPORTS_DOMAIN}`], "em_1", forged)).status).toBe(400);
  const res = await client.app.request("/hooks/resend/inbound", { method: "POST", body: "{}" });
  expect(res.status).toBe(400);
  expect(events.sent).toHaveLength(0);
});

test("inbound hook drops unknown addresses without an error", async () => {
  expect((await inbound([`d-doesnotexist@${REPORTS_DOMAIN}`, "someone@else.test"])).status).toBe(200);
  expect(events.sent).toHaveLength(0);
});

test("a report becomes rows, once", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "example.com");

  // Routed by the address; the display name and case do not matter.
  const res = await inbound([`DMARC <${domain.rua.toUpperCase()}>`], "em_google");
  expect(res.status).toBe(200);
  expect(events.sent.at(-1)).toEqual({
    name: "report/received",
    id: "received-em_google",
    data: { emailId: "em_google", domainId: domain.id, accountId: me },
  });

  mail.byEmail.em_google = fixture("google.xml.gz");
  const key = await storeAttachment(deps, { domainId: domain.id, emailId: "em_google" });
  expect(key).toBe(`${domain.id}/em_google/att_1`);

  const first = await ingestStored(deps, { domainId: domain.id, accountId: me, key: key! });
  expect(first.duplicate).toBe(false);
  const again = await ingestStored(deps, { domainId: domain.id, accountId: me, key: key! });
  expect(again).toEqual({ duplicate: true });

  const list = await client.call(me, "GET", `/api/domains/${domain.id}/reports`);
  expect(list.body.reports).toHaveLength(1);
  expect(list.body.reports[0]).toMatchObject({ reporterOrg: "google.com", messages: 419, policyPublished: { p: "none", pct: 100 } });

  const records = await client.call(me, "GET", `/api/reports/${list.body.reports[0].id}/records`);
  expect(records.body.records[0]).toMatchObject({
    sourceIp: "209.85.220.41",
    count: 400,
    dkimAligned: true,
    spfAligned: true,
    headerFrom: "example.com",
  });

  // Another tenant sees nothing.
  const other = newAccount();
  expect((await client.call(other, "GET", `/api/domains/${domain.id}/reports`)).status).toBe(404);
  expect((await client.call(other, "GET", `/api/reports/${list.body.reports[0].id}/records`)).status).toBe(404);
});

test("the domain in the report body does not choose the tenant", async () => {
  const victim = newAccount();
  const attacker = newAccount();
  const victimDomain = await verifiedDomainFor(client, deps, victim, "victim.test");
  const attackerDomain = await verifiedDomainFor(client, deps, attacker, "attacker.test");

  // A report that claims to be about victim.test, sent to the attacker's address.
  const xml = new TextDecoder().decode(fixture("yahoo.xml")).replaceAll("example.com", "victim.test");
  mail.byEmail.em_claim = gzipSync(xml);
  const key = await storeAttachment(deps, { domainId: attackerDomain.id, emailId: "em_claim" });
  await ingestStored(deps, { domainId: attackerDomain.id, accountId: attacker, key: key! });

  expect((await client.call(victim, "GET", `/api/domains/${victimDomain.id}/reports`)).body.reports).toHaveLength(0);
  expect((await client.call(attacker, "GET", `/api/domains/${attackerDomain.id}/reports`)).body.reports).toHaveLength(1);
});

test("an unverified domain shows no data", async () => {
  const me = newAccount();
  const created = await client.call(me, "POST", "/api/domains", { name: "pending.test" });
  const res = await client.call(me, "GET", `/api/domains/${created.body.id}/reports`);
  expect(res).toEqual({ status: 403, body: { error: "domain_unverified" } });
});

test("hostile attachments fail the parse step", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "hostile.test");
  mail.byEmail.em_xxe = fixture("xxe.xml");
  const key = await storeAttachment(deps, { domainId: domain.id, emailId: "em_xxe" });
  await expect(ingestStored(deps, { domainId: domain.id, accountId: me, key: key! })).rejects.toMatchObject({ code: "not_xml" });
});
