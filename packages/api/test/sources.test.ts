import { eq } from "drizzle-orm";
import { afterAll, beforeAll, expect, test } from "vitest";
import { ipIntel } from "../src/db/schema.js";
import type { Deps } from "../src/deps.js";
import { ingestStored, storeAttachment } from "../src/ingest.js";
import { classifySource, distinctSourceIps } from "../src/intel/sources.js";
import { FIXTURE_NOW, fakeMail, fakeResolver, fixture, newAccount, setupDb, testClient, testDeps, verifiedDomainFor } from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
let deps: Deps;
let client: ReturnType<typeof testClient>;
const mail = fakeMail();
const resolver = fakeResolver({
  ptr: {
    "209.85.220.41": ["mail-sor-f41.google.com"],
    "209.85.220.69": ["mail-sor-f69.google.com"],
    // Anyone can publish a PTR. This one claims Google and does not resolve back.
    "45.33.12.9": ["mail.google.com"],
  },
  a: {
    "mail-sor-f41.google.com": ["209.85.220.41"],
    "mail-sor-f69.google.com": ["209.85.220.69"],
    "mail.google.com": ["142.250.0.1"],
  },
});

beforeAll(async () => {
  db = await setupDb();
  deps = testDeps(db, { mail, resolver });
  client = testClient(deps);
});
afterAll(() => db.close());

const NOW = FIXTURE_NOW;

async function ingest(accountId: string, domainId: string, file: string, emailId: string) {
  mail.byEmail[emailId] = fixture(file);
  const key = await storeAttachment(deps, { domainId, emailId });
  const r = await ingestStored(deps, { domainId, accountId, key: key! });
  if (r.duplicate) throw new Error("unexpected duplicate");
  return r.reportId;
}

test("sources are enriched, labelled and listed", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "example.com");
  const reportId = await ingest(me, domain.id, "google.xml.gz", "em_g");

  const ips = await distinctSourceIps(db.workerDb, reportId);
  expect(ips.sort()).toEqual(["209.85.220.41", "209.85.220.69", "45.33.12.9"]);
  const changes = await Promise.all(ips.map((ip) => classifySource(deps, { domainId: domain.id, accountId: me }, ip, NOW)));
  expect(changes.every((c) => c.isNew)).toBe(true);

  const spoof = changes.find((c) => c.ip === "45.33.12.9")!;
  expect(spoof).toMatchObject({ classification: "unknown", spoofing: true, provider: null, ptr: null, asn: 63949 });

  const res = await client.call(me, "GET", `/api/domains/${domain.id}/sources?days=30`);
  expect(res.status).toBe(200);
  const byIp = Object.fromEntries(res.body.sources.map((s: { ip: string }) => [s.ip, s]));
  expect(byIp["209.85.220.41"]).toMatchObject({
    classification: "aligned_sender",
    provider: "Google Workspace",
    ptr: "mail-sor-f41.google.com",
    ptrConfirmed: true,
    asn: 15169,
    messages: 400,
    aligned: 400,
    spoofing: false,
  });
  // DKIM aligned, SPF did not: still aligned for DMARC.
  expect(byIp["209.85.220.69"].classification).toBe("aligned_sender");
  expect(byIp["45.33.12.9"]).toMatchObject({ classification: "unknown", spoofing: true, ptrConfirmed: false });

  const charts = await client.call(me, "GET", `/api/domains/${domain.id}/charts?days=30`);
  expect(charts.body.days).toEqual([
    { day: "2025-11-10", aligned_sender: 412, known_forwarder: 0, unknown: 7, total: 419, aligned: 412, alignedRate: 412 / 419 },
  ]);
});

test("a second report updates sources without calling them new", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "again.test");
  const xml = new TextDecoder().decode(fixture("google.xml")).replaceAll("example.com", "again.test");
  mail.byEmail.em_a1 = new TextEncoder().encode(xml);
  const k1 = await storeAttachment(deps, { domainId: domain.id, emailId: "em_a1" });
  const r1 = await ingestStored(deps, { domainId: domain.id, accountId: me, key: k1! });
  if (r1.duplicate) throw new Error();
  await classifySource(deps, { domainId: domain.id, accountId: me }, "45.33.12.9", NOW);

  mail.byEmail.em_a2 = new TextEncoder().encode(xml.replace("12715390811045927493", "second-report"));
  const k2 = await storeAttachment(deps, { domainId: domain.id, emailId: "em_a2" });
  await ingestStored(deps, { domainId: domain.id, accountId: me, key: k2! });
  const second = await classifySource(deps, { domainId: domain.id, accountId: me }, "45.33.12.9", NOW);
  expect(second).toMatchObject({ isNew: false, previous: "unknown", classification: "unknown", messages: 14 });
});

test("intel is cached for 30 days", async () => {
  const lookups: string[] = [];
  const counting = { ...resolver, reverse: (ip: string) => (lookups.push(ip), resolver.reverse(ip)) };
  const d2 = testDeps(db, { resolver: counting });
  await db.workerDb.delete(ipIntel).where(eq(ipIntel.ip, "209.85.220.41"));
  const { intelFor } = await import("../src/intel/enrich.js");

  await intelFor(d2, "209.85.220.41", NOW);
  await intelFor(d2, "209.85.220.41", new Date(NOW.getTime() + 29 * 86_400_000));
  expect(lookups).toHaveLength(1);
  await intelFor(d2, "209.85.220.41", new Date(NOW.getTime() + 31 * 86_400_000));
  expect(lookups).toHaveLength(2);
});

test("another tenant cannot list the sources", async () => {
  const owner = newAccount();
  const domain = await verifiedDomainFor(client, deps, owner, "mine.test");
  expect((await client.call(newAccount(), "GET", `/api/domains/${domain.id}/sources`)).status).toBe(404);
  expect((await client.call(newAccount(), "GET", `/api/domains/${domain.id}/charts`)).status).toBe(404);
});
