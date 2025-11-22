import { eq } from "drizzle-orm";
import { afterAll, beforeAll, expect, test } from "vitest";
import { auditDomain, checkOwnership, expireRaw } from "../src/daily.js";
import { domains, reports } from "../src/db/schema.js";
import type { Deps } from "../src/deps.js";
import { ingestStored, storeAttachment } from "../src/ingest.js";
import { classifySource, distinctSourceIps } from "../src/intel/sources.js";
import { FIXTURE_NOW, fakeMail, fakeResolver, fixture, newAccount, REPORTS_DOMAIN, setupDb, testClient, testDeps, verifiedDomainFor } from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
let deps: Deps;
let client: ReturnType<typeof testClient>;
const mail = fakeMail();
const resolver = fakeResolver({ txt: {}, ptr: {}, a: {} });

beforeAll(async () => {
  db = await setupDb();
  deps = testDeps(db, { mail, resolver });
  client = testClient(deps);
});
afterAll(() => db.close());

async function domainWithReport(name: string) {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, name);
  mail.byEmail[`em_${name}`] = new TextEncoder().encode(new TextDecoder().decode(fixture("google.xml")).replaceAll("example.com", name));
  const key = await storeAttachment(deps, { domainId: domain.id, emailId: `em_${name}` });
  const r = await ingestStored(deps, { domainId: domain.id, accountId: me, key: key! });
  if (r.duplicate) throw new Error();
  for (const ip of await distinctSourceIps(db.workerDb, r.reportId)) {
    await classifySource(deps, { domainId: domain.id, accountId: me }, ip, FIXTURE_NOW);
  }
  const [row] = await db.workerDb.select().from(domains).where(eq(domains.id, domain.id));
  return { me, domain, row: row! };
}

test("readiness reflects classified volume", async () => {
  const { me, domain } = await domainWithReport("ready.test");
  const res = await client.call(me, "GET", `/api/domains/${domain.id}/readiness`);
  expect(res.status).toBe(200);
  expect(res.body).toMatchObject({
    published: "none",
    // 412 of 419 messages aligned: 98.3%, below the quarantine bar.
    recommended: "none",
    volume: { total: 419, aligned: 412, knownForwarder: 0, unknown: 7 },
    blockers: [{ ip: "45.33.12.9", messages: 7 }],
  });
  expect(res.body.survival.quarantine).toBeCloseTo(412 / 419);
  expect(res.body.record).toBe(`v=DMARC1; p=none; pct=100; rua=mailto:${domain.rua}; adkim=r; aspf=r`);
});

test("the first audit is a baseline; later new findings raise alerts", async () => {
  const { me, domain, row } = await domainWithReport("audited.test");
  resolver.records.txt!["audited.test"] = [["v=spf1 include:_spf.google.com -all"]];
  resolver.records.txt!["_spf.google.com"] = [["v=spf1 ip4:209.85.128.0/17 ~all"]];
  resolver.records.txt!["_dmarc.audited.test"] = [[`v=DMARC1; p=none; rua=mailto:${domain.rua}`]];

  const first = await auditDomain(deps, row, REPORTS_DOMAIN, FIXTURE_NOW);
  expect(first.alerts.filter((a) => a.kind === "audit_finding")).toEqual([]);

  // Someone adds +all.
  resolver.records.txt!["audited.test"] = [["v=spf1 include:_spf.google.com +all"]];
  const second = await auditDomain(deps, row, REPORTS_DOMAIN, new Date(FIXTURE_NOW.getTime() + 86_400_000));
  expect(second.alerts.map((a) => [a.kind, a.payload.code])).toEqual([["audit_finding", "spf_plus_all"]]);

  const audit = await client.call(me, "GET", `/api/domains/${domain.id}/audit`);
  expect(audit.body.records.spf).toBe("v=spf1 include:_spf.google.com +all");
  // DKIM selector "google" came from the report and has no key published here.
  expect(audit.body.findings.map((f: { code: string }) => f.code)).toEqual(
    expect.arrayContaining(["spf_plus_all", "dmarc_p_none", "dkim_missing", "mta_sts_missing", "tls_rpt_missing"]),
  );
  expect(audit.body.history[0]).toMatchObject({ code: "spf_plus_all", change: "appeared" });
});

test("a domain whose TXT disappears loses verification and its data", async () => {
  const { me, domain, row } = await domainWithReport("lost.test");
  delete resolver.records.txt!["_rua.lost.test"];
  const r = await checkOwnership(deps, row, FIXTURE_NOW);
  expect(r).toMatchObject({ verified: false, alert: { kind: "ownership_lost" } });
  expect((await client.call(me, "GET", `/api/domains/${domain.id}/reports`)).status).toBe(403);
});

test("a policy recommendation stricter than published raises policy_ready", async () => {
  const me = newAccount();
  const domain = await verifiedDomainFor(client, deps, me, "clean.test");
  // One source, every message aligned.
  const xml = new TextDecoder()
    .decode(fixture("yahoo.xml"))
    .replaceAll("example.com", "clean.test");
  mail.byEmail.em_clean = new TextEncoder().encode(xml);
  const key = await storeAttachment(deps, { domainId: domain.id, emailId: "em_clean" });
  const rep = await ingestStored(deps, { domainId: domain.id, accountId: me, key: key! });
  if (rep.duplicate) throw new Error();
  await classifySource(deps, { domainId: domain.id, accountId: me }, "198.2.180.5", FIXTURE_NOW);
  const [row] = await db.workerDb.select().from(domains).where(eq(domains.id, domain.id));
  const result = await auditDomain(deps, row!, REPORTS_DOMAIN, FIXTURE_NOW);
  expect(result.alerts.find((a) => a.kind === "policy_ready")).toMatchObject({
    dedupKey: "policy_ready:reject",
    payload: { published: "none", recommended: "reject" },
  });
});

test("raw objects expire after 30 days; parsed rows stay", async () => {
  const { domain } = await domainWithReport("expire.test");
  const [rep] = await db.workerDb.select().from(reports).where(eq(reports.domainId, domain.id));
  expect(await deps.store.get(rep!.rawObjectKey!)).toBeTruthy();

  expect(await expireRaw(deps, new Date(Date.now() + 29 * 86_400_000))).toBe(0);
  expect(await expireRaw(deps, new Date(Date.now() + 31 * 86_400_000))).toBeGreaterThanOrEqual(1);
  const [after] = await db.workerDb.select().from(reports).where(eq(reports.id, rep!.id));
  expect(after!.rawObjectKey).toBeNull();
  await expect(deps.store.get(rep!.rawObjectKey!)).rejects.toThrow();
});
