import { generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "vitest";
import { auditDkim, keyBits } from "../src/audit/dkim.js";
import { auditDmarc, parseDmarc } from "../src/audit/dmarc.js";
import { findingHistory } from "../src/audit/domain.js";
import { auditExtras } from "../src/audit/extras.js";
import { auditSpf, countLookups } from "../src/audit/spf.js";
import { readiness } from "../src/readiness.js";
import { fakeResolver } from "./helpers.js";

const NOW = new Date("2025-11-22T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000);

describe("readiness", () => {
  const vol = (aligned: number, fwd: number, unknown: number, failing: Array<{ messages: number; lastSeen: Date }> = []) => ({
    total: aligned + fwd + unknown,
    aligned,
    knownForwarder: fwd,
    unknown,
    unknownFailing: failing.map((f, i) => ({ ip: `10.0.0.${i}`, classification: "unknown", ...f })),
  });

  test("no data recommends nothing", () => {
    expect(readiness(vol(0, 0, 0), NOW)).toEqual({ survival: null, recommended: "none", blockers: [] });
  });

  test("all legitimate recommends reject", () => {
    expect(readiness(vol(9_000, 1_000, 0), NOW).recommended).toBe("reject");
  });

  test("99% recommends quarantine, below that none", () => {
    expect(readiness(vol(990, 2, 8), NOW).recommended).toBe("quarantine");
    expect(readiness(vol(980, 0, 20), NOW).recommended).toBe("none");
  });

  test("a recent unknown failing source blocks reject even at 99.9%", () => {
    const r = readiness(vol(9_990, 0, 10, [{ messages: 10, lastSeen: daysAgo(3) }]), NOW);
    expect(r.survival!.reject).toBeCloseTo(0.999);
    expect(r.recommended).toBe("quarantine");
    expect(r.blockers).toHaveLength(1);
  });

  test("an old one does not", () => {
    expect(readiness(vol(9_990, 0, 10, [{ messages: 10, lastSeen: daysAgo(20) }]), NOW).recommended).toBe("reject");
  });
});

describe("SPF", () => {
  // The example from the spec: 3 top-level lookups, Google adds 3 nested, SendGrid adds n.
  const resolver = fakeResolver({
    txt: {
      "example.com": [["v=spf1 include:_spf.google.com include:sendgrid.net mx -all"], ["google-site-verification=x"]],
      "_spf.google.com": [["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"]],
      "_netblocks.google.com": [["v=spf1 ip4:35.190.247.0/24 ~all"]],
      "_netblocks2.google.com": [["v=spf1 ip6:2001:4860:4000::/36 ~all"]],
      "_netblocks3.google.com": [["v=spf1 ip4:172.217.0.0/19 ~all"]],
      "sendgrid.net": [["v=spf1 ip4:167.89.0.0/17 include:a.sg.test include:b.sg.test ~all"]],
      "a.sg.test": [["v=spf1 a mx ~all"]],
      "b.sg.test": [["v=spf1 exists:%{i}.x.test ~all"]],
      "plus.test": [["v=spf1 +all"]],
      "two.test": [["v=spf1 -all"], ["v=spf1 ~all"]],
      "voids.test": [["v=spf1 include:gone1.test include:gone2.test include:gone3.test -all"]],
      "loop.test": [["v=spf1 include:loop.test -all"]],
    },
  });

  test("counts lookups through nested includes", async () => {
    const r = await countLookups(resolver, "v=spf1 include:_spf.google.com include:sendgrid.net mx -all");
    expect(r.chain).toEqual([
      { term: "include:_spf.google.com", cost: 4 },
      { term: "include:sendgrid.net", cost: 6 },
      { term: "mx", cost: 1 },
    ]);
    expect(r.lookups).toBe(11);
  });

  test("over the limit is a finding with the chain in the fix", async () => {
    const { record, findings } = await auditSpf(resolver, "example.com");
    expect(record).toMatch(/^v=spf1 include:_spf.google.com/);
    expect(findings).toEqual([
      expect.objectContaining({
        code: "spf_lookup_limit",
        severity: "high",
        message: "SPF needs 11 DNS lookups; receivers stop at 10 and treat the result as permerror.",
        fix: "Remove or flatten one include. Current chain: include:_spf.google.com (4), include:sendgrid.net (6), mx (1)",
      }),
    ]);
  });

  test.each([
    ["plus.test", "spf_plus_all"],
    ["two.test", "spf_multiple"],
    ["voids.test", "spf_void_lookups"],
    ["loop.test", "spf_include_loop"],
    ["missing.test", "spf_missing"],
  ])("%s → %s", async (name, code) => {
    const { findings } = await auditSpf(resolver, name);
    expect(findings.map((f) => f.code)).toContain(code);
  });
});

describe("DMARC", () => {
  const ctx = { ruaAddress: "d-abc@reports.rua.test", subdomainsSeen: [], relaxedOnlySenders: false };
  const at = (record: string | null) => fakeResolver({ txt: record ? { "_dmarc.x.test": [[record]] } : {} });
  const codes = async (record: string | null, c = ctx) => (await auditDmarc(at(record), "x.test", c)).findings.map((f) => f.code);

  test("parses tags", () => {
    expect(parseDmarc("v=DMARC1; p=reject; rua=mailto:a@b.test")).toEqual({ v: "DMARC1", p: "reject", rua: "mailto:a@b.test" });
    expect(parseDmarc("p=reject; v=DMARC1")).toBeNull();
  });

  test("a good record has no findings", async () => {
    expect(await codes("v=DMARC1; p=reject; rua=mailto:d-abc@reports.rua.test,mailto:me@x.test")).toEqual([]);
  });

  test("findings", async () => {
    expect(await codes(null)).toEqual(["dmarc_missing"]);
    expect(await codes("v=DMARC1; p=maybe")).toEqual(["dmarc_syntax"]);
    expect(await codes("v=DMARC1; p=none; pct=50")).toEqual(["dmarc_p_none", "dmarc_pct", "dmarc_rua_missing"]);
    expect(await codes("v=DMARC1; p=quarantine; rua=mailto:other@x.test")).toEqual(["dmarc_rua_not_rua"]);
    expect(
      await codes("v=DMARC1; p=reject; adkim=s; rua=mailto:d-abc@reports.rua.test", {
        ...ctx,
        subdomainsSeen: ["news.x.test"],
        relaxedOnlySenders: true,
      }),
    ).toEqual(["dmarc_sp_missing", "dmarc_strict_alignment"]);
  });
});

describe("DKIM", () => {
  const spki = (bits: number) =>
    generateKeyPairSync("rsa", { modulusLength: bits }).publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const k2048 = spki(2048);
  const k1024 = spki(1024);

  test("reads key sizes", () => {
    expect(keyBits(k2048)).toBe(2048);
    expect(keyBits(k1024)).toBe(1024);
    expect(keyBits("bm90IGEga2V5")).toBeNull();
  });

  test("findings per selector", async () => {
    const resolver = fakeResolver({
      txt: {
        "good._domainkey.x.test": [[`v=DKIM1; k=rsa; p=${k2048.slice(0, 200)}`, k2048.slice(200)]],
        "weak._domainkey.x.test": [[`v=DKIM1; t=y; p=${k1024}`]],
        "revoked._domainkey.x.test": [["v=DKIM1; p="]],
      },
      cname: { "dangling._domainkey.x.test": ["s1.esp.test"] },
    });
    const { records, findings } = await auditDkim(resolver, "x.test", ["good", "weak", "revoked", "dangling", "gone"]);
    expect(records.good).toContain("p=");
    expect(findings.map((f) => [f.selector, f.code])).toEqual([
      ["weak", "dkim_weak_key"],
      ["weak", "dkim_testing"],
      ["revoked", "dkim_revoked"],
      ["dangling", "dkim_dangling_cname"],
      ["gone", "dkim_missing"],
    ]);
  });
});

describe("MTA-STS, TLS-RPT, BIMI", () => {
  test("testing mode and missing records", async () => {
    const resolver = fakeResolver({ txt: { "_mta-sts.x.test": [["v=STSv1; id=20251122"]] } });
    const r = await auditExtras(resolver, async () => "version: STSv1\nmode: testing\nmx: mx.x.test\nmax_age: 86400\n", "x.test", "reject");
    expect(r.findings.map((f) => f.code)).toEqual(["mta_sts_testing", "tls_rpt_missing", "bimi_missing"]);
  });

  test("unreachable policy file", async () => {
    const resolver = fakeResolver({ txt: { "_mta-sts.x.test": [["v=STSv1; id=1"]], "_smtp._tls.x.test": [["v=TLSRPTv1; rua=mailto:t@x.test"]] } });
    const r = await auditExtras(resolver, async () => null, "x.test", "none");
    expect(r.findings.map((f) => f.code)).toEqual(["mta_sts_policy_unreachable"]);
  });
});

test("finding history shows when each finding appeared and cleared", () => {
  const f = (code: string) => ({ code, severity: "high" as const, message: "", fix: "" });
  const history = findingHistory([
    { takenAt: daysAgo(0), findings: [f("b")] },
    { takenAt: daysAgo(2), findings: [f("a")] },
    { takenAt: daysAgo(1), findings: [f("a"), f("b")] },
  ]);
  expect(history.map((h) => [h.code, h.change, h.at.toISOString().slice(0, 10)])).toEqual([
    ["a", "cleared", "2025-11-22"],
    ["b", "appeared", "2025-11-21"],
    ["a", "appeared", "2025-11-20"],
  ]);
});
