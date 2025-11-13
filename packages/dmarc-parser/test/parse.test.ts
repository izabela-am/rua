import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { describe, expect, test } from "vitest";
import { decompress, parseAggregateReport, ReportError } from "../src/index.js";

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`../fixtures/${name}`, import.meta.url)));

function expectCode(fn: () => unknown, code: ReportError["code"]) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ReportError);
    expect((e as ReportError).code).toBe(code);
    return;
  }
  throw new Error(`expected ReportError ${code}`);
}

describe("real-shaped reports", () => {
  test.each([
    ["google.xml.gz", "google.com", 3],
    ["microsoft.zip", "enterprise outlook", 2],
    ["yahoo.xml", "yahoo", 1],
    ["amazonses.xml", "amazon ses", 2],
    ["fastmail.xml", "fastmail.com", 1],
  ])("%s", (file, org, records) => {
    const report = parseAggregateReport(decompress(fixture(file)));
    expect(report.reporter.orgName).toBe(org);
    expect(report.records).toHaveLength(records);
    expect(report.policyPublished.domain).toBe("example.com");
  });

  test("normalizes a Google record", () => {
    const report = parseAggregateReport(decompress(fixture("google.xml.gz")));
    expect(report.dateRange.begin.toISOString()).toBe("2025-11-10T00:00:00.000Z");
    expect(report.policyPublished).toEqual({ domain: "example.com", p: "none", sp: "none", pct: 100, adkim: "r", aspf: "r" });
    expect(report.records[0]).toEqual({
      sourceIp: "209.85.220.41",
      count: 400,
      disposition: "none",
      dkim: "pass",
      spf: "pass",
      headerFrom: "example.com",
      authResults: [
        { type: "dkim", domain: "example.com", selector: "google", result: "pass" },
        { type: "spf", domain: "example.com", result: "pass" },
      ],
    });
  });

  test("keeps IPv6 sources", () => {
    const report = parseAggregateReport(fixture("amazonses.xml"));
    expect(report.records[1]!.sourceIp).toBe("2a01:111:f400:fe5a::712");
  });
});

describe("hostile input", () => {
  test("oversized attachment", () => {
    const oversized = gzipSync(new Uint8Array(6 * 1024 * 1024), { level: 0 });
    expectCode(() => decompress(oversized), "too_large");
  });

  test("gzip bomb stops at the decompressed cap", () => {
    // 1 GB of zeros compresses to about 1 MB; build a smaller bomb against a smaller cap
    // so the test stays fast, then check the default cap rejects a 60 MB one.
    const bomb = gzipSync(new Uint8Array(60 * 1024 * 1024));
    expect(bomb.byteLength).toBeLessThan(1024 * 1024);
    expectCode(() => decompress(bomb), "too_large");
  });

  test("nested archive", () => {
    expectCode(() => decompress(fixture("nested.zip")), "nested_archive");
    expectCode(() => decompress(gzipSync(gzipSync(fixture("yahoo.xml")))), "nested_archive");
  });

  test("zip with more than one member", () => {
    expectCode(() => decompress(fixture("two.zip")), "nested_archive");
  });

  test("XXE and billion laughs are rejected before parsing", () => {
    expectCode(() => parseAggregateReport(fixture("xxe.xml")), "not_xml");
    expectCode(() => parseAggregateReport(fixture("laughs.xml")), "not_xml");
  });

  test("deep nesting", () => {
    const deep = "<feedback>" + "<a>".repeat(50) + "</a>".repeat(50) + "</feedback>";
    expectCode(() => parseAggregateReport(deep), "not_xml");
  });

  test("not a report", () => {
    expectCode(() => parseAggregateReport(fixture("not-feedback.xml")), "schema");
    expectCode(() => decompress(new TextEncoder().encode("PK? no")), "not_xml");
  });

  test("bad source IP", () => {
    const xml = new TextDecoder().decode(fixture("yahoo.xml")).replace("198.2.180.5", "$(rm -rf)");
    expectCode(() => parseAggregateReport(xml), "schema");
  });

  test("wide report parses well under the step timeout", () => {
    const one = new TextDecoder().decode(fixture("yahoo.xml")).match(/<record>[\s\S]*<\/record>/)![0];
    const wide = new TextDecoder().decode(fixture("yahoo.xml")).replace(one, one.repeat(20_000));
    const started = performance.now();
    const report = parseAggregateReport(wide);
    expect(report.records).toHaveLength(20_000);
    expect(performance.now() - started).toBeLessThan(30_000);
  });
});
