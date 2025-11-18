import { describe, expect, test } from "vitest";
import { parseAsnTsv } from "../src/intel/asn.js";
import { classify, isSpoofing } from "../src/intel/classify.js";
import { ipToBigInt } from "../src/intel/ip.js";
import { loadProviders, providers } from "../src/intel/providers.js";
import { testAsn } from "./helpers.js";

describe("ipToBigInt", () => {
  test.each([
    ["0.0.0.0", 0n],
    ["1.2.3.4", 0x01020304n],
    ["255.255.255.255", 0xffffffffn],
    ["::1", 1n],
    ["2a01:111::", 0x2a010111n << 96n],
    ["::ffff:1.2.3.4", 0xffff01020304n],
  ])("%s", (ip, n) => expect(ipToBigInt(ip)).toBe(n));
});

describe("ASN table", () => {
  test("finds ranges for both families", () => {
    expect(testAsn.lookup("209.85.220.41")).toEqual({ asn: 15169, asName: "GOOGLE" });
    expect(testAsn.lookup("2a01:111:f400:fe5a::712")?.asn).toBe(8075);
    expect(testAsn.lookup("45.33.12.9")?.asn).toBe(63949);
  });

  test("returns null between ranges and outside them", () => {
    expect(testAsn.lookup("209.85.127.255")).toBeNull();
    expect(testAsn.lookup("1.1.1.1")).toBeNull();
    expect(testAsn.lookup("::1")).toBeNull();
  });

  test("skips AS 0 rows and sorts its input", () => {
    const t = parseAsnTsv("10.0.0.0\t10.0.0.255\t0\tNone\tNot routed\n2.0.0.0\t2.0.0.255\t2\tUS\tB\n1.0.0.0\t1.0.0.255\t1\tUS\tA\n");
    expect(t.size).toBe(2);
    expect(t.lookup("1.0.0.7")?.asn).toBe(1);
    expect(t.lookup("10.0.0.1")).toBeNull();
  });
});

describe("providers", () => {
  const p = providers();

  test("matches PTR suffixes on label boundaries", () => {
    expect(p.match({ asn: null, ptr: "mail-sor-f41.google.com." })?.name).toBe("Google Workspace");
    expect(p.match({ asn: null, ptr: "o1.ptr1234.sendgrid.net" })?.name).toBe("SendGrid");
    expect(p.match({ asn: null, ptr: "notgoogle.com" })).toBeNull();
    expect(p.match({ asn: null, ptr: "google.com.evil.test" })).toBeNull();
  });

  test("falls back to ASN", () => {
    expect(p.match({ asn: 8075, ptr: null })?.name).toBe("Microsoft 365");
    expect(p.match({ asn: 63949, ptr: null })).toBeNull();
  });

  test("rejects a malformed file", () => {
    expect(() => loadProviders("providers: [{ asn: [1] }]")).toThrow();
  });
});

describe("classify", () => {
  const p = providers();

  test("aligned when every message aligned", () => {
    expect(classify({ messages: 10, aligned: 10, failingBoth: 0 }, null, p)).toBe("aligned_sender");
  });

  test("forwarder when a forwarding provider breaks alignment", () => {
    expect(classify({ messages: 10, aligned: 7, failingBoth: 3 }, "Google Workspace", p)).toBe("known_forwarder");
  });

  test("an ESP that does not align is unknown", () => {
    expect(classify({ messages: 10, aligned: 0, failingBoth: 10 }, "SendGrid", p)).toBe("unknown");
  });

  test("spoofing is unknown and failing both", () => {
    expect(isSpoofing("unknown", { messages: 3, aligned: 0, failingBoth: 3 })).toBe(true);
    expect(isSpoofing("unknown", { messages: 3, aligned: 0, failingBoth: 0 })).toBe(false);
    expect(isSpoofing("known_forwarder", { messages: 3, aligned: 0, failingBoth: 3 })).toBe(false);
  });
});
