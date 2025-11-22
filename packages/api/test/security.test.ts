import { describe, expect, test } from "vitest";
import { domainOf } from "../src/delivery.js";
import { decrypt, encrypt, keyringFromEnv } from "../src/lib/crypto.js";
import { isPublicAddress, pinnedPoster, resolveSafeUrl } from "../src/lib/safe-url.js";
import { signAlert, verifyAlert } from "../src/lib/sign.js";
import { fakeResolver, testKeyring } from "./helpers.js";

describe("secrets at rest", () => {
  test("round trip with a fresh IV each time", () => {
    const a = encrypt(testKeyring, "whsec_abc");
    const b = encrypt(testKeyring, "whsec_abc");
    expect(Buffer.from(a.blob).equals(Buffer.from(b.blob))).toBe(false);
    expect(decrypt(testKeyring, a.blob, a.keyId)).toBe("whsec_abc");
  });

  test("tampering and the wrong key fail", () => {
    const { blob } = encrypt(testKeyring, "secret");
    const flipped = Uint8Array.from(blob);
    flipped[flipped.length - 1]! ^= 1;
    expect(() => decrypt(testKeyring, flipped, "k1")).toThrow();
    expect(() => decrypt(testKeyring, blob, "k0")).toThrow();
    expect(() => decrypt(testKeyring, blob, "nope")).toThrow(/no key/);
  });

  test("old rows still decrypt after rotation", () => {
    const old = encrypt({ ...testKeyring, current: "k0" }, "legacy");
    expect(old.keyId).toBe("k0");
    expect(decrypt(testKeyring, old.blob, old.keyId)).toBe("legacy");
  });

  test("keyring from env validates sizes and the current key", () => {
    const k = Buffer.alloc(32, 1).toString("base64");
    expect(keyringFromEnv({ RUA_KEK_CURRENT: "a", RUA_KEK_a: k }).current).toBe("a");
    expect(() => keyringFromEnv({ RUA_KEK_CURRENT: "a", RUA_KEK_a: "c2hvcnQ=" })).toThrow(/32 bytes/);
    expect(() => keyringFromEnv({ RUA_KEK_CURRENT: "b", RUA_KEK_a: k })).toThrow(/RUA_KEK_CURRENT/);
  });
});

describe("alert signatures", () => {
  const now = 1_763_000_000_000;

  test("verify accepts its own signature", () => {
    const header = signAlert("s3cret", '{"a":1}', now);
    expect(header).toMatch(/^t=1763000000,v1=[0-9a-f]{64}$/);
    expect(verifyAlert("s3cret", '{"a":1}', header, now)).toBe(true);
  });

  test("verify rejects a changed body, the wrong secret and old timestamps", () => {
    const header = signAlert("s3cret", '{"a":1}', now);
    expect(verifyAlert("s3cret", '{"a":2}', header, now)).toBe(false);
    expect(verifyAlert("other", '{"a":1}', header, now)).toBe(false);
    expect(verifyAlert("s3cret", '{"a":1}', header, now + 301_000)).toBe(false);
    expect(verifyAlert("s3cret", '{"a":1}', "garbage", now)).toBe(false);
  });
});

describe("outbound webhook URLs", () => {
  test.each([
    ["8.8.8.8", true],
    ["2606:4700::1111", true],
    ["10.1.2.3", false],
    ["127.0.0.1", false],
    ["169.254.169.254", false],
    ["100.64.0.1", false],
    ["192.168.1.1", false],
    ["::1", false],
    ["fd00::1", false],
    ["fe80::1", false],
    ["::ffff:127.0.0.1", false],
    ["::ffff:7f00:1", false],
    ["::ffff:8.8.8.8", true],
    ["64:ff9b::a00:1", false],
    ["not-an-ip", false],
  ])("isPublicAddress(%s) = %s", (ip, ok) => expect(isPublicAddress(ip)).toBe(ok));

  const resolver = fakeResolver({
    a: {
      "hooks.example.com": ["93.184.216.34"],
      "metadata.evil.test": ["169.254.169.254"],
      "mixed.evil.test": ["93.184.216.34", "10.0.0.1"],
    },
    aaaa: { "v6.example.com": ["2606:2800:220:1:248:1893:25c8:1946"] },
  });

  test("accepts https hostnames that resolve to public addresses", async () => {
    expect(await resolveSafeUrl(resolver, "https://hooks.example.com/rua")).toMatchObject({ address: "93.184.216.34", family: 4 });
    expect((await resolveSafeUrl(resolver, "https://v6.example.com/")).family).toBe(6);
  });

  test.each([
    ["http://hooks.example.com/", /https only/],
    ["https://hooks.example.com:8443/", /port 443/],
    ["https://user:pw@hooks.example.com/", /credentials/],
    ["https://93.184.216.34/", /hostname/],
    ["https://[::1]/", /hostname/],
    ["https://metadata.evil.test/", /non-public/],
    ["https://mixed.evil.test/", /non-public/],
    ["https://nowhere.test/", /does not resolve/],
    ["javascript:alert(1)", /https only/],
    ["nope", /not a URL/],
  ])("rejects %s", async (url, reason) => {
    await expect(resolveSafeUrl(resolver, url)).rejects.toThrow(reason);
  });

  test("the poster checks before it connects", async () => {
    await expect(pinnedPoster(resolver)("https://metadata.evil.test/", "{}", {})).rejects.toThrow(/non-public/);
  });
});

test("domainOf reads the sender domain", () => {
  expect(domainOf("Acme <news@Example.com>")).toBe("example.com");
  expect(domainOf("ops@mail.example.com")).toBe("mail.example.com");
  expect(domainOf("no address")).toBeNull();
});
