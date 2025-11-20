import { createHmac, timingSafeEqual } from "node:crypto";

/** X-Rua-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of `${t}.${body}`>. */
export function signAlert(secret: string, body: string, now = Date.now()) {
  const t = Math.floor(now / 1000);
  const v1 = createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");
  return `t=${t},v1=${v1}`;
}

/** The receiver side. Copied verbatim into the README for tenants. */
export function verifyAlert(secret: string, body: string, header: string, now = Date.now(), toleranceSec = 300) {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=", 2) as [string, string]));
  const t = Number(parts.t);
  if (!Number.isInteger(t) || !parts.v1 || Math.abs(now / 1000 - t) > toleranceSec) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  const given = Buffer.from(parts.v1, "hex");
  return given.length === expected.length && timingSafeEqual(given, expected);
}
