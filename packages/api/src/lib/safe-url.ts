import { request } from "node:https";
import { BlockList, isIP } from "node:net";
import { ipToBigInt } from "../intel/ip.js";
import { orEmpty, type Resolver } from "./dns.js";

// Everything that is not public unicast address space.
const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(net, bits, "ipv4");
}
for (const [net, bits] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  blocked.addSubnet(net, bits, "ipv6");
}

export function isPublicAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 0) return false;
  if (v === 6) {
    // IPv4-mapped (::ffff:a.b.c.d): judge the embedded IPv4 address. Not a
    // BlockList rule, because BlockList applies ::ffff:0:0/96 to every IPv4 check.
    const n = ipToBigInt(ip);
    if (n >> 32n === 0xffffn) {
      const v4 = [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 0xffn)).join(".");
      return isPublicAddress(v4);
    }
  }
  return !blocked.check(ip, v === 4 ? "ipv4" : "ipv6");
}

export class UnsafeUrl extends Error {}

/**
 * Checks an outbound webhook URL: https, default port, hostname (not a literal
 * IP) that resolves only to public addresses. Returns the address to connect
 * to, so the check and the connection use the same DNS answer.
 */
export async function resolveSafeUrl(resolver: Resolver, raw: string): Promise<{ url: URL; address: string; family: 4 | 6 }> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrl("not a URL");
  }
  if (url.protocol !== "https:") throw new UnsafeUrl("https only");
  if (url.username || url.password) throw new UnsafeUrl("credentials in URL");
  if (url.port && url.port !== "443") throw new UnsafeUrl("port 443 only");
  const host = url.hostname;
  if (isIP(host.replace(/^\[|\]$/g, ""))) throw new UnsafeUrl("use a hostname, not an IP");

  const v4 = await orEmpty(resolver.resolve4(host));
  const v6 = await orEmpty(resolver.resolve6(host));
  const all = [...v4, ...v6];
  if (all.length === 0) throw new UnsafeUrl("hostname does not resolve");
  // Every answer must be public: a mixed answer is a rebinding setup.
  if (!all.every(isPublicAddress)) throw new UnsafeUrl("hostname resolves to a non-public address");
  return v4.length ? { url, address: v4[0]!, family: 4 } : { url, address: v6[0]!, family: 6 };
}

export type PostResult = { status: number };
export type PostWebhook = (raw: string, body: string, headers: Record<string, string>) => Promise<PostResult>;

/** POSTs to a checked URL, connecting to the pinned address. No redirects, 5 s timeout. */
export function pinnedPoster(resolver: Resolver): PostWebhook {
  return async (raw, body, headers) => {
    const { url, address, family } = await resolveSafeUrl(resolver, raw);
    return new Promise((resolve, reject) => {
      const req = request(
        url,
        {
          method: "POST",
          headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), ...headers },
          timeout: 5000,
          // Called instead of DNS; TLS still verifies the certificate for url.hostname.
          lookup: (_host, opts, cb) => {
            if ((opts as { all?: boolean }).all) cb(null, [{ address, family }] as never);
            else cb(null, address, family);
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        },
      );
      req.on("timeout", () => req.destroy(new Error("webhook timed out")));
      req.on("error", reject);
      req.end(body);
    });
  };
}
