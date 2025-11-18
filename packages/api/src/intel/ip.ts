import { isIPv4, isIPv6 } from "node:net";

/** An address as a bigint, for range comparisons. IPv4 and IPv6 live in separate tables. */
export function ipToBigInt(ip: string): bigint {
  if (isIPv4(ip)) return ip.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
  if (!isIPv6(ip)) throw new Error(`not an IP: ${ip}`);

  let s = ip.toLowerCase();
  // IPv4-mapped tail, such as ::ffff:1.2.3.4
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = ipToBigInt(v4[1]!);
    s = s.slice(0, -v4[1]!.length) + `${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const [head, tail] = s.split("::") as [string, string | undefined];
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}

export const ipVersion = (ip: string): 4 | 6 => (isIPv4(ip) ? 4 : 6);
