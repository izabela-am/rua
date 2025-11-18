import { eq } from "drizzle-orm";
import type { Db } from "../db/client.js";
import { ipIntel } from "../db/schema.js";
import { orEmpty, type Resolver } from "../lib/dns.js";
import type { AsnTable } from "./asn.js";
import { ipToBigInt, ipVersion } from "./ip.js";
import type { Providers } from "./providers.js";

export const INTEL_TTL_DAYS = 30;

export type Intel = typeof ipIntel.$inferSelect;
export type EnrichDeps = { workerDb: Db; resolver: Resolver; asn: AsnTable; providers: Providers };

/**
 * Returns cached intel for an IP, refreshing it when older than 30 days.
 * The only names resolved are PTRs of report source IPs and the forward lookup
 * that confirms them; nothing a tenant controls.
 */
export async function intelFor(deps: EnrichDeps, ip: string, now = new Date()): Promise<Intel> {
  const [cached] = await deps.workerDb.select().from(ipIntel).where(eq(ipIntel.ip, ip));
  if (cached && now.getTime() - cached.refreshedAt.getTime() < INTEL_TTL_DAYS * 86_400_000) return cached;

  const [ptrRaw] = await orEmpty(deps.resolver.reverse(ip));
  const ptr = ptrRaw ? ptrRaw.toLowerCase().replace(/\.$/, "") : null;
  const confirmed = ptr ? await forwardConfirms(deps.resolver, ptr, ip) : false;
  const asn = deps.asn.lookup(ip);
  // An unconfirmed PTR is whatever the IP's owner chose to publish, so it may
  // not name a provider; only the ASN counts then.
  const provider = deps.providers.match({ asn: asn?.asn ?? null, ptr: confirmed ? ptr : null });

  const row = {
    ip,
    ptr,
    ptrConfirmed: confirmed,
    asn: asn?.asn ?? null,
    asName: asn?.asName ?? null,
    provider: provider?.name ?? null,
    refreshedAt: now,
  };
  await deps.workerDb.insert(ipIntel).values(row).onConflictDoUpdate({ target: ipIntel.ip, set: row });
  return row;
}

async function forwardConfirms(resolver: Resolver, ptr: string, ip: string) {
  const addrs = ipVersion(ip) === 4 ? await orEmpty(resolver.resolve4(ptr)) : await orEmpty(resolver.resolve6(ptr));
  const want = ipToBigInt(ip);
  return addrs.some((a) => {
    try {
      return ipToBigInt(a) === want;
    } catch {
      return false;
    }
  });
}
