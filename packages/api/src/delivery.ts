import { eq, sql } from "drizzle-orm";
import type { Db } from "./db/client.js";
import { deliveryStats, domains, resendConnections } from "./db/schema.js";
import { decrypt, type Keyring } from "./lib/crypto.js";
import type { VerifyWebhook } from "./routes/hooks.js";

const COUNTED = { "email.delivered": "delivered", "email.bounced": "bounced", "email.complained": "complained" } as const;

type TenantEvent = { type: string; created_at?: string; data?: { from?: string } };

export function domainOf(from: string): string | null {
  const m = from.match(/@([^\s>]+)>?\s*$/);
  return m ? m[1]!.toLowerCase().replace(/\.$/, "") : null;
}

export type TenantHookResult = { status: 204 | 400 | 404; counted?: keyof typeof COUNTED };

/**
 * Handles one event from a tenant's own Resend account. The connection id in
 * the path picks the signing secret; the secret verifies the body; the sender
 * domain must be the connected domain.
 */
export async function ingestTenantEvent(
  deps: { workerDb: Db; keyring: Keyring; verify: (secret: string) => VerifyWebhook },
  connectionId: string,
  rawBody: string,
  headers: { id: string; timestamp: string; signature: string },
): Promise<TenantHookResult> {
  const [conn] = await deps.workerDb
    .select({ c: resendConnections, domainName: domains.name })
    .from(resendConnections)
    .innerJoin(domains, eq(domains.id, resendConnections.domainId))
    .where(eq(resendConnections.id, connectionId));
  if (!conn) return { status: 404 };

  let event: TenantEvent;
  try {
    const secret = decrypt(deps.keyring, conn.c.signingSecretEnc, conn.c.keyId);
    event = deps.verify(secret)(rawBody, headers) as TenantEvent;
  } catch {
    return { status: 400 };
  }

  const column = COUNTED[event.type as keyof typeof COUNTED];
  if (!column) return { status: 204 };
  if (domainOf(event.data?.from ?? "") !== conn.domainName) return { status: 204 };

  const day = (event.created_at ? new Date(event.created_at) : new Date()).toISOString().slice(0, 10);
  await deps.workerDb
    .insert(deliveryStats)
    .values({ accountId: conn.c.accountId, domainId: conn.c.domainId, day, [column]: 1 })
    .onConflictDoUpdate({
      target: [deliveryStats.domainId, deliveryStats.day],
      set: { [column]: sql`${deliveryStats[column]} + 1` },
    });
  return { status: 204, counted: event.type as keyof typeof COUNTED };
}
