import { sql } from "drizzle-orm";
import type { Db, Tx } from "./client.js";

/**
 * Runs fn in a transaction bound to one tenant. Every request handler that
 * touches a tenant table goes through here; handlers receive tx, never db.
 *
 * db must connect as rua_app, which has no BYPASSRLS, so a query outside this
 * helper sees zero rows rather than every tenant's rows.
 */
export async function withTenant<T>(db: Db, accountId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return db.transaction(async (tx) => {
    // SET LOCAL does not accept bind parameters, so the value is passed
    // through set_config, whose third argument scopes it to the transaction.
    await tx.execute(sql`select set_config('app.account_id', ${accountId}, true)`);
    return fn(tx);
  });
}
