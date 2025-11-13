import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

export type Db = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];

export function connect(url: string, max = 5): { db: Db; close: () => Promise<void> } {
  // prepare: false keeps the client compatible with Supabase's transaction pooler.
  const client = postgres(url, { max, prepare: false });
  return { db: drizzle(client, { schema }), close: () => client.end() };
}
