import { randomUUID } from "node:crypto";
import postgres from "postgres";
import { SignJWT } from "jose";
import type { VerifyJwt } from "../src/auth.js";
import { connect, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import type { Resolver } from "../src/lib/dns.js";

export const OWNER_URL = process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@127.0.0.1:54329/postgres";

function asRole(role: string) {
  const u = new URL(OWNER_URL);
  u.username = role;
  u.password = role;
  return u.toString();
}

/** Migrates the test database, sets role passwords, truncates tenant tables, and opens role connections. */
export async function setupDb() {
  await migrate(OWNER_URL, () => {});
  const owner = postgres(OWNER_URL, { max: 1, onnotice: () => {} });
  await owner.unsafe(`alter role rua_app password 'rua_app'; alter role rua_worker password 'rua_worker'`);
  const tables = await owner<{ tablename: string }[]>`
    select tablename from pg_tables where schemaname = 'public' and tablename <> 'rua_migrations'`;
  await owner.unsafe(`truncate ${tables.map((t) => `"${t.tablename}"`).join(", ")} cascade`);
  await owner.end();

  const app = connect(asRole("rua_app"));
  const worker = connect(asRole("rua_worker"));
  return {
    appDb: app.db,
    workerDb: worker.db,
    close: async () => {
      await app.close();
      await worker.close();
    },
  };
}

export const JWT_SECRET = "test-secret-at-least-32-characters-long";
export const SUPABASE_URL = "http://supabase.test";

export async function tokenFor(accountId: string) {
  return new SignJWT({ email: `${accountId.slice(0, 8)}@example.test` })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(accountId)
    .setIssuer(`${SUPABASE_URL}/auth/v1`)
    .setAudience("authenticated")
    .setExpirationTime("10m")
    .sign(new TextEncoder().encode(JWT_SECRET));
}

export const newAccount = () => randomUUID();

/** A resolver backed by a map. Unknown names fail with ENOTFOUND, as the real one does. */
export function fakeResolver(records: {
  txt?: Record<string, string[][]>;
  ptr?: Record<string, string[]>;
  a?: Record<string, string[]>;
  aaaa?: Record<string, string[]>;
  mx?: Record<string, { exchange: string; priority: number }[]>;
  cname?: Record<string, string[]>;
}): Resolver & { records: typeof records } {
  const lookup = <T>(table: Record<string, T[]> | undefined, name: string) => {
    const v = table?.[name];
    if (v) return Promise.resolve(v);
    return Promise.reject(Object.assign(new Error(`queryX ENOTFOUND ${name}`), { code: "ENOTFOUND" }));
  };
  return {
    records,
    resolveTxt: (n) => lookup(records.txt, n),
    reverse: (ip) => lookup(records.ptr, ip),
    resolve4: (n) => lookup(records.a, n),
    resolve6: (n) => lookup(records.aaaa, n),
    resolveMx: (n) => lookup(records.mx, n),
    resolveCname: (n) => lookup(records.cname, n),
  };
}

export type TestDbs = { appDb: Db; workerDb: Db };
export type { VerifyJwt };
