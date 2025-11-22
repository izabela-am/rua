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

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Resend } from "resend";
import { createApp } from "../src/app.js";
import { supabaseVerifier } from "../src/auth.js";
import type { Deps } from "../src/deps.js";
import type { InboundMail } from "../src/lib/inbound.js";
import { fsStore } from "../src/lib/storage.js";
import { parseAsnTsv } from "../src/intel/asn.js";
import { providers } from "../src/intel/providers.js";

export const testAsn = parseAsnTsv(readFileSync(new URL("../data/asn-sample.tsv", import.meta.url), "utf8"));

export const INBOUND_SECRET = `whsec_${Buffer.from("inbound-test-secret").toString("base64")}`;
export const REPORTS_DOMAIN = "reports.rua.test";
/** The fixtures cover 2025-11-10; tests run as of the next day. */
export const FIXTURE_NOW = new Date("2025-11-11T12:00:00Z");

export const fixture = (name: string) =>
  new Uint8Array(readFileSync(new URL(`../../dmarc-parser/fixtures/${name}`, import.meta.url)));

/** Records sent events instead of calling Inngest. */
export function eventRecorder() {
  const sent: Array<{ name: string; id?: string; data: Record<string, unknown> }> = [];
  return {
    sent,
    async send(e: unknown) {
      sent.push(...((Array.isArray(e) ? e : [e]) as typeof sent));
    },
  };
}

/** Attachments keyed by email id. */
export function fakeMail(byEmail: Record<string, Uint8Array> = {}): InboundMail & { byEmail: typeof byEmail } {
  return {
    byEmail,
    async reportAttachment(emailId) {
      const bytes = byEmail[emailId];
      return bytes ? { id: "att_1", filename: "report.xml.gz", contentType: "application/gzip", bytes } : null;
    },
  };
}

export const testKeyring = { current: "k1", keys: { k1: Buffer.alloc(32, 7), k0: Buffer.alloc(32, 3) } };

export function mailRecorder() {
  const sent: Array<{ to: string; subject: string; text: string }> = [];
  return { sent, async send(m: (typeof sent)[number]) { sent.push(m); } };
}

export function webhookRecorder(status = 200) {
  const posts: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
  return {
    posts,
    status,
    async post(url: string, body: string, headers: Record<string, string>) {
      posts.push({ url, body, headers });
      return { status: this.status };
    },
  };
}

export function testDeps(dbs: TestDbs, overrides: Partial<Deps> = {}): Deps {
  const resend = new Resend("re_test_unused");
  return {
    ...dbs,
    verifyJwt: supabaseVerifier(SUPABASE_URL, JWT_SECRET),
    resolver: fakeResolver({}),
    reportsDomain: REPORTS_DOMAIN,
    events: eventRecorder(),
    verifyInbound: (payload, headers) => resend.webhooks.verify({ payload, headers, webhookSecret: INBOUND_SECRET }),
    mail: fakeMail(),
    store: fsStore(mkdtempSync(join(tmpdir(), "rua-raw-"))),
    asn: testAsn,
    providers: providers(),
    now: () => FIXTURE_NOW,
    keyring: testKeyring,
    mailer: mailRecorder(),
    postWebhook: webhookRecorder().post,
    verifyTenant: (webhookSecret) => (payload, headers) => resend.webhooks.verify({ payload, headers, webhookSecret }),
    publicUrl: "https://rua.test",
    ...overrides,
  };
}

export function testClient(deps: Deps) {
  const app = createApp(deps);
  return {
    app,
    async call(accountId: string | null, method: string, path: string, body?: unknown) {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (accountId) headers.authorization = `Bearer ${await tokenFor(accountId)}`;
      const res = await app.request(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json: any = res.status === 204 ? null : await res.json();
      return { status: res.status, body: json };
    },
  };
}

/** Creates and verifies a domain for an account through the API. */
export async function verifiedDomainFor(client: ReturnType<typeof testClient>, deps: Deps, accountId: string, name: string) {
  const created = await client.call(accountId, "POST", "/api/domains", { name });
  const resolver = deps.resolver as ReturnType<typeof fakeResolver>;
  resolver.records.txt ??= {};
  resolver.records.txt[`_rua.${name}`] = [[created.body.txt.value]];
  await client.call(accountId, "POST", `/api/domains/${created.body.id}/verify`);
  return created.body as { id: string; name: string; rua: string };
}
