import { afterAll, beforeAll, expect, test } from "vitest";
import { createApp } from "../src/app.js";
import { supabaseVerifier } from "../src/auth.js";
import { fakeResolver, JWT_SECRET, newAccount, setupDb, SUPABASE_URL, tokenFor } from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
const resolver = fakeResolver({ txt: {} });
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  db = await setupDb();
  app = createApp({
    ...db,
    verifyJwt: supabaseVerifier(SUPABASE_URL, JWT_SECRET),
    resolver,
    reportsDomain: "reports.rua.test",
  });
});
afterAll(() => db.close());

async function call(accountId: string | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (accountId) headers.authorization = `Bearer ${await tokenFor(accountId)}`;
  const res = await app.request(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: res.status === 204 ? null : await res.json() };
}

test("rejects requests without a valid token", async () => {
  expect((await call(null, "GET", "/api/domains")).status).toBe(401);
  const res = await app.request("/api/domains", { headers: { authorization: "Bearer nope" } });
  expect(res.status).toBe(401);
});

test("add, verify and list a domain", async () => {
  const me = newAccount();
  const created = await call(me, "POST", "/api/domains", { name: "Example.COM." });
  expect(created.status).toBe(201);
  expect(created.body).toMatchObject({
    name: "example.com",
    verified: false,
    txt: { host: "_rua.example.com" },
  });
  expect(created.body.rua).toMatch(/^d-[a-z2-7]{12}@reports\.rua\.test$/);

  const notYet = await call(me, "POST", `/api/domains/${created.body.id}/verify`);
  expect(notYet.status).toBe(409);
  expect(notYet.body).toEqual({ error: "txt_not_found", observed: [] });

  // TXT strings longer than 255 bytes arrive in chunks; they are joined before comparing.
  const value: string = created.body.txt.value;
  resolver.records.txt!["_rua.example.com"] = [["v=spf1 -all"], [value.slice(0, 10), value.slice(10)]];
  const ok = await call(me, "POST", `/api/domains/${created.body.id}/verify`);
  expect(ok.status).toBe(200);
  expect(ok.body.verified).toBe(true);

  const list = await call(me, "GET", "/api/domains");
  expect(list.body.domains).toHaveLength(1);
  expect(list.body.domains[0].verified).toBe(true);
});

test("another tenant cannot see or verify the domain", async () => {
  const owner = newAccount();
  const other = newAccount();
  const created = await call(owner, "POST", "/api/domains", { name: "private.test" });
  expect((await call(other, "GET", `/api/domains/${created.body.id}`)).status).toBe(404);
  expect((await call(other, "POST", `/api/domains/${created.body.id}/verify`)).status).toBe(404);
  expect((await call(other, "DELETE", `/api/domains/${created.body.id}`)).status).toBe(404);
  expect((await call(other, "GET", "/api/domains")).body.domains).toEqual([]);
});

test("two tenants may each add the same name", async () => {
  expect((await call(newAccount(), "POST", "/api/domains", { name: "shared.test" })).status).toBe(201);
  expect((await call(newAccount(), "POST", "/api/domains", { name: "shared.test" })).status).toBe(201);
});

test("rejects bad names, duplicates and the cap", async () => {
  const me = newAccount();
  for (const name of ["localhost", "1.2.3.4", "-bad.test", "a..b"]) {
    expect((await call(me, "POST", "/api/domains", { name })).status, name).toBe(400);
  }
  expect((await call(me, "POST", "/api/domains", { name: "dup.test" })).status).toBe(201);
  expect((await call(me, "POST", "/api/domains", { name: "dup.test" })).body.error).toBe("domain_exists");
  for (let i = 0; i < 9; i++) await call(me, "POST", "/api/domains", { name: `n${i}.test` });
  expect((await call(me, "POST", "/api/domains", { name: "eleven.test" })).body.error).toBe("domain_limit");
});

test("unknown or malformed ids are 404", async () => {
  const me = newAccount();
  expect((await call(me, "GET", "/api/domains/not-a-uuid")).status).toBe(404);
  expect((await call(me, "GET", "/api/domains/00000000-0000-0000-0000-000000000000")).status).toBe(404);
});
