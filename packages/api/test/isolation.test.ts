import { sql } from "drizzle-orm";
import { afterAll, beforeAll, expect, test } from "vitest";
import { accounts, domains } from "../src/db/schema.js";
import { withTenant } from "../src/db/tenant.js";
import { newAccount, setupDb } from "./helpers.js";

let db: Awaited<ReturnType<typeof setupDb>>;
const a = newAccount();
const b = newAccount();

beforeAll(async () => {
  db = await setupDb();
});
afterAll(() => db.close());

/** Drizzle wraps driver errors; the Postgres message is on cause. */
async function rejectsByRls(p: Promise<unknown>) {
  const err = await p.then(
    () => null,
    (e: Error & { cause?: Error }) => e,
  );
  expect(err, "expected the query to fail").not.toBeNull();
  expect(err!.cause?.message ?? err!.message).toMatch(/row-level security/);
}

const domain = (accountId: string, name: string, local: string) => ({
  accountId,
  name,
  ruaLocalPart: local,
  verifyToken: "t",
});

test("tenant A cannot read tenant B", async () => {
  await withTenant(db.appDb, a, async (tx) => {
    await tx.insert(accounts).values({ id: a });
    await tx.insert(domains).values(domain(a, "a.test", "d-a"));
  });
  await withTenant(db.appDb, b, async (tx) => {
    await tx.insert(accounts).values({ id: b });
    await tx.insert(domains).values(domain(b, "b.test", "d-b"));
  });

  const seenByA = await withTenant(db.appDb, a, (tx) => tx.select().from(domains));
  expect(seenByA.map((d) => d.name)).toEqual(["a.test"]);
  const seenByB = await withTenant(db.appDb, b, (tx) => tx.select().from(domains));
  expect(seenByB.map((d) => d.name)).toEqual(["b.test"]);

  // No GUC, no rows. Run it twice: the second time the pooled connection has
  // already seen a transaction-local value, which leaves '' behind.
  expect(await db.appDb.select().from(domains)).toHaveLength(0);
  expect(await db.appDb.select().from(domains)).toHaveLength(0);
});

test("tenant A cannot write rows for tenant B", async () => {
  await rejectsByRls(withTenant(db.appDb, a, (tx) => tx.insert(domains).values(domain(b, "evil.test", "d-evil"))));
});

test("tenant A cannot move its row to tenant B", async () => {
  await rejectsByRls(withTenant(db.appDb, a, (tx) => tx.update(domains).set({ accountId: b })));
});

test("tenant A cannot update or delete tenant B's rows", async () => {
  await withTenant(db.appDb, a, async (tx) => {
    await tx.update(domains).set({ verifyToken: "pwned" }).where(sql`name = 'b.test'`);
    await tx.delete(domains).where(sql`name = 'b.test'`);
  });
  const rows = await withTenant(db.appDb, b, (tx) => tx.select().from(domains));
  expect(rows[0]?.verifyToken).toBe("t");
});

test("rua_app cannot switch off RLS or escape it", async () => {
  await expect(db.appDb.execute(sql`set row_security = off`).then(() => db.appDb.select().from(domains))).rejects.toThrow();
  await expect(db.appDb.execute(sql`alter table domains disable row level security`)).rejects.toThrow();
});

test("rua_worker sees every tenant", async () => {
  const rows = await db.workerDb.select().from(domains);
  expect(rows.map((d) => d.name).sort()).toEqual(["a.test", "b.test"]);
});
