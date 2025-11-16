import { sql } from "drizzle-orm";
import { bigint, boolean, inet, integer, jsonb, pgTable, text, timestamp, unique, uuid } from "drizzle-orm/pg-core";
import type { AuthResult } from "@rua/dmarc-parser";

export const accounts = pgTable("accounts", {
  id: uuid("id").primaryKey(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const domains = pgTable(
  "domains",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    accountId: uuid("account_id").notNull().references(() => accounts.id),
    name: text("name").notNull(),
    ruaLocalPart: text("rua_local_part").notNull().unique(),
    verifyToken: text("verify_token").notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    lastVerifiedAt: timestamp("last_verified_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [unique().on(t.accountId, t.name)],
);

export type PolicyPublished = { p: string; sp?: string; pct: number; adkim: string; aspf: string };

export const reports = pgTable(
  "reports",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    accountId: uuid("account_id").notNull().references(() => accounts.id),
    domainId: uuid("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
    reporterOrg: text("reporter_org").notNull(),
    reportId: text("report_id").notNull(),
    beginAt: timestamp("begin_at", { withTimezone: true }).notNull(),
    endAt: timestamp("end_at", { withTimezone: true }).notNull(),
    policyPublished: jsonb("policy_published").$type<PolicyPublished>().notNull(),
    rawObjectKey: text("raw_object_key"),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [unique().on(t.domainId, t.reporterOrg, t.reportId)],
);

export const reportRecords = pgTable("report_records", {
  id: bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity(),
  accountId: uuid("account_id").notNull().references(() => accounts.id),
  reportId: uuid("report_id").notNull().references(() => reports.id, { onDelete: "cascade" }),
  sourceIp: inet("source_ip").notNull(),
  count: integer("count").notNull(),
  disposition: text("disposition").notNull(),
  dkimAligned: boolean("dkim_aligned").notNull(),
  spfAligned: boolean("spf_aligned").notNull(),
  headerFrom: text("header_from").notNull(),
  envelopeFrom: text("envelope_from"),
  authResults: jsonb("auth_results").$type<AuthResult[]>().notNull(),
});
