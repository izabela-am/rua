import { sql } from "drizzle-orm";
import { bigint, boolean, customType, date, inet, integer, jsonb, pgTable, primaryKey, text, timestamp, unique, uuid } from "drizzle-orm/pg-core";
import type { AuthResult } from "@rua/dmarc-parser";

const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType: () => "bytea",
  toDriver: (v) => Buffer.from(v),
  fromDriver: (v) => new Uint8Array(v),
});

export const accounts = pgTable("accounts", {
  id: uuid("id").primaryKey(),
  email: text("email"),
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

export const ipIntel = pgTable("ip_intel", {
  ip: inet("ip").primaryKey(),
  ptr: text("ptr"),
  ptrConfirmed: boolean("ptr_confirmed").notNull().default(false),
  asn: integer("asn"),
  asName: text("as_name"),
  provider: text("provider"),
  refreshedAt: timestamp("refreshed_at", { withTimezone: true }).notNull(),
});

export type Classification = "aligned_sender" | "known_forwarder" | "unknown";

export const domainSources = pgTable(
  "domain_sources",
  {
    accountId: uuid("account_id").notNull().references(() => accounts.id),
    domainId: uuid("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
    sourceIp: inet("source_ip").notNull(),
    classification: text("classification").$type<Classification>().notNull(),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.domainId, t.sourceIp] })],
);

export type AlertKind = "new_source" | "spoofing_source" | "policy_ready" | "ownership_lost" | "audit_finding";

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    accountId: uuid("account_id").notNull().references(() => accounts.id),
    domainId: uuid("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
    kind: text("kind").$type<AlertKind>().notNull(),
    dedupKey: text("dedup_key").notNull(),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    emailedAt: timestamp("emailed_at", { withTimezone: true }),
    webhookDeliveredAt: timestamp("webhook_delivered_at", { withTimezone: true }),
  },
  (t) => [unique().on(t.domainId, t.dedupKey)],
);

export const alertWebhooks = pgTable("alert_webhooks", {
  accountId: uuid("account_id").primaryKey().references(() => accounts.id),
  url: text("url").notNull(),
  secretEnc: bytea("secret_enc").notNull(),
  keyId: text("key_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const resendConnections = pgTable("resend_connections", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  accountId: uuid("account_id").notNull().references(() => accounts.id),
  domainId: uuid("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  signingSecretEnc: bytea("signing_secret_enc").notNull(),
  keyId: text("key_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const deliveryStats = pgTable(
  "delivery_stats",
  {
    accountId: uuid("account_id").notNull().references(() => accounts.id),
    domainId: uuid("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
    day: date("day").notNull(),
    delivered: integer("delivered").notNull().default(0),
    bounced: integer("bounced").notNull().default(0),
    complained: integer("complained").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.domainId, t.day] })],
);
