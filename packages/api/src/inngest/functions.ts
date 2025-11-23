import { ReportError } from "@rua/dmarc-parser";
import { alertsFromChanges, deliverWebhook, emailAlert, storeAlert, type AlertDeps } from "../alerts.js";
import { eq, isNotNull } from "drizzle-orm";
import { NonRetriableError } from "inngest";
import type { AuditDeps } from "../audit/domain.js";
import { auditDomain, checkOwnership, expireRaw } from "../daily.js";
import { domains } from "../db/schema.js";
import { ingestStored, storeAttachment, type IngestDeps } from "../ingest.js";
import type { EnrichDeps } from "../intel/enrich.js";
import { classifySource, distinctSourceIps, reportEnd, type SourceChange } from "../intel/sources.js";
import { AttachmentTooLarge } from "../lib/inbound.js";
import { log } from "../log.js";
import { inngest } from "./client.js";

export type FunctionDeps = IngestDeps & EnrichDeps & AlertDeps & AuditDeps & { reportsDomain: string; now: () => Date };

export function createFunctions(deps: FunctionDeps) {
  const parseReport = inngest.createFunction(
    { id: "parse-report", retries: 3, timeouts: { finish: "2m" } },
    { event: "report/received" },
    async ({ event, step }) => {
      const { domainId, accountId, emailId } = event.data;

      // Raw bytes stay in Storage; only the key passes between steps, which
      // keeps step state small and lets a parser fix replay the same object.
      const key = await step.run("fetch-and-store", async () => {
        try {
          return await storeAttachment(deps, { domainId, emailId });
        } catch (e) {
          if (e instanceof AttachmentTooLarge) throw new NonRetriableError(e.message);
          throw e;
        }
      });
      if (!key) {
        log.warn("report email without a report attachment", { domainId, emailId });
        return { skipped: "no_attachment" };
      }

      const result = await step.run("parse-and-upsert", async () => {
        try {
          return await ingestStored(deps, { domainId, accountId, key });
        } catch (e) {
          if (e instanceof ReportError) throw new NonRetriableError(`${e.code}: ${e.message}`, { cause: e });
          throw e;
        }
      });
      if (result.duplicate) return { duplicate: true };

      await step.sendEvent("report-parsed", {
        name: "report/parsed",
        data: { reportId: result.reportId, domainId, accountId },
      });
      return { reportId: result.reportId };
    },
  );

  const classifySources = inngest.createFunction(
    { id: "classify-sources", retries: 3 },
    { event: "report/parsed" },
    async ({ event, step }) => {
      const { reportId, domainId, accountId } = event.data;
      const { ips, asOf } = await step.run("distinct", async () => ({
        ips: await distinctSourceIps(deps.workerDb, reportId),
        asOf: (await reportEnd(deps.workerDb, reportId)).toISOString(),
      }));

      // One step per IP so a slow PTR lookup retries alone; five at a time.
      const changes: SourceChange[] = [];
      for (let i = 0; i < ips.length; i += 5) {
        const batch = ips.slice(i, i + 5);
        changes.push(
          ...(await Promise.all(
            batch.map((ip) => step.run(`classify-${ip}`, () => classifySource(deps, { domainId, accountId }, ip, new Date(asOf)))),
          )),
        );
      }

      await step.sendEvent("sources-classified", {
        name: "sources/classified",
        data: { reportId, domainId, accountId, changes },
      });
      return { sources: changes.length, new: changes.filter((c) => c.isNew).length };
    },
  );

  const raiseFromSources = inngest.createFunction(
    { id: "alerts-from-sources" },
    { event: "sources/classified" },
    async ({ event, step }) => {
      const requests = alertsFromChanges(event.data, event.data.changes);
      if (requests.length === 0) return { alerts: 0 };
      await step.sendEvent(
        "raise",
        // The event id makes a re-run of classification raise nothing new.
        requests.map((data) => ({ name: "alert/raise" as const, id: `alert-${data.domainId}-${data.dedupKey}`, data })),
      );
      return { alerts: requests.length };
    },
  );

  // One run per alert. Store first, then each channel in its own retried step.
  const raiseAlert = inngest.createFunction(
    { id: "raise-alert", retries: 5 },
    { event: "alert/raise" },
    async ({ event, step }) => {
      const alertId = await step.run("store", () => storeAlert(deps.workerDb, event.data));
      if (!alertId) return { duplicate: true };
      const email = await step.run("email", () => emailAlert(deps, alertId));
      const webhook = await step.run("webhook", () => deliverWebhook(deps, alertId));
      return { alertId, email, webhook };
    },
  );

  // Once a day: fan out one audit per verified domain, expire raw objects.
  // The daily reads and writes also keep a free Supabase project from pausing.
  const daily = inngest.createFunction({ id: "daily" }, { cron: "TZ=UTC 0 6 * * *" }, async ({ step }) => {
    const list = await step.run("list-domains", () =>
      deps.workerDb.select({ domainId: domains.id, accountId: domains.accountId }).from(domains).where(isNotNull(domains.verifiedAt)),
    );
    if (list.length) {
      await step.sendEvent(
        "fan-out",
        list.map((data) => ({ name: "domain/audit" as const, data })),
      );
    }
    const expired = await step.run("expire-raw", () => expireRaw(deps, deps.now()));
    return { domains: list.length, expired };
  });

  const auditOne = inngest.createFunction(
    { id: "audit-domain", retries: 2, concurrency: { limit: 5 } },
    { event: "domain/audit" },
    async ({ event, step }) => {
      const load = async () => {
        const [d] = await deps.workerDb.select().from(domains).where(eq(domains.id, event.data.domainId));
        return d;
      };
      const ownership = await step.run("ownership", async () => {
        const d = await load();
        return d ? checkOwnership(deps, d, deps.now()) : null;
      });
      if (!ownership) return { skipped: "domain_gone" };
      if (!ownership.verified) {
        await step.sendEvent("ownership-lost", {
          name: "alert/raise",
          id: `alert-${event.data.domainId}-${ownership.alert.dedupKey}`,
          data: ownership.alert,
        });
        return { verified: false };
      }

      const result = await step.run("audit", async () => auditDomain(deps, (await load())!, deps.reportsDomain, deps.now()));
      if (result.alerts.length) {
        await step.sendEvent(
          "alerts",
          result.alerts.map((data) => ({ name: "alert/raise" as const, id: `alert-${data.domainId}-${data.dedupKey}`, data })),
        );
      }
      return { snapshotId: result.snapshotId, findings: result.findings, alerts: result.alerts.length };
    },
  );

  return [parseReport, classifySources, raiseFromSources, raiseAlert, daily, auditOne];
}
