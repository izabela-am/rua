import { ReportError } from "@rua/dmarc-parser";
import { alertsFromChanges, deliverWebhook, emailAlert, storeAlert, type AlertDeps } from "../alerts.js";
import { NonRetriableError } from "inngest";
import { ingestStored, storeAttachment, type IngestDeps } from "../ingest.js";
import type { EnrichDeps } from "../intel/enrich.js";
import { classifySource, distinctSourceIps, type SourceChange } from "../intel/sources.js";
import { AttachmentTooLarge } from "../lib/inbound.js";
import { log } from "../log.js";
import { inngest } from "./client.js";

export function createFunctions(deps: IngestDeps & EnrichDeps & AlertDeps) {
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
      const ips = await step.run("distinct", () => distinctSourceIps(deps.workerDb, reportId));

      // One step per IP so a slow PTR lookup retries alone; five at a time.
      const changes: SourceChange[] = [];
      for (let i = 0; i < ips.length; i += 5) {
        const batch = ips.slice(i, i + 5);
        changes.push(
          ...(await Promise.all(
            batch.map((ip) => step.run(`classify-${ip}`, () => classifySource(deps, { domainId, accountId }, ip))),
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

  return [parseReport, classifySources, raiseFromSources, raiseAlert];
}
