import { ReportError } from "@rua/dmarc-parser";
import { NonRetriableError } from "inngest";
import { ingestStored, storeAttachment, type IngestDeps } from "../ingest.js";
import { AttachmentTooLarge } from "../lib/inbound.js";
import { log } from "../log.js";
import { inngest } from "./client.js";

export function createFunctions(deps: IngestDeps) {
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

  return [parseReport];
}
