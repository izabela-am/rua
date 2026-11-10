import { eventType, Inngest, staticSchema } from "inngest";
import type { AlertRequest } from "../alerts.js";
import type { SourceChange } from "../intel/sources.js";

type Ids = { domainId: string; accountId: string };

export type Events = {
  "report/received": Ids & { emailId: string };
  "report/parsed": Ids & { reportId: string };
  "sources/classified": Ids & { reportId: string; changes: SourceChange[] };
  "alert/raise": AlertRequest;
  "domain/audit": Ids;
};

export const events = {
  reportReceived: eventType("report/received", { schema: staticSchema<Events["report/received"]>() }),
  reportParsed: eventType("report/parsed", { schema: staticSchema<Events["report/parsed"]>() }),
  sourcesClassified: eventType("sources/classified", { schema: staticSchema<Events["sources/classified"]>() }),
  alertRaise: eventType("alert/raise", { schema: staticSchema<Events["alert/raise"]>() }),
  domainAudit: eventType("domain/audit", { schema: staticSchema<Events["domain/audit"]>() }),
};

export const inngest = new Inngest({ id: "rua" });

export type Payload = { [K in keyof Events]: { name: K; data: Events[K]; id?: string } }[keyof Events];

/** The one thing handlers need from Inngest. Tests pass a recorder. */
export type EventSink = { send(events: Payload | Payload[]): Promise<unknown> };
