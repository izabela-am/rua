import { EventSchemas, Inngest } from "inngest";

type Ids = { domainId: string; accountId: string };

export type Events = {
  "report/received": { data: Ids & { emailId: string } };
  "report/parsed": { data: Ids & { reportId: string } };
};

export const inngest = new Inngest({ id: "rua", schemas: new EventSchemas().fromRecord<Events>() });

type Payload = { [K in keyof Events]: { name: K; data: Events[K]["data"]; id?: string } }[keyof Events];

/** The one thing handlers need from Inngest. Tests pass a recorder. */
export type EventSink = { send(events: Payload | Payload[]): Promise<unknown> };
