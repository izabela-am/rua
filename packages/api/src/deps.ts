import type { VerifyJwt } from "./auth.js";
import type { Db } from "./db/client.js";
import type { EventSink } from "./inngest/client.js";
import type { AsnTable } from "./intel/asn.js";
import type { Providers } from "./intel/providers.js";
import type { Resolver } from "./lib/dns.js";
import type { InboundMail } from "./lib/inbound.js";
import type { RawStore } from "./lib/storage.js";
import type { VerifyWebhook } from "./routes/hooks.js";

/** Everything the app talks to. server.ts builds the real ones; tests build fakes. */
export type Deps = {
  appDb: Db;
  workerDb: Db;
  verifyJwt: VerifyJwt;
  resolver: Resolver;
  reportsDomain: string;
  events: EventSink;
  verifyInbound: VerifyWebhook;
  mail: InboundMail;
  store: RawStore;
  asn: AsnTable;
  providers: Providers;
  /** Clock for time windows. Tests pin it to the fixture dates. */
  now: () => Date;
};
