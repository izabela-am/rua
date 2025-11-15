import type { VerifyJwt } from "./auth.js";
import type { Db } from "./db/client.js";
import type { Resolver } from "./lib/dns.js";

/** Everything the app talks to. server.ts builds the real ones; tests build fakes. */
export type Deps = {
  appDb: Db;
  workerDb: Db;
  verifyJwt: VerifyJwt;
  resolver: Resolver;
  reportsDomain: string;
};
