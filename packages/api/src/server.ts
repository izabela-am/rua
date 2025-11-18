import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";
import { serve as serveInngest } from "inngest/hono";
import { Resend } from "resend";
import { createApp } from "./app.js";
import { supabaseVerifier } from "./auth.js";
import { connect } from "./db/client.js";
import type { Deps } from "./deps.js";
import { env } from "./env.js";
import { inngest } from "./inngest/client.js";
import { createFunctions } from "./inngest/functions.js";
import { asnTable } from "./intel/asn.js";
import { providers } from "./intel/providers.js";
import { systemResolver } from "./lib/dns.js";
import { fsInbound, resendInbound } from "./lib/inbound.js";
import { fsStore, supabaseStore } from "./lib/storage.js";
import { log } from "./log.js";

const e = env();
const local = !e.RESEND_API_KEY;
// webhooks.verify does not call the API, so a placeholder key is enough when running locally.
const resend = new Resend(e.RESEND_API_KEY ?? "re_local_unused");

const deps: Deps = {
  appDb: connect(e.DATABASE_URL_APP).db,
  workerDb: connect(e.DATABASE_URL_WORKER).db,
  verifyJwt: supabaseVerifier(e.SUPABASE_URL, e.SUPABASE_JWT_SECRET || undefined),
  resolver: systemResolver,
  reportsDomain: e.REPORTS_DOMAIN,
  events: inngest,
  verifyInbound: (payload, headers) => resend.webhooks.verify({ payload, headers, webhookSecret: e.RESEND_INBOUND_SECRET }),
  mail: local ? fsInbound(`${e.LOCAL_DATA_DIR}/inbound`) : resendInbound(resend),
  store: e.SUPABASE_SERVICE_ROLE_KEY
    ? supabaseStore(e.SUPABASE_URL, e.SUPABASE_SERVICE_ROLE_KEY)
    : fsStore(`${e.LOCAL_DATA_DIR}/raw`),
  asn: asnTable(),
  providers: providers(),
  now: () => new Date(),
};
if (local) log.warn("RESEND_API_KEY unset: reading inbound attachments from disk");

const app = createApp(deps, (app) => {
  app.on(["GET", "POST", "PUT"], "/api/inngest", serveInngest({ client: inngest, functions: createFunctions(deps) }));
});

// The built SPA. serveStatic resolves root against the working directory.
const webDist = relative(process.cwd(), fileURLToPath(new URL("../../web/dist/", import.meta.url)));
app.use("/*", serveStatic({ root: webDist }));
app.get("*", serveStatic({ root: webDist, path: "index.html" }));

serve({ fetch: app.fetch, port: e.PORT }, (info) => log.info("listening", { port: info.port }));
