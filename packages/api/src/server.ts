import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { createApp } from "./app.js";
import { supabaseVerifier } from "./auth.js";
import { connect } from "./db/client.js";
import { env } from "./env.js";
import { systemResolver } from "./lib/dns.js";
import { log } from "./log.js";

const e = env();
const app = createApp({
  appDb: connect(e.DATABASE_URL_APP).db,
  workerDb: connect(e.DATABASE_URL_WORKER).db,
  verifyJwt: supabaseVerifier(e.SUPABASE_URL, e.SUPABASE_JWT_SECRET || undefined),
  resolver: systemResolver,
  reportsDomain: e.REPORTS_DOMAIN,
});

// The built SPA. Unknown paths fall back to index.html for client-side routing.
const webDist = new URL("../../web/dist/", import.meta.url).pathname;
app.use("/*", serveStatic({ root: webDist }));
app.get("*", serveStatic({ root: webDist, path: "index.html" }));

serve({ fetch: app.fetch, port: e.PORT }, (info) => log.info("listening", { port: info.port }));
