import { Hono } from "hono";
import { requireAccount, type AuthVars } from "./auth.js";
import type { Deps } from "./deps.js";
import { log } from "./log.js";
import { domainRoutes } from "./routes/domains.js";
import { hookRoutes } from "./routes/hooks.js";
import { reportRoutes } from "./routes/reports.js";
import { policyRoutes } from "./routes/policy.js";
import { settingsRoutes } from "./routes/settings.js";
import { sourceRoutes } from "./routes/sources.js";

export function createApp(deps: Deps, extra?: (app: Hono) => void) {
  const app = new Hono();

  app.onError((err, c) => {
    log.error("unhandled", { path: c.req.path, err: err.message, stack: err.stack });
    return c.json({ error: "internal" }, 500);
  });

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.route("/hooks", hookRoutes(deps));
  // Inngest is mounted before the session middleware; it signs its own requests.
  extra?.(app);

  const api = new Hono<{ Variables: AuthVars }>();
  api.use("*", requireAccount(deps.verifyJwt));
  api.get("/me", (c) => c.json({ accountId: c.var.accountId, email: c.var.email }));
  api.route("/domains", domainRoutes(deps));
  api.route("/", reportRoutes(deps));
  api.route("/", sourceRoutes(deps));
  api.route("/", settingsRoutes(deps));
  api.route("/", policyRoutes(deps));
  app.route("/api", api);

  return app;
}
