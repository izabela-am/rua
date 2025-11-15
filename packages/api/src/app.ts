import { Hono } from "hono";
import { requireAccount, type AuthVars } from "./auth.js";
import type { Deps } from "./deps.js";
import { log } from "./log.js";
import { domainRoutes } from "./routes/domains.js";

export function createApp(deps: Deps) {
  const app = new Hono();

  app.onError((err, c) => {
    log.error("unhandled", { path: c.req.path, err: err.message, stack: err.stack });
    return c.json({ error: "internal" }, 500);
  });

  app.get("/healthz", (c) => c.json({ ok: true }));

  const api = new Hono<{ Variables: AuthVars }>();
  api.use("*", requireAccount(deps.verifyJwt));
  api.get("/me", (c) => c.json({ accountId: c.var.accountId, email: c.var.email }));
  api.route("/domains", domainRoutes(deps));
  app.route("/api", api);

  return app;
}
