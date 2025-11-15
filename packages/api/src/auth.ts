import type { MiddlewareHandler } from "hono";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export type VerifyJwt = (token: string) => Promise<{ accountId: string; email?: string }>;

/**
 * Verifies Supabase access tokens. Production projects sign with asymmetric
 * keys published at the JWKS endpoint; local `supabase start` signs with HS256.
 */
export function supabaseVerifier(supabaseUrl: string, hsSecret?: string): VerifyJwt {
  const issuer = `${supabaseUrl.replace(/\/$/, "")}/auth/v1`;
  const key: Uint8Array | JWTVerifyGetKey = hsSecret
    ? new TextEncoder().encode(hsSecret)
    : createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  return async (token) => {
    const { payload } = await jwtVerify(token, key as JWTVerifyGetKey, { issuer, audience: "authenticated" });
    if (typeof payload.sub !== "string") throw new Error("token has no subject");
    return { accountId: payload.sub, email: typeof payload.email === "string" ? payload.email : undefined };
  };
}

export type AuthVars = { accountId: string; email?: string };

export function requireAccount(verify: VerifyJwt): MiddlewareHandler<{ Variables: AuthVars }> {
  return async (c, next) => {
    const header = c.req.header("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return c.json({ error: "unauthorized" }, 401);
    try {
      const { accountId, email } = await verify(token);
      c.set("accountId", accountId);
      c.set("email", email);
    } catch {
      return c.json({ error: "unauthorized" }, 401);
    }
    await next();
  };
}
