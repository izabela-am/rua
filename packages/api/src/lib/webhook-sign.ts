import { createHmac, randomUUID } from "node:crypto";

/**
 * Signs a body the way Resend (Standard Webhooks / svix) does. Rua verifies
 * with the Resend SDK; this exists for the replay script and tests.
 */
export function signStandardWebhook(secret: string, body: string, now = Date.now()) {
  const id = `msg_${randomUUID()}`;
  const timestamp = String(Math.floor(now / 1000));
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const sig = createHmac("sha256", key).update(`${id}.${timestamp}.${body}`).digest("base64");
  return { "svix-id": id, "svix-timestamp": timestamp, "svix-signature": `v1,${sig}` };
}
