// Posts a report fixture to the local inbound hook as if Resend had received it.
//   pnpm --filter @rua/api replay google.xml.gz --domain <domain id>
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, mkdir } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { eq } from "drizzle-orm";
import { connect } from "../db/client.js";
import { domains } from "../db/schema.js";
import { signStandardWebhook } from "../lib/webhook-sign.js";

const { positionals, values } = parseArgs({ allowPositionals: true, options: { domain: { type: "string" } } });
const [file] = positionals;
if (!file || !values.domain) {
  console.error("usage: replay <fixture> --domain <domain id>");
  process.exit(2);
}

const fixtures = fileURLToPath(new URL("../../../dmarc-parser/fixtures/", import.meta.url));
const path = [resolve(file), resolve(fixtures, file), resolve(fixtures, basename(file))].find(existsSync);
if (!path) throw new Error(`no such file: ${file}`);

const need = (k: string) => process.env[k] ?? (() => { throw new Error(`${k} is required`); })();
const { db, close } = connect(need("DATABASE_URL_WORKER"), 1);
const [domain] = await db.select().from(domains).where(eq(domains.id, values.domain));
await close();
if (!domain) throw new Error(`no domain ${values.domain}`);

const emailId = randomUUID();
const dir = `${process.env.LOCAL_DATA_DIR ?? ".local"}/inbound/${emailId}`;
await mkdir(dir, { recursive: true });
await copyFile(path, `${dir}/${basename(path)}`);

const body = JSON.stringify({
  type: "email.received",
  created_at: new Date().toISOString(),
  data: {
    email_id: emailId,
    created_at: new Date().toISOString(),
    from: "replay@rua.local",
    to: [`${domain.ruaLocalPart}@${need("REPORTS_DOMAIN")}`],
    received_for: [],
    subject: `Report domain: ${domain.name}`,
    attachments: [{ id: "local", filename: basename(path), content_type: "application/octet-stream" }],
  },
});
const url = `${process.env.PUBLIC_URL ?? "http://localhost:3000"}/hooks/resend/inbound`;
const res = await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json", ...signStandardWebhook(need("RESEND_INBOUND_SECRET"), body) },
  body,
});
console.log(`${res.status} ${await res.text()} (email ${emailId})`);
