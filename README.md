# Rua

DMARC aggregate report pipeline and sender reputation dashboard. Rua gives each domain a unique report address, parses the reports receivers send there, labels every sending IP, alerts on new and spoofing sources, audits the domain's mail DNS records daily, and says when it is safe to move to `p=quarantine` or `p=reject`. Tenants who send through Resend can connect their Resend webhooks to see bounce and complaint rates next to the DMARC data. Other vendors support for this feature will be added soon

The design is in `specs/rua.md` (view it with `pnpm spec`).

## Layout

| Path | What it holds |
| --- | --- |
| `packages/dmarc-parser` | `@rua/dmarc-parser`: decompress and parse RFC 7489 aggregate reports under size, archive and XML limits. No I/O. |
| `packages/api` | `@rua/api`: Hono app serving the REST API, the Resend webhooks, the Inngest functions and the built dashboard. |
| `packages/api/migrations` | SQL migrations, including the roles and row-level security policies. |
| `packages/api/data` | Bundled ASN sample and the curated provider map. |
| `packages/web` | `@rua/web`: React dashboard. |
| `infra/dns` | Terraform for the Cloudflare DNS records Rua needs. |

## Running locally

Requires Node 22, pnpm 10 and Docker.

```sh
pnpm install
pnpm --filter @rua/dmarc-parser build
supabase start                          # Postgres on 54322, Auth, Storage
cp packages/api/.env.example packages/api/.env      # fill in RUA_KEK_k1 and SUPABASE_JWT_SECRET
cp packages/web/.env.example packages/web/.env      # anon key from `supabase status`
pnpm --filter @rua/api db:migrate
psql "$DATABASE_URL" -c "alter role rua_app password 'rua_app'; alter role rua_worker password 'rua_worker'"
npx inngest-cli@latest dev -u http://localhost:3000/api/inngest
pnpm dev                                # api on :3000, web on :5173
```

Without `RESEND_API_KEY`, the API reads inbound attachments from `.local/inbound`, keeps raw reports in `.local/raw`, and writes alert emails to the log. To feed it a report:

```sh
pnpm --filter @rua/api replay google.xml.gz --domain <domain id>
```

`replay` takes a path or a file name from `packages/dmarc-parser/fixtures`, and posts a signed `email.received` event to the local hook.

Domain verification needs a real TXT record. For local work, set `verified_at` on the row by hand.

## Tests

```sh
docker compose -f docker-compose.test.yml -p rua-test up -d   # Postgres on 54329
pnpm test
```

The API tests run against a real Postgres as the `rua_app` and `rua_worker` roles. `test/isolation.test.ts` is the proof that one tenant cannot read, write, move or delete another tenant's rows. Set `TEST_DATABASE_URL` to use another database; the tests truncate every table in it.

## Deploying

Everything runs on free tiers.

1. **Supabase.** Create a project. Run `db:migrate` with the owner connection string. Set passwords on `rua_app` and `rua_worker`. Create a private Storage bucket named `reports`. Under Auth, configure SMTP through Resend and set the site URL.
2. **Resend.** Verify the sending domain. Enable inbound for `reports.<domain>`. Create a webhook for `email.received` pointing at `https://rua.<domain>/hooks/resend/inbound`, and copy its signing secret into `RESEND_INBOUND_SECRET`.
3. **DNS.** Apply `infra/dns` (see its README).
4. **Render.** Create a web service from this repo. Build command: `pnpm install --frozen-lockfile && pnpm build`. Start command: `pnpm --filter @rua/api start`. Set the variables from `packages/api/.env.example`, with `DATABASE_URL_APP` and `DATABASE_URL_WORKER` using the pooler and the role credentials. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` as build variables.
5. **Inngest.** Create an app and sync `https://rua.<domain>/api/inngest`. Set `INNGEST_SIGNING_KEY` and `INNGEST_EVENT_KEY` on Render.
6. **ASN data.** Run `pnpm --filter @rua/api fetch-asn` in the build to replace the bundled sample with the full iptoasn.com dataset.

## Alert webhooks

Each alert is POSTed as JSON with an `X-Rua-Signature: t=<unix>,v1=<hex>` header. `v1` is HMAC-SHA256 of `` `${t}.${body}` `` with the secret shown once in Settings. Reject requests older than five minutes.

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyRua(secret, rawBody, header, now = Date.now()) {
  const p = Object.fromEntries(header.split(",").map((kv) => kv.split("=", 2)));
  const t = Number(p.t);
  if (!Number.isInteger(t) || !p.v1 || Math.abs(now / 1000 - t) > 300) return false;
  const want = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest();
  const got = Buffer.from(p.v1, "hex");
  return got.length === want.length && timingSafeEqual(got, want);
}
```

## Where the implementation differs from the spec

- The parse function passes only the Storage key between steps, not the attachment bytes. Inngest persists step output, and a 5 MB report does not belong there.
- Inngest timeouts apply to a whole function run, not to one step. The parse function has a 2-minute run timeout. A parser test shows a 20,000-record report parses well under the 30-second budget.
- Supabase Storage has no lifecycle rules. The daily job deletes raw objects older than 30 days and clears `raw_object_key`.
- Classification looks back 30 days from the end of the report being processed, not from the current time, so late or replayed reports get the right label.
- A PTR record counts toward provider identity only when it is forward-confirmed. Otherwise any IP owner could claim to be Google.
- The fixture corpus uses synthetic reports in the shape each reporter sends, not captured real reports. The 6 MB oversized file and the decompression bomb are generated in the test instead of committed.
- `@rua/dmarc-parser` is ready to publish but not published.
