import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(3000),
  PUBLIC_URL: z.string().url().default("http://localhost:3000"),
  DATABASE_URL_APP: z.string().min(1),
  DATABASE_URL_WORKER: z.string().min(1),
  SUPABASE_URL: z.string().url(),
  SUPABASE_JWT_SECRET: z.string().optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  REPORTS_DOMAIN: z.string().min(1),
  RESEND_API_KEY: z.string().optional(),
  RESEND_INBOUND_SECRET: z.string().min(1),
  // Development without Resend or Supabase Storage: attachments and raw reports live on disk.
  LOCAL_DATA_DIR: z.string().default(".local"),
  ALERT_FROM: z.string().default("Rua <alerts@example.net>"),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  cached ??= schema.parse(process.env);
  return cached;
}
