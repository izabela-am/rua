import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(3000),
  PUBLIC_URL: z.string().url().default("http://localhost:3000"),
  DATABASE_URL_APP: z.string().min(1),
  DATABASE_URL_WORKER: z.string().min(1),
  SUPABASE_URL: z.string().url(),
  SUPABASE_JWT_SECRET: z.string().optional(),
  REPORTS_DOMAIN: z.string().min(1),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  cached ??= schema.parse(process.env);
  return cached;
}
