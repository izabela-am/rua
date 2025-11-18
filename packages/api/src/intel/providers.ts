import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { z } from "zod";

const schema = z.object({
  providers: z.array(
    z.object({
      name: z.string(),
      forwarder: z.boolean().default(false),
      asn: z.array(z.number().int()).default([]),
      ptr: z.array(z.string()).default([]),
    }),
  ),
});

export type Provider = z.infer<typeof schema>["providers"][number];
export type Providers = { match(q: { asn: number | null; ptr: string | null }): Provider | null; all: Provider[] };

export function loadProviders(yamlText: string): Providers {
  const { providers } = schema.parse(parse(yamlText));
  return {
    all: providers,
    match({ asn, ptr }) {
      const host = ptr?.toLowerCase().replace(/\.$/, "");
      // PTR first: it names the service, while an ASN may host several.
      if (host) {
        for (const p of providers) {
          if (p.ptr.some((s) => host === s || host.endsWith(`.${s}`))) return p;
        }
      }
      if (asn !== null) return providers.find((p) => p.asn.includes(asn)) ?? null;
      return null;
    },
  };
}

let cached: Providers | undefined;

export function providers(): Providers {
  cached ??= loadProviders(readFileSync(fileURLToPath(new URL("../../data/providers.yaml", import.meta.url)), "utf8"));
  return cached;
}
