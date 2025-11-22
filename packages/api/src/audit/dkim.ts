import { createPublicKey } from "node:crypto";
import type { Finding } from "../db/schema.js";
import { orEmpty, type Resolver } from "../lib/dns.js";

/** Bits in a DKIM p= key, or null when it is not a parseable RSA or Ed25519 key. */
export function keyBits(p: string, k = "rsa"): number | null {
  try {
    if (k.toLowerCase() === "ed25519") return 256;
    const key = createPublicKey({ key: Buffer.from(p, "base64"), format: "der", type: "spki" });
    return key.asymmetricKeyDetails?.modulusLength ?? null;
  } catch {
    return null;
  }
}

function tags(record: string) {
  return Object.fromEntries(
    record.split(";").map((t) => t.trim()).filter(Boolean).map((t) => {
      const i = t.indexOf("=");
      return [t.slice(0, i).trim().toLowerCase(), t.slice(i + 1).replace(/\s/g, "")];
    }),
  ) as Record<string, string>;
}

/** Checks every selector the reports show for this domain. Rua cannot guess selectors it has not seen. */
export async function auditDkim(resolver: Resolver, name: string, selectors: string[]) {
  const records: Record<string, string | null> = {};
  const findings: Finding[] = [];

  for (const selector of selectors) {
    const host = `${selector}._domainkey.${name}`;
    const txt = (await orEmpty(resolver.resolveTxt(host))).map((c) => c.join(""));
    const record = txt.find((t) => /(^|;)\s*p=/.test(t)) ?? null;
    records[selector] = record;

    if (!record) {
      const cname = await orEmpty(resolver.resolveCname(host));
      findings.push(
        cname.length
          ? {
              code: "dkim_dangling_cname",
              selector,
              severity: "high",
              message: `${host} is a CNAME to ${cname[0]}, which has no DKIM key. Mail signed with this selector fails DKIM.`,
              fix: "Fix the target at your provider or remove the CNAME and stop signing with this selector.",
            }
          : {
              code: "dkim_missing",
              selector,
              severity: "high",
              message: `Reports show selector "${selector}", but ${host} has no DKIM key.`,
              fix: "Publish the key from your sending provider, or stop signing with this selector.",
            },
      );
      continue;
    }

    const t = tags(record);
    if (!t.p) {
      findings.push({
        code: "dkim_revoked",
        selector,
        severity: "info",
        message: `Selector "${selector}" has an empty p= tag: the key is revoked.`,
        fix: "Expected after a rotation. Remove the record once nothing signs with it.",
      });
      continue;
    }
    const bits = keyBits(t.p, t.k);
    if (bits === null) {
      findings.push({
        code: "dkim_bad_key",
        selector,
        severity: "high",
        message: `The key at ${host} does not parse.`,
        fix: "Copy the record again from your provider; long keys are often split wrongly.",
      });
    } else if (bits < 2048 && (t.k ?? "rsa").toLowerCase() === "rsa") {
      findings.push({
        code: "dkim_weak_key",
        selector,
        severity: bits < 1024 ? "high" : "medium",
        message: `Selector "${selector}" uses a ${bits}-bit RSA key.`,
        fix: "Rotate to a 2048-bit key.",
      });
    }
    if (t.t?.split(":").includes("y")) {
      findings.push({
        code: "dkim_testing",
        selector,
        severity: "low",
        message: `Selector "${selector}" has t=y; some receivers treat its signatures as unsigned.`,
        fix: "Remove t=y once signing works.",
      });
    }
  }
  return { records, findings };
}
