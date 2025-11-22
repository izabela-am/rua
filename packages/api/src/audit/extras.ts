import type { Finding } from "../db/schema.js";
import { orEmpty, type Resolver } from "../lib/dns.js";

export type FetchText = (url: string) => Promise<string | null>;

const txtAt = async (resolver: Resolver, host: string, prefix: RegExp) =>
  (await orEmpty(resolver.resolveTxt(host))).map((c) => c.join("")).find((t) => prefix.test(t)) ?? null;

/** MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and BIMI. All advisory. */
export async function auditExtras(resolver: Resolver, fetchText: FetchText, name: string, policy: string | null) {
  const findings: Finding[] = [];

  const mtaSts = await txtAt(resolver, `_mta-sts.${name}`, /^v=STSv1/i);
  if (!mtaSts) {
    findings.push({
      code: "mta_sts_missing",
      severity: "low",
      message: "No MTA-STS policy: senders may deliver to this domain without TLS if an attacker strips STARTTLS.",
      fix: `Publish _mta-sts.${name} TXT "v=STSv1; id=<date>" and serve https://mta-sts.${name}/.well-known/mta-sts.txt`,
    });
  } else {
    const body = await fetchText(`https://mta-sts.${name}/.well-known/mta-sts.txt`);
    const mode = body?.match(/^mode:\s*(\w+)/im)?.[1]?.toLowerCase();
    if (!body || !mode) {
      findings.push({
        code: "mta_sts_policy_unreachable",
        severity: "medium",
        message: `_mta-sts.${name} exists but the policy file is missing or unreadable, so senders ignore it.`,
        fix: `Serve the policy at https://mta-sts.${name}/.well-known/mta-sts.txt with a valid certificate.`,
      });
    } else if (mode === "testing") {
      findings.push({
        code: "mta_sts_testing",
        severity: "low",
        message: "MTA-STS is in testing mode: failures are reported, not enforced.",
        fix: "Switch to mode: enforce once TLS-RPT reports are clean.",
      });
    }
  }

  const tlsRpt = await txtAt(resolver, `_smtp._tls.${name}`, /^v=TLSRPTv1/i);
  if (!tlsRpt) {
    findings.push({
      code: "tls_rpt_missing",
      severity: "low",
      message: "No TLS-RPT record, so nobody reports TLS delivery failures to you.",
      fix: `Publish _smtp._tls.${name} TXT "v=TLSRPTv1; rua=mailto:<you>"`,
    });
  }

  const bimi = await txtAt(resolver, `default._bimi.${name}`, /^v=BIMI1/i);
  if (!bimi && (policy === "quarantine" || policy === "reject")) {
    findings.push({
      code: "bimi_missing",
      severity: "info",
      message: "The domain enforces DMARC and could show a logo in supporting inboxes with BIMI.",
      fix: `Publish default._bimi.${name} TXT "v=BIMI1; l=https://.../logo.svg"`,
    });
  }
  return { mtaSts, tlsRpt, bimi, findings };
}
