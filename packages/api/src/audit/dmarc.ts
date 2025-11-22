import type { Finding } from "../db/schema.js";
import { orEmpty, type Resolver } from "../lib/dns.js";

export type DmarcTags = Record<string, string>;

/** Parses "v=DMARC1; p=none; rua=mailto:a@b" into tags. Returns null when v=DMARC1 is not the first tag. */
export function parseDmarc(record: string): DmarcTags | null {
  const tags: DmarcTags = {};
  const parts = record.split(";").map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i < 1) return null;
    tags[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim();
  }
  if (parts[0]?.replace(/\s/g, "").toLowerCase() !== "v=dmarc1") return null;
  return tags;
}

export type DmarcContext = {
  ruaAddress: string;
  /** Header-from domains seen in reports that are subdomains of this domain. */
  subdomainsSeen: string[];
  /** True when some aligned mail aligned only under relaxed rules (DKIM or SPF domain is a parent or child, not equal). */
  relaxedOnlySenders: boolean;
};

export async function auditDmarc(resolver: Resolver, name: string, ctx: DmarcContext): Promise<{ record: string | null; findings: Finding[] }> {
  const records = (await orEmpty(resolver.resolveTxt(`_dmarc.${name}`)))
    .map((c) => c.join(""))
    .filter((t) => /^v\s*=\s*DMARC1/i.test(t));
  const findings: Finding[] = [];
  const recommended = `v=DMARC1; p=none; rua=mailto:${ctx.ruaAddress}`;

  if (records.length === 0) {
    findings.push({
      code: "dmarc_missing",
      severity: "high",
      message: `_dmarc.${name} has no DMARC record. Receivers apply no policy and send no reports.`,
      fix: `Publish a TXT record at _dmarc.${name}: "${recommended}"`,
    });
    return { record: null, findings };
  }
  if (records.length > 1) {
    findings.push({
      code: "dmarc_multiple",
      severity: "high",
      message: `_dmarc.${name} has ${records.length} DMARC records; receivers ignore all of them.`,
      fix: "Keep exactly one.",
    });
  }

  const record = records[0]!;
  const tags = parseDmarc(record);
  const p = tags?.p?.toLowerCase();
  if (!tags || !p || !["none", "quarantine", "reject"].includes(p)) {
    findings.push({
      code: "dmarc_syntax",
      severity: "high",
      message: "The DMARC record does not parse: it needs v=DMARC1 first and a p= tag of none, quarantine or reject.",
      fix: `Replace it with "${recommended}"`,
    });
    return { record, findings };
  }

  if (p === "none") {
    findings.push({
      code: "dmarc_p_none",
      severity: "medium",
      message: "p=none monitors but does not protect: receivers deliver spoofed mail.",
      fix: "Check the readiness card, then move to p=quarantine.",
    });
  }
  const pct = tags.pct === undefined ? 100 : Number(tags.pct);
  if (pct < 100) {
    findings.push({
      code: "dmarc_pct",
      severity: "low",
      message: `pct=${pct} applies the policy to only part of failing mail.`,
      fix: "Raise pct to 100 or remove the tag.",
    });
  }

  const rua = (tags.rua ?? "").split(",").map((u) => u.trim().replace(/^mailto:/i, "").replace(/!.*$/, "").toLowerCase());
  if (!tags.rua) {
    findings.push({
      code: "dmarc_rua_missing",
      severity: "medium",
      message: "No rua= tag, so no receiver sends aggregate reports.",
      fix: `Add rua=mailto:${ctx.ruaAddress}`,
    });
  } else if (!rua.includes(ctx.ruaAddress.toLowerCase())) {
    findings.push({
      code: "dmarc_rua_not_rua",
      severity: "medium",
      message: "rua= does not include this domain's Rua address, so new reports will not reach Rua.",
      fix: `Add mailto:${ctx.ruaAddress} to rua= (comma-separated).`,
    });
  }

  if (!tags.sp && ctx.subdomainsSeen.length) {
    findings.push({
      code: "dmarc_sp_missing",
      severity: "low",
      message: `Mail from ${ctx.subdomainsSeen.slice(0, 3).join(", ")} inherits p=${p}; there is no separate sp= policy.`,
      fix: "Add sp= if subdomains need a different policy, or confirm that inheriting is intended.",
    });
  }

  if ((tags.adkim === "s" || tags.aspf === "s") && ctx.relaxedOnlySenders) {
    findings.push({
      code: "dmarc_strict_alignment",
      severity: "medium",
      message: "Strict alignment is set, but some senders align only under relaxed rules; their mail fails DMARC.",
      fix: "Use adkim=r and aspf=r, or sign and bounce with the exact header-from domain.",
    });
  }
  return { record, findings };
}
