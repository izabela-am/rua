import type { Finding } from "../db/schema.js";
import { orEmpty, type Resolver } from "../lib/dns.js";

export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;

/** SPF records published at a name: TXT strings starting with v=spf1, chunks joined. */
export async function spfRecords(resolver: Resolver, name: string): Promise<string[]> {
  const txt = await orEmpty(resolver.resolveTxt(name));
  return txt.map((c) => c.join("")).filter((t) => /^v=spf1(\s|$)/i.test(t));
}

type Walk = { lookups: number; voids: number; seen: Set<string>; loops: string[] };

/**
 * Counts DNS-querying terms (RFC 7208 section 4.6.4): include, a, mx, ptr,
 * exists and redirect cost one each; ip4, ip6 and all cost nothing. Includes
 * and redirects are followed. Returns the total and the cost of each
 * top-level term so the fix can say where the lookups go.
 */
export async function countLookups(resolver: Resolver, record: string) {
  const w: Walk = { lookups: 0, voids: 0, seen: new Set(), loops: [] };
  const chain: Array<{ term: string; cost: number }> = [];
  for (const term of terms(record)) {
    const before = w.lookups;
    await visit(resolver, term, w, 0);
    if (w.lookups > before) chain.push({ term, cost: w.lookups - before });
  }
  return { lookups: w.lookups, voids: w.voids, chain, loops: w.loops };
}

function terms(record: string) {
  return record.trim().split(/\s+/).slice(1);
}

async function visit(resolver: Resolver, term: string, w: Walk, depth: number): Promise<void> {
  // Stop well past the limit; the record is already broken.
  if (w.lookups > SPF_LOOKUP_LIMIT + 10 || depth > 10) return;
  const t = term.replace(/^[+?~-]/, "").toLowerCase();
  const [mech, arg] = splitTerm(t);

  if (mech === "include" || mech === "redirect") {
    w.lookups++;
    if (!arg) return;
    if (w.seen.has(arg)) {
      w.loops.push(arg);
      return;
    }
    w.seen.add(arg);
    const [child] = await spfRecords(resolver, arg);
    if (!child) {
      w.voids++;
      return;
    }
    for (const c of terms(child)) await visit(resolver, c, w, depth + 1);
  } else if (mech === "a" || mech === "mx" || mech === "ptr" || mech === "exists") {
    w.lookups++;
  }
}

function splitTerm(t: string): [string, string | undefined] {
  const m = t.match(/^([a-z0-9]+)(?:[:=]([^/]*))?/);
  return m ? [m[1]!, m[2]] : [t, undefined];
}

export async function auditSpf(resolver: Resolver, name: string): Promise<{ record: string | null; findings: Finding[] }> {
  const records = await spfRecords(resolver, name);
  const findings: Finding[] = [];
  if (records.length === 0) {
    findings.push({
      code: "spf_missing",
      severity: "high",
      message: `${name} publishes no SPF record, so no sender can pass SPF for it.`,
      fix: `Publish a TXT record at ${name}: "v=spf1 <your senders> -all", or "v=spf1 -all" if the domain sends no mail.`,
    });
    return { record: null, findings };
  }
  if (records.length > 1) {
    findings.push({
      code: "spf_multiple",
      severity: "high",
      message: `${name} publishes ${records.length} SPF records; receivers treat that as permerror.`,
      fix: "Merge them into one TXT record.",
    });
  }

  const record = records[0]!;
  const all = terms(record).find((t) => /^[+?~-]?all$/i.test(t));
  if (all && /^\+?all$/i.test(all)) {
    findings.push({
      code: "spf_plus_all",
      severity: "high",
      message: "SPF ends in +all, which authorizes every host on the internet.",
      fix: "Replace +all with -all or ~all.",
    });
  } else if (all?.toLowerCase() === "?all") {
    findings.push({
      code: "spf_neutral_all",
      severity: "medium",
      message: "SPF ends in ?all, which tells receivers nothing about unlisted hosts.",
      fix: "Replace ?all with ~all, then -all once the sender list is complete.",
    });
  }

  const { lookups, voids, chain, loops } = await countLookups(resolver, record);
  if (lookups > SPF_LOOKUP_LIMIT) {
    findings.push({
      code: "spf_lookup_limit",
      severity: "high",
      message: `SPF needs ${lookups} DNS lookups; receivers stop at ${SPF_LOOKUP_LIMIT} and treat the result as permerror.`,
      fix: `Remove or flatten one include. Current chain: ${chain.map((c) => `${c.term} (${c.cost})`).join(", ")}`,
    });
  }
  if (voids > SPF_VOID_LIMIT) {
    findings.push({
      code: "spf_void_lookups",
      severity: "medium",
      message: `${voids} includes point at names with no SPF record; receivers may permerror after ${SPF_VOID_LIMIT}.`,
      fix: "Remove includes for services you no longer use.",
    });
  }
  if (loops.length) {
    findings.push({
      code: "spf_include_loop",
      severity: "high",
      message: `SPF includes ${loops[0]} more than once.`,
      fix: "Remove the repeated include.",
    });
  }
  return { record, findings };
}
