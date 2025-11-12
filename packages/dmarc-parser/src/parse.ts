import { XMLParser, XMLValidator } from "fast-xml-parser";
import { ReportError } from "./errors.js";
import { DEFAULT_LIMITS, type Limits } from "./limits.js";
import type { AggregateRecord, AggregateReport, AuthResult, Policy } from "./types.js";

const parser = new XMLParser({
  ignoreAttributes: true,
  processEntities: false,
  htmlEntities: false,
  parseTagValue: false,
  trimValues: true,
  isArray: (name) => ["record", "dkim", "spf", "reason"].includes(name),
});

/**
 * Parses an RFC 7489 aggregate report. Input is XML text or bytes, never an
 * archive; call decompress first. No I/O. Throws ReportError on anything that
 * is not a well-formed aggregate report.
 */
export function parseAggregateReport(xml: string | Uint8Array, limits: Partial<Limits> = {}): AggregateReport {
  const l = { ...DEFAULT_LIMITS, ...limits };
  const text = typeof xml === "string" ? xml : new TextDecoder("utf-8", { fatal: false }).decode(xml);

  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    throw new ReportError("not_xml", "DTD and entity declarations are not accepted");
  }
  checkDepth(text, l.maxXmlDepth);
  const valid = XMLValidator.validate(text);
  if (valid !== true) throw new ReportError("not_xml", `malformed XML: ${valid.err.msg}`);

  const doc = parser.parse(text) as { feedback?: Feedback };
  const fb = doc.feedback;
  if (!fb) throw new ReportError("schema", "root element is not <feedback>");

  const meta = req(fb.report_metadata, "report_metadata");
  const pp = req(fb.policy_published, "policy_published");
  const range = req(meta.date_range, "report_metadata.date_range");
  const rows = fb.record ?? [];
  if (rows.length > l.maxRecords) throw new ReportError("too_large", `report has ${rows.length} records`);

  return {
    reporter: {
      orgName: str(meta.org_name, "org_name").toLowerCase(),
      email: str(meta.email, "email"),
      reportId: str(meta.report_id, "report_id"),
    },
    dateRange: { begin: epoch(range.begin, "begin"), end: epoch(range.end, "end") },
    policyPublished: {
      domain: str(pp.domain, "policy_published.domain").toLowerCase(),
      p: policy(pp.p, "p"),
      sp: pp.sp ? policy(pp.sp, "sp") : undefined,
      pct: pp.pct === undefined || pp.pct === "" ? 100 : int(pp.pct, "pct"),
      adkim: pp.adkim === "s" ? "s" : "r",
      aspf: pp.aspf === "s" ? "s" : "r",
    },
    records: rows.map(toRecord),
  };
}

type Text = string | undefined;
type Feedback = {
  report_metadata?: {
    org_name?: Text;
    email?: Text;
    report_id?: Text;
    date_range?: { begin?: Text; end?: Text };
  };
  policy_published?: { domain?: Text; p?: Text; sp?: Text; pct?: Text; adkim?: Text; aspf?: Text };
  record?: Array<{
    row?: {
      source_ip?: Text;
      count?: Text;
      policy_evaluated?: { disposition?: Text; dkim?: Text[]; spf?: Text[] };
    };
    identifiers?: { header_from?: Text; envelope_from?: Text };
    auth_results?: {
      dkim?: Array<{ domain?: Text; selector?: Text; result?: Text }>;
      spf?: Array<{ domain?: Text; result?: Text }>;
    };
  }>;
};

function toRecord(r: NonNullable<Feedback["record"]>[number], i: number): AggregateRecord {
  const row = req(r.row, `record[${i}].row`);
  const pe = req(row.policy_evaluated, `record[${i}].policy_evaluated`);
  const ids = req(r.identifiers, `record[${i}].identifiers`);
  const auth: AuthResult[] = [
    ...(r.auth_results?.dkim ?? []).map((d) => ({
      type: "dkim" as const,
      domain: (d.domain ?? "").toLowerCase(),
      ...(d.selector ? { selector: d.selector } : {}),
      result: (d.result ?? "none").toLowerCase(),
    })),
    ...(r.auth_results?.spf ?? []).map((s) => ({
      type: "spf" as const,
      domain: (s.domain ?? "").toLowerCase(),
      result: (s.result ?? "none").toLowerCase(),
    })),
  ];
  return {
    sourceIp: ip(str(row.source_ip, `record[${i}].source_ip`)),
    count: int(row.count, `record[${i}].count`),
    disposition: policy(pe.disposition, `record[${i}].disposition`),
    dkim: passFail(pe.dkim?.[0]),
    spf: passFail(pe.spf?.[0]),
    headerFrom: str(ids.header_from, `record[${i}].header_from`).toLowerCase(),
    ...(ids.envelope_from ? { envelopeFrom: ids.envelope_from.toLowerCase() } : {}),
    authResults: auth,
  };
}

function checkDepth(text: string, max: number) {
  let depth = 0;
  for (const m of text.matchAll(/<(\/?)[A-Za-z_][^>]*?(\/?)>/g)) {
    if (m[1]) depth--;
    else if (!m[2]) depth++;
    if (depth > max) throw new ReportError("not_xml", `XML nesting deeper than ${max}`);
  }
}

function req<T>(v: T | undefined, path: string): T {
  if (v === undefined || v === null || (typeof v === "string" && v === "")) {
    throw new ReportError("schema", `missing ${path}`);
  }
  return v;
}

function str(v: unknown, path: string): string {
  if (typeof v !== "string" || v === "") throw new ReportError("schema", `missing ${path}`);
  return v;
}

function int(v: unknown, path: string): number {
  const n = Number(v);
  if (typeof v !== "string" || !/^\d+$/.test(v.trim()) || !Number.isSafeInteger(n)) {
    throw new ReportError("schema", `${path} is not an integer`);
  }
  return n;
}

function epoch(v: unknown, path: string): Date {
  return new Date(int(v, path) * 1000);
}

function policy(v: unknown, path: string): Policy {
  const s = typeof v === "string" ? v.toLowerCase() : v;
  if (s === "none" || s === "quarantine" || s === "reject") return s;
  throw new ReportError("schema", `${path} is not a DMARC policy`);
}

function passFail(v: unknown): "pass" | "fail" {
  return typeof v === "string" && v.toLowerCase() === "pass" ? "pass" : "fail";
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function ip(v: string): string {
  const s = v.trim().toLowerCase();
  if (IPV4.test(s) || (s.includes(":") && /^[0-9a-f:.]+$/.test(s))) return s;
  throw new ReportError("schema", `source_ip ${v} is not an IP address`);
}
