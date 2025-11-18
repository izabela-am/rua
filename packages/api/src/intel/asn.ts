import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { ipToBigInt, ipVersion } from "./ip.js";

type Table = { starts: bigint[]; ends: bigint[]; asn: number[]; name: string[] };
export type AsnTable = { lookup(ip: string): { asn: number; asName: string } | null; size: number };

const DATA = fileURLToPath(new URL("../../data/", import.meta.url));

/** Parses ip2asn-combined TSV. Rows with AS 0 mean "not routed" and are skipped. */
export function parseAsnTsv(text: string): AsnTable {
  const tables: Record<4 | 6, Table> = {
    4: { starts: [], ends: [], asn: [], name: [] },
    6: { starts: [], ends: [], asn: [], name: [] },
  };
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const [start, end, asn, , name] = line.split("\t");
    if (!start || !end || !asn || asn === "0") continue;
    const t = tables[ipVersion(start)];
    t.starts.push(ipToBigInt(start));
    t.ends.push(ipToBigInt(end));
    t.asn.push(Number(asn));
    t.name.push(name ?? "");
  }
  // The upstream file is sorted; sort anyway so a hand-edited sample cannot break the search.
  for (const v of [4, 6] as const) {
    const t = tables[v];
    const order = t.starts.map((_, i) => i).sort((a, b) => (t.starts[a]! < t.starts[b]! ? -1 : 1));
    tables[v] = {
      starts: order.map((i) => t.starts[i]!),
      ends: order.map((i) => t.ends[i]!),
      asn: order.map((i) => t.asn[i]!),
      name: order.map((i) => t.name[i]!),
    };
  }

  return {
    size: tables[4].starts.length + tables[6].starts.length,
    lookup(ip) {
      const t = tables[ipVersion(ip)];
      const n = ipToBigInt(ip);
      let lo = 0;
      let hi = t.starts.length - 1;
      // Last range whose start <= n.
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (t.starts[mid]! <= n) lo = mid + 1;
        else hi = mid - 1;
      }
      if (hi < 0 || n > t.ends[hi]!) return null;
      return { asn: t.asn[hi]!, asName: t.name[hi]! };
    },
  };
}

let loaded: AsnTable | undefined;

/** Loads the full dataset if fetched, else the bundled sample. Once per process. */
export function asnTable(): AsnTable {
  if (loaded) return loaded;
  const full = `${DATA}ip2asn-combined.tsv.gz`;
  const text = existsSync(full)
    ? gunzipSync(readFileSync(full)).toString("utf8")
    : readFileSync(`${DATA}asn-sample.tsv`, "utf8");
  loaded = parseAsnTsv(text);
  return loaded;
}
