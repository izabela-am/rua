// Downloads the iptoasn.com combined IPv4+IPv6 dataset (public domain, updated hourly).
//   pnpm --filter @rua/api fetch-asn
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
const out = fileURLToPath(new URL("../../data/ip2asn-combined.tsv.gz", import.meta.url));

const res = await fetch(url);
if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
const bytes = new Uint8Array(await res.arrayBuffer());
await writeFile(out, bytes);
console.log(`wrote ${out} (${(bytes.byteLength / 1e6).toFixed(1)} MB)`);
