import { promises as dns } from "node:dns";

/** The subset of dns.promises Rua uses. Injected so tests never touch the network. */
export type Resolver = {
  resolveTxt(name: string): Promise<string[][]>;
  reverse(ip: string): Promise<string[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolveCname(name: string): Promise<string[]>;
};

export const systemResolver: Resolver = dns;

const EMPTY = new Set(["ENOTFOUND", "ENODATA", "ESERVFAIL", "ENOTIMP", "EREFUSED"]);

/** Calls a lookup and turns "no such record" errors into an empty answer. */
export async function orEmpty<T>(lookup: Promise<T[]>): Promise<T[]> {
  try {
    return await lookup;
  } catch (e) {
    if (EMPTY.has((e as NodeJS.ErrnoException).code ?? "")) return [];
    throw e;
  }
}
