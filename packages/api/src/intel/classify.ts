import type { Classification } from "../db/schema.js";
import type { Providers } from "./providers.js";

export type AlignmentStats = {
  messages: number;
  /** Messages that passed DMARC through SPF or DKIM alignment. */
  aligned: number;
  /** Messages that failed both. */
  failingBoth: number;
};

/**
 * aligned_sender: every message from this IP in the window aligned.
 * known_forwarder: not all aligned, but the IP belongs to a provider that forwards mail.
 * unknown: everything else.
 */
export function classify(stats: AlignmentStats, provider: string | null, providers: Providers): Classification {
  if (stats.messages > 0 && stats.aligned === stats.messages) return "aligned_sender";
  if (provider && providers.all.some((p) => p.name === provider && p.forwarder)) return "known_forwarder";
  return "unknown";
}

/** The spoofing signal: an unknown source whose mail fails both SPF and DKIM. */
export const isSpoofing = (c: Classification, stats: AlignmentStats) => c === "unknown" && stats.failingBoth > 0;
