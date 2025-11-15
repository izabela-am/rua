import { randomBytes } from "node:crypto";
import { domainToASCII } from "node:url";

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

/** d- plus 12 base32 characters: 60 bits, unguessable, safe in an email local part. */
export function newRuaLocalPart(): string {
  const bytes = randomBytes(12);
  let out = "d-";
  for (const b of bytes) out += BASE32[b & 31];
  return out;
}

export function newVerifyToken(): string {
  return randomBytes(24).toString("base64url");
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** Lowercases and IDNA-encodes a domain. Returns null for anything that is not a registrable-looking name. */
export function normalizeDomain(input: string): string | null {
  const ascii = domainToASCII(input.trim().replace(/\.$/, "").toLowerCase());
  if (!ascii || ascii.length > 253) return null;
  const labels = ascii.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  if (/^\d+$/.test(labels.at(-1)!)) return null;
  return ascii;
}
