import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Key encryption keys by id. Loaded from RUA_KEK_<id> (base64, 32 bytes);
 * RUA_KEK_CURRENT names the one new rows use.
 *
 * Rotation: add RUA_KEK_<new>, point RUA_KEK_CURRENT at it, re-encrypt rows in
 * a migration script, then remove the old variable.
 */
export type Keyring = { current: string; keys: Record<string, Buffer> };

export function keyringFromEnv(env: NodeJS.ProcessEnv = process.env): Keyring {
  const keys: Record<string, Buffer> = {};
  for (const [k, v] of Object.entries(env)) {
    const m = k.match(/^RUA_KEK_(\w+)$/);
    if (!m || m[1] === "CURRENT" || !v) continue;
    const key = Buffer.from(v, "base64");
    if (key.length !== 32) throw new Error(`${k} must be 32 bytes of base64`);
    keys[m[1]!] = key;
  }
  const current = env.RUA_KEK_CURRENT ?? "";
  if (!keys[current]) throw new Error("RUA_KEK_CURRENT must name a configured RUA_KEK_<id>");
  return { current, keys };
}

const IV = 12;
const TAG = 16;

/** AES-256-GCM. Output is iv(12) || tag(16) || ciphertext. */
export function encrypt(ring: Keyring, plain: string): { blob: Uint8Array; keyId: string } {
  const iv = randomBytes(IV);
  const cipher = createCipheriv("aes-256-gcm", ring.keys[ring.current]!, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return { blob: Buffer.concat([iv, cipher.getAuthTag(), ct]), keyId: ring.current };
}

export function decrypt(ring: Keyring, blob: Uint8Array, keyId: string): string {
  const key = ring.keys[keyId];
  if (!key) throw new Error(`no key ${keyId}`);
  const b = Buffer.from(blob);
  const decipher = createDecipheriv("aes-256-gcm", key, b.subarray(0, IV));
  decipher.setAuthTag(b.subarray(IV, IV + TAG));
  return Buffer.concat([decipher.update(b.subarray(IV + TAG)), decipher.final()]).toString("utf8");
}
