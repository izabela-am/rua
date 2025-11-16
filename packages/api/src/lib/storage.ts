import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, normalize } from "node:path";
import { createClient } from "@supabase/supabase-js";

/** Raw report objects. Keys look like <domainId>/<emailId>/<attachmentId>. */
export type RawStore = {
  put(key: string, bytes: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array>;
  remove(keys: string[]): Promise<void>;
};

export function supabaseStore(url: string, serviceRoleKey: string, bucket = "reports"): RawStore {
  const storage = createClient(url, serviceRoleKey, { auth: { persistSession: false } }).storage.from(bucket);
  return {
    async put(key, bytes) {
      const { error } = await storage.upload(key, bytes, { contentType: "application/octet-stream", upsert: true });
      if (error) throw error;
    },
    async get(key) {
      const { data, error } = await storage.download(key);
      if (error) throw error;
      return new Uint8Array(await data.arrayBuffer());
    },
    async remove(keys) {
      if (keys.length === 0) return;
      const { error } = await storage.remove(keys);
      if (error) throw error;
    },
  };
}

/** Local directory store for development and tests. */
export function fsStore(root: string): RawStore {
  const path = (key: string) => {
    const p = normalize(join(root, key));
    if (!p.startsWith(normalize(root))) throw new Error(`key escapes store: ${key}`);
    return p;
  };
  return {
    async put(key, bytes) {
      await mkdir(dirname(path(key)), { recursive: true });
      await writeFile(path(key), bytes);
    },
    async get(key) {
      return new Uint8Array(await readFile(path(key)));
    },
    async remove(keys) {
      await Promise.all(keys.map((k) => rm(path(k), { force: true })));
    },
  };
}
