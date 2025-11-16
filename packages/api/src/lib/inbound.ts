import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Resend } from "resend";
import { DEFAULT_LIMITS } from "@rua/dmarc-parser";

export type Attachment = { id: string; filename: string; contentType: string; bytes: Uint8Array };

/** Fetches the report attachment of a received email. */
export type InboundMail = {
  reportAttachment(emailId: string): Promise<Attachment | null>;
};

export class AttachmentTooLarge extends Error {}

const MAX = DEFAULT_LIMITS.maxAttachmentBytes;

export function isReportFile(filename: string, contentType: string) {
  const f = filename.toLowerCase();
  return (
    /\.(xml|xml\.gz|gz|zip)$/.test(f) ||
    /(gzip|zip|xml)/.test(contentType.toLowerCase())
  );
}

export function resendInbound(resend: Resend, fetchImpl: typeof fetch = fetch): InboundMail {
  return {
    async reportAttachment(emailId) {
      const { data, error } = await resend.emails.receiving.attachments.list({ emailId });
      if (error) throw new Error(`resend attachments.list: ${error.message}`);
      const att = data.data.find((a) => isReportFile(a.filename ?? "", a.content_type));
      if (!att) return null;
      if (att.size > MAX) throw new AttachmentTooLarge(`attachment is ${att.size} bytes`);

      const res = await fetchImpl(att.download_url, { redirect: "error" });
      if (!res.ok || !res.body) throw new Error(`attachment download: HTTP ${res.status}`);
      return {
        id: att.id,
        filename: att.filename ?? "report",
        contentType: att.content_type,
        bytes: await readCapped(res.body, MAX),
      };
    },
  };
}

/** Reads a stream and stops once it exceeds max, whatever Content-Length said. */
export async function readCapped(body: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new AttachmentTooLarge(`attachment exceeds ${max} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/**
 * Development stand-in for Resend: the replay script writes the attachment to
 * <dir>/<emailId>/<filename> and this reads it back.
 */
export function fsInbound(dir: string): InboundMail {
  return {
    async reportAttachment(emailId) {
      if (!/^[\w-]+$/.test(emailId)) return null;
      const folder = join(dir, emailId);
      const [file] = await readdir(folder).catch(() => []);
      if (!file) return null;
      if ((await stat(join(folder, file))).size > MAX) throw new AttachmentTooLarge(file);
      return { id: "local", filename: file, contentType: "application/octet-stream", bytes: await readFile(join(folder, file)) };
    },
  };
}
