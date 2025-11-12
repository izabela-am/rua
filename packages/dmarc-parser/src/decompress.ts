import { Gunzip, Unzip, UnzipInflate, UnzipPassThrough } from "fflate";
import { ReportError } from "./errors.js";
import { DEFAULT_LIMITS, type Limits } from "./limits.js";

const CHUNK = 64 * 1024;

/**
 * Turns a report attachment into XML bytes. Accepts gzip, zip with exactly one
 * .xml member, or plain XML. Counts output bytes as it goes and aborts past the
 * limit, so a small bomb never allocates its full size.
 */
export function decompress(bytes: Uint8Array, limits: Partial<Limits> = {}): Uint8Array {
  const l = { ...DEFAULT_LIMITS, ...limits };
  if (bytes.byteLength > l.maxAttachmentBytes) {
    throw new ReportError("too_large", `attachment is ${bytes.byteLength} bytes; limit ${l.maxAttachmentBytes}`);
  }
  if (isGzip(bytes)) return gunzip(bytes, l.maxDecompressedBytes);
  if (isZip(bytes)) return unzip(bytes, l.maxDecompressedBytes);
  if (looksLikeXml(bytes)) return bytes;
  throw new ReportError("not_xml", "attachment is not gzip, zip or XML");
}

function isGzip(b: Uint8Array) {
  return b[0] === 0x1f && b[1] === 0x8b;
}

function isZip(b: Uint8Array) {
  return b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04;
}

function looksLikeXml(b: Uint8Array) {
  const head = new TextDecoder().decode(b.subarray(0, 64)).replace(/^﻿/, "").trimStart();
  return head.startsWith("<");
}

class Sink {
  private chunks: Uint8Array[] = [];
  private total = 0;
  constructor(private readonly max: number) {}

  push(chunk: Uint8Array) {
    this.total += chunk.byteLength;
    if (this.total > this.max) {
      throw new ReportError("too_large", `decompressed size exceeds ${this.max} bytes`);
    }
    this.chunks.push(chunk);
  }

  concat() {
    const out = new Uint8Array(this.total);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  }
}

function gunzip(bytes: Uint8Array, max: number): Uint8Array {
  const sink = new Sink(max);
  const g = new Gunzip((chunk) => sink.push(chunk));
  for (let i = 0; i < bytes.byteLength; i += CHUNK) {
    const end = Math.min(i + CHUNK, bytes.byteLength);
    g.push(bytes.subarray(i, end), end === bytes.byteLength);
  }
  const out = sink.concat();
  if (isGzip(out) || isZip(out)) throw new ReportError("nested_archive", "archive inside archive");
  return out;
}

function unzip(bytes: Uint8Array, max: number): Uint8Array {
  const sink = new Sink(max);
  const names: string[] = [];
  let failure: unknown;

  const u = new Unzip((file) => {
    names.push(file.name);
    if (names.length > 1 || file.name.endsWith("/") || !file.name.toLowerCase().endsWith(".xml")) {
      failure = new ReportError("nested_archive", `zip must hold exactly one .xml member; found ${file.name}`);
      return;
    }
    file.ondata = (err, chunk) => {
      if (err) failure ??= new ReportError("schema", `zip member is corrupt: ${err.message}`);
      else if (!failure) {
        try {
          sink.push(chunk);
        } catch (e) {
          failure = e;
          file.terminate();
        }
      }
    };
    file.start();
  });
  u.register(UnzipInflate);
  u.register(UnzipPassThrough);

  for (let i = 0; i < bytes.byteLength && !failure; i += CHUNK) {
    const end = Math.min(i + CHUNK, bytes.byteLength);
    u.push(bytes.subarray(i, end), end === bytes.byteLength);
  }
  if (failure) throw failure;
  if (names.length !== 1) throw new ReportError("nested_archive", "zip holds no .xml member");
  const out = sink.concat();
  if (isGzip(out) || isZip(out)) throw new ReportError("nested_archive", "archive inside archive");
  return out;
}
