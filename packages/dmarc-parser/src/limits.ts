export type Limits = {
  /** Largest compressed attachment accepted, in bytes. */
  maxAttachmentBytes: number;
  /** Decompression stops once this many bytes have been produced. */
  maxDecompressedBytes: number;
  /** Deepest XML nesting accepted. The aggregate schema needs 5. */
  maxXmlDepth: number;
  /** Most <record> elements accepted in one report. */
  maxRecords: number;
};

export const DEFAULT_LIMITS: Limits = {
  maxAttachmentBytes: 5 * 1024 * 1024,
  maxDecompressedBytes: 50 * 1024 * 1024,
  maxXmlDepth: 16,
  maxRecords: 100_000,
};
