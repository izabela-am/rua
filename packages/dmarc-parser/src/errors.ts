export type ReportErrorCode = "too_large" | "nested_archive" | "not_xml" | "schema";

export class ReportError extends Error {
  constructor(
    readonly code: ReportErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ReportError";
  }
}
