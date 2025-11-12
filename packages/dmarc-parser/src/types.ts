export type Policy = "none" | "quarantine" | "reject";

export type AuthResult = {
  type: "dkim" | "spf";
  domain: string;
  selector?: string;
  result: string;
};

export type AggregateRecord = {
  sourceIp: string;
  count: number;
  disposition: Policy;
  /** policy_evaluated: the reporter's DMARC alignment verdict. */
  dkim: "pass" | "fail";
  spf: "pass" | "fail";
  headerFrom: string;
  envelopeFrom?: string;
  authResults: AuthResult[];
};

export type AggregateReport = {
  reporter: { orgName: string; email: string; reportId: string };
  dateRange: { begin: Date; end: Date };
  policyPublished: {
    domain: string;
    p: Policy;
    sp?: Policy;
    pct: number;
    adkim: "r" | "s";
    aspf: "r" | "s";
  };
  records: AggregateRecord[];
};
