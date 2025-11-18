export const fmtDate = (s: string | Date) =>
  new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

export const fmtDateTime = (s: string | Date) =>
  new Date(s).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export const fmtNum = (n: number) => n.toLocaleString();

export const fmtPct = (n: number, digits = 1) => `${(n * 100).toFixed(digits)}%`;
