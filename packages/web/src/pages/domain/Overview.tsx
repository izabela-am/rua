import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, Copy, ErrorText } from "../../components/ui";
import { fmtDate, fmtNum, fmtPct } from "../../lib/format";
import { useApi } from "../../lib/useApi";

type Readiness = {
  published: string | null;
  recommended: "none" | "quarantine" | "reject";
  survival: { quarantine: number; reject: number } | null;
  volume: { total: number; aligned: number; knownForwarder: number; unknown: number };
  blockers: Array<{ ip: string; messages: number; lastSeen: string }>;
  record: string;
};

type Finding = { code: string; severity: "high" | "medium" | "low" | "info"; message: string; fix: string; selector?: string };
type Audit = {
  takenAt: string | null;
  findings: Finding[];
  history: Array<{ code: string; selector?: string; change: "appeared" | "cleared"; at: string }>;
};
type DeliveryDay = { day: string; delivered: number; bounced: number; complained: number };

const SEVERITY = { high: "red", medium: "amber", low: "zinc", info: "blue" } as const;
const POLICY_TONE = { none: "amber", quarantine: "blue", reject: "green" } as const;

export function Overview({ domainId }: { domainId: string }) {
  const r = useApi<Readiness>(`/domains/${domainId}/readiness`);
  const audit = useApi<Audit>(`/domains/${domainId}/audit`);
  const delivery = useApi<{ days: DeliveryDay[] }>(`/domains/${domainId}/delivery?days=30`);

  return (
    <div className="space-y-4">
      <Card title="Policy readiness, last 30 days">
        <ErrorText error={r.error} />
        {r.data && (
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-4">
              <span>
                Published: <Badge tone={POLICY_TONE[(r.data.published ?? "none") as keyof typeof POLICY_TONE] ?? "zinc"}>p={r.data.published ?? "unknown"}</Badge>
              </span>
              <span>
                Recommended: <Badge tone={POLICY_TONE[r.data.recommended]}>p={r.data.recommended}</Badge>
              </span>
              {r.data.survival && (
                <span className="text-zinc-600">
                  {fmtPct(r.data.survival.quarantine, 2)} of {fmtNum(r.data.volume.total)} messages come from aligned senders or known
                  forwarders and would survive enforcement.
                </span>
              )}
            </div>
            {!r.data.survival && <p className="text-zinc-500">No report data in the last 30 days.</p>}
            {r.data.blockers.length > 0 && (
              <div>
                <p className="mb-1 font-medium">Unknown sources failing SPF and DKIM</p>
                <ul className="text-xs">
                  {r.data.blockers.slice(0, 10).map((b) => (
                    <li key={b.ip} className="font-mono">
                      {b.ip} · {fmtNum(b.messages)} msgs · last seen {fmtDate(b.lastSeen)}
                    </li>
                  ))}
                </ul>
                <p className="mt-1 text-xs text-zinc-500">Stop them if they are spoofing, or authenticate them if they are yours.</p>
              </div>
            )}
            <div>
              <p className="mb-1 font-medium">Record to publish at _dmarc</p>
              <Copy value={r.data.record} />
            </div>
          </div>
        )}
      </Card>

      <Card title="Delivery from Resend">
        {delivery.data?.days.length ? (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={delivery.data.days}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" />
              <XAxis dataKey="day" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="delivered" stackId="a" fill="#059669" name="Delivered" />
              <Bar dataKey="bounced" stackId="a" fill="#d97706" name="Bounced" />
              <Bar dataKey="complained" stackId="a" fill="#dc2626" name="Complained" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-sm text-zinc-500">No Resend events yet. Connect a Resend webhook on the Setup tab.</p>
        )}
      </Card>

      <Card title={audit.data?.takenAt ? `DNS records, checked ${fmtDate(audit.data.takenAt)}` : "DNS records"}>
        {audit.data && !audit.data.takenAt && <p className="text-sm text-zinc-500">The first audit runs at 06:00 UTC.</p>}
        <ul className="space-y-2">
          {audit.data?.findings.map((f) => (
            <li key={f.code + (f.selector ?? "")} className="text-sm">
              <div className="flex items-center gap-2">
                <Badge tone={SEVERITY[f.severity]}>{f.severity}</Badge>
                <span>{f.message}</span>
              </div>
              <p className="ml-14 text-xs text-zinc-600">{f.fix}</p>
            </li>
          ))}
        </ul>
        {audit.data && audit.data.history.length > 0 && (
          <details className="mt-3 text-xs text-zinc-600">
            <summary className="cursor-pointer">History</summary>
            <ul className="mt-1">
              {audit.data.history.map((h, i) => (
                <li key={i}>
                  {fmtDate(h.at)} · {h.code}
                  {h.selector && ` (${h.selector})`} {h.change}
                </li>
              ))}
            </ul>
          </details>
        )}
      </Card>
    </div>
  );
}
