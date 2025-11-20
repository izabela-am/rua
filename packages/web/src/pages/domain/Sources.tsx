import { Area, AreaChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, ErrorText } from "../../components/ui";
import { fmtDate, fmtNum, fmtPct } from "../../lib/format";
import { useApi } from "../../lib/useApi";

export type Classification = "aligned_sender" | "known_forwarder" | "unknown";

type Source = {
  ip: string;
  ptr: string | null;
  ptrConfirmed: boolean;
  asn: number | null;
  asName: string | null;
  provider: string | null;
  classification: Classification;
  spoofing: boolean;
  messages: number;
  aligned: number;
  firstSeen: string;
  lastSeen: string;
};

type Day = { day: string; aligned_sender: number; known_forwarder: number; unknown: number; alignedRate: number | null };

export const LABELS: Record<Classification, { text: string; tone: "green" | "blue" | "amber"; color: string }> = {
  aligned_sender: { text: "Aligned sender", tone: "green", color: "#059669" },
  known_forwarder: { text: "Known forwarder", tone: "blue", color: "#0284c7" },
  unknown: { text: "Unknown", tone: "amber", color: "#d97706" },
};

export function Sources({ domainId }: { domainId: string }) {
  const sources = useApi<{ sources: Source[] }>(`/domains/${domainId}/sources?days=30`);
  const charts = useApi<{ days: Day[] }>(`/domains/${domainId}/charts?days=30`);

  const groups = new Map<string, Source[]>();
  for (const s of sources.data?.sources ?? []) {
    const key = s.provider ?? (s.asName ? `AS${s.asn} ${s.asName}` : "No identity");
    groups.set(key, [...(groups.get(key) ?? []), s]);
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Daily volume by label">
          <ErrorText error={charts.error} />
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={charts.data?.days ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" />
              <XAxis dataKey="day" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {(Object.keys(LABELS) as Classification[]).map((k) => (
                <Area key={k} type="monotone" dataKey={k} name={LABELS[k].text} stackId="1" stroke={LABELS[k].color} fill={LABELS[k].color} fillOpacity={0.5} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </Card>
        <Card title="DMARC alignment rate">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={charts.data?.days ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" />
              <XAxis dataKey="day" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 1]} tickFormatter={(v: number) => fmtPct(v, 0)} tick={{ fontSize: 11 }} />
              <Tooltip formatter={(v) => fmtPct(Number(v))} />
              <Line type="monotone" dataKey="alignedRate" name="Aligned" stroke="#18181b" dot={false} connectNulls />
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card title="Sources, last 30 days">
        <ErrorText error={sources.error} />
        {sources.data?.sources.length === 0 && <p className="text-sm text-zinc-500">No sources yet.</p>}
        <div className="space-y-4">
          {[...groups].map(([name, list]) => (
            <div key={name}>
              <h3 className="mb-1 text-xs font-semibold tracking-wide text-zinc-500 uppercase">{name}</h3>
              <table className="w-full text-sm">
                <tbody>
                  {list.map((s) => (
                    <tr key={s.ip} id={`ip-${s.ip}`} className={`border-t border-zinc-100 ${s.spoofing ? "bg-red-50" : ""}`}>
                      <td className="w-40 py-1.5 font-mono text-xs">{s.ip}</td>
                      <td className="text-xs text-zinc-600">
                        {s.ptr ?? "no PTR"}
                        {s.ptr && !s.ptrConfirmed && <span className="ml-1 text-amber-700">(unconfirmed)</span>}
                        {s.asn && <span className="ml-2 text-zinc-400">AS{s.asn}</span>}
                      </td>
                      <td>
                        <Badge tone={LABELS[s.classification].tone}>{LABELS[s.classification].text}</Badge>
                        {s.spoofing && (
                          <span className="ml-1">
                            <Badge tone="red">fails SPF and DKIM</Badge>
                          </span>
                        )}
                      </td>
                      <td className="text-right text-xs tabular-nums">
                        {fmtNum(s.messages)} msgs · {s.messages ? fmtPct(s.aligned / s.messages, 0) : "—"} aligned
                      </td>
                      <td className="text-right text-xs text-zinc-500">{fmtDate(s.lastSeen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
