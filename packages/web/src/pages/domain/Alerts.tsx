import { Badge, Card, ErrorText } from "../../components/ui";
import { fmtDateTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

type Alert = {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
  createdAt: string;
  emailedAt: string | null;
  webhookDeliveredAt: string | null;
};

const KINDS: Record<string, { text: string; tone: "red" | "amber" | "green" | "blue" | "zinc" }> = {
  spoofing_source: { text: "Spoofing", tone: "red" },
  new_source: { text: "New source", tone: "blue" },
  policy_ready: { text: "Policy ready", tone: "green" },
  ownership_lost: { text: "Ownership lost", tone: "red" },
  audit_finding: { text: "DNS finding", tone: "amber" },
};

function summary(a: Alert) {
  const p = a.payload;
  if (p.ip) return [p.provider, p.ptr, p.ip].filter(Boolean).join(" · ") + (p.messages ? ` · ${p.messages} msgs` : "");
  return String(p.message ?? p.recommended ?? "");
}

export function Alerts({ domainId }: { domainId: string }) {
  const { data, error } = useApi<{ alerts: Alert[] }>(`/domains/${domainId}/alerts`);
  return (
    <Card title="Alerts">
      <ErrorText error={error} />
      {data?.alerts.length === 0 && <p className="text-sm text-zinc-500">No alerts yet.</p>}
      <ul className="divide-y divide-zinc-100">
        {data?.alerts.map((a) => (
          <li key={a.id} className="flex items-center gap-3 py-2 text-sm">
            <Badge tone={KINDS[a.kind]?.tone ?? "zinc"}>{KINDS[a.kind]?.text ?? a.kind}</Badge>
            <span className="flex-1">{summary(a)}</span>
            <span className="text-xs text-zinc-500">
              {a.emailedAt ? "emailed" : "not emailed"}
              {a.webhookDeliveredAt && " · webhook ✓"}
            </span>
            <span className="w-32 text-right text-xs text-zinc-500">{fmtDateTime(a.createdAt)}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
