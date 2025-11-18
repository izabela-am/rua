import { useState } from "react";
import { Badge, Card, ErrorText } from "../../components/ui";
import { fmtDate, fmtNum } from "../../lib/format";
import { useApi } from "../../lib/useApi";

type Report = {
  id: string;
  reporterOrg: string;
  reportId: string;
  beginAt: string;
  endAt: string;
  messages: number;
  policyPublished: { p: string; pct: number };
};

type Record = {
  sourceIp: string;
  count: number;
  disposition: string;
  dkimAligned: boolean;
  spfAligned: boolean;
  headerFrom: string;
  envelopeFrom: string | null;
};

export function Reports({ domainId }: { domainId: string }) {
  const { data, error } = useApi<{ reports: Report[] }>(`/domains/${domainId}/reports`);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <Card title="Aggregate reports">
      <ErrorText error={error} />
      {data?.reports.length === 0 && (
        <p className="text-sm text-zinc-500">No reports yet. Receivers send one a day once the rua= address is published.</p>
      )}
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-zinc-500">
          <tr>
            <th className="py-1">Reporter</th>
            <th>Period</th>
            <th>Policy</th>
            <th className="text-right">Messages</th>
          </tr>
        </thead>
        <tbody>
          {data?.reports.map((r) => (
            <ReportRow key={r.id} report={r} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} />
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function ReportRow({ report, open, onToggle }: { report: Report; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="cursor-pointer border-t border-zinc-100 hover:bg-zinc-50" onClick={onToggle}>
        <td className="py-2 font-medium">{report.reporterOrg}</td>
        <td>
          {fmtDate(report.beginAt)} – {fmtDate(report.endAt)}
        </td>
        <td>
          p={report.policyPublished.p}
          {report.policyPublished.pct !== 100 && ` pct=${report.policyPublished.pct}`}
        </td>
        <td className="text-right tabular-nums">{fmtNum(report.messages)}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={4} className="bg-zinc-50 p-2">
            <Records reportId={report.id} />
          </td>
        </tr>
      )}
    </>
  );
}

const pass = (ok: boolean) => <Badge tone={ok ? "green" : "red"}>{ok ? "pass" : "fail"}</Badge>;

function Records({ reportId }: { reportId: string }) {
  const { data, error } = useApi<{ records: Record[] }>(`/reports/${reportId}/records`);
  return (
    <>
      <ErrorText error={error} />
      <table className="w-full text-xs">
        <thead className="text-left text-zinc-500">
          <tr>
            <th>Source IP</th>
            <th className="text-right">Count</th>
            <th>Disposition</th>
            <th>DKIM</th>
            <th>SPF</th>
            <th>Envelope from</th>
          </tr>
        </thead>
        <tbody>
          {data?.records.map((r, i) => (
            <tr key={i} className="border-t border-zinc-200">
              <td className="py-1 font-mono">{r.sourceIp}</td>
              <td className="text-right tabular-nums">{fmtNum(r.count)}</td>
              <td>{r.disposition}</td>
              <td>{pass(r.dkimAligned)}</td>
              <td>{pass(r.spfAligned)}</td>
              <td className="text-zinc-500">{r.envelopeFrom ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
