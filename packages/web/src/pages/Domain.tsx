import { useState } from "react";
import { NavLink, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { Badge, Button, Card, Copy, ErrorText } from "../components/ui";
import { api, ApiError, type Domain as DomainT } from "../lib/api";
import { useApi } from "../lib/useApi";

export function Domain() {
  const { id } = useParams();
  const { data: domain, error, reload } = useApi<DomainT>(`/domains/${id}`);
  if (error) return <ErrorText error={error} />;
  if (!domain) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold">{domain.name}</h1>
        {domain.verified ? <Badge tone="green">verified</Badge> : <Badge tone="amber">unverified</Badge>}
      </div>
      {!domain.verified ? (
        <Setup domain={domain} onVerified={reload} />
      ) : (
        <>
          <Tabs id={domain.id} />
          <Routes>
            <Route index element={<Setup domain={domain} onVerified={reload} />} />
          </Routes>
        </>
      )}
    </div>
  );
}

function Tabs({ id }: { id: string }) {
  const tabs = [{ to: "", label: "Setup" }];
  return (
    <nav className="flex gap-1 border-b border-zinc-200">
      {tabs.map((t) => (
        <NavLink
          key={t.to}
          end
          to={`/domains/${id}/${t.to}`}
          className={({ isActive }) =>
            `-mb-px border-b-2 px-3 py-2 text-sm ${isActive ? "border-zinc-900 font-medium" : "border-transparent text-zinc-500"}`
          }
        >
          {t.label}
        </NavLink>
      ))}
    </nav>
  );
}

function Setup({ domain, onVerified }: { domain: DomainT; onVerified: () => void }) {
  const [checking, setChecking] = useState(false);
  const [observed, setObserved] = useState<string[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const navigate = useNavigate();

  async function verify() {
    setChecking(true);
    try {
      await api(`/domains/${domain.id}/verify`, { method: "POST" });
      setObserved(null);
      onVerified();
    } catch (e) {
      if (e instanceof ApiError && e.body.error === "txt_not_found") setObserved(e.body.observed as string[]);
      else setError(e as Error);
    } finally {
      setChecking(false);
    }
  }

  async function remove() {
    if (!confirm(`Remove ${domain.name} and all its data?`)) return;
    await api(`/domains/${domain.id}`, { method: "DELETE" });
    navigate("/");
  }

  return (
    <div className="space-y-4">
      <Card title="1. Prove you own the domain">
        <p className="mb-2 text-sm text-zinc-600">Publish this TXT record. Rua shows no data until it resolves.</p>
        <div className="space-y-2">
          <Copy value={domain.txt.host} />
          <Copy value={domain.txt.value} />
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button onClick={verify} disabled={checking}>
            {domain.verified ? "Check again" : "Verify"}
          </Button>
          {observed && (
            <span className="text-sm text-amber-700">
              Not found. {observed.length ? `Saw: ${observed.join(", ")}` : "No TXT records at that name yet."}
            </span>
          )}
        </div>
        <ErrorText error={error} />
      </Card>
      <Card title="2. Send DMARC reports to Rua">
        <p className="mb-2 text-sm text-zinc-600">
          Add this address to the <code>rua=</code> tag of <code>_dmarc.{domain.name}</code>. Reports arrive within 48 hours.
        </p>
        <Copy value={`v=DMARC1; p=none; rua=mailto:${domain.rua}`} />
      </Card>
      <div className="text-right">
        <Button variant="danger" onClick={remove}>
          Remove domain
        </Button>
      </div>
    </div>
  );
}
