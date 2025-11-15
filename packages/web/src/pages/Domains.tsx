import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Card, ErrorText, Input } from "../components/ui";
import { api, type Domain } from "../lib/api";
import { useApi } from "../lib/useApi";

export function Domains() {
  const { data, error, reload } = useApi<{ domains: Domain[] }>("/domains");
  const [name, setName] = useState("");
  const [addError, setAddError] = useState<Error | null>(null);

  async function add(e: FormEvent) {
    e.preventDefault();
    try {
      await api("/domains", { method: "POST", body: { name } });
      setName("");
      setAddError(null);
      await reload();
    } catch (err) {
      setAddError(err as Error);
    }
  }

  return (
    <div className="space-y-4">
      <Card title="Add a domain">
        <form onSubmit={add} className="flex gap-2">
          <Input placeholder="example.com" value={name} onChange={(e) => setName(e.target.value)} required />
          <Button type="submit">Add</Button>
        </form>
        <ErrorText error={addError} />
      </Card>
      <Card title="Domains">
        <ErrorText error={error} />
        {data?.domains.length === 0 && <p className="text-sm text-zinc-500">No domains yet.</p>}
        <ul className="divide-y divide-zinc-100">
          {data?.domains.map((d) => (
            <li key={d.id} className="flex items-center justify-between py-2">
              <Link to={`/domains/${d.id}`} className="font-medium hover:underline">
                {d.name}
              </Link>
              {d.verified ? <Badge tone="green">verified</Badge> : <Badge tone="amber">unverified</Badge>}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
