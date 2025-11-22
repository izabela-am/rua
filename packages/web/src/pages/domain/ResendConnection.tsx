import { useState, type FormEvent } from "react";
import { Button, Card, Copy, ErrorText, Input } from "../../components/ui";
import { api } from "../../lib/api";
import { useApi } from "../../lib/useApi";

type Connection = { id: string; endpoint: string; createdAt: string };

export function ResendConnection({ domainId }: { domainId: string }) {
  const { data, reload } = useApi<{ connections: Connection[] }>(`/domains/${domainId}/resend-connections`);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<Error | null>(null);

  async function connect(e: FormEvent) {
    e.preventDefault();
    try {
      await api(`/domains/${domainId}/resend-connections`, { method: "POST", body: { signingSecret: secret } });
      setSecret("");
      setError(null);
      await reload();
    } catch (err) {
      setError(err as Error);
    }
  }

  async function remove(id: string) {
    await api(`/domains/${domainId}/resend-connections/${id}`, { method: "DELETE" });
    await reload();
  }

  return (
    <Card title="3. Optional: bounce and complaint rates from Resend">
      <p className="mb-2 text-sm text-zinc-600">
        In Resend, create a webhook for <code>email.delivered</code>, <code>email.bounced</code> and{" "}
        <code>email.complained</code>, paste its signing secret here, and point the webhook at the endpoint Rua gives you.
      </p>
      {data?.connections.map((c) => (
        <div key={c.id} className="mb-2 flex items-center gap-2">
          <div className="flex-1">
            <Copy value={c.endpoint} />
          </div>
          <Button variant="ghost" onClick={() => void remove(c.id)}>
            Disconnect
          </Button>
        </div>
      ))}
      <form onSubmit={connect} className="flex gap-2">
        <Input placeholder="whsec_…" value={secret} onChange={(e) => setSecret(e.target.value)} required />
        <Button type="submit">Connect</Button>
      </form>
      <ErrorText error={error} />
    </Card>
  );
}
