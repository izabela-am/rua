import { useState, type FormEvent } from "react";
import { Button, Card, Copy, ErrorText, Input } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { useApi } from "../lib/useApi";

const VERIFY_SNIPPET = `import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyRua(secret, rawBody, header, now = Date.now()) {
  const p = Object.fromEntries(header.split(",").map((kv) => kv.split("=", 2)));
  const t = Number(p.t);
  if (!Number.isInteger(t) || !p.v1 || Math.abs(now / 1000 - t) > 300) return false;
  const want = createHmac("sha256", secret).update(\`\${t}.\${rawBody}\`).digest();
  const got = Buffer.from(p.v1, "hex");
  return got.length === want.length && timingSafeEqual(got, want);
}`;

export function Settings() {
  const { data, reload } = useApi<{ url: string | null }>("/settings/alert-webhook");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    try {
      const res = await api<{ secret: string }>("/settings/alert-webhook", { method: "POST", body: { url } });
      setSecret(res.secret);
      setUrl("");
      setError(null);
      await reload();
    } catch (err) {
      setError(err instanceof ApiError && err.body.reason ? String(err.body.reason) : (err as Error).message);
    }
  }

  async function remove() {
    await api("/settings/alert-webhook", { method: "DELETE" });
    setSecret(null);
    await reload();
  }

  return (
    <div className="space-y-4">
      <Card title="Alert webhook">
        <p className="mb-3 text-sm text-zinc-600">
          Rua emails every alert. It can also POST each alert as JSON to an HTTPS endpoint, signed in the{" "}
          <code>X-Rua-Signature</code> header.
        </p>
        {data?.url && (
          <div className="mb-3 flex items-center gap-2 text-sm">
            <span className="flex-1">
              Posting to <code>{data.url}</code>
            </span>
            <Button variant="ghost" onClick={() => void remove()}>
              Remove
            </Button>
          </div>
        )}
        <form onSubmit={save} className="flex gap-2">
          <Input placeholder="https://ops.example.com/hooks/rua" value={url} onChange={(e) => setUrl(e.target.value)} required />
          <Button type="submit">{data?.url ? "Replace" : "Save"}</Button>
        </form>
        {error && <ErrorText error={new Error(error)} />}
        {secret && (
          <div className="mt-3 rounded border border-amber-300 bg-amber-50 p-3">
            <p className="mb-2 text-sm font-medium">Signing secret. Rua will not show it again.</p>
            <Copy value={secret} />
          </div>
        )}
      </Card>
      <Card title="Verifying the signature">
        <pre className="overflow-x-auto rounded bg-zinc-100 p-3 text-xs">{VERIFY_SNIPPET}</pre>
      </Card>
    </div>
  );
}
