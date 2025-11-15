import { useState, type FormEvent } from "react";
import { Button, Card, Input } from "../components/ui";
import { supabase } from "../lib/supabase";

export function Login() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [message, setMessage] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setState("sending");
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: { emailRedirectTo: window.location.origin },
    });
    if (error) {
      setState("error");
      setMessage(error.message);
    } else setState("sent");
  }

  return (
    <div className="mx-auto mt-24 max-w-sm">
      <h1 className="mb-1 text-2xl font-semibold">Rua</h1>
      <p className="mb-6 text-sm text-zinc-600">DMARC reports, sources and policy readiness for your domains.</p>
      <Card>
        {state === "sent" ? (
          <p className="text-sm">Check {email} for a sign-in link.</p>
        ) : (
          <form onSubmit={submit} className="space-y-3">
            <Input type="email" required placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            <Button type="submit" disabled={state === "sending"} className="w-full">
              Send magic link
            </Button>
            {state === "error" && <p className="text-sm text-red-600">{message}</p>}
          </form>
        )}
      </Card>
    </div>
  );
}
