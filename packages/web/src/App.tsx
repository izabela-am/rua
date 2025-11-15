import type { Session } from "@supabase/supabase-js";
import { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { Button } from "./components/ui";
import { supabase } from "./lib/supabase";
import { Domain } from "./pages/Domain";
import { Domains } from "./pages/Domains";
import { Login } from "./pages/Login";

export function App() {
  const [session, setSession] = useState<Session | null | undefined>(undefined);

  useEffect(() => {
    void supabase.auth.getSession().then(({ data }) => setSession(data.session));
    const { data } = supabase.auth.onAuthStateChange((_event, s) => setSession(s));
    return () => data.subscription.unsubscribe();
  }, []);

  if (session === undefined) return null;
  if (!session) return <Login />;

  return (
    <div className="mx-auto max-w-5xl px-4 py-6">
      <header className="mb-6 flex items-center justify-between">
        <Link to="/" className="text-lg font-semibold">
          Rua
        </Link>
        <div className="flex items-center gap-3 text-sm text-zinc-600">
          <span>{session.user.email}</span>
          <Button variant="ghost" onClick={() => void supabase.auth.signOut()}>
            Sign out
          </Button>
        </div>
      </header>
      <Routes>
        <Route path="/" element={<Domains />} />
        <Route path="/domains/:id/*" element={<Domain />} />
      </Routes>
    </div>
  );
}
