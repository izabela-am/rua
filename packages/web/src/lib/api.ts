import { supabase } from "./supabase";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: { error?: string; [k: string]: unknown },
  ) {
    super(body.error ?? `HTTP ${status}`);
  }
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const { data } = await supabase.auth.getSession();
  const res = await fetch(`/api${path}`, {
    method: init.method ?? "GET",
    headers: {
      "content-type": "application/json",
      ...(data.session ? { authorization: `Bearer ${data.session.access_token}` } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body);
  return body as T;
}

export type Domain = {
  id: string;
  name: string;
  verified: boolean;
  verifiedAt: string | null;
  txt: { host: string; value: string };
  rua: string;
  createdAt: string;
};
