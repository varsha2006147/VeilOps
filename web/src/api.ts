// Cloud API (JWT; tenant comes only from the token) and the collector's local API (customer side).
export const CLOUD = import.meta.env.VITE_CLOUD_URL ?? "http://localhost:8000";
export const COLLECTOR = import.meta.env.VITE_COLLECTOR_URL ?? "http://localhost:8100";
export const APP = (import.meta.env.VITE_APP ?? (import.meta.env.MODE === "site" ? "site" : "cloud")) as "cloud" | "site";
const DEMO_PASSWORD = import.meta.env.VITE_DEMO_PASSWORD ?? "veilops-demo-1";

export type User = { id: string; name: string; tenant_id: string; role: string };
export const DEMO_USERS = [
  { email: "operator@acme.test", label: "Asha · Acme operator" },
  { email: "approver@acme.test", label: "Ravi · Acme approver" },
  { email: "operator@globex.test", label: "Mia · Globex operator" },
];
const KEY = "veilops.session";

export function session(): { token: string; user: User; email: string } | null {
  try { return JSON.parse(sessionStorage.getItem(KEY) ?? "null"); } catch { return null; }
}

/** No sign-in page: the dashboard signs in as a demo account (server still checks password, role, tenant). */
export async function signInAs(email: string): Promise<User> {
  const r = await fetch(`${CLOUD}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: DEMO_PASSWORD }) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body?.detail?.code ?? `HTTP ${r.status}`);
  sessionStorage.setItem(KEY, JSON.stringify({ token: body.token, user: body.user, email }));
  return body.user;
}
export async function ensureSession() { if (!session()) await signInAs(DEMO_USERS[0].email); }

export class ApiError extends Error { constructor(public status: number, public code: string) { super(code); } }

export async function cloud<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const go = () => fetch(`${CLOUD}${path}`, { ...init, headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), Authorization: `Bearer ${session()?.token}`, ...init.headers } });
  let r = await go();
  if (r.status === 401 && session()) { await signInAs(session()!.email); r = await go(); }
  if (!r.ok) { const b = await r.json().catch(() => ({})); throw new ApiError(r.status, b?.detail?.code ?? `HTTP ${r.status}`); }
  return r.headers.get("content-type")?.includes("json") ? r.json() : (r.text() as any);
}

export async function local<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(`${COLLECTOR}${path}`, init);
  if (!r.ok) throw new ApiError(r.status, `HTTP ${r.status}`);
  return r.json();
}

/** Server-sent events over fetch (EventSource cannot send the Authorization header). */
export function subscribe(onEvent: (event: string, data: any) => void, onState?: (live: boolean) => void): () => void {
  const ctrl = new AbortController();
  (async () => {
    while (!ctrl.signal.aborted) {
      try {
        const r = await fetch(`${CLOUD}/api/v1/events`, { headers: { Authorization: `Bearer ${session()?.token}` }, signal: ctrl.signal });
        if (!r.ok || !r.body) throw new Error("sse");
        onState?.(true);
        const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "", ev = "message";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let i;
          while ((i = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, i).trimEnd(); buf = buf.slice(i + 1);
            if (line.startsWith("event:")) ev = line.slice(6).trim();
            else if (line.startsWith("data:")) { try { onEvent(ev, JSON.parse(line.slice(5))); } catch { /* ignore */ } }
            else if (line === "") ev = "message";
          }
        }
      } catch { /* reconnect */ }
      onState?.(false);
      await new Promise((res) => setTimeout(res, 2000));
    }
  })();
  return () => ctrl.abort();
}

/** Tell Judge Mode when telemetry reached the screen (real collection -> dashboard latency). */
export function renderAck(payloadId: string) {
  const now = new Date().toISOString();
  cloud("/api/v1/slo/render-ack", { method: "POST", body: JSON.stringify({ record_key: `payload:${payloadId}`, rendered_at: now, client_sent_at: now }) }).catch(() => {});
}

export const hhmmss = (iso?: string | null) => (iso ? new Date(iso).toISOString().slice(11, 19) : "—");
export const short = (id?: string | null, n = 12) => (id ? (id.length > n + 2 ? id.slice(0, n) + "…" : id) : "—");
export const ago = (iso?: string | null) => {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - +new Date(iso)) / 1000);
  return s < 60 ? `${Math.round(s)} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};
export const HEALTH: Record<string, string> = { Excellent: "var(--ok)", Good: "var(--ok)", Fair: "var(--warn)", Poor: "var(--crit)" };
/** Several API fields are JSON stored as text (reasons, context, details, heartbeat body). */
export function j<T = any>(v: unknown, fallback: T): T {
  if (v == null) return fallback;
  if (typeof v !== "string") return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
}
export const csv = (rows: (string | number | null | undefined)[][]) =>
  URL.createObjectURL(new Blob([rows.map((r) => r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\n")], { type: "text/csv" }));
