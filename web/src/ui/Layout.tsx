import { ReactNode, useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { APP, DEMO_USERS, cloud, local, session, signInAs } from "../api";
import { usePoll, useRange } from "../hooks";

export function CloudLayout({ crumb, live, children }: { crumb: string; live: boolean; children: ReactNode }) {
  const nav = useNavigate();
  const s = session();
  const { minutes, set } = useRange();
  const [inc] = usePoll<any>(() => cloud("/api/v1/incidents?status=open&limit=50"), 5000);
  const [q, setQ] = useState("");
  const open = inc?.incidents?.length ?? 0;
  async function switchTo(email: string) { await signInAs(email); location.reload(); }
  return (
    <div className="app">
      <aside className="nav" aria-label="Main">
        <div className="brand">VeilOps</div>
        <div className="brand-sub">cloud · metadata only</div>
        <NavLink to="/" end>Explorer</NavLink>
        <NavLink to="/incidents">Incidents<span className="count" style={{ color: open ? "var(--crit)" : "var(--muted)" }}>{open}</span></NavLink>
        <NavLink to="/boundary">Boundary &amp; proof</NavLink>
        <NavLink to="/reliability">Reliability (SLOs)</NavLink>
        <NavLink to="/collectors">Collectors</NavLink>
        <NavLink to="/audit">Audit</NavLink>
        <div style={{ marginTop: "auto", borderTop: "1px solid var(--line)", padding: "12px 4px 4px", display: "flex", flexDirection: "column", gap: 6 }}>
          <span style={{ color: "var(--hi)", padding: "0 6px" }}>{s?.user.name}</span>
          <span className="muted" style={{ fontSize: 11.5, padding: "0 6px" }}>{s?.user.role} · {s?.user.tenant_id}</span>
          <select aria-label="Switch demo account" value={s?.email} onChange={(e) => switchTo(e.target.value)}
            style={{ background: "#14171B", border: "1px solid var(--line2)", borderRadius: 6, padding: "5px 6px", color: "var(--t2)" }}>
            {DEMO_USERS.map((u) => <option key={u.email} value={u.email}>{u.label}</option>)}
          </select>
        </div>
      </aside>
      <header className="top">
        <span className="muted">{s?.user.tenant_id}</span><span style={{ color: "var(--line3)" }}>/</span><span>{crumb}</span>
        <span className="chip">Region IN</span>
        <form onSubmit={(e) => { e.preventDefault(); if (q.trim()) nav(`/entities/${q.trim()}`); }} style={{ display: "contents" }}>
          <input className="search" placeholder="Go to entity code (e.g. h_7f3a21c90b)" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Go to entity" />
        </form>
        <div style={{ flex: 1 }} />
        <div className="seg" role="group" aria-label="Time range">
          {[15, 30, 60].map((m) => <button key={m} className={minutes === m ? "on" : ""} onClick={() => set(m)}>{m} min</button>)}
        </div>
        <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: live ? "var(--t3)" : "var(--warn)" }}>
          <span className="dot" style={{ background: live ? "var(--ok)" : "var(--warn)" }} />{live ? "Live" : "Reconnecting"}
        </span>
      </header>
      <main style={{ minWidth: 0 }}>{children}</main>
    </div>
  );
}

const SIMS: [string, string, string][] = [
  ["cpu_drift", "CPU runaway", "CPU on one host climbs for ~75 s. Watch Local alerts on the right, then an incident on the cloud dashboard within ~30 s."],
  ["latency", "Link failure", "The core network link starts dropping packets. The cloud should name the link as root cause and suggest a failover."],
  ["secret", "Secret in log", "A log line with a password is injected. Watch “secrets scrubbed” go up; the secret never leaves this machine."],
  ["failed_logins", "Brute force", "Repeated failed logins from one IP. A security alert appears here with the real user and IP; the cloud only gets codes."],
];

export function SiteLayout({ crumb, children }: { crumb: string; children: ReactNode }) {
  const [status] = usePoll<any>(() => local("/local/status"), 5000);
  const [link] = usePoll<any>(() => local("/local/cloud"), 2000);
  const [fired, setFired] = useState<string | null>(null);
  useEffect(() => { if (APP !== "site") return; document.title = "VeilOps Collector"; }, []);
  const [note, setNote] = useState<string | null>(null);
  async function fire(s: string) {
    setFired(s);
    const ok = await local(`/local/chaos/${s}`, { method: "POST" }).then(() => true).catch(() => false);
    setNote(ok ? SIMS.find((x) => x[0] === s)![2] : "Simulation is not available on this collector (DEMO_MODE off).");
    setTimeout(() => setFired(null), 1500); setTimeout(() => setNote(null), 9000);
  }
  const online = link?.online !== false;
  return (
    <div className="app">
      <aside className="nav" aria-label="Main">
        <div className="brand">VeilOps Collector</div>
        <div className="brand-sub">runs inside {status?.tenant_id ?? "the customer"} · {status?.collector_id ?? "…"}</div>
        <NavLink to="/" end>Overview</NavLink>
        <NavLink to="/boundary">Boundary & cloud</NavLink>
        <NavLink to="/codes">Codes & audit</NavLink>
        <div style={{ marginTop: "auto", border: "1px solid var(--line2)", borderRadius: 6, padding: 10, fontSize: 11.5, color: "var(--t3)", lineHeight: 1.55 }}>
          This screen is on the customer's network. Real names and raw logs are shown here only; viewing them is logged.
        </div>
      </aside>
      <header className="top">
        <span className="muted">{status?.tenant_id}</span><span style={{ color: "var(--line3)" }}>/</span><span>{crumb}</span>
        <span className="chip local">LOCAL · real names</span>
        <div style={{ flex: 1 }} />
        <span className="muted" style={{ fontSize: 12 }}>Simulate</span>
        {SIMS.map(([k, l, d]) => <button key={k} title={d} className={`btn ${fired === k ? "on" : ""}`} onClick={() => fire(k)}>{l}</button>)}
        <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: online ? "var(--t3)" : "var(--warn)", marginLeft: 8 }}>
          <span className="dot" style={{ background: online ? "var(--ok)" : "var(--warn)" }} />
          {online ? `Connected to VeilOps cloud (${status?.region?.toUpperCase() ?? "IN"})` : `Cloud unreachable · ${link?.outbox?.outbox_depth ?? 0} payloads held`}
        </span>
      </header>
      <main style={{ minWidth: 0 }}>{children}</main>
      {note && <div className="toast fade" role="status"><b style={{ color: "var(--hi)", fontWeight: 500 }}>Simulation started.</b> {note}</div>}
      {note && <div className="toast fade" role="status"><b style={{ color: "var(--hi)", fontWeight: 500 }}>Simulation started.</b> {note}</div>}
    </div>
  );
}
