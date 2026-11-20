import { useState } from "react";
import { ApiError, ago, cloud, hhmmss, j } from "../api";
import { usePoll, useLiveTick } from "../hooks";

export function Collectors() {
  const tick = useLiveTick();
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 5000, [tick]);
  const [sel, setSel] = useState<string | null>(null);
  const cols: any[] = fleet?.collectors ?? [];
  const id = sel ?? cols[0]?.collector_id;
  const [det] = usePoll<any>(() => (id ? cloud(`/api/v1/collectors/${id}`) : Promise.resolve(null)), 5000, [id, tick]);
  const [tok, setTok] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const hb = j<any>(det?.last_heartbeat?.body, {});
  const stale = (ts?: string) => !ts || Date.now() - +new Date(ts) > 30e3;
  const g = "14px 200px 70px 90px 110px minmax(0,1fr)";
  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="h">Collectors</span><span className="muted">agents running inside customer sites; offline after 30 s without a heartbeat</span>
          <div style={{ flex: 1 }} />
          <button className="btn primary" onClick={() => { setErr(null); cloud("/api/v1/collectors/enrollment-tokens", { method: "POST" }).then(setTok).catch((e) => setErr(e instanceof ApiError && e.status === 403 ? "Only an approver or admin can add a collector. Switch account." : String(e.code ?? e))); }}>Add collector</button>
        </div>
        {tok && (
          <div className="box" style={{ padding: 14, display: "flex", flexDirection: "column", gap: 8 }}>
            <span className="h2">One-time enrollment token · expires {hhmmss(tok.expires_at)} UTC · region {String(tok.region).toUpperCase()}</span>
            <code className="mono" style={{ background: "#0B0D10", padding: "10px 12px", borderRadius: 6, fontSize: 12, wordBreak: "break-all", color: "var(--hi)" }}>VEILOPS_ENROLLMENT_TOKEN={tok.enrollment_token}</code>
            <span className="muted" style={{ fontSize: 12 }}>Set this on the customer machine with INGEST_URL pointing at this cloud and start the collector. The token works once; the cloud keeps only its hash.</span>
          </div>
        )}
        {err && <div className="banner">{err}</div>}
        <div className="tbl box" style={{ padding: "4px 14px" }}>
          <div className="tr th" style={{ gridTemplateColumns: g }}><span /><span>collector</span><span>region</span><span>entities</span><span>heartbeat</span><span>status</span></div>
          {cols.map((c) => { const off = stale(c.last_heartbeat); return (
            <div key={c.collector_id} className="tr click" style={{ gridTemplateColumns: g, background: c.collector_id === id ? "var(--hover)" : undefined }} onClick={() => setSel(c.collector_id)}>
              <span className="dot" style={{ background: off ? "var(--crit)" : "var(--ok)" }} /><span className="mono" style={{ fontSize: 12 }}>{c.collector_id}</span>
              <span>{String(c.region).toUpperCase()}</span><span>{c.entity_count}</span><span className={off ? "crit" : "t3"}>{ago(c.last_heartbeat)}</span><span className="t3">{off ? "offline — site is buffering" : c.status}</span>
            </div>); })}
          {!cols.length && <div className="empty">No collectors yet. Add one to start receiving data.</div>}
        </div>
      </section>
      <aside className="rail">
        <span className="h2">Last heartbeat</span>
        {det ? (
          <div className="tbl">
            {[["Version", hb.version], ["Uptime", hb.uptime_s != null ? `${hb.uptime_s} s` : null], ["CPU", hb.cpu_pct != null ? `${hb.cpu_pct}%` : null], ["Memory", hb.mem_mb != null ? `${hb.mem_mb} MB` : null],
              ["Outbox waiting", hb.outbox_depth], ["Enrolled", hhmmss(det.collector.enrolled_at)], ["Config", String(hb.config_hash ?? "").slice(0, 19)]].map(([k, v]) => (
              <div key={k} className="tr" style={{ gridTemplateColumns: "110px minmax(0,1fr)" }}><span className="t3">{k}</span><span className="mono" style={{ fontSize: 12 }}>{v ?? "—"}</span></div>
            ))}
            <span className="h2" style={{ marginTop: 12 }}>Sources</span>
            {Object.entries(hb.sources_ok ?? {}).map(([k, v]) => <div key={k} className="tr" style={{ gridTemplateColumns: "14px 1fr" }}><span className="dot" style={{ background: v ? "var(--ok)" : "var(--crit)" }} /><span>{k}</span></div>)}
          </div>
        ) : <span className="muted">Select a collector.</span>}
      </aside>
    </div>
  );
}

export function CloudAudit() {
  const tick = useLiveTick();
  const [d] = usePoll<any>(() => cloud("/api/v1/audit?limit=200"), 5000, [tick]);
  const [q, setQ] = useState("");
  const rows = (d?.events ?? []).filter((e: any) => !q || JSON.stringify(e).toLowerCase().includes(q.toLowerCase()));
  const g = "90px 140px 190px minmax(0,1fr)";
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Audit</span><span className="muted">every sign-in, approval, token and fix in this tenant</span><div style={{ flex: 1 }} /><input className="field" placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: g }}><span>time</span><span>actor</span><span>action</span><span>details</span></div>
        {rows.map((e: any, k: number) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: g }}><span className="t3">{hhmmss(e.at_utc)}</span><span className="mono" style={{ fontSize: 12 }}>{e.actor_id}</span><span>{e.action}</span>
            <span className="mono muted" style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.resource_type}:{e.resource_id} {typeof e.details === "string" ? e.details : JSON.stringify(e.details)}</span></div>
        ))}
        {!rows.length && <div className="empty">No events.</div>}
      </div>
    </section>
  );
}
