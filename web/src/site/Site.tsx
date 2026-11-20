import { useMemo, useState } from "react";
import { ago, hhmmss, local, short } from "../api";
import { usePoll } from "../hooks";
import { Spark } from "../ui/charts";

const KEY: Record<string, string> = { host: "cpu.util_pct", service: "svc.resp_ms", link: "net.loss_pct" };
const useCodes = () => {
  const [codes] = usePoll<any[]>(() => local("/local/codes"), 10000);
  return useMemo(() => Object.fromEntries((codes ?? []).map((c) => [c.real, c.pseudo])), [codes]) as Record<string, string>;
};
const Stat = ({ label, value, tone }: { label: string; value: string | number; tone?: string }) => (
  <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 4 }}>
    <span className="t3" style={{ fontSize: 12 }}>{label}</span><span style={{ fontSize: 24, color: tone ?? "var(--hi)", letterSpacing: "-.5px" }}>{value}</span>
  </div>
);

export function Feed() {
  const [st] = usePoll<any>(() => local("/local/status"), 2000);
  const [cl] = usePoll<any>(() => local("/local/cloud"), 2000);
  const [win] = usePoll<any[]>(() => local("/local/windows?limit=300"), 2000);
  const [raw] = usePoll<any[]>(() => local("/api/side-by-side?reveal=true"), 2000);
  const codes = useCodes();
  const hosts = useMemo(() => {
    const by: Record<string, { kind: string; vals: number[] }> = {};
    [...(win ?? [])].reverse().forEach((w) => { if (w.metric !== KEY[w.entity_kind]) return; (by[w.entity] ??= { kind: w.entity_kind, vals: [] }).vals.push(w.avg); });
    return Object.entries(by).sort();
  }, [win]);
  const p = st?.pipeline ?? {};
  const latest = (win ?? [])[0];
  const lastRaw = (raw ?? [])[0];
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Local feed</span><span className="muted">{st?.environment} · everything on this page stays on this machine</span></div>
      <div className="grid4">
        <Stat label="Raw events read" value={p.raw_in ?? "—"} />
        <Stat label="5-second summaries made" value={p.windows_out ?? "—"} />
        <Stat label="Records sent to cloud" value={cl?.outbox?.total_sent_records ?? "—"} />
        <Stat label="Blocked at the boundary" value={(cl?.egress_blocked ?? 0) + (cl?.dropped_invalid ?? 0)} tone={(cl?.egress_blocked ?? 0) ? "var(--warn)" : undefined} />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
          <span className="h2">Stays here — raw event</span>
          <pre className="mono" style={{ margin: 0, fontSize: 11.5, whiteSpace: "pre-wrap", color: "var(--t3)", lineHeight: 1.6 }}>{lastRaw ? JSON.stringify(JSON.parse(lastRaw.raw_preview), null, 1) : "…"}</pre>
        </div>
        <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
          <span className="h2">Crosses to the cloud — 5 s summary, name replaced by a code</span>
          <pre className="mono" style={{ margin: 0, fontSize: 11.5, whiteSpace: "pre-wrap", color: "var(--hi)", lineHeight: 1.6 }}>{latest ? JSON.stringify({ entity: codes[latest.entity] ?? "(code pending)", kind: latest.entity_kind, metric: latest.metric, window_s: latest.window_s, avg: +latest.avg.toFixed(2), min: +latest.min.toFixed(2), max: +latest.max.toFixed(2), count: latest.count, event_ts: latest.event_ts }, null, 1) : "…"}</pre>
        </div>
      </div>
      <span className="h2">Hosts, services and links</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: "160px 80px 150px 140px minmax(0,1fr)" }}><span>real name</span><span>kind</span><span>code sent to cloud</span><span>key signal</span><span>last minute</span></div>
        {hosts.map(([name, h]) => (
          <div key={name} className="tr" style={{ gridTemplateColumns: "160px 80px 150px 140px minmax(0,1fr)" }}>
            <span style={{ color: "var(--hi)" }}>{name}</span><span className="t3">{h.kind}</span><span className="mono t3" style={{ fontSize: 12 }}>{codes[name] ?? "—"}</span>
            <span>{KEY[h.kind]} {h.vals.at(-1)?.toFixed(1)}</span><Spark values={h.vals.slice(-24)} w={220} />
          </div>
        ))}
      </div>
    </section>
  );
}

export function SiteBoundary() {
  const [p] = usePoll<any>(() => local("/api/egress-proof"), 3000);
  const [cl] = usePoll<any>(() => local("/local/cloud"), 3000);
  const g = "60px 90px 70px minmax(0,1fr) 80px 90px";
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Boundary</span><span className="muted">every payload that left this machine, signed and chained to the one before</span></div>
      <div className="grid4">
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Chain</div><div style={{ fontSize: 22 }} className={p?.chain_valid ? "ok" : "crit"}>{p ? (p.chain_valid ? "intact" : "broken") : "—"}</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Secrets scrubbed</div><div style={{ fontSize: 22 }}>{p?.redaction_summary?.secrets_scrubbed ?? "—"}</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Payloads blocked</div><div style={{ fontSize: 22 }} className={cl?.egress_blocked ? "warn" : ""}>{(cl?.egress_blocked ?? 0) + (p?.redaction_summary?.canaries_blocked ?? 0)}</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Policy</div><div className="mono" style={{ fontSize: 13, marginTop: 6 }}>v{p?.policy_version} · {String(p?.policy_hash ?? "").slice(7, 19)}</div></div>
      </div>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: g }}><span>seq</span><span>sent</span><span>records</span><span>payload hash · previous hash</span><span>receipt</span><span>status</span></div>
        {(p?.recent_envelopes ?? []).map((e: any) => (
          <div key={e.seq} className="tr" style={{ gridTemplateColumns: g }}>
            <span className="mono">#{e.seq}</span><span className="t3">{hhmmss(e.sent_at)}</span><span>{e.record_count}</span>
            <span className="mono muted" style={{ fontSize: 11.5 }}>{e.payload_hash.slice(7, 23)} ← {String(e.prev_hash).slice(7, 23)}</span>
            <span className={e.has_receipt ? "ok" : "muted"}>{e.has_receipt ? "signed" : "—"}</span><span className={e.status === "acked" ? "t3" : "warn"}>{e.status}{e.attempts > 1 ? ` · ${e.attempts} tries` : ""}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

export function CloudLink() {
  const [cl] = usePoll<any>(() => local("/local/cloud"), 1500);
  if (!cl) return <section className="page"><span className="muted">Loading…</span></section>;
  const o = cl.outbox ?? {}, held = (o.highest_seq ?? 0) - (o.last_acked_seq ?? 0);
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Cloud link</span>
        <span className={cl.online ? "ok" : "crit"}>{cl.online ? "online" : `offline since ${hhmmss(cl.outage_started_at)}`}</span>
        <span className="muted">{cl.collector_id} · tenant {cl.tenant_id}</span></div>
      {!cl.online && <div className="banner">The cloud cannot be reached. Data is being held here in order and will be sent when the link returns. Nothing is dropped.</div>}
      <div className="grid4">
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Payloads held</div><div style={{ fontSize: 26 }} className={held ? "warn" : ""}>{held}</div><div className="muted" style={{ fontSize: 11.5 }}>oldest {o.oldest_unsent_s?.toFixed?.(0) ?? 0} s</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Last confirmed by cloud</div><div style={{ fontSize: 26 }}>#{o.last_acked_seq}</div><div className="muted" style={{ fontSize: 11.5 }}>{ago(cl.last_ack_at)}</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Last reconcile</div><div style={{ fontSize: 14, marginTop: 6 }}>{cl.last_reconcile ? `#${cl.last_reconcile.from_seq}–${cl.last_reconcile.to_seq} · ${cl.last_reconcile.missing_sequences?.length ?? 0} missing · ${ago(cl.last_reconcile.at)}` : "none yet — runs after an outage"}</div></div>
        <div className="box" style={{ padding: "12px 14px" }}><div className="t3" style={{ fontSize: 12 }}>Network map</div><div style={{ fontSize: 26 }}>{cl.topology?.edges ?? 0}</div><div className="muted" style={{ fontSize: 11.5 }}>connections sent · v{cl.topology?.version_sent}</div></div>
      </div>
      {cl.last_error && <span className="muted mono" style={{ fontSize: 12 }}>last error: {cl.last_error}</span>}
      <span className="h2">Fixes received from the cloud</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {(cl.actions ?? []).map((a: any, k: number) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: "90px 220px 120px minmax(0,1fr)" }}>
            <span className="t3">{hhmmss(a.at)}</span><span className="mono" style={{ fontSize: 12 }}>{a.type}</span>
            <span className={a.decision === "allow" ? "ok" : "crit"}>local {a.decision === "allow" ? "allowed" : "vetoed"}</span>
            <span className="t3" style={{ fontSize: 12 }}>{a.status}{a.health_before ? ` · health ${a.health_before} → ${a.health_after}` : ""}{a.reason ? ` · ${a.reason}` : ""}{a.steps?.length ? ` · ${a.steps.map((x: any) => (typeof x === "string" ? x : x.step ?? x.name ?? JSON.stringify(x))).join(" → ")}` : ""}</span>
          </div>
        ))}
        {!(cl.actions ?? []).length && <div className="empty">No fixes received. A fix arrives only after two people approve it in the cloud, and this collector can still refuse it.</div>}
      </div>
    </section>
  );
}

export function Lookup() {
  const [q, setQ] = useState("");
  const [hit, setHit] = useState<any>(null);
  const [codes] = usePoll<any[]>(() => local("/local/codes"), 10000);
  const go = (c: string) => local(`/local/resolve/${encodeURIComponent(c.trim())}`).then(setHit).catch(() => setHit({ miss: c }));
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Look up a code</span><span className="muted">turn a code from the cloud dashboard back into a real name. Every lookup is logged.</span></div>
      <form onSubmit={(e) => { e.preventDefault(); go(q); }} style={{ display: "flex", gap: 8 }}>
        <input className="field mono" style={{ width: 320 }} placeholder="h_8a9af56384" value={q} onChange={(e) => setQ(e.target.value)} /><button className="btn primary">Look up</button>
      </form>
      {hit && (hit.miss ? <div className="banner">No code {hit.miss} was issued by this collector.</div> :
        <div className="box" style={{ padding: 16, display: "flex", gap: 16, alignItems: "baseline" }}><span className="mono t3">{hit.pseudo}</span><span>→</span><span style={{ fontSize: 22, color: "var(--hi)" }}>{hit.real}</span><span className="muted">{hit.kind}</span></div>)}
      <span className="h2">All codes issued here</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {(codes ?? []).map((c) => (
          <div key={c.pseudo} className="tr click" style={{ gridTemplateColumns: "200px 100px minmax(0,1fr)" }} onClick={() => { setQ(c.pseudo); go(c.pseudo); }}>
            <span className="mono" style={{ fontSize: 12 }}>{c.pseudo}</span><span className="t3">{c.kind}</span><span>{c.real}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

export function LocalAlerts() {
  const [s] = usePoll<any[]>(() => local("/local/signals?limit=200"), 2000);
  const codes = useCodes();
  const g = "90px 80px 200px 150px minmax(0,1fr)";
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Local alerts</span><span className="muted">raised on this machine within seconds; security alerts keep real user names and IPs here only</span></div>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: g }}><span>time</span><span>severity</span><span>rule</span><span>entity</span><span>details</span></div>
        {(s ?? []).map((x, k) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: g }}>
            <span className="t3">{hhmmss(x.event_ts)}</span><span className={x.severity === "critical" ? "crit" : "warn"}>{x.severity}</span><span>{x.rule}</span>
            <span><span style={{ color: "var(--hi)" }}>{x.entity}</span> <span className="mono muted" style={{ fontSize: 11 }}>{short(codes[x.entity], 10)}</span></span>
            <span className="t3" style={{ fontSize: 12 }}>{[...(x.subjects ?? []), ...(x.sources ?? [])].join(", ")} {Object.entries(x.params ?? {}).map(([k, v]) => `${k} ${v}`).join(" · ")}{x.risk_score ? ` · risk ${x.risk_score}` : ""}</span>
          </div>
        ))}
        {!(s ?? []).length && <div className="empty">No alerts. Use Simulate above to trigger one.</div>}
      </div>
    </section>
  );
}

export function SiteAudit() {
  const [a] = usePoll<any[]>(() => local("/local/audit?limit=200"), 3000);
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}><span className="h">Audit</span><span className="muted">code lookups, simulations, fixes and restarts on this collector</span></div>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {(a ?? []).map((e, k) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: "90px 110px 200px minmax(0,1fr)" }}><span className="t3">{hhmmss(e.ts)}</span><span className="mono" style={{ fontSize: 12 }}>{e.actor}</span><span>{e.action}</span><span className="muted mono" style={{ fontSize: 12 }}>{e.detail}</span></div>
        ))}
      </div>
    </section>
  );
}
