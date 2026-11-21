import { useMemo, useRef, useState } from "react";
import { ago, hhmmss, local } from "../api";
import { usePoll } from "../hooks";
import { Spark } from "../ui/charts";

const KEY: Record<string, string> = { host: "cpu.util_pct", service: "svc.resp_ms", link: "net.loss_pct" };
const useCodes = () => {
  const [codes] = usePoll<any[]>(() => local("/local/codes"), 10000);
  return useMemo(() => Object.fromEntries((codes ?? []).map((c) => [c.real, c.pseudo])), [codes]) as Record<string, string>;
};
/** Change per 5 s of a growing counter, measured in the browser. */
function useRate(v: number | undefined) {
  const hist = useRef<[number, number][]>([]);
  if (v != null) { const now = Date.now(); hist.current = [...hist.current.filter(([t]) => now - t < 5000), [now, v]]; }
  const h = hist.current;
  return h.length > 1 ? Math.max(0, h.at(-1)![1] - h[0][1]) : 0;
}
const n = (v: any) => (v == null ? "—" : Number(v).toLocaleString("en-IN"));

/* ---------------- Overview ---------------- */
export function Overview() {
  const [st] = usePoll<any>(() => local("/local/status"), 1000);
  const [cl] = usePoll<any>(() => local("/local/cloud"), 1000);
  const [eg] = usePoll<any>(() => local("/api/egress-proof"), 2000);
  const [win] = usePoll<any[]>(() => local("/local/windows?limit=300"), 2000);
  const [raw] = usePoll<any[]>(() => local("/api/side-by-side?reveal=true"), 2000);
  const [sig] = usePoll<any[]>(() => local("/local/signals?limit=50"), 1500);
  const codes = useCodes();
  const p = st?.pipeline ?? {}, o = cl?.outbox ?? {}, red = eg?.redaction_summary ?? {};
  const online = cl?.online !== false;
  const held = (o.highest_seq ?? 0) - (o.last_acked_seq ?? 0);
  const rIn = useRate(p.raw_in), rWin = useRate(p.windows_out), rSent = useRate(o.total_sent_records), rAck = useRate(o.last_acked_seq);
  const hosts = useMemo(() => {
    const by: Record<string, { kind: string; vals: number[] }> = {};
    [...(win ?? [])].reverse().forEach((w) => { if (w.metric !== KEY[w.entity_kind]) return; (by[w.entity] ??= { kind: w.entity_kind, vals: [] }).vals.push(w.avg); });
    return Object.entries(by).sort();
  }, [win]);
  const latest = (win ?? [])[0], lastRaw = (raw ?? [])[0];
  // every metric per host, oldest -> newest, for the live machine panel
  const machines = useMemo(() => {
    const by: Record<string, Record<string, number[]>> = {};
    [...(win ?? [])].reverse().forEach((w) => {
      if (w.entity_kind !== "host") return;
      ((by[w.entity] ??= {})[w.metric] ??= []).push(w.avg);
    });
    return Object.entries(by).sort();
  }, [win]);
  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}><span className="h">What this collector is doing</span><span className="muted">{st?.environment} · live, refreshed every second</span></div>
        <div className="zone"><span>On this machine — real names, raw logs</span><span>Leaves the site</span></div>
        <div className="pipe">
          <div className="stage"><span className="r">{rIn ? `+${rIn} in 5 s` : ""}</span><span className="n">{n(p.raw_in)}</span><span className="l">Read</span><span className="s">events from host metrics, probes, syslog and the stream</span></div>
          <div className="flow">{rIn > 0 && <><i /><i /></>}</div>
          <div className="stage"><span className="r">{rWin ? `+${rWin} in 5 s` : ""}</span><span className="n">{n(p.windows_out)}</span><span className="l">Summarise & detect</span><span className="s">5-second summaries · <b style={{ color: p.signals_out ? "var(--warn)" : "inherit", fontWeight: 400 }}>{n(p.signals_out)} local alerts</b></span></div>
          <div className="flow">{rWin > 0 && <><i /><i /></>}</div>
          <div className="stage"><span className="n">{n(Object.keys(codes).length)}</span><span className="l">Hide names & secrets</span><span className="s">names swapped for codes · {n(red.secrets_scrubbed)} secrets scrubbed · {n((cl?.egress_blocked ?? 0) + (cl?.dropped_invalid ?? 0))} blocked</span></div>
          <div className="flow">{rSent > 0 && <><i /><i /></>}</div>
          <div className="stage" style={{ borderColor: held ? "#5A4A1E" : undefined }}><span className="n">#{n(o.highest_seq)}</span><span className="l">Sign & queue</span><span className="s">hash-chained, signed · <span style={{ color: held ? "var(--warn)" : "inherit" }}>{held} waiting</span> · chain {eg?.chain_valid ? "intact" : "—"}</span></div>
          <div className="wall"><b /><span>network boundary</span><b /></div>
          <div className="stage" style={{ borderColor: online ? undefined : "#5A3034" }}><span className="r">{rAck ? `+${rAck} in 5 s` : ""}</span><span className="n" style={{ color: online ? "var(--hi)" : "var(--crit)" }}>{online ? `#${n(o.last_acked_seq)}` : "offline"}</span><span className="l">Cloud confirmed</span><span className="s">{online ? `signed receipt ${ago(cl?.last_ack_at)}` : `holding ${held} payloads since ${hhmmss(cl?.outage_started_at)} — nothing is lost`}</span></div>
        </div>
        {cl?.last_error && !cl?.enrolled && <div className="toast" style={{ position: "static", maxWidth: "none" }}>{cl.last_error}</div>}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
            <span className="h2">Stays here · a raw event</span>
            <pre className="mono" style={{ margin: 0, fontSize: 11.5, whiteSpace: "pre-wrap", color: "var(--t3)", lineHeight: 1.6 }}>{lastRaw ? JSON.stringify(JSON.parse(lastRaw.raw_preview), null, 1) : "…"}</pre>
          </div>
          <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8, borderColor: "#2E3A33" }}>
            <span className="h2">Crosses · 5-second summary, name replaced by code</span>
            <pre className="mono" style={{ margin: 0, fontSize: 11.5, whiteSpace: "pre-wrap", color: "var(--hi)", lineHeight: 1.6 }}>{latest ? JSON.stringify({ entity: codes[latest.entity] ?? "(code pending)", kind: latest.entity_kind, metric: latest.metric, window_s: latest.window_s, avg: +latest.avg.toFixed(2), max: +latest.max.toFixed(2), count: latest.count, event_ts: latest.event_ts }, null, 1) : "…"}</pre>
          </div>
        </div>
        {machines.map(([name, m]) => (
          <div key={name} className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
              <span className="h2">Live machine · {name}</span>
              <span className="muted" style={{ fontSize: 12 }}>cloud sees it as <span className="mono">{codes[name] ?? "—"}</span> · 5-second averages</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0,1fr))", gap: 12 }}>
              {([["cpu.util_pct", "CPU", "%"], ["mem.util_pct", "Memory", "%"], ["disk.util_pct", "Disk", "%"], ["net.bw_in_mbps", "Network in", " Mbps"]] as const).map(([k, label, unit]) => {
                const v = m[k] ?? [];
                const now = v.at(-1);
                return (
                  <div key={k} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <span className="t3" style={{ fontSize: 12 }}>{label}</span>
                    <span style={{ fontSize: 24, color: "var(--hi)", letterSpacing: "-.5px" }}>{now == null ? "—" : `${now.toFixed(k === "net.bw_in_mbps" ? 2 : 1)}${unit}`}</span>
                    <Spark values={v.slice(-24)} w={180} />
                  </div>
                );
              })}
            </div>
          </div>
        ))}
        <span className="h2">Systems on this site</span>
        <div className="tbl box" style={{ padding: "4px 14px" }}>
          <div className="tr th" style={{ gridTemplateColumns: "150px 80px 150px 150px minmax(0,1fr)" }}><span>real name</span><span>kind</span><span>code the cloud sees</span><span>now</span><span>last 2 minutes</span></div>
          {hosts.map(([name, h]) => (
            <div key={name} className="tr" style={{ gridTemplateColumns: "150px 80px 150px 150px minmax(0,1fr)" }}>
              <span style={{ color: "var(--hi)" }}>{name}</span><span className="t3">{h.kind}</span><span className="mono t3" style={{ fontSize: 12 }}>{codes[name] ?? "—"}</span>
              <span>{KEY[h.kind].split(".")[1].replace("_pct", " %").replace("_ms", " ms").replace("util", "cpu").replace("resp", "response").replace("loss", "loss")} {h.vals.at(-1)?.toFixed(1)}</span><Spark values={h.vals.slice(-24)} w={220} />
            </div>
          ))}
        </div>
      </section>
      <aside className="rail">
        <div style={{ display: "flex", justifyContent: "space-between" }}><span className="h2">Local alerts</span><span className="muted" style={{ fontSize: 12 }}>raised here in seconds</span></div>
        {(sig ?? []).slice(0, 10).map((x, k) => (
          <div key={k} className="fade" style={{ borderLeft: `3px solid ${x.severity === "critical" ? "var(--crit)" : "var(--warn)"}`, background: "#121418", borderRadius: 6, padding: "9px 12px", display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontSize: 11.5 }} className="muted">{hhmmss(x.event_ts)} · {x.kind} · <span className={x.severity === "critical" ? "crit" : "warn"}>{x.severity}</span></span>
            <span style={{ color: "var(--hi)" }}>{x.rule} on {x.entity}</span>
            {(x.subjects?.length || x.sources?.length) ? <span className="t3" style={{ fontSize: 12 }}>{[...(x.subjects ?? []), ...(x.sources ?? [])].join(", ")} <span className="muted">· real values, never sent</span></span> : null}
            {Object.keys(x.params ?? {}).length ? <span className="muted mono" style={{ fontSize: 11 }}>{Object.entries(x.params).map(([k, v]) => `${k}=${typeof v === "number" ? +v.toFixed(2) : v}`).join(" ")}</span> : null}
          </div>
        ))}
        {!(sig ?? []).length && <div className="empty">All quiet. Use <b>Simulate</b> at the top to cause a problem and watch it travel through the stages.</div>}
      </aside>
    </div>
  );
}

/* ---------------- Boundary & cloud ---------------- */
export function BoundaryCloud() {
  const [p] = usePoll<any>(() => local("/api/egress-proof"), 2000);
  const [cl] = usePoll<any>(() => local("/local/cloud"), 1500);
  const o = cl?.outbox ?? {}, held = (o.highest_seq ?? 0) - (o.last_acked_seq ?? 0), online = cl?.online !== false;
  const g = "60px 80px 60px minmax(0,1fr) 70px 90px";
  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}><span className="h">Everything that left this site</span><span className="muted">each payload is signed and points to the one before it, so nothing can be removed or inserted unnoticed</span></div>
        <div className="kpi">
          <div><span className="n" style={{ color: online ? "var(--ok)" : "var(--crit)" }}>{online ? "online" : "offline"}</span><span className="l">cloud link · {ago(cl?.last_ack_at)}</span></div>
          <div><span className="n" style={{ color: held ? "var(--warn)" : undefined }}>{held}</span><span className="l">payloads waiting to send</span></div>
          <div><span className="n" style={{ color: p?.chain_valid ? undefined : "var(--crit)" }}>{p ? (p.chain_valid ? "intact" : "broken") : "—"}</span><span className="l">signature chain</span></div>
          <div><span className="n">{n(p?.redaction_summary?.secrets_scrubbed)}</span><span className="l">secrets scrubbed</span></div>
          <div><span className="n" style={{ color: cl?.egress_blocked ? "var(--warn)" : undefined }}>{n((cl?.egress_blocked ?? 0) + (p?.redaction_summary?.canaries_blocked ?? 0))}</span><span className="l">payloads blocked</span></div>
        </div>
        {!online && <div className="toast" style={{ position: "static", maxWidth: "none" }}>The cloud can't be reached{cl?.last_error ? ` (${cl.last_error})` : ""}. Payloads are kept here in order and sent when the link returns; the cloud then checks that none are missing.</div>}
        {cl?.last_reconcile && <div className="box" style={{ padding: "10px 14px" }}>Last check after an outage: payloads #{cl.last_reconcile.from_seq}–#{cl.last_reconcile.to_seq} · <span className={cl.last_reconcile.missing_sequences?.length ? "crit" : "ok"}>{cl.last_reconcile.missing_sequences?.length ?? 0} missing</span> · {ago(cl.last_reconcile.at)}</div>}
        <div className="tbl box" style={{ padding: "4px 14px" }}>
          <div className="tr th" style={{ gridTemplateColumns: g }}><span>payload</span><span>sent</span><span>records</span><span>fingerprint ← previous fingerprint</span><span>receipt</span><span>status</span></div>
          {(p?.recent_envelopes ?? []).map((e: any) => (
            <div key={e.seq} className="tr" style={{ gridTemplateColumns: g }}>
              <span className="mono">#{e.seq}</span><span className="t3">{hhmmss(e.sent_at)}</span><span>{e.record_count}</span>
              <span className="mono muted" style={{ fontSize: 11.5 }}>{e.payload_hash.slice(7, 19)} ← {String(e.prev_hash).slice(7, 19)}</span>
              <span className={e.has_receipt ? "ok" : "muted"}>{e.has_receipt ? "signed" : "—"}</span><span className={e.status === "acked" ? "t3" : "warn"}>{e.status === "acked" ? "confirmed" : e.status}{e.attempts > 1 ? ` · ${e.attempts} tries` : ""}</span>
            </div>
          ))}
        </div>
        <span className="muted" style={{ fontSize: 11.5 }}>Policy v{p?.policy_version} · {String(p?.policy_hash ?? "").slice(7, 23)} · only fields on the allow-list can leave.</span>
      </section>
      <aside className="rail">
        <span className="h2">Fixes sent by the cloud</span>
        <span className="muted" style={{ fontSize: 12, lineHeight: 1.55 }}>A fix arrives only after two people approve it in the cloud. This collector checks it against local rules and can still refuse.</span>
        {(cl?.actions ?? []).map((a: any, k: number) => (
          <div key={k} style={{ border: "1px solid var(--line2)", borderRadius: 8, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
            <span className="mono" style={{ color: "var(--hi)", fontSize: 12 }}>{a.type}</span>
            <span style={{ fontSize: 12 }}><span className={a.decision === "allow" ? "ok" : "crit"}>{a.decision === "allow" ? "allowed locally" : "refused locally"}</span> <span className="muted">· {a.status} · {ago(a.at)}</span></span>
            {(a.steps ?? []).map((s: any, i: number) => <span key={i} className="t3" style={{ fontSize: 12 }}>{i + 1}. {s.step}{s.health ? ` — health ${s.health}` : ""}{s.plan ? ` — ${s.plan}` : ""}</span>)}
          </div>
        ))}
        {!(cl?.actions ?? []).length && <div className="empty">No fixes received yet.</div>}
      </aside>
    </div>
  );
}

/* ---------------- Codes & audit ---------------- */
export function CodesAudit() {
  const [tab, setTab] = useState<"codes" | "audit">("codes");
  const [q, setQ] = useState("");
  const [hit, setHit] = useState<any>(null);
  const [codes] = usePoll<any[]>(() => local("/local/codes"), 10000);
  const [a] = usePoll<any[]>(() => local("/local/audit?limit=200"), 3000);
  const go = (c: string) => local(`/local/resolve/${encodeURIComponent(c.trim())}`).then(setHit).catch(() => setHit({ miss: c }));
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}><span className="h">Codes</span><span className="muted">the cloud only knows codes; this is the only place they turn back into names</span></div>
      <form onSubmit={(e) => { e.preventDefault(); go(q); }} style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input className="field mono" style={{ width: 340 }} placeholder="Paste a code from the cloud dashboard, e.g. h_8a9af56384" value={q} onChange={(e) => setQ(e.target.value)} /><button className="btn primary">Look up</button>
        <span className="muted" style={{ fontSize: 12 }}>Every lookup is recorded in the audit log.</span>
      </form>
      {hit && (hit.miss ? <div className="empty">No code “{hit.miss}” was issued by this collector.</div> :
        <div className="box fade" style={{ padding: "16px 18px", display: "flex", gap: 18, alignItems: "baseline" }}><span className="mono t3">{hit.pseudo}</span><span className="muted">is</span><span style={{ fontSize: 24, color: "var(--hi)" }}>{hit.real}</span><span className="muted">{hit.kind}</span></div>)}
      <div className="tabs"><button className={tab === "codes" ? "on" : ""} onClick={() => setTab("codes")}>All codes ({codes?.length ?? 0})</button><button className={tab === "audit" ? "on" : ""} onClick={() => setTab("audit")}>Audit log ({a?.length ?? 0})</button></div>
      {tab === "codes" ? (
        <div className="tbl">
          {(codes ?? []).map((c) => (
            <div key={c.pseudo} className="tr click" style={{ gridTemplateColumns: "200px 90px minmax(0,1fr)" }} onClick={() => { setQ(c.pseudo); go(c.pseudo); }}>
              <span className="mono" style={{ fontSize: 12 }}>{c.pseudo}</span><span className="t3">{c.kind}</span><span>{c.real}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="tbl">
          {(a ?? []).map((e, k) => (
            <div key={k} className="tr" style={{ gridTemplateColumns: "90px 110px 200px minmax(0,1fr)" }}><span className="t3">{hhmmss(e.ts)}</span><span className="mono" style={{ fontSize: 12 }}>{e.actor}</span><span>{e.action}</span><span className="muted mono" style={{ fontSize: 12 }}>{e.detail}</span></div>
          ))}
        </div>
      )}
    </section>
  );
}
