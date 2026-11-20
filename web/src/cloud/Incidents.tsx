import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, cloud, hhmmss, j, session, short } from "../api";
import { usePoll, useLiveTick } from "../hooks";
import { Golden, kindOf } from "./Explorer";

const SEV: Record<string, string> = { critical: "var(--crit)", warning: "var(--warn)", info: "var(--t3)" };

export function IncidentList() {
  const nav = useNavigate();
  const tick = useLiveTick();
  const [status, setStatus] = useState("open");
  const [d] = usePoll<any>(() => cloud(`/api/v1/incidents?limit=100${status === "all" ? "" : `&status=${status}`}`), 5000, [status, tick]);
  const rows: any[] = d?.incidents ?? [];
  const g = "90px minmax(0,1fr) 150px 90px 90px";
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span className="h">Incidents</span><span className="muted">alerts grouped by the AI engine; one incident per root cause</span>
        <div style={{ flex: 1 }} />
        <div className="seg">{["open", "resolved", "all"].map((s) => <button key={s} className={status === s ? "on" : ""} onClick={() => setStatus(s)}>{s}</button>)}</div>
      </div>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: g }}><span>severity</span><span>title</span><span>root cause</span><span>opened</span><span>status</span></div>
        {rows.map((i) => (
          <div key={i.incident_id} className="tr click" style={{ gridTemplateColumns: g }} onClick={() => nav(`/incidents/${i.incident_id}`)}>
            <span style={{ color: SEV[i.severity] }}>{i.severity}</span>
            <span style={{ color: "var(--hi)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{i.title}</span>
            <span className="mono t3" style={{ fontSize: 12 }}>{short(i.root_cause_entity)} · {(i.root_cause_score ?? 0).toFixed(2)}</span>
            <span className="t3">{hhmmss(i.opened_at)}</span><span className={i.status === "open" ? "crit" : "muted"}>{i.status}</span>
          </div>
        ))}
        {!rows.length && <div className="empty">No {status === "all" ? "" : status} incidents.</div>}
      </div>
    </section>
  );
}

const FIX: Record<string, string> = { "cpu": "INVESTIGATE_TOP_PROCESSES", "svc": "RESTART_SERVICE", "net": "FAILOVER_TO_SECONDARY_LINK", "auth": "TEMP_BLOCK_SOURCE_15M" };
const guessFix = (rule?: string) => Object.entries(FIX).find(([k]) => rule?.includes(k))?.[1] ?? "INVESTIGATE_TOP_PROCESSES";

export function IncidentDetail() {
  const { id } = useParams();
  const tick = useLiveTick();
  const [tl, err] = usePoll<any>(() => cloud(`/api/v1/incidents/${id}/timeline`), 5000, [id, tick]);
  const [det] = usePoll<any>(() => cloud(`/api/v1/incidents/${id}`), 15000, [id]);
  const [rec, setRec] = useState<any>(null);
  const [pos, setPos] = useState<number | null>(null);
  const recId = (det?.evidence_links ?? []).find((l: any) => l.recommendation_id)?.recommendation_id;
  useEffect(() => { if (recId) cloud(`/api/v1/recommendations/${recId}`).then((r) => setRec(r.recommendation)).catch(() => {}); }, [recId, tick]);
  if (err) return <section className="page"><div className="empty">Could not load this incident ({err}).</div></section>;
  if (!tl) return <section className="page"><div className="muted">Loading…</div></section>;
  const inc = tl.incident, alerts: any[] = tl.alerts ?? [], rank: any[] = tl.root_cause_ranking ?? [], ev: any[] = tl.evidence ?? [];
  // flight recorder: every alert on one time axis
  const t0 = Math.min(...alerts.map((a) => +new Date(a.first_ts)), +new Date(inc.opened_at)) - 30e3;
  const t1 = Math.max(...alerts.map((a) => +new Date(a.last_ts)), inc.closed_at ? +new Date(inc.closed_at) : Date.now()) + 15e3;
  const X = (t: number) => ((t - t0) / (t1 - t0)) * 100;
  const cursor = pos ?? 100;
  const at = t0 + (cursor / 100) * (t1 - t0);
  const summary = String(inc.summary ?? "").split(/(\[\d+\])/);
  const root = inc.root_cause_entity;
  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 12 }}><span style={{ color: SEV[inc.severity] }}>{String(inc.severity).toUpperCase()}</span> <span className="muted">· {inc.status} · opened {hhmmss(inc.opened_at)} UTC{inc.closed_at ? ` · resolved ${hhmmss(inc.closed_at)}` : ""}</span></span>
          <span className="h">{inc.title}</span>
        </div>
        <div className="box" style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span className="h2">Flight recorder</span>
            <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="mono t3" style={{ fontSize: 12 }}>{new Date(at).toISOString().slice(11, 19)}</span>
              <Replay onPos={setPos} />
            </span>
          </div>
          <div style={{ position: "relative", marginTop: 10 }}>
            {alerts.map((a) => {
              const s = X(+new Date(a.first_ts)), e = X(+new Date(a.last_ts)), on = +new Date(a.first_ts) <= at;
              return (
                <div key={a.alert_id} style={{ display: "grid", gridTemplateColumns: "150px 1fr", alignItems: "center", height: 26, opacity: on ? 1 : 0.25 }}>
                  <span className="mono" style={{ fontSize: 11.5, color: a.entity === root ? "var(--hi)" : "var(--t3)" }}>{short(a.entity)}</span>
                  <span style={{ position: "relative", height: 10 }}>
                    <span title={`${a.rule} · ${a.occurrences}×`} style={{ position: "absolute", left: `${s}%`, width: `${Math.max(1, e - s)}%`, top: 0, bottom: 0, borderRadius: 3, background: SEV[a.severity] ?? "var(--t3)" }} />
                    <span className="muted" style={{ position: "absolute", ...(e > 62 ? { right: `calc(${100 - s}% + 8px)` } : { left: `calc(${e}% + 8px)` }), top: -2, fontSize: 11, whiteSpace: "nowrap" }}>{a.rule} · {a.occurrences}×</span>
                  </span>
                </div>
              );
            })}
            <span style={{ position: "absolute", left: `calc(150px + (100% - 150px) * ${cursor / 100})`, top: -4, bottom: -4, width: 1, background: "var(--hi)", opacity: 0.6 }} />
          </div>
          <input type="range" min={0} max={100} step={0.5} value={cursor} onChange={(e) => setPos(+e.target.value)} style={{ width: "calc(100% - 150px)", marginLeft: 150, accentColor: "#9AA0A8" }} aria-label="Scrub timeline" />
        </div>
        <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
          <span className="h2">What happened</span>
          <p style={{ margin: 0, lineHeight: 1.65, color: "var(--hi)" }}>{summary.map((p: string, k: number) => /^\[\d+\]$/.test(p) ? <a key={k} href={`#ev${p.slice(1, -1)}`} className="mono" style={{ fontSize: 11, verticalAlign: "super" }}>{p}</a> : p)}</p>
          <div className="tbl">
            {ev.map((e) => (
              <div key={e.id} id={`ev${e.evidence_number}`} className="tr" style={{ gridTemplateColumns: "30px 70px minmax(0,1fr) minmax(0,1fr)" }}>
                <span className="mono t3">[{e.evidence_number}]</span><span className="muted">{e.evidence_type}</span>
                <span>{e.description}</span><span className="mono muted" style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis" }}>{e.payload_id ? `payload ${short(e.payload_id, 18)}` : e.reference}</span>
              </div>
            ))}
            {!ev.length && <span className="muted">The engine has not attached evidence yet.</span>}
          </div>
        </div>
        {root && <Golden id={root} kind={kindOf(root)} minutes={15} tick={tick} />}
      </section>
      <aside className="rail">
        <span className="h2">Root cause ranking</span>
        <div className="tbl">
          {rank.map((r, k) => (
            <Link key={r.entity} to={`/entities/${r.entity}`} className="tr click" style={{ gridTemplateColumns: "18px minmax(0,1fr) 44px" }}>
              <span className="muted">{k + 1}</span>
              <span style={{ display: "flex", flexDirection: "column" }}><span className="mono" style={{ fontSize: 12, color: k ? "var(--t3)" : "var(--hi)" }}>{r.entity}</span>
                <span className="muted" style={{ fontSize: 11 }}>upstream {r.upstream.toFixed(1)} · earliest {r.earliness.toFixed(1)} · severity {r.severity.toFixed(1)}</span></span>
              <span style={{ textAlign: "right" }}>{r.score.toFixed(2)}</span>
            </Link>
          ))}
        </div>
        <FixFlow rec={rec} rule={inc.root_cause_rule} target={rec?.target_entity ?? root} />
        <span className="h2">Was this alert right?</span>
        {alerts.slice(0, 4).map((a) => <Feedback key={a.alert_id} a={a} />)}
      </aside>
    </div>
  );
}

function Replay({ onPos }: { onPos: (n: number) => void }) {
  const [run, setRun] = useState(false);
  useEffect(() => {
    if (!run) return;
    let p = 0; onPos(0);
    const t = setInterval(() => { p += 1.25; onPos(Math.min(100, p)); if (p >= 100) setRun(false); }, 60);
    return () => clearInterval(t);
  }, [run]); // eslint-disable-line
  return <button className="btn" onClick={() => setRun(!run)}>{run ? "Pause" : "Replay"}</button>;
}

function FixFlow({ rec, rule, target }: { rec: any; rule?: string; target?: string }) {
  const tick = useLiveTick();
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 30000);
  const [acts, , refresh] = usePoll<any>(() => cloud("/api/v1/actions"), 3000, [tick]);
  const [msg, setMsg] = useState<string | null>(null);
  const role = session()?.user.role;
  const type = rec?.action_type ?? guessFix(rule);
  const mine = (acts?.actions ?? []).find((a: any) => a.action_type === type && a.policy_ref === `incident:${target}`);
  // Send the fix to the collector that reports the target entity; fall back to the most recently seen one.
  const owner = (fleet?.entities ?? []).find((e: any) => e.entity === (rec?.target_entity ?? target))?.collector_id;
  const freshest = [...(fleet?.collectors ?? [])].sort((a: any, b: any) => String(b.last_heartbeat).localeCompare(String(a.last_heartbeat)))[0]?.collector_id;
  const collector = owner ?? freshest;
  const steps = ["Requested", "Approved", "Delivered", "Executed"];
  const stage = !mine ? -1 : mine.status === "pending" ? 0 : mine.status === "approved" ? 1 : mine.status === "delivered" ? 2 : 3;
  const result = j<any>(mine?.result, null);
  async function act(fn: () => Promise<any>) { setMsg(null); try { await fn(); refresh(); } catch (e) { setMsg(e instanceof ApiError ? e.code : String(e)); } }
  return (
    <div style={{ border: "1px solid var(--line2)", borderRadius: 6, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
      <span className="h2">Suggested fix</span>
      <span style={{ color: "var(--hi)" }} className="mono">{type}</span>
      {rec && <span className="t3" style={{ fontSize: 12, lineHeight: 1.55 }}>{rec.rationale} <span className="muted">· confidence {Number(rec.confidence).toFixed(2)}</span></span>}
      <span className="muted" style={{ fontSize: 11.5 }}>Runs on the customer's collector only after a second person approves. The collector can still refuse it locally.</span>
      <div style={{ display: "flex", gap: 4 }}>{steps.map((s, k) => <span key={s} style={{ flex: 1, fontSize: 11, padding: "4px 0", textAlign: "center", borderTop: `2px solid ${k <= stage ? "var(--ok)" : "var(--line2)"}`, color: k <= stage ? "var(--hi)" : "var(--muted)" }}>{s}</span>)}</div>
      {!mine && <button className="btn primary" disabled={!collector || role === "approver"} onClick={() => act(() => cloud("/api/v1/actions", { method: "POST", body: JSON.stringify({ collector_id: collector, action_type: type, policy_ref: `incident:${target}`, params: target ? { target } : {} }) }))}>Request fix</button>}
      {!mine && role === "approver" && <span className="muted" style={{ fontSize: 11.5 }}>An operator requests; you approve. Switch account to request.</span>}
      {mine?.status === "pending" && (role === "approver"
        ? <div style={{ display: "flex", gap: 6 }}><button className="btn primary" onClick={() => act(() => cloud(`/api/v1/actions/${mine.action_id}/approve`, { method: "POST" }))}>Approve</button><button className="btn" onClick={() => act(() => cloud(`/api/v1/actions/${mine.action_id}/reject`, { method: "POST" }))}>Reject</button></div>
        : <span className="warn" style={{ fontSize: 12 }}>Waiting for an approver. Switch to “Ravi · Acme approver” to approve.</span>)}
      {result && <span style={{ fontSize: 12 }} className={["executed", "succeeded", "success"].includes(result.status) ? "ok" : "warn"}>Result: {result.status} · local policy {result.local_policy_decision}{result.health_before ? ` · health ${result.health_before} → ${result.health_after}` : ""}</span>}
      {mine && ["rejected", "expired", "refused"].includes(mine.status) && <span className="crit" style={{ fontSize: 12 }}>{mine.status}</span>}
      {msg && <span className="crit" style={{ fontSize: 12 }}>{msg}</span>}
    </div>
  );
}

function Feedback({ a }: { a: any }) {
  const [v, setV] = useState<string | null>(null);
  const send = (verdict: string) => cloud(`/api/v1/alerts/${a.alert_id}/feedback`, { method: "POST", body: JSON.stringify({ verdict }) }).then(() => setV(verdict)).catch((e) => setV(`error ${e.code ?? e}`));
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
      <span className="mono t3" style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{short(a.entity, 10)} · {a.rule}</span>
      {v ? <span className="muted">{v.replace("_", " ")}</span> : <><button className="btn" onClick={() => send("valid")}>Valid</button><button className="btn" onClick={() => send("false_alarm")}>False alarm</button></>}
    </div>
  );
}
