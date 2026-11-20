import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, cloud, fmtTime, session, short } from "../api";
import Shell from "../components/Shell";
import { usePoll } from "../hooks";
import "./incidents.css";

const RULE_METRIC: [RegExp, string][] = [
  [/cpu/, "cpu.util_pct"], [/mem/, "mem.util_pct"], [/disk/, "disk.util_pct"], [/loss/, "net.loss_pct"],
  [/latency/, "net.latency_ms"], [/resp_ms/, "svc.resp_ms"], [/svc\.down/, "svc.up"], [/unreachable/, "net.reachable"],
];
const metricFor = (rule: string) => RULE_METRIC.find(([re]) => re.test(rule))?.[1] ?? "cpu.util_pct";
const W = 900, X0 = 170, LANE = 78;

export default function Incidents() {
  const { id } = useParams();
  const nav = useNavigate();
  const [list] = usePoll<any>(() => cloud("/api/v1/incidents?limit=30"), 4000);
  const incidents: any[] = list?.incidents ?? [];
  useEffect(() => { if (!id && incidents[0]) nav(`/incidents/${incidents[0].incident_id}`, { replace: true }); }, [id, incidents.length]); // eslint-disable-line

  return (
    <Shell>
      <div className="inc-page">
        <aside className="inc-list" aria-label="Incidents">
          <div className="eyebrow" style={{ padding: "0 4px 10px" }}>Incidents</div>
          {incidents.map((i) => (
            <Link key={i.incident_id} to={`/incidents/${i.incident_id}`} className={`inc-item ${i.incident_id === id ? "on" : ""}`}>
              <span className="mono" style={{ fontSize: 11 }}><span className={i.status === "open" ? "red" : "muted"}>{i.status}</span> · {fmtTime(i.opened_at)}</span>
              <span className="ttl">{i.title}</span>
            </Link>
          ))}
          {!incidents.length && <p className="muted" style={{ padding: 4 }}>No incidents yet. Use <b>Live → CPU runaway</b> or <b>Link failure</b> to create one.</p>}
        </aside>
        {id ? <Recorder id={id} /> : <div className="muted" style={{ padding: 40 }}>Select an incident.</div>}
      </div>
    </Shell>
  );
}

function Recorder({ id }: { id: string }) {
  const [tl] = usePoll<any>(() => cloud(`/api/v1/incidents/${id}/timeline`), 5000, [id]);
  const [lanes, setLanes] = useState<{ entity: string; metric: string; pts: [number, number][]; hot: boolean }[]>([]);
  const [p, setP] = useState(1);
  const [playing, setPlaying] = useState(false);
  const inc = tl?.incident;
  const alerts: any[] = tl?.alerts ?? [];
  const ranking: any[] = tl?.root_cause_ranking ?? [];
  const evidence: any[] = tl?.evidence ?? [];
  const root = inc?.root_cause_entity;

  const t0 = useMemo(() => (alerts.length ? Math.min(...alerts.map((a) => +new Date(a.first_ts))) - 5 * 60e3 : 0), [alerts]);
  const t1 = useMemo(() => (alerts.length ? Math.max(Date.now() - 2000, ...alerts.map((a) => +new Date(a.last_ts))) : 1), [alerts]);
  const x = (ts: number) => X0 + ((ts - t0) / Math.max(1, t1 - t0)) * (W - X0);

  useEffect(() => {
    if (!alerts.length) return;
    const ents = [...new Map(alerts.map((a) => [a.entity, metricFor(a.rule)])).entries()]
      .sort(([a], [b]) => (a === root ? -1 : b === root ? 1 : 0)).slice(0, 6);
    const since = new Date(t0).toISOString();
    Promise.all(ents.map(async ([entity, metric]) => {
      const r = await cloud(`/api/v1/entities/${entity}/metrics?since=${encodeURIComponent(since)}&limit=2000`).catch(() => ({ metrics: [] }));
      const pts = (r.metrics as any[]).filter((m) => m.metric === metric).map((m) => [+new Date(m.event_ts), m.max ?? m.avg] as [number, number]).sort((a, b) => a[0] - b[0]);
      return { entity, metric, pts, hot: true };
    })).then(setLanes);
  }, [id, alerts.length, root]); // eslint-disable-line

  function replay() {
    if (playing) return;
    setPlaying(true); setP(0);
    const start = performance.now();
    const tick = (now: number) => {
      const v = Math.min(1, (now - start) / 6500);
      setP(v);
      if (v < 1) requestAnimationFrame(tick); else setPlaying(false);
    };
    requestAnimationFrame(tick);
  }

  if (!inc) return <div className="muted" style={{ padding: 40 }}>Loading incident…</div>;
  const playX = X0 + p * (W - X0);
  const shown = alerts.filter((a) => x(+new Date(a.first_ts)) <= playX);
  const grouped = p >= 0.82 || !playing && p === 1;
  const rows = lanes.length || 1;
  const H = 30 + rows * LANE + 30;
  const ticks = Array.from({ length: 6 }, (_, i) => t0 + ((t1 - t0) * i) / 5);
  const recId = evidence.find((e) => e.recommendation_id)?.recommendation_id;

  return (
    <div className="rec-wrap">
      <section className="rec" aria-label="Flight recorder">
        <div className="rec-head">
          <div><div className="eyebrow">Flight recorder · {fmtTime(new Date(t0).toISOString())} → {fmtTime(new Date(t1).toISOString())} UTC</div>
            <h1 className="h1">{grouped ? `${alerts.length} alert${alerts.length === 1 ? "" : "s"} became 1 incident` : `${shown.length} alerts, not yet grouped`}</h1></div>
          <button className="btn" onClick={replay}>{playing ? "Replaying…" : "↻ Replay"}</button>
        </div>
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Metric lanes for every entity in this incident">
          {ticks.map((t, i) => <g key={i}><line x1={x(t)} x2={x(t)} y1={20} y2={H - 26} stroke="#16171a" />
            <text x={x(t)} y={H - 8} fill="#6b6f76" fontSize="11" textAnchor="middle">{fmtTime(new Date(t).toISOString()).slice(0, 5)}</text></g>)}
          {lanes.map((l, i) => {
            const base = 30 + i * LANE + 56;
            const vals = l.pts.map(([, v]) => v);
            const lo = Math.min(...vals, 0), hi = Math.max(...vals, 1);
            const pts = l.pts.map(([t, v]) => `${x(t).toFixed(1)},${(base - ((v - lo) / (hi - lo || 1)) * 46).toFixed(1)}`).join(" ");
            return (
              <g key={l.entity}>
                <text x="0" y={base - 30} fill={l.entity === root ? "#f2f3f5" : "#9c9fa5"} fontSize="12">{l.metric}</text>
                <text x="0" y={base - 15} fill={l.entity === root ? "#eb5757" : "#6b6f76"} fontSize="10.5" fontFamily="JetBrains Mono, monospace">{short(l.entity)}{l.entity === root ? " · root" : ""}</text>
                <line x1={X0} x2={W} y1={base} y2={base} stroke="#1b1c20" />
                {pts && <polyline points={pts} fill="none" stroke={l.entity === root ? "#e2e4e7" : "#8a8f98"} strokeWidth="1.4" />}
              </g>
            );
          })}
          {alerts.map((a) => {
            const lane = lanes.findIndex((l) => l.entity === a.entity);
            if (lane < 0) return null;
            const cx = x(+new Date(a.first_ts));
            return <circle key={a.alert_id} cx={cx} cy={30 + lane * LANE + 20} r="4.5" fill="#0b0c0e" stroke="#eb5757" strokeWidth="1.5" opacity={cx <= playX ? 1 : 0} />;
          })}
          {grouped && lanes.length > 0 && (() => {
            const xs = alerts.map((a) => x(+new Date(a.first_ts)));
            const bx = Math.min(...xs) - 14, bw = Math.max(...xs) - Math.min(...xs) + 28;
            return <g><rect x={bx} y={22} width={Math.max(bw, 40)} height={rows * LANE - 4} rx="6" fill="rgba(235,87,87,.05)" stroke="#eb5757" strokeDasharray="4 3" />
              <text x={bx} y={16} fill="#eb5757" fontSize="11" fontFamily="JetBrains Mono, monospace">{alerts.length} alerts → 1 incident</text></g>;
          })()}
          {p < 1 && <g><rect x={playX} y={14} width={W - playX} height={H - 36} fill="#0b0c0e" opacity=".78" />
            <line x1={playX} x2={playX} y1={14} y2={H - 22} stroke="#e2e4e7" /></g>}
        </svg>
        <div className="rank">
          <span className="eyebrow">Root-cause ranking (AI)</span>
          {ranking.slice(0, 4).map((r, i) => (
            <div key={r.entity} className="rank-row">
              <span className="mono" style={{ color: i === 0 ? "var(--text-hi)" : "var(--text-3)" }}>{short(r.entity)}</span>
              <span className="bar"><span style={{ width: `${Math.min(100, (r.score ?? 0) * 100)}%`, background: i === 0 ? "var(--text)" : "var(--muted-2)" }} /></span>
              <span className="mono muted">{(r.score ?? 0).toFixed(2)}</span>
            </div>
          ))}
        </div>
      </section>
      <Explain inc={inc} evidence={evidence} recId={recId} show={grouped} />
    </div>
  );
}

function Explain({ inc, evidence, recId, show }: { inc: any; evidence: any[]; recId?: string; show: boolean }) {
  const [rec, setRec] = useState<any>(null);
  const [actions, , refresh] = usePoll<any>(() => cloud("/api/v1/actions?limit=20"), 3000);
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 15000);
  const [msg, setMsg] = useState<string | null>(null);
  const role = session()?.user.role;
  useEffect(() => { if (recId) cloud(`/api/v1/recommendations/${recId}`).then((r) => setRec(r.recommendation)).catch(() => {}); }, [recId]);
  const action = rec?.action_type;
  const mine = (actions?.actions ?? []).find((a: any) => a.action_type === action && +new Date(a.created_at) >= +new Date(inc.opened_at));
  const collector = fleet?.collectors?.[0]?.collector_id;

  async function request() {
    setMsg(null);
    try { await cloud("/api/v1/actions", { method: "POST", body: JSON.stringify({ collector_id: collector, action_type: action, policy_ref: `aiops.${action.toLowerCase()}` }) }); refresh(); }
    catch (e) { setMsg(e instanceof ApiError ? e.code : "failed"); }
  }
  async function approve() {
    setMsg(null);
    try { await cloud(`/api/v1/actions/${mine.action_id}/approve`, { method: "POST" }); refresh(); }
    catch (e) { setMsg(e instanceof ApiError ? ({ TWO_PERSON_APPROVAL_REQUIRED: "A different person must approve.", INSUFFICIENT_ROLE: "Sign in as an approver to approve." } as any)[e.code] ?? e.code : "failed"); }
  }

  if (!show) return <aside className="explain"><span className="muted" style={{ fontSize: 15 }}>Watching…</span><p className="muted">Alerts appear as the playhead passes them.</p></aside>;
  const steps = ["pending", "approved", "delivered", "executed"];
  const at = mine ? (mine.status === "rolled_back" ? 3 : steps.indexOf(mine.status)) : -1;
  return (
    <aside className="explain" aria-label="Explanation">
      <span className="mono muted" style={{ fontSize: 12 }}><span className="red">{inc.severity}</span> · opened {fmtTime(inc.opened_at)} UTC · {inc.status}</span>
      <h2>{inc.title}</h2>
      <p className="sum">{inc.summary}</p>
      {evidence.length > 0 && <ol className="ev">{evidence.map((e, i) => (
        <li key={e.id ?? i}><span className="mono">{e.evidence_type}</span> {e.description ?? e.reference}{e.payload_id && <span className="mono muted"> · payload {short(e.payload_id)}</span>}</li>
      ))}</ol>}
      {rec && (
        <div className="fix">
          <span className="muted" style={{ fontSize: 12 }}>Suggested fix · confidence {Number(rec.confidence ?? 0).toFixed(2)}</span>
          <b>{rec.title}</b>
          <span className="muted" style={{ fontSize: 12 }}>{action ? <>Action <span className="mono">{action}</span> on {short(rec.target_entity)}. Runs as snapshot → dry run → execute → verify, with automatic rollback.</> : rec.rationale}</span>
          {action && (
            <>
              <div className="steps">{steps.map((s, i) => <span key={s} className={i <= at ? "on" : ""}>{s}</span>)}</div>
              {mine?.result && <span className="mono" style={{ fontSize: 12, color: mine.result.status === "executed" ? "var(--green)" : "var(--yellow)" }}>
                {mine.result.status} · health {mine.result.health_before} → {mine.result.health_after}</span>}
              <div style={{ display: "flex", gap: 8 }}>
                {!mine && <button className="btn primary" onClick={request} disabled={!collector || role === "viewer"}>Request fix</button>}
                {mine?.status === "pending" && <button className="btn primary" onClick={approve}>Approve</button>}
                {mine?.status === "pending" && <span className="muted" style={{ fontSize: 12, alignSelf: "center" }}>needs a second person (approver)</span>}
              </div>
              {msg && <span className="red" style={{ fontSize: 12 }}>{msg}</span>}
            </>
          )}
        </div>
      )}
    </aside>
  );
}
