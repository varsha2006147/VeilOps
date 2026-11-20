import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { cloud, local, renderAck, short, subscribe } from "../api";
import Shell from "../components/Shell";
import { usePoll } from "../hooks";
import "./live.css";

type Win = { entity: string; entity_kind: string; metric: string; avg: number; max: number; event_ts: string };
const SCENARIOS: [string, string][] = [["cpu_drift", "CPU runaway"], ["latency", "Link failure"], ["secret", "Secret in log"], ["failed_logins", "Brute force"]];

export default function Live() {
  const [windows] = usePoll<Win[]>(() => local("/local/windows?limit=600"), 2000);
  const [status] = usePoll<any>(() => local("/local/status"), 4000);
  const [proof, , refreshProof] = usePoll<any>(() => local("/api/egress-proof"), 2000);
  const [link] = usePoll<any>(() => local("/local/cloud"), 2000);
  const [incidents, , refreshIncidents] = usePoll<any>(() => cloud("/api/v1/incidents?status=open&limit=5"), 4000);
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 5000);
  const [fired, setFired] = useState<string | null>(null);
  const [lastEvent, setLastEvent] = useState<string | null>(null);

  useEffect(() => subscribe((ev, data) => {
    if (ev === "telemetry_processed" && data.payload_id) {
      setLastEvent(data.payload_id);
      renderAck(data.payload_id);
      refreshProof(); refreshIncidents();
    }
  }), []); // eslint-disable-line

  const hosts = useMemo(() => {
    const by: Record<string, Win[]> = {};
    for (const w of windows ?? []) if (w.metric === "cpu.util_pct") (by[w.entity] ??= []).push(w);
    return Object.entries(by).map(([name, ws]) => {
      const s = ws.sort((a, b) => a.event_ts.localeCompare(b.event_ts)).slice(-30);
      return { name, values: s.map((w) => w.avg), cpu: s.at(-1)?.avg ?? 0 };
    }).sort((a, b) => a.name.localeCompare(b.name));
  }, [windows]);

  const envelopes: any[] = proof?.recent_envelopes ?? [];
  const pending = proof?.stats?.outbox_depth ?? 0;
  const blocked = link?.egress_blocked ?? 0;
  const online = link?.online !== false;
  const open = incidents?.incidents ?? [];
  const sentKb = ((proof?.stats?.total_sent_records ?? 0) * 0.21).toFixed(1); // ~210 B per window record on the wire

  async function fire(s: string) {
    setFired(s);
    try { await local(`/local/chaos/${s}`, { method: "POST" }); } finally { setTimeout(() => setFired(null), 1500); }
  }

  return (
    <Shell right={
      <div className="seg" role="group" aria-label="Simulate a problem">
        {SCENARIOS.map(([k, label]) => <button key={k} className={fired === k ? "on" : ""} onClick={() => fire(k)}>{label}</button>)}
      </div>
    }>
      {!online && <div className="notice">Cloud unreachable since {link?.outage_started_at?.slice(11, 19)} UTC · {pending} payloads held safely in the collector and sent when it returns</div>}
      <div className="live">
        <section className="inside" aria-label="Inside the customer network">
          <div><div className="eyebrow">Inside {status?.tenant_id ?? "the"} network</div>
            <h1 className="h1">{hosts.length} hosts, read locally by the collector</h1></div>
          <div className="tbl">
            <div className="tr th"><span>host (real name)</span><span>cpu · last 2.5 min</span><span className="r">cpu</span></div>
            {hosts.map((h) => <div className="tr" key={h.name}>
              <span>{h.name}</span><Spark values={h.values} hot={h.cpu} /><span className="r" style={{ color: tone(h.cpu) }}>{Math.round(h.cpu)}%</span>
            </div>)}
            {!hosts.length && <div className="tr muted">Waiting for the collector at the local address…</div>}
          </div>
          <div className="cells">
            <div><span className="muted">raw records kept here</span><b>{status?.raw_rows?.toLocaleString() ?? "—"}</b></div>
            <div><span className="muted">blocked at the boundary</span><b className={blocked ? "red" : ""}>{blocked}</b></div>
            <div><span className="muted">naming key</span><b>never leaves</b></div>
          </div>
        </section>

        <div className="boundary" aria-label="Trust boundary">
          <span className="lbl">BOUNDARY</span>
          <div className="lane">
            {envelopes.slice(0, 6).map((e, i) => (
              <span key={e.seq} className={`chip ${e.status === "acked" ? "go" : "wait"}`} style={{ animationDelay: `${-i * 0.53}s` }}>
                #{e.seq} {e.status === "acked" ? "→" : "…"}
              </span>
            ))}
          </div>
          <span className="foot">{sentKb} KB<br /><span className="muted">metadata sent</span></span>
        </div>

        <section className="cloudside" aria-label="VeilOps cloud">
          <div><div className="eyebrow">VeilOps cloud · metadata only</div>
            <h1 className="h1">{open.length ? `${open.length} incident${open.length > 1 ? "s" : ""} need${open.length > 1 ? "" : "s"} attention` : pending ? `${pending} payloads waiting to be sent` : "All payloads matched their receipts"}</h1></div>
          {open.slice(0, 2).map((inc: any) => (
            <Link key={inc.incident_id} to={`/incidents/${inc.incident_id}`} className="inc">
              <span className="mono muted"><span className="red">{inc.severity}</span> · {short(inc.root_cause_entity ?? inc.root_entity)}</span>
              <b>{inc.title}</b>
              <span className="muted clamp">{inc.summary}</span>
              <span>Open in recorder →</span>
            </Link>
          ))}
          <div className="ledger">
            <div className="tr th"><span>seq</span><span>records</span><span>hash chain</span><span className="r">receipt</span></div>
            {envelopes.slice(0, 7).map((e) => (
              <div className="tr" key={e.seq}>
                <span className="mono">#{e.seq}</span><span>{e.record_count} records</span>
                <span className="mono muted">{e.payload_hash?.slice(7, 15)}…</span>
                <span className="r" style={{ color: e.has_receipt ? "var(--text-3)" : "var(--yellow)" }}>{e.has_receipt ? "signed ✓" : "pending"}</span>
              </div>
            ))}
          </div>
          <div className="foot-row muted">
            <span>chain {proof?.chain_valid ? "verified" : "—"}</span>
            <span>{fleet?.entities?.length ?? 0} entities (codes only)</span>
            <span>reconcile: {link?.last_reconcile ? `${link.last_reconcile.missing_sequences.length} missing` : "—"}</span>
            {lastEvent && <span className="mono">live ✓</span>}
          </div>
        </section>
      </div>
    </Shell>
  );
}

const tone = (v: number) => (v >= 90 ? "var(--red)" : v >= 75 ? "var(--yellow)" : "var(--text-3)");

function Spark({ values, hot }: { values: number[]; hot: number }) {
  if (values.length < 2) return <svg width="120" height="24" />;
  const pts = values.map((v, i) => `${(i * 120) / (values.length - 1)},${22 - Math.min(100, v) * 0.2}`).join(" ");
  return <svg width="120" height="24" viewBox="0 0 120 24" aria-hidden="true"><polyline points={pts} fill="none" stroke={tone(hot)} strokeWidth="1.3" /></svg>;
}
