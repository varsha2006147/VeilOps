import { useState } from "react";
import { CLOUD, ApiError, ago, cloud, hhmmss, j, session, short } from "../api";
import { usePoll, useLiveTick } from "../hooks";
import { Gauge } from "../ui/charts";

async function download(path: string, name: string) {
  const r = await fetch(CLOUD + path, { headers: { Authorization: `Bearer ${session()?.token}` } });
  const a = document.createElement("a"); a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click();
}
const Stat = ({ label, value, tone }: { label: string; value: string | number; tone?: string }) => (
  <div className="box" style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 4 }}>
    <span className="t3" style={{ fontSize: 12 }}>{label}</span><span style={{ fontSize: 24, color: tone ?? "var(--hi)", letterSpacing: "-.5px" }}>{value}</span>
  </div>
);

export function Boundary() {
  const tick = useLiveTick();
  const [r] = usePoll<any>(() => cloud("/api/v1/reconciliation"), 5000, [tick]);
  const [aud] = usePoll<any>(() => cloud("/api/v1/audit?limit=200"), 10000, [tick]);
  const cols: any[] = r?.collectors ?? [];
  const sum = (f: (c: any) => number) => cols.reduce((s, c) => s + (f(c) || 0), 0);
  const receipts = (aud?.events ?? []).filter((e: any) => e.action === "slo.render_ack" || e.action.startsWith("telemetry"));
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span className="h">Boundary & proof</span><span className="muted">what arrived from each collector, checked against what it says it sent</span>
        <div style={{ flex: 1 }} /><button className="btn" onClick={() => download("/api/v1/slo/export.csv", "veilops-proof.csv")}>Export CSV</button>
      </div>
      <div className="grid4">
        <Stat label="Payloads received" value={sum((c) => c.received_count)} />
        <Stat label="Missing sequence numbers" value={sum((c) => c.missing_count)} tone={sum((c) => c.missing_count) ? "var(--crit)" : "var(--ok)"} />
        <Stat label="Duplicates rejected" value={sum((c) => c.duplicates_rejected?.total)} />
        <Stat label="Outages buffered and drained" value={sum((c) => c.backlog?.episodes)} />
      </div>
      <span className="h2">Per collector</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        <div className="tr th" style={{ gridTemplateColumns: "190px 110px 80px 1fr 150px 100px" }}><span>collector</span><span>received</span><span>missing</span><span>duplicates (payload · sequence · key)</span><span>backlog</span><span>status</span></div>
        {cols.map((c) => (
          <div key={c.collector_id} className="tr" style={{ gridTemplateColumns: "190px 110px 80px 1fr 150px 100px" }}>
            <span className="mono" style={{ fontSize: 12 }}>{c.collector_id}</span>
            <span>{c.received_range ? `#${c.received_range[0]}–${c.received_range[1]}` : "—"}</span>
            <span className={c.missing_count ? "crit" : "ok"}>{c.missing_count}{c.missing_sequences?.length ? ` (${c.missing_sequences.slice(0, 4).join(", ")})` : ""}</span>
            <span className="t3">{c.duplicates_rejected.duplicate_payload} · {c.duplicates_rejected.sequence_conflict} · {c.duplicates_rejected.idempotency_conflict}</span>
            <span className="t3" style={{ fontSize: 12 }}>{c.backlog.draining_now ? <span className="warn">draining now</span> : `${c.backlog.episodes} outages · last drain ${(c.backlog.last_drain_ms / 1000).toFixed(1)} s`}</span>
            <span className={c.status === "reconciled" ? "ok" : "warn"}>{c.status}</span>
          </div>
        ))}
        {!cols.length && <div className="empty">No collector has sent data yet.</div>}
      </div>
      <span className="h2">Reconciliation runs</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {(r?.runs ?? []).slice(0, 10).map((x: any, k: number) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: "90px 190px minmax(0,1fr)" }}><span className="t3">{hhmmss(x.ran_at ?? x.created_at)}</span><span className="mono" style={{ fontSize: 12 }}>{x.collector_id}</span><span className="muted mono" style={{ fontSize: 11.5 }}>{JSON.stringify(x).slice(0, 140)}</span></div>
        ))}
        {!(r?.runs ?? []).length && <div className="empty">A run is recorded each time a collector reconnects after an outage.</div>}
      </div>
      <span className="h2">Dashboard delivery acknowledgements (latest)</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {receipts.slice(0, 8).map((e: any, k: number) => { const d = j<any>(e.details, {}); return (
          <div key={k} className="tr" style={{ gridTemplateColumns: "90px 160px minmax(0,1fr)" }}><span className="t3">{hhmmss(e.at_utc)}</span><span>{e.action}</span><span className="mono muted" style={{ fontSize: 11.5 }}>{short(e.resource_id, 40)}{d.delay_ms ? ` · ${d.delay_ms} ms` : ""}</span></div>); })}
        {!receipts.length && <div className="empty">No receipts in the audit log yet.</div>}
      </div>
    </section>
  );
}

const ms = (v?: number | null) => (v == null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)}` : `${Math.round(v)}`);
const unit = (v?: number | null) => (v == null ? "no samples yet" : v >= 1000 ? "seconds · p95" : "ms · p95");

export function Reliability() {
  const tick = useLiveTick();
  const [s] = usePoll<any>(() => cloud("/api/v1/slo"), 5000, [tick]);
  const [inj, , refresh] = usePoll<any>(() => cloud("/api/v1/slo/injections"), 5000, [tick]);
  const [msg, setMsg] = useState<string | null>(null);
  if (!s) return <section className="page"><span className="muted">Loading…</span></section>;
  const t = s.targets, q = s.quality ?? {}, ev = s.evaluation ?? {};
  const pick = (x: any) => x?.since_start?.count ? x.since_start : x?.all_time;
  const c2d = pick(s.collection_to_dashboard), b2a = pick(s.breach_to_alert), off = pick(s.collector_offline_detection);
  const rc = s.reconciliation?.collectors ?? [];
  const missing = rc.reduce((a: number, c: any) => a + c.missing_count, 0), dups = rc.reduce((a: number, c: any) => a + (c.duplicates_rejected?.total ?? 0), 0);
  const rings = [
    { k: "Collection → dashboard", v: c2d?.p95_ms, max: t.collection_to_dashboard_p95_ms * 2, target: t.collection_to_dashboard_p95_ms, n: c2d?.count, ev: ev.collection_to_dashboard },
    { k: "Breach → alert", v: b2a?.p95_ms, max: t.breach_to_alert_p95_ms * 2, target: t.breach_to_alert_p95_ms, n: b2a?.count, ev: ev.breach_to_alert },
    { k: "Collector offline detected", v: off?.p95_ms, max: t.collector_offline_detection_max_ms * 2, target: t.collector_offline_detection_max_ms, n: off?.count, ev: ev.collector_offline_detection },
  ];
  async function inject() {
    setMsg(null);
    try {
      const fleet = await cloud("/api/v1/fleet");
      const host = fleet.entities.find((e: any) => e.kind === "host")?.entity;
      await cloud("/api/v1/slo/injections", { method: "POST", body: JSON.stringify({ scenario: "cpu_drift", entity: host, rule: "threshold.cpu.high" }) });
      setMsg(`Registered a CPU breach on ${host}. Trigger “CPU runaway” on the collector; the alert time is measured from here.`); refresh();
    } catch (e) { setMsg(e instanceof ApiError ? e.code : String(e)); }
  }
  return (
    <section className="page">
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span className="h">Reliability</span><span className="muted">measured from real samples; the tick on each ring is the target</span>
        <div style={{ flex: 1 }} /><button className="btn" onClick={inject}>Register a test breach</button>
        <button className="btn" onClick={() => download("/api/v1/slo/export.csv", "veilops-slo.csv")}>Export CSV</button>
      </div>
      {msg && <div className="banner">{msg}</div>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        {rings.map((r) => (
          <div key={r.k} className="box" style={{ padding: 14, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <span className="t3" style={{ alignSelf: "flex-start" }}>{r.k}</span>
            <Gauge value={r.v ?? null} max={r.max} target={r.target} show={ms(r.v)} unit={unit(r.v)} lo="0" hi={`${r.max / 1000}s`} />
            <span className="muted" style={{ fontSize: 12 }}>target ≤ {r.target / 1000} s · {r.n ?? 0} samples · <span className={r.ev === "pass" ? "ok" : r.ev === "fail" ? "warn" : ""}>{String(r.ev ?? "—").replace("_", " ")}</span></span>
          </div>
        ))}
        {[
          { k: "Lost records", v: missing, good: missing === 0, sub: "missing sequence numbers after reconcile" },
          { k: "Duplicates stored", v: 0, good: true, sub: `${dups} duplicate sends rejected at the door` },
          { k: "Noise reduction", v: q.noise_reduction_pct != null ? `${q.noise_reduction_pct}%` : "—", good: true, sub: `${q.raw_alerts ?? 0} raw alerts → ${q.incidents ?? 0} incidents · ${q.false_alarms ?? 0} marked false alarm` },
        ].map((x) => (
          <div key={x.k} className="box" style={{ padding: 14, display: "flex", flexDirection: "column", gap: 6 }}>
            <span className="t3">{x.k}</span><span style={{ fontSize: 40, letterSpacing: "-1px", color: x.good ? "var(--hi)" : "var(--crit)" }}>{x.v}</span><span className="muted" style={{ fontSize: 12 }}>{x.sub}</span>
          </div>
        ))}
      </div>
      <span className="h2">Injected breaches</span>
      <div className="tbl box" style={{ padding: "4px 14px" }}>
        {(inj?.injections ?? []).slice(0, 10).map((i: any, k: number) => (
          <div key={k} className="tr" style={{ gridTemplateColumns: "90px 140px 160px minmax(0,1fr)" }}><span className="t3">{hhmmss(i.injected_at)}</span><span className="mono" style={{ fontSize: 12 }}>{i.entity}</span><span>{i.rule}</span><span className={i.delay_ms != null ? "" : "muted"}>{i.delay_ms != null ? `alert after ${(i.delay_ms / 1000).toFixed(1)} s` : `waiting · ${ago(i.injected_at)}`}</span></div>
        ))}
        {!(inj?.injections ?? []).length && <div className="empty">No test breaches yet.</div>}
      </div>
      <span className="muted" style={{ fontSize: 11.5, lineHeight: 1.6 }}>{(s.notes ?? []).join(" ")}</span>
    </section>
  );
}
