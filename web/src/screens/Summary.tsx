import { useEffect, useState } from "react";
import { CLOUD, cloud, session } from "../api";
import Shell from "../components/Shell";
import { usePoll } from "../hooks";
import "./summary.css";

const ARC = 293.2, C = 439.8;
type G = { name: string; value: number | null; show: string; unit: string; max: number; target: number; hi?: boolean; targetText: string; lo: string; hiLbl: string };

export default function Summary() {
  const [slo] = usePoll<any>(() => cloud("/api/v1/slo?limit=0"), 5000);
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 10000);
  const [a, setA] = useState(0);
  useEffect(() => { const t = setTimeout(() => setA(1), 120); return () => clearTimeout(t); }, []);

  const p95 = (k: string) => slo?.[k]?.recent_5m?.p95_ms ?? slo?.[k]?.since_start?.p95_ms ?? slo?.[k]?.all_time?.p95_ms ?? null;
  const rec = slo?.reconciliation ?? {};
  const q = slo?.quality ?? {};
  const ents: any[] = fleet?.entities ?? [];
  const healthy = ents.length ? (100 * ents.filter((e) => e.state === "Excellent" || e.state === "Good" || !e.state).length) / ents.length : null;
  const off = slo?.collector_offline_detection?.all_time?.max_ms ?? null;
  const matched = rec.sent_count ? (100 * Math.min(rec.received_count, rec.sent_count)) / rec.sent_count : null;

  const gauges: G[] = [
    { name: "Fleet health", value: healthy, show: fmt(healthy, 0), unit: "% healthy", max: 100, target: 90, hi: true, targetText: "target ≥ 90%", lo: "0", hiLbl: "100" },
    { name: "Collection → dashboard", value: s(p95("collection_to_dashboard")), show: fmt(s(p95("collection_to_dashboard")), 1), unit: "seconds · p95", max: 20, target: 10, targetText: "target ≤ 10 s", lo: "0", hiLbl: "20 s" },
    { name: "Breach → alert", value: s(p95("breach_to_alert")), show: fmt(s(p95("breach_to_alert")), 1), unit: "seconds · p95", max: 30, target: 15, targetText: "target ≤ 15 s", lo: "0", hiLbl: "30 s" },
    { name: "Offline detected in", value: s(off), show: fmt(s(off), 0), unit: "seconds", max: 90, target: 60, targetText: "target ≤ 60 s", lo: "0", hiLbl: "90 s" },
    { name: "Received vs sent", value: matched, show: fmt(matched, 1), unit: rec.sent_count ? `${rec.received_count} of ${rec.sent_count} payloads` : "after a reconcile", max: 100, target: 100, hi: true, targetText: `${rec.missing_count ?? 0} lost · ${rec.duplicate_records_stored ?? 0} duplicated`, lo: "0", hiLbl: "100" },
    { name: "Alerts per incident", value: q.alert_to_incident_ratio ?? null, show: fmt(q.alert_to_incident_ratio, 1), unit: "noise reduction", max: 10, target: 2, hi: true, targetText: `${q.raw_alerts ?? 0} alerts → ${q.incidents ?? 0} incidents`, lo: "1", hiLbl: "10" },
  ];
  const passed = gauges.filter((g) => g.value != null && ok(g)).length;
  const measured = gauges.filter((g) => g.value != null).length;

  async function download() {
    const r = await fetch(`${CLOUD}/api/v1/slo/export.csv`, { headers: { Authorization: `Bearer ${session()?.token}` } });
    const url = URL.createObjectURL(await r.blob());
    Object.assign(document.createElement("a"), { href: url, download: "veilops-slo-evidence.csv" }).click();
    URL.revokeObjectURL(url);
  }

  return (
    <Shell>
      <div className="sum-page">
        <div className="sum-head">
          <div><div className="eyebrow">Summary · Judge Mode · measured live</div>
            <h1 className="h1">{measured ? `${passed} of ${measured} measured targets met` : "Waiting for the first measurements"}</h1></div>
          <span className="muted" style={{ fontSize: 12 }}>Each ring is computed from stored timestamps, not typed in. The small mark is the target.</span>
        </div>
        <div className="gauges">
          {gauges.map((g) => <Gauge key={g.name} g={g} a={a} />)}
        </div>
        <div className="counts">
          {[[ents.length, "entities (codes only)"], [rec.received_count ?? 0, "payloads received"], [rec.duplicates_rejected ?? 0, "duplicates rejected"],
            [rec.missing_count ?? 0, "payloads missing"], [q.false_alarms ?? 0, "marked false alarm"], [rec.backlog_last_drain_ms != null ? `${(rec.backlog_last_drain_ms / 1000).toFixed(1)} s` : "—", "last backlog drain"]]
            .map(([v, k]) => <div key={k as string}><b>{v as any}</b><span className="muted">{k as string}</span></div>)}
        </div>
        <div className="sum-foot">
          <button className="btn" onClick={download}>Download evidence (CSV)</button>
          <span className="muted">Targets are the CICADA judging limits. Status: {Object.entries(slo?.evaluation ?? {}).map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`).join(" · ")}</span>
        </div>
      </div>
    </Shell>
  );
}

const s = (ms: number | null) => (ms == null ? null : ms / 1000);
const fmt = (v: number | null | undefined, d: number) => (v == null ? "—" : v.toFixed(d));
const ok = (g: G) => (g.hi ? (g.value ?? 0) >= g.target : (g.value ?? Infinity) <= g.target);

function Gauge({ g, a }: { g: G; a: number }) {
  const f = g.value == null ? 0 : Math.max(0, Math.min(1, g.value / g.max));
  const pt = (frac: number, r: number) => { const ang = ((150 + 240 * frac) * Math.PI) / 180; return [100 + r * Math.cos(ang), 96 + r * Math.sin(ang)]; };
  const [x1, y1] = pt(g.target / g.max, 60), [x2, y2] = pt(g.target / g.max, 80);
  const pass = g.value != null && ok(g);
  const col = g.value == null ? "#2a2b30" : pass ? "#e2e4e7" : "#f2c94c";
  return (
    <div className="gauge">
      <svg width="200" height="160" viewBox="0 0 200 160" role="img" aria-label={`${g.name} ${g.show} ${g.unit}, ${g.targetText}`}>
        <circle cx="100" cy="96" r="70" fill="none" stroke="#1d1e22" strokeWidth="10" strokeLinecap="round" strokeDasharray={`${ARC} ${C}`} transform="rotate(150 100 96)" />
        <circle className="arc" cx="100" cy="96" r="70" fill="none" stroke={col} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(ARC * f * a).toFixed(1)} ${C}`} transform="rotate(150 100 96)" />
        <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#9c9fa5" strokeWidth="2" />
        <text x="100" y="98" textAnchor="middle" fill="#f2f3f5" fontSize="30" fontWeight="500" letterSpacing="-1">{g.show}</text>
        <text x="100" y="120" textAnchor="middle" fill="#6b6f76" fontSize="11.5">{g.unit}</text>
        <text x="38" y="154" textAnchor="middle" fill="#4e5157" fontSize="10" fontFamily="JetBrains Mono, monospace">{g.lo}</text>
        <text x="162" y="154" textAnchor="middle" fill="#4e5157" fontSize="10" fontFamily="JetBrains Mono, monospace">{g.hiLbl}</text>
      </svg>
      <span className="nm">{g.name}</span>
      <span className="muted" style={{ fontSize: 12 }}>{g.targetText} · <span style={{ color: g.value == null ? "var(--muted)" : pass ? "var(--text-3)" : "var(--yellow)" }}>{g.value == null ? "no data yet" : pass ? "pass" : "at risk"}</span></span>
    </div>
  );
}
