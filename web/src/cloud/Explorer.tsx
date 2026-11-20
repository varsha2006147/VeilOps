import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { HEALTH, cloud, j, local, short } from "../api";
import { usePoll, useLiveTick, useRange } from "../hooks";
import { Area } from "../ui/charts";

type Ent = { entity: string; kind: string; state?: string | null; reasons?: any; collector_id: string };
export const KEY_METRIC: Record<string, string> = { host: "cpu.util_pct", service: "svc.resp_ms", link: "net.loss_pct" };
export const SIGNALS: Record<string, [string, string, number | null, boolean?][]> = {
  host: [["cpu.util_pct", "CPU %", 90], ["mem.util_pct", "Memory %", 92], ["disk.util_pct", "Disk %", 95], ["net.bw_in_mbps", "Network in Mbps", null]],
  service: [["svc.resp_ms", "Response time ms", 500], ["svc.up", "Up", 0.5, true]],
  link: [["net.loss_pct", "Packet loss %", 5], ["net.latency_ms", "Latency ms", 200], ["net.reachable", "Reachable", 0.5, true]],
};
export const kindOf = (id: string, fallback?: string) => fallback ?? ({ h: "host", svc: "service", lnk: "link" } as any)[id.split("_")[0]] ?? "host";
const fmt = (m: string, v: number | null | undefined) => (v == null ? "—" : m.endsWith("pct") ? `${v.toFixed(v < 10 ? 1 : 0)}%` : m.endsWith("_ms") ? `${Math.round(v)} ms` : m === "svc.up" || m === "net.reachable" ? (v >= 0.5 ? "up" : "down") : v.toFixed(0));

export default function Explorer() {
  const nav = useNavigate();
  const tick = useLiveTick();
  const { minutes } = useRange();
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 5000, [tick]);
  const [topo] = usePoll<any>(() => cloud("/api/v1/topology"), 15000);
  const [inc] = usePoll<any>(() => cloud("/api/v1/incidents?status=open&limit=5"), 5000, [tick]);
  const [view, setView] = useState<"map" | "navigator" | "list">("map");
  const [sel, setSel] = useState<string | null>(null);
  const [latest, setLatest] = useState<Record<string, number | null>>({});
  const ents: Ent[] = fleet?.entities ?? [];
  const byId = useMemo(() => Object.fromEntries(ents.map((e) => [e.entity, e])), [ents]);
  const health = (id: string) => byId[id]?.state ?? null;
  const col = (id: string) => HEALTH[health(id) ?? ""] ?? "var(--muted)";

  // latest key metric per entity, for map labels and the entity list
  useEffect(() => {
    if (!ents.length) return;
    Promise.all(ents.map(async (e) => {
      const m = KEY_METRIC[kindOf(e.entity, e.kind)];
      const r = await cloud(`/api/v1/entities/${e.entity}/metrics?limit=40`).catch(() => ({ metrics: [] }));
      const row = (r.metrics as any[]).find((x) => x.metric === m);
      return [e.entity, row ? row.avg ?? row.max : null] as const;
    })).then((rows) => setLatest(Object.fromEntries(rows)));
  }, [fleet]); // eslint-disable-line

  const order = ["Poor", "Fair", "Good", "Excellent"];
  const sorted = [...ents].sort((a, b) => (order.indexOf(a.state ?? "Excellent") + 4) % 5 - (order.indexOf(b.state ?? "Excellent") + 4) % 5);
  const selected = sel ?? sorted[0]?.entity ?? null;
  const open: any[] = inc?.incidents ?? [];

  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="h">Service map</span>
          <span className="muted">{ents.length} entities · {topo?.edges?.length ?? 0} connections · names are codes; real names stay with the customer</span>
          <div style={{ flex: 1 }} />
          <div className="seg">{(["map", "navigator", "list"] as const).map((v) => <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{v[0].toUpperCase() + v.slice(1)}</button>)}</div>
        </div>
        <div className="box" style={{ position: "relative", minHeight: 420 }}>
          {view === "map" && <ServiceMap topo={topo} ents={ents} col={col} latest={latest} sel={selected} onPick={setSel} onOpen={(id) => nav(`/entities/${id}`)} />}
          {view === "navigator" && <Navigator ents={sorted} col={col} sel={selected} onPick={setSel} />}
          {view === "list" && <EntityTable ents={sorted} col={col} latest={latest} onOpen={(id) => nav(`/entities/${id}`)} />}
          <Simulate />
        </div>
        {selected && <Golden id={selected} kind={kindOf(selected, byId[selected]?.kind)} minutes={minutes} tick={tick} />}
      </section>
      <aside className="rail">
        <div style={{ display: "flex", justifyContent: "space-between" }}><span className="h2">Issues</span><span className="muted" style={{ fontSize: 12 }}>grouped by the AI engine</span></div>
        {open.slice(0, 3).map((i) => (
          <Link key={i.incident_id} to={`/incidents/${i.incident_id}`} className="fade" style={{ border: "1px solid var(--line2)", borderLeft: "3px solid var(--crit)", borderRadius: 6, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 6, background: "#121418" }}>
            <span style={{ fontSize: 11.5 }}><span className="crit">{String(i.severity).toUpperCase()}</span> <span className="muted">· root cause {short(i.root_cause_entity)}</span></span>
            <span style={{ color: "var(--hi)", fontWeight: 500, lineHeight: 1.4 }}>{i.title}</span>
            <span className="t3" style={{ fontSize: 12, lineHeight: 1.55, display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{i.summary}</span>
            <span style={{ fontSize: 12 }}>Open incident →</span>
          </Link>
        ))}
        {!open.length && <div className="empty">Nothing needs you right now.</div>}
        <span className="h2" style={{ marginTop: 6 }}>Entities</span>
        <div className="tbl">
          <div className="tr th" style={{ gridTemplateColumns: "14px minmax(0,1fr) 70px" }}><span /><span>code</span><span style={{ textAlign: "right" }}>key signal</span></div>
          {sorted.map((e) => (
            <div key={e.entity} className="tr click" style={{ gridTemplateColumns: "14px minmax(0,1fr) 70px", background: e.entity === selected ? "var(--hover)" : undefined }} onClick={() => setSel(e.entity)} onDoubleClick={() => nav(`/entities/${e.entity}`)}>
              <span className="dot" style={{ background: col(e.entity) }} />
              <span style={{ display: "flex", flexDirection: "column" }}><span className="mono" style={{ fontSize: 12 }}>{e.entity}</span><span className="muted" style={{ fontSize: 11 }}>{kindOf(e.entity, e.kind)} · {e.state ?? "no health yet"}</span></span>
              <span style={{ textAlign: "right", fontSize: 12, color: col(e.entity) }}>{fmt(KEY_METRIC[kindOf(e.entity, e.kind)], latest[e.entity])}</span>
            </div>
          ))}
        </div>
        <span className="muted" style={{ marginTop: "auto", fontSize: 11.5, lineHeight: 1.6 }}>This cloud stores codes, numbers and counts. Real names are visible only on the customer's collector console.</span>
      </aside>
    </div>
  );
}

function ServiceMap({ topo, ents, col, latest, sel, onPick, onOpen }: { topo: any; ents: Ent[]; col: (id: string) => string; latest: Record<string, number | null>; sel: string | null; onPick: (id: string) => void; onOpen: (id: string) => void }) {
  const edges: { src: string; dst: string; rel: string }[] = topo?.edges ?? [];
  const ids = [...new Set([...edges.flatMap((e) => [e.src, e.dst]), ...ents.map((e) => e.entity)])];
  // columns: services -> hosts -> links -> upstream links
  const colOf = (id: string) => {
    const k = kindOf(id);
    if (k === "service") return 0;
    if (k === "host") return 1;
    return edges.some((e) => e.dst === id && e.src.startsWith("lnk_")) ? 3 : 2;
  };
  const cols: string[][] = [[], [], [], []];
  ids.sort().forEach((id) => cols[colOf(id)].push(id));
  const W = 860, H = 420, BW = 140, BH = 46;
  const used = cols.map((c, i) => (c.length ? i : -1)).filter((i) => i >= 0);
  const pos: Record<string, [number, number]> = {};
  used.forEach((ci, k) => {
    const x = 20 + (k * (W - BW - 40)) / Math.max(1, used.length - 1);
    cols[ci].forEach((id, j) => { pos[id] = [x, ((j + 1) * H) / (cols[ci].length + 1) - BH / 2]; });
  });
  if (!ids.length) return <div className="muted" style={{ padding: 24 }}>Waiting for the first collector to send its network map…</div>;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Service map with live traffic">
      <defs><radialGradient id="glow"><stop offset="0" stopColor="#EB5757" stopOpacity=".35" /><stop offset="1" stopColor="#EB5757" stopOpacity="0" /></radialGradient></defs>
      {edges.map((e, k) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        const [x1, y1, x2, y2] = a[0] < b[0] ? [a[0] + BW, a[1] + BH / 2, b[0], b[1] + BH / 2] : [b[0] + BW, b[1] + BH / 2, a[0], a[1] + BH / 2];
        const mx = (x1 + x2) / 2, d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
        const bad = [e.src, e.dst].some((id) => col(id) === "var(--crit)");
        const dur = `${2.2 + (k % 3) * 0.5}s`;
        return (
          <g key={k}>
            <path d={d} fill="none" stroke={bad ? "#5A3034" : "#2A2E35"} strokeWidth="1.4" strokeDasharray={bad ? "4 4" : undefined} />
            {[0, 0.5].map((off) => <circle key={off} r="2.6" fill={bad ? "#EB5757" : "#9AA0A8"} opacity={bad ? 0.4 : 0.9}>
              <animateMotion dur={dur} begin={`${off * (2.2 + (k % 3) * 0.5)}s`} repeatCount="indefinite" path={d} /></circle>)}
          </g>
        );
      })}
      {ids.map((id) => {
        const p = pos[id];
        if (!p) return null;
        const c = col(id), crit = c === "var(--crit)", k = kindOf(id);
        return (
          <g key={id} style={{ cursor: "pointer" }} onClick={() => onPick(id)} onDoubleClick={() => onOpen(id)}>
            {crit && <circle cx={p[0] + BW / 2} cy={p[1] + BH / 2} r="44" fill="url(#glow)" />}
            <rect x={p[0]} y={p[1]} width={BW} height={BH} rx="8" fill="#14171B" stroke={id === sel ? "#9AA0A8" : crit ? "#5A3034" : "#2A2E35"} strokeWidth={id === sel ? 1.5 : 1} />
            <circle cx={p[0] + 14} cy={p[1] + BH / 2} r="4" fill={c} />
            <text x={p[0] + 26} y={p[1] + 20} fill="#F4F5F7" fontSize="12" fontFamily="JetBrains Mono, monospace">{short(id, 12)}</text>
            <text x={p[0] + 26} y={p[1] + 35} fill="#6E747C" fontSize="11">{k} · {fmt(KEY_METRIC[k], latest[id])}</text>
          </g>
        );
      })}
    </svg>
  );
}

function Navigator({ ents, col, sel, onPick }: { ents: Ent[]; col: (id: string) => string; sel: string | null; onPick: (id: string) => void }) {
  return (
    <div style={{ padding: 16, display: "flex", flexWrap: "wrap", gap: 6 }}>
      {ents.map((e) => (
        <button key={e.entity} title={`${e.entity} · ${e.state ?? "no health yet"}`} onClick={() => onPick(e.entity)}
          style={{ width: 54, height: 54, borderRadius: 8, border: e.entity === sel ? "1.5px solid #9AA0A8" : "1px solid var(--line2)", background: "#14171B", cursor: "pointer", display: "grid", placeItems: "center" }}>
          <span className="dot" style={{ width: 16, height: 16, background: col(e.entity) }} />
        </button>
      ))}
    </div>
  );
}

function EntityTable({ ents, col, latest, onOpen }: { ents: Ent[]; col: (id: string) => string; latest: Record<string, number | null>; onOpen: (id: string) => void }) {
  const g = "14px 160px 90px 110px minmax(0,1fr)";
  return (
    <div className="tbl" style={{ padding: "8px 14px" }}>
      <div className="tr th" style={{ gridTemplateColumns: g }}><span /><span>code</span><span>kind</span><span>key signal</span><span>reasons</span></div>
      {ents.map((e) => (
        <div key={e.entity} className="tr click" style={{ gridTemplateColumns: g }} onClick={() => onOpen(e.entity)}>
          <span className="dot" style={{ background: col(e.entity) }} /><span className="mono" style={{ fontSize: 12 }}>{e.entity}</span>
          <span className="t3">{kindOf(e.entity, e.kind)}</span><span>{fmt(KEY_METRIC[kindOf(e.entity, e.kind)], latest[e.entity])}</span>
          <span className="muted" style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{j<string[]>(e.reasons, []).join(" · ")}</span>
        </div>
      ))}
    </div>
  );
}

function Simulate() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => { local("/local/status").then(() => setOk(true)).catch(() => setOk(false)); }, []);
  if (!ok) return null;   // only shown when this machine can reach a collector (single-laptop demo)
  const run = (s: string) => local(`/local/chaos/${s}`, { method: "POST" }).catch(() => {});
  return (
    <div style={{ position: "absolute", right: 12, top: 10, display: "flex", gap: 6, alignItems: "center" }}>
      <span className="muted" style={{ fontSize: 11.5 }}>Simulate</span>
      <button className="btn" onClick={() => run("latency")}>Link failure</button>
      <button className="btn" onClick={() => run("cpu_drift")}>CPU runaway</button>
    </div>
  );
}

export function Golden({ id, kind, minutes, tick, big = false }: { id: string; kind: string; minutes: number; tick: number; big?: boolean }) {
  const [rows] = usePoll<any>(() => cloud(`/api/v1/entities/${id}/metrics?since=${encodeURIComponent(new Date(Date.now() - minutes * 60e3).toISOString())}&limit=2000`), 5000, [id, minutes, tick]);
  const series = (m: string) => ((rows?.metrics ?? []) as any[]).filter((r) => r.metric === m).map((r) => [+new Date(r.event_ts), r.avg ?? r.max] as [number, number]).sort((a, b) => a[0] - b[0]);
  return (
    <>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}><span className="h2">Golden signals</span><span className="mono t3">{id}</span><span className="muted">{kind} · 5 s windows · last {minutes} min</span></div>
      <div style={{ display: "grid", gap: 12, gridTemplateColumns: `repeat(${SIGNALS[kind].length}, minmax(0,1fr))` }}>
        {SIGNALS[kind].map(([m, label, th, below]) => {
          const s = series(m), v = s.at(-1)?.[1];
          const hot = th != null && v != null && (below ? v <= th : v >= th);
          return (
            <div key={m} className="box" style={{ padding: "10px 12px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }} className="t3"><span>{label}</span><span style={{ color: hot ? "var(--crit)" : "var(--t3)" }}>{fmt(m, v)}</span></div>
              <Area points={s} threshold={th} height={big ? 90 : 54} below={below} />
              <div className="muted" style={{ fontSize: 11 }}>{th != null ? `threshold ${below ? "below " : ""}${th}` : "no threshold"}</div>
            </div>
          );
        })}
      </div>
    </>
  );
}
