import { Link, useParams } from "react-router-dom";
import { HEALTH, cloud, hhmmss, j, short } from "../api";
import { usePoll, useLiveTick, useRange } from "../hooks";
import { Golden, kindOf } from "./Explorer";

export default function Entity() {
  const { code = "" } = useParams();
  const tick = useLiveTick();
  const { minutes } = useRange();
  const [fleet] = usePoll<any>(() => cloud("/api/v1/fleet"), 5000, [tick]);
  const [hist] = usePoll<any>(() => cloud(`/api/v1/entities/${code}/health-history`), 10000, [code, tick]);
  const [topo] = usePoll<any>(() => cloud("/api/v1/topology"), 30000);
  const [al] = usePoll<any>(() => cloud(`/api/v1/alerts?limit=200`), 5000, [tick]);
  const e = (fleet?.entities ?? []).find((x: any) => x.entity === code);
  const kind = kindOf(code, e?.kind);
  const related = (topo?.edges ?? []).filter((x: any) => x.src === code || x.dst === code);
  const alerts = (al?.alerts ?? []).filter((a: any) => a.entity === code);
  const trans: any[] = hist?.transitions ?? [];
  const [incs] = usePoll<any>(() => cloud("/api/v1/incidents?limit=100"), 10000, [tick]);
  const involved = (incs?.incidents ?? []).filter((i: any) => i.root_cause_entity === code || String(i.summary ?? "").includes(code));
  const col = (fleet?.collectors ?? []).find((c: any) => c.collector_id === e?.collector_id);
  if (fleet && !e) return <section className="page"><span className="h">{code}</span><div className="empty">No entity with this code in this tenant.</div></section>;
  return (
    <div className="split">
      <section className="page">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="dot" style={{ width: 10, height: 10, background: HEALTH[e?.state] ?? "var(--muted)" }} />
          <span className="h mono">{code}</span><span className="muted">{kind} · {e?.state ?? "no health yet"} · {j<string[]>(e?.reasons, []).join(" · ")}</span>
        </div>
        <Golden id={code} kind={kind} minutes={minutes} tick={tick} big />
        <span className="h2">Health history</span>
        <div className="tbl box" style={{ padding: "4px 14px" }}>
          {trans.slice(0, 12).map((t, k) => (
            <div key={k} className="tr" style={{ gridTemplateColumns: "80px 170px minmax(0,1fr)" }}>
              <span className="t3">{hhmmss(t.at_utc)}</span>
              <span><span style={{ color: HEALTH[t.from_state] }}>{t.from_state ?? "—"}</span> → <span style={{ color: HEALTH[t.to_state] }}>{t.to_state}</span></span>
              <span className="muted" style={{ fontSize: 12 }}>{j<string[]>(t.reasons, []).join(" · ")}</span>
            </div>
          ))}
          {!trans.length && <div className="empty">No health changes recorded.</div>}
        </div>
      </section>
      <aside className="rail">
        <span className="h2">About</span>
        <div className="tbl">
          {[["Code", code], ["Kind", kind], ["Health", `${e?.state ?? "—"} since ${hhmmss(e?.since)}`], ["Last data", hhmmss(e?.last_data_ts)],
            ["Reported by", e?.collector_id], ["Region", String(col?.region ?? "—").toUpperCase()], ["Real name", "known only on the customer's collector"]].map(([k, v]) => (
            <div key={k} className="tr" style={{ gridTemplateColumns: "100px minmax(0,1fr)" }}><span className="t3">{k}</span><span className={k === "Code" || k === "Reported by" ? "mono" : ""} style={{ fontSize: 12.5 }}>{v}</span></div>
          ))}
        </div>
        <span className="h2">Incidents involving it</span>
        <div className="tbl">
          {involved.slice(0, 6).map((i: any) => (
            <Link key={i.incident_id} to={`/incidents/${i.incident_id}`} className="tr click" style={{ gridTemplateColumns: "minmax(0,1fr) 64px" }}>
              <span style={{ display: "flex", flexDirection: "column" }}><span style={{ fontSize: 12.5, color: "var(--hi)" }}>{i.title}</span><span className="muted" style={{ fontSize: 11 }}>{hhmmss(i.opened_at)} · {i.root_cause_entity === code ? "root cause" : "affected"}</span></span>
              <span className={i.status === "open" ? "crit" : "muted"} style={{ textAlign: "right", fontSize: 12 }}>{i.status}</span>
            </Link>
          ))}
          {!involved.length && <span className="muted">None so far.</span>}
        </div>
        <span className="h2">Related entities</span>
        <div className="tbl">
          {related.map((r: any, k: number) => { const other = r.src === code ? r.dst : r.src; return (
            <Link key={k} to={`/entities/${other}`} className="tr click" style={{ gridTemplateColumns: "minmax(0,1fr) 90px" }}>
              <span className="mono" style={{ fontSize: 12 }}>{other}</span><span className="muted" style={{ fontSize: 11.5 }}>{r.src === code ? r.rel : `← ${r.rel}`}</span>
            </Link>); })}
          {!related.length && <span className="muted">No connections reported.</span>}
        </div>
        <span className="h2">Alerts</span>
        <div className="tbl">
          {alerts.slice(0, 15).map((a: any) => (
            <div key={a.alert_id} className="tr" style={{ gridTemplateColumns: "minmax(0,1fr) 60px" }}>
              <span style={{ display: "flex", flexDirection: "column" }}><span style={{ fontSize: 12, color: a.status === "open" ? "var(--crit)" : "var(--t3)" }}>{a.rule}</span>
                <span className="muted" style={{ fontSize: 11 }}>{hhmmss(a.first_ts)} · {a.occurrences}× · {a.severity}</span></span>
              <span className="muted" style={{ textAlign: "right", fontSize: 11.5 }}>{a.status}</span>
            </div>
          ))}
          {!alerts.length && <span className="muted">No alerts for {short(code)}.</span>}
        </div>
      </aside>
    </div>
  );
}
