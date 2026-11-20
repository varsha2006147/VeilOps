import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/jetbrains-mono/400.css";
import "./ui/theme.css";
import { ReactNode, StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { APP, ensureSession, renderAck, subscribe } from "./api";
import { LiveTick, Range } from "./hooks";
import { CloudLayout, SiteLayout } from "./ui/Layout";
import Explorer from "./cloud/Explorer";
import { IncidentDetail, IncidentList } from "./cloud/Incidents";
import Entity from "./cloud/Entity";
import { Boundary, Reliability } from "./cloud/Proof";
import { CloudAudit, Collectors } from "./cloud/Fleet";
import { CloudLink, Feed, Lookup, LocalAlerts, SiteAudit, SiteBoundary } from "./site/Site";

function CloudApp() {
  const [ready, setReady] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [live, setLive] = useState(false);
  const [minutes, set] = useState(15);
  useEffect(() => { document.title = "VeilOps"; ensureSession().then(() => setReady(true)).catch((e) => setErr(String(e?.code ?? e))); }, []);
  useEffect(() => {
    if (!ready) return;
    let last = 0;
    return subscribe((ev, d) => {
      if (ev === "telemetry_processed" && d?.payload_id) requestAnimationFrame(() => renderAck(d.payload_id));
      const now = Date.now();
      if (now - last > 1000) { last = now; setTick((t) => t + 1); }   // coalesce bursts into one refresh per second
    }, setLive);
  }, [ready]);
  if (err) return <div className="page"><div className="banner">The VeilOps cloud is unreachable ({err}). Check that the cloud laptop is on this network.</div></div>;
  if (!ready) return null;
  const L = (crumb: string, el: ReactNode) => <CloudLayout crumb={crumb} live={live}>{el}</CloudLayout>;
  return (
    <LiveTick.Provider value={tick}>
      <Range.Provider value={{ minutes, set }}>
        <Routes>
          <Route path="/" element={L("Explorer", <Explorer />)} />
          <Route path="/incidents" element={L("Incidents", <IncidentList />)} />
          <Route path="/incidents/:id" element={L("Incident", <IncidentDetail />)} />
          <Route path="/entities/:code" element={L("Entity", <Entity />)} />
          <Route path="/boundary" element={L("Boundary & proof", <Boundary />)} />
          <Route path="/reliability" element={L("Reliability", <Reliability />)} />
          <Route path="/collectors" element={L("Collectors", <Collectors />)} />
          <Route path="/audit" element={L("Audit", <CloudAudit />)} />
          <Route path="*" element={L("Not found", <div className="page empty">No such page.</div>)} />
        </Routes>
      </Range.Provider>
    </LiveTick.Provider>
  );
}

function SiteApp() {
  const L = (crumb: string, el: ReactNode) => <SiteLayout crumb={crumb}>{el}</SiteLayout>;
  return (
    <Routes>
      <Route path="/" element={L("Local feed", <Feed />)} />
      <Route path="/boundary" element={L("Boundary", <SiteBoundary />)} />
      <Route path="/cloud-link" element={L("Cloud link", <CloudLink />)} />
      <Route path="/lookup" element={L("Look up a code", <Lookup />)} />
      <Route path="/alerts" element={L("Local alerts", <LocalAlerts />)} />
      <Route path="/audit" element={L("Audit", <SiteAudit />)} />
      <Route path="*" element={L("Not found", <div className="page empty">No such page.</div>)} />
    </Routes>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode><BrowserRouter>{APP === "site" ? <SiteApp /> : <CloudApp />}</BrowserRouter></StrictMode>,
);
