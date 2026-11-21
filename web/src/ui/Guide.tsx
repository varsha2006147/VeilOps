import { ReactNode, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { DEMO_USERS, cloud, local, session, signInAs } from "../api";
import { usePoll } from "../hooks";

/** A guided walkthrough for evaluators: one step at a time, each ticked off by real data, never by a timer. */
type Snap = Record<string, any>;
type Step = { title: string; what: ReactNode; watch: ReactNode; go?: { label: string; run?: () => void; to?: string }; done?: (s: Snap, base: Snap) => boolean };

const store = {
  get: (k: string, d: any) => { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set: (k: string, v: any) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};
const chaos = (s: string) => () => { local(`/local/chaos/${s}`, { method: "POST" }).catch(() => {}); };

const SITE: Step[] = [
  { title: "Data starts flowing in", what: "The collector reads raw events from this site's systems: host metrics, network probes, logs and the event stream.",
    watch: <>The <b>Read</b> number at the top left climbs every second.</>, done: (s) => (s.raw ?? 0) > 0 },
  { title: "Names become codes", what: "Before anything leaves, every real name (app-01, checkout) is replaced by a code, and raw events are reduced to 5-second summaries.",
    watch: <>Compare <b>Stays here</b> (real host name, raw event) with <b>Crosses</b> (a code, numbers only).</>, done: (s) => (s.codes ?? 0) > 0 },
  { title: "The cloud confirms receipt", what: "Summaries are signed, chained to the previous payload and sent. The cloud returns a signed receipt for each one.",
    watch: <><b>Cloud confirmed</b> shows a payload number. On the cloud dashboard, the same systems now appear, as codes only.</>, done: (s) => (s.acked ?? 0) > 0 },
  { title: "A password leaks into a log", what: "We inject a log line that contains a password, as happens in real incidents.",
    watch: <><b>secrets scrubbed</b> goes up. The password stays on this machine; the cloud never receives it.</>,
    go: { label: "Inject a leaked password", run: chaos("secret") }, done: (s, b) => (s.secrets ?? 0) > (b.secrets ?? 0) },
  { title: "Someone tries to break in", what: "We send repeated failed logins from one address.",
    watch: <>A red <b>auth.bruteforce</b> alert appears on the right within ~10 s, showing the real user and IP. The cloud only gets a code.</>,
    go: { label: "Start failed logins", run: chaos("failed_logins") }, done: (s, b) => (s.security ?? 0) > (b.security ?? 0) },
  { title: "The core network link fails", what: "We make the main network link drop packets. Services behind it slow down.",
    watch: <>Local alerts appear here. Switch to the <b>cloud dashboard</b>: within ~40 s an incident names the link as the root cause and suggests a failover.</>,
    go: { label: "Break the network link", run: chaos("latency") }, done: (s, b) => (s.signals ?? 0) > (b.signals ?? 0) },
  { title: "A fix comes back, approved by two people", what: "On the cloud dashboard: Asha requests the suggested fix, then Ravi approves it. Only then is it sent here.",
    watch: <>Open <b>Boundary & cloud</b>: the fix appears on the right with its 4 steps (snapshot, dry run, execute, verify). This collector could still refuse it.</>,
    go: { label: "Open Boundary & cloud", to: "/boundary" }, done: (s, b) => (s.executed ?? 0) > (b.executed ?? 0) },
  { title: "Cut the network", what: "Turn off this laptop's Wi-Fi (or unplug the cable). The cloud is now unreachable.",
    watch: <>The top right turns to <b>Cloud unreachable</b> and <b>waiting</b> payloads pile up. Nothing is thrown away.</>, done: (s) => s.online === false },
  { title: "Reconnect — nothing lost", what: "Turn the Wi-Fi back on.",
    watch: <>Waiting payloads drain to 0. On the cloud, <b>Boundary & proof</b> shows 0 missing and duplicates rejected, not stored.</>,
    done: (s) => s.sawOffline && s.online === true && (s.held ?? 1) === 0 },
];

const CLOUD: Step[] = [
  { title: "A customer site connects", what: "A collector inside the customer's network enrolled with a one-time token and sends signed summaries.",
    watch: <>The status strip shows <b>1 / 1 collectors online</b>.</>, done: (s) => (s.online ?? 0) > 0 },
  { title: "Systems appear — as codes only", what: "The map is built from what the collector reports. This cloud never sees a real host name, IP or user.",
    watch: <>Hover a moving <b>dot</b>: it is one request route from a service, through its host, out through the links.</>, done: (s) => (s.entities ?? 0) > 0 },
  { title: "Wait for a problem", what: "On the collector console, run step 6 (Break the network link).",
    watch: <>Within ~40 s an <b>issue</b> appears on the right and the dots through the link turn red.</>, done: (s) => (s.open ?? 0) > 0 },
  { title: "Read what the AI concluded", what: "Open the incident. The engine grouped many alerts into one problem and ranked the root cause.",
    watch: <>Click <b>Replay</b> to watch the alerts arrive in order. Each claim in “What happened” has a numbered piece of evidence.</>,
    go: { label: "Open the incident", to: "/incidents" } },
  { title: "Asha requests the fix", what: "Asha is an operator. She can ask for the suggested fix but cannot approve her own request.",
    watch: <>Click <b>Request fix</b>. The steps bar shows <b>Requested</b>.</>, done: (s) => (s.actions ?? 0) > 0 },
  { title: "Ravi approves it", what: "A second person must approve before anything runs on the customer's machine.",
    watch: <>Switch to Ravi, then click <b>Approve</b>.</>,
    go: { label: "Switch to Ravi (approver)", run: () => { signInAs(DEMO_USERS[1].email).then(() => location.reload()); } }, done: (s) => (s.approved ?? 0) > 0 },
  { title: "The fix runs on the site", what: "The collector picks up the approved fix, checks it against its own rules, runs it in 4 steps and reports back.",
    watch: <>The steps bar reaches <b>Executed</b> with a green result. The collector console shows the same steps.</>, done: (s) => (s.executed ?? 0) > 0 },
  { title: "The site goes offline", what: "On the customer laptop, turn off Wi-Fi.",
    watch: <>Within ~30 s <b>Collectors</b> shows it offline. The site keeps everything it collects.</>,
    go: { label: "Open Collectors", to: "/collectors" }, done: (s) => (s.offline ?? 0) > 0 },
  { title: "It reconnects — and we prove nothing was lost", what: "Turn the Wi-Fi back on. The site sends what it held, in order.",
    watch: <><b>Boundary & proof</b> shows <b>0 missing</b>, an outage drained, and any repeats rejected rather than stored.</>,
    go: { label: "Open Boundary & proof", to: "/boundary" }, done: (s, b) => (s.drains ?? 0) > (b.drains ?? 0) && (s.missing ?? 1) === 0 },
];

async function siteSnap(): Promise<Snap> {
  const [st, cl, eg, sig, codes] = await Promise.all([
    local("/local/status").catch(() => ({})), local("/local/cloud").catch(() => ({})), local("/api/egress-proof").catch(() => ({})),
    local("/local/signals?limit=300").catch(() => []), local("/local/codes").catch(() => []),
  ]);
  const o = cl.outbox ?? {};
  return {
    raw: st.pipeline?.raw_in, codes: codes.length, acked: o.last_acked_seq, secrets: eg.redaction_summary?.secrets_scrubbed,
    security: sig.filter((x: any) => x.kind === "security").length, signals: st.pipeline?.signals_out ?? sig.length,
    executed: (cl.actions ?? []).filter((a: any) => a.status === "executed").length, online: cl.online !== false,
    held: (o.highest_seq ?? 0) - (o.last_acked_seq ?? 0),
  };
}
async function cloudSnap(): Promise<Snap> {
  const [fleet, inc, acts, rec] = await Promise.all([
    cloud("/api/v1/fleet").catch(() => ({})), cloud("/api/v1/incidents?status=open&limit=50").catch(() => ({})),
    cloud("/api/v1/actions").catch(() => ({})), cloud("/api/v1/reconciliation").catch(() => ({})),
  ]);
  const cols: any[] = fleet.collectors ?? [], a: any[] = acts.actions ?? [], rc: any[] = rec.collectors ?? [];
  const fresh = (c: any) => Date.now() - +new Date(c.last_heartbeat) < 30e3;
  return {
    online: cols.filter(fresh).length, offline: cols.filter((c) => !fresh(c)).length, entities: (fleet.entities ?? []).length,
    open: (inc.incidents ?? []).length, actions: a.length, approved: a.filter((x) => x.status !== "pending").length,
    executed: a.filter((x) => x.status === "executed").length,
    drains: rc.reduce((s, c) => s + (c.backlog?.episodes ?? 0), 0), missing: rc.reduce((s, c) => s + (c.missing_count ?? 0), 0),
  };
}

export function Guide({ app }: { app: "site" | "cloud" }) {
  const steps = app === "site" ? SITE : CLOUD;
  const key = `veilops.guide.${app}`;
  const [open, setOpen] = useState<boolean>(() => store.get(`${key}.open`, false));
  const [i, setI] = useState<number>(() => store.get(`${key}.step`, 0));
  const [snap] = usePoll<Snap>(() => (open ? (app === "site" ? siteSnap() : cloudSnap()) : Promise.resolve({})), 1500, [open]);
  const base = useRef<Snap>(store.get(`${key}.base`, {}));
  const [ticked, setTicked] = useState<boolean[]>(() => store.get(`${key}.done`, []));
  useEffect(() => { store.set(`${key}.open`, open); }, [open]); // eslint-disable-line
  useEffect(() => { store.set(`${key}.step`, i); }, [i]); // eslint-disable-line
  // Baseline = the numbers at the moment a step becomes current, so "goes up" means "went up because of this step".
  const baseFor = useRef(-1);
  useEffect(() => {
    if (!snap || !Object.keys(snap).length || baseFor.current === i) return;
    if (store.get(`${key}.baseStep`, -1) !== i) { base.current = snap; store.set(`${key}.base`, snap); store.set(`${key}.baseStep`, i); }
    baseFor.current = i;
  }, [snap, i]); // eslint-disable-line
  // A disconnect is a moment, not a state: remember that it happened so the "reconnect" step can tick.
  if (snap?.online === false) store.set(`${key}.sawOffline`, true);
  const live = snap ? { ...snap, sawOffline: store.get(`${key}.sawOffline`, false) } : null;
  const step = steps[i];
  const ok = !!(live && step.done && baseFor.current === i && step.done(live, base.current));
  useEffect(() => { if (ok && !ticked[i]) { const t = [...ticked]; t[i] = true; setTicked(t); store.set(`${key}.done`, t); } }, [ok]); // eslint-disable-line
  const go = (n: number) => setI(Math.max(0, Math.min(steps.length - 1, n)));
  const restart = () => { store.set(`${key}.sawOffline`, false); setTicked([]); store.set(`${key}.done`, []); store.set(`${key}.baseStep`, -1); baseFor.current = -1; setI(0); };
  const role = session()?.user.role;

  if (!open) return <button className="btn guide-open" onClick={() => setOpen(true)}>Guided demo</button>;
  return (
    <div className="guide fade" role="dialog" aria-label="Guided demo">
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span className="muted" style={{ fontSize: 11.5, letterSpacing: ".05em", textTransform: "uppercase" }}>Guided demo · step {i + 1} of {steps.length}</span>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={restart} title="Start again from step 1">Restart</button>
        <button className="btn" onClick={() => setOpen(false)} aria-label="Hide guide">Hide</button>
      </div>
      <div style={{ display: "flex", gap: 3 }}>{steps.map((_, k) => <button key={k} onClick={() => go(k)} title={steps[k].title} style={{ flex: 1, height: 4, border: "none", borderRadius: 2, cursor: "pointer", background: ticked[k] ? "var(--ok)" : k === i ? "var(--t2)" : "var(--line2)" }} />)}</div>
      <div style={{ fontSize: 16, color: "var(--hi)", fontWeight: 500 }}>{step.title}</div>
      <div className="t3" style={{ lineHeight: 1.6 }}>{step.what}</div>
      <div style={{ borderLeft: "2px solid var(--line3)", paddingLeft: 10, lineHeight: 1.6 }}><span className="muted" style={{ fontSize: 11.5 }}>WATCH </span>{step.watch}</div>
      {step.title === "Ravi approves it" && role === "approver" && <div className="ok" style={{ fontSize: 12 }}>You are Ravi now. Open the incident and click Approve.</div>}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {step.go && (step.go.to ? <Link className="btn primary" to={step.go.to}>{step.go.label}</Link> : <button className="btn primary" onClick={step.go.run}>{step.go.label}</button>)}
        <span style={{ fontSize: 12 }} className={ticked[i] ? "ok" : "muted"}>{step.done ? (ticked[i] ? "✓ seen in the live data" : "waiting for it to happen…") : ""}</span>
        <div style={{ flex: 1 }} />
        <button className="btn" disabled={i === 0} onClick={() => go(i - 1)}>Back</button>
        <button className={`btn ${ticked[i] || !step.done ? "primary" : ""}`} disabled={i === steps.length - 1} onClick={() => go(i + 1)}>Next</button>
      </div>
    </div>
  );
}
