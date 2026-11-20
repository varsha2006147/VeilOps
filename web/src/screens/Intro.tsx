import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./intro.css";

/* A 30-second story, drawn live in SVG (no video): what VeilOps does, in six acts. */
const ACTS = [
  { at: 0, title: "Your servers write logs full of secrets.", sub: "Passwords, user names, IP addresses, host names." },
  { at: 5, title: "VeilOps reads them inside your network.", sub: "A collector runs next to your servers. Raw logs never leave." },
  { at: 10, title: "Secrets are removed. Names become codes.", sub: "Redacted before anything is sent. The naming key stays with you." },
  { at: 15, title: "Only the shape of operations crosses.", sub: "Numbers, codes and counts, signed and receipted. A payload with a secret is stopped." },
  { at: 20, title: "The cloud finds the cause. Six alerts, one incident.", sub: "Learned baselines and the network map point to the root cause." },
  { at: 25, title: "A person approves. The fix runs safely.", sub: "Snapshot, dry run, execute, verify, and roll back if health does not improve." },
];
const END = 31;

const HOSTS = [
  { name: "app-01", code: "h_7f3a21c90b", y: 150 },
  { name: "app-02", code: "h_19c0e8a4d2", y: 260 },
  { name: "db-01", code: "h_b52e07f13c", y: 370 },
  { name: "core-sw1", code: "lnk_84c24eda", y: 480 },
];
const LOGS: { host: number; raw: string; secret?: [number, number]; clean: string }[] = [
  { host: 0, raw: "GET /checkout 200 182ms user=asha.k@acme.in", secret: [27, 41], clean: "GET /checkout 200 182ms user=usr_3b91c0" },
  { host: 2, raw: "db connect user=svc_pay password=Hunter2!", secret: [33, 41], clean: "db connect user=svc_pay password=[REDACTED]" },
  { host: 1, raw: "Failed password for admin from 203.0.113.9", secret: [31, 42], clean: "Failed password for usr_8e21aa from src_5c1d" },
  { host: 0, raw: "worker pid 4412 cpu 34% rps 118", clean: "worker cpu 34% rps 118" },
  { host: 3, raw: "uplink loss 0.1% rtt 2ms", clean: "uplink loss 0.1% rtt 2ms" },
  { host: 2, raw: "AKIAIOSFODNN7EXAMPLE rotated", secret: [0, 20], clean: "[REDACTED] rotated" },
];

const clamp = (v: number, a = 0, b = 1) => Math.max(a, Math.min(b, v));
const ease = (v: number) => 1 - Math.pow(1 - clamp(v), 3);
const span = (t: number, start: number, dur: number) => ease((t - start) / dur);

export default function Intro() {
  const nav = useNavigate();
  const [t, setT] = useState(0);
  const [paused, setPaused] = useState(false);
  const raf = useRef(0);
  const last = useRef<number | null>(null);
  const reduced = useMemo(() => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches, []);

  useEffect(() => {
    if (reduced) { setT(END); return; }
    const step = (now: number) => {
      if (last.current != null && !paused) setT((v) => Math.min(END, v + (now - last.current!) / 1000));
      last.current = now;
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [paused, reduced]);

  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === " ") { e.preventDefault(); setPaused((p) => !p); }
      if (e.key === "Escape" || e.key === "Enter") nav("/login");
      if (e.key === "ArrowRight") setT((v) => Math.min(END, Math.floor(v / 5) * 5 + 5));
      if (e.key === "ArrowLeft") setT((v) => Math.max(0, Math.floor(v / 5) * 5 - 5));
    };
    addEventListener("keydown", key);
    return () => removeEventListener("keydown", key);
  }, [nav]);

  const act = Math.min(ACTS.length - 1, ACTS.filter((a) => t >= a.at).length - 1);
  const done = t >= END - 0.01;
  const cpu = t < 20 ? 34 : t < 21.5 ? 34 + (t - 20) * 41 : t < 28.5 ? 96 : Math.max(31, 96 - (t - 28.5) * 60);

  return (
    <div className="intro">
      <header className="intro-top">
        <span className="brand"><Shield /> VeilOps</span>
        <span className="muted mono">{String(act + 1).padStart(2, "0")} / 06</span>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={() => setPaused((p) => !p)}>{paused ? "Play" : "Pause"}</button>
        <button className="btn" onClick={() => nav("/login")}>Skip intro</button>
      </header>

      <svg className="stage" viewBox="0 0 1440 640" role="img" aria-label="Animated explanation of how VeilOps keeps secrets inside the customer network">
        <defs>
          <pattern id="stripes" width="14" height="14" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="14" height="14" fill="#0b0c0e" /><rect width="7" height="14" fill="#0f1013" />
          </pattern>
        </defs>

        {/* zones */}
        <text x="60" y="70" className="zone">INSIDE ACME'S NETWORK</text>
        <text x="1000" y="70" className="zone">VEILOPS CLOUD · METADATA ONLY</text>
        <rect x="830" y="90" width="110" height="520" fill="url(#stripes)" opacity={span(t, 4, 2)} />
        <line x1="830" x2="830" y1="90" y2="610" stroke="#2a2b30" />
        <line x1="940" x2="940" y1="90" y2="610" stroke="#2a2b30" />
        <text x="885" y="112" textAnchor="middle" className="zone small" opacity={span(t, 4, 2)}>BOUNDARY</text>

        {/* hosts: real names morph into pseudonyms in act 3 */}
        {HOSTS.map((h, i) => {
          const show = span(t, 0.2 + i * 0.25, 0.8);
          const morph = span(t, 11 + i * 0.4, 0.9);
          return (
            <g key={h.name} opacity={show} transform={`translate(60 ${h.y})`}>
              <rect width="170" height="64" rx="6" fill="#0d0e10" stroke={morph > 0.5 ? "#3a3c42" : "#2a2b30"} />
              <text x="16" y="28" className="host" opacity={1 - morph}>{h.name}</text>
              <text x="16" y="28" className="host mono code" opacity={morph}>{h.code}</text>
              <text x="16" y="48" className="tiny">{i === 3 ? "link" : "host"}{i === 0 && t > 20 ? ` · cpu ${Math.round(cpu)}%` : ""}</text>
              {i === 0 && t > 20 && t < 29 && <rect width="170" height="64" rx="6" fill="none" stroke="#eb5757" opacity={0.6 + 0.4 * Math.sin(t * 6)} />}
            </g>
          );
        })}

        {/* logs stream out, secrets underlined red; scanner redacts them */}
        {LOGS.map((l, i) => {
          const appear = span(t, 0.8 + i * 0.6, 0.5);
          const y = 150 + i * 62;
          const scan = clamp((t - 10.2) / 3.2);              // scanner sweeps top -> bottom
          const cleaned = scan * LOGS.length > i + 0.5;
          const inflow = span(t, 6 + i * 0.25, 1.4);           // lines drift into the collector
          const x = 270 + inflow * 120;
          const text = cleaned ? l.clean : l.raw;
          return (
            <g key={i} opacity={appear * (t > 15.5 ? Math.max(0.25, 1 - (t - 15.5) / 2) : 1)}>
              <text x={x} y={y + 22} className="log mono">{text}</text>
              {l.secret && !cleaned && (
                <line x1={x + l.secret[0] * 7.25} x2={x + l.secret[1] * 7.25} y1={y + 27} y2={y + 27} stroke="#eb5757" strokeWidth="1.5" />
              )}
              {cleaned && l.secret && <text x={x - 16} y={y + 22} className="tick">✓</text>}
            </g>
          );
        })}
        {t > 10 && t < 13.6 && (
          <line x1="260" x2="800" y1={150 + clamp((t - 10.2) / 3.2) * 372} y2={150 + clamp((t - 10.2) / 3.2) * 372} stroke="#e2e4e7" strokeOpacity=".5" />
        )}

        {/* collector at the boundary */}
        <g opacity={span(t, 5, 1)} transform="translate(700 270)">
          <rect width="110" height="110" rx="8" fill="#111215" stroke="#3a3c42" />
          <text x="55" y="48" textAnchor="middle" className="host">collector</text>
          <text x="55" y="68" textAnchor="middle" className="tiny">redact · code · sign</text>
          <text x="55" y="88" textAnchor="middle" className="tiny mono">raw stays here</text>
        </g>

        {/* payload chips cross the boundary; one with a secret is stopped */}
        {[0, 1, 2, 3, 4, 5].map((i) => {
          const start = 15.4 + i * 0.6;
          const p = clamp((t - start) / 1.6);
          if (p <= 0) return null;
          const blocked = i === 3;
          const x = blocked ? 812 + Math.min(p, 0.35) * 40 : 812 + p * 230;
          const y = 300 + ((i * 37) % 70);
          const fade = blocked ? 1 : 1 - clamp((p - 0.9) * 10);
          return (
            <g key={i} transform={`translate(${x} ${y})`} opacity={fade}>
              <rect width="106" height="24" rx="4" fill="#0b0c0e" stroke={blocked ? "#eb5757" : "#3a3c42"} />
              <text x="9" y="16" className="chip mono" fill={blocked ? "#eb5757" : "#b9bcc2"}>
                {blocked ? "#1043 ✕ secret" : `#${1038 + i} h_7f3a`}
              </text>
            </g>
          );
        })}
        {t > 17.5 && t < 20.5 && <text x="885" y="590" textAnchor="middle" className="tiny red">payload #1043 blocked</text>}

        {/* cloud: lanes, six alerts collapse into one incident */}
        <g transform="translate(1000 130)">
          {["cpu · h_7f3a", "latency · svc_c43e", "errors · svc_c43e", "requests / s", "rtt · lnk_84c2"].map((name, i) => {
            const vis = span(t, 16 + i * 0.3, 1);
            const y = 30 + i * 70;
            const spike = i < 3 && t > 20.5 ? Math.min(1, (t - 20.5) / 1.2) * (t > 28.6 ? Math.max(0, 1 - (t - 28.6)) : 1) : 0;
            const pts = Array.from({ length: 40 }, (_, k) => {
              const base = 10 + Math.sin(k * 0.8 + i) * 3;
              const s = k > 26 ? spike * (i === 0 ? 34 : 24) : 0;
              return `${k * 9},${y + 20 - base * 0.6 - s}`;
            }).join(" ");
            return (
              <g key={name} opacity={vis}>
                <text x="0" y={y - 6} className="tiny">{name}</text>
                <line x1="0" x2="360" y1={y + 20} y2={y + 20} stroke="#1b1c20" />
                <polyline points={pts} fill="none" stroke={i < 3 && spike > 0 ? "#e2e4e7" : "#6b6f76"} strokeWidth="1.3" />
              </g>
            );
          })}
          {[0, 1, 2, 3, 4, 5].map((k) => {
            const lane = k % 3;
            const p = span(t, 21 + k * 0.25, 0.4);
            const collapse = span(t, 23, 1);
            const cx = 250 + (k > 2 ? 40 : 0);
            const cy = 30 + lane * 70 + (k > 2 ? -14 : -4);
            return <circle key={k} cx={cx} cy={cy} r={4} fill="#0b0c0e" stroke="#eb5757" strokeWidth="1.5" opacity={p * (1 - collapse * 0.6)} />;
          })}
          <g opacity={span(t, 23, 0.8)}>
            <rect x="225" y="-2" width="110" height="200" rx="6" fill="rgba(235,87,87,.05)" stroke="#eb5757" strokeDasharray="4 3" />
            <text x="225" y="-10" className="chip mono" fill="#eb5757">INC-014 · 6 alerts → 1</text>
            <text x="0" y="375" className="caption-small">Root cause <tspan className="mono" fill="#f2f3f5">h_7f3a21c90b</tspan> · CPU runaway, requests flat · confidence 0.84</text>
          </g>
        </g>

        {/* act 6: approval and safe execution */}
        <g opacity={span(t, 25, 0.6)} transform="translate(1000 540)">
          {["approve", "snapshot", "dry run", "restart", "verified"].map((s, i) => {
            const on = t > 25.6 + i * 0.7;
            return (
              <g key={s} transform={`translate(${i * 82} 0)`}>
                <rect width="74" height="26" rx="5" fill={on ? (i === 4 ? "rgba(76,183,130,.12)" : "#17181b") : "#0b0c0e"} stroke={on ? (i === 4 ? "#4cb782" : "#3a3c42") : "#1b1c20"} />
                <text x="37" y="17" textAnchor="middle" className="chip" fill={on ? (i === 4 ? "#4cb782" : "#e2e4e7") : "#4e5157"}>{i === 4 && on ? "✓ verified" : s}</text>
              </g>
            );
          })}
        </g>
      </svg>

      <footer className="intro-caption">
        {!done ? (
          <div key={act} className="caption-in">
            <h1>{ACTS[act].title}</h1>
            <p>{ACTS[act].sub}</p>
          </div>
        ) : (
          <div className="caption-in">
            <h1>The SaaS sees the shape of operations, never the secrets.</h1>
            <div className="cta">
              <button className="btn primary" onClick={() => nav("/login")}>Enter VeilOps</button>
              <button className="btn" onClick={() => setT(0)}>Replay</button>
            </div>
          </div>
        )}
        <div className="progress"><span style={{ width: `${(t / END) * 100}%` }} /></div>
        <div className="acts">
          {ACTS.map((a, i) => (
            <button key={i} className={i === act && !done ? "on" : ""} onClick={() => setT(a.at)} aria-label={`Go to step ${i + 1}`}>{String(i + 1).padStart(2, "0")}</button>
          ))}
        </div>
      </footer>
    </div>
  );
}

export function Shield() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true">
      <path d="M12 3l8 3v6c0 4.5-3.2 8-8 9.5C7.2 20 4 16.5 4 12V6z" />
    </svg>
  );
}
