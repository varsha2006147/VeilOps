import { ReactNode, useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { session, signOut } from "../api";
import { Shield } from "../screens/Intro";
import "./shell.css";

export default function Shell({ right, children }: { right?: ReactNode; children: ReactNode }) {
  const nav = useNavigate();
  const s = session();
  const [clock, setClock] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setClock(new Date()), 1000); return () => clearInterval(t); }, []);
  return (
    <div className="shell">
      <header className="top">
        <span className="brand"><Shield /> VeilOps</span>
        <span className="muted">{s?.user.tenant_id}</span>
        <nav aria-label="Views">
          <NavLink to="/live">Live</NavLink>
          <NavLink to="/incidents">Incidents</NavLink>
          <NavLink to="/summary">Summary</NavLink>
          <NavLink to="/">How it works</NavLink>
        </nav>
        <div style={{ flex: 1 }} />
        {right}
        <span className="muted mono" style={{ fontSize: 12 }}>{clock.toISOString().slice(11, 19)} UTC</span>
        <button className="btn" title={`${s?.user.name} · ${s?.user.role}`} onClick={() => { signOut(); nav("/login"); }}>
          {s?.user.role} · sign out
        </button>
      </header>
      <main>{children}</main>
    </div>
  );
}
