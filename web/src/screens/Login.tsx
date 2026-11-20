import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { signIn } from "../api";
import { Shield } from "./Intro";
import "./login.css";

const DEMO = [
  { email: "operator@acme.test", label: "Acme · operator", note: "runs the dashboard, requests fixes" },
  { email: "approver@acme.test", label: "Acme · approver", note: "second person who approves fixes" },
  { email: "operator@globex.test", label: "Globex · operator", note: "another company: sees none of Acme" },
];

export default function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState(DEMO[0].email);
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try { await signIn(email, password); nav("/live"); }
    catch (x: any) {
      setErr({ INVALID_CREDENTIALS: "Wrong email or password.", TOO_MANY_ATTEMPTS: "Too many attempts. Wait a minute.",
               TENANT_MEMBERSHIP_REQUIRED: "This account has no company access." }[x.message as string] ?? "Cloud unreachable.");
    } finally { setBusy(false); }
  }

  return (
    <div className="login">
      <form onSubmit={submit} className="login-card">
        <span className="brand"><Shield /> VeilOps</span>
        <h1 className="h1" style={{ marginTop: 28 }}>Sign in</h1>
        <p className="muted" style={{ margin: "6px 0 22px" }}>Your company's data is separated in the database itself, not only in the app.</p>
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus /></label>
        {err && <div className="red" role="alert" style={{ marginTop: 4 }}>{err}</div>}
        <button className="btn primary" disabled={busy || !password} style={{ marginTop: 14, padding: "9px 14px" }}>{busy ? "Signing in…" : "Sign in"}</button>
        <div className="demo">
          <span className="eyebrow">Demo accounts</span>
          {DEMO.map((d) => (
            <button type="button" key={d.email} className={email === d.email ? "on" : ""} onClick={() => setEmail(d.email)}>
              <span>{d.label}</span><span className="muted">{d.note}</span>
            </button>
          ))}
        </div>
      </form>
    </div>
  );
}
