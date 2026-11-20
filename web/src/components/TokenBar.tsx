import { useState } from 'react';
import { APPROVER_TOKEN_KEY, TOKEN_KEY, USE_MOCK } from '../api';

export default function TokenBar() {
  const [hasToken, setHasToken] = useState(() => !!localStorage.getItem(TOKEN_KEY));
  const [editing, setEditing] = useState(false);
  const [token, setToken] = useState('');
  const [approver, setApprover] = useState('');
  if (USE_MOCK) return null;
  if (hasToken && !editing) return <div className="cloud-status">Token saved.<button onClick={() => setEditing(true)}>Update tokens</button></div>;
  return <form className="token-bar" onSubmit={event => {
    event.preventDefault();
    if (token.trim()) localStorage.setItem(TOKEN_KEY, token.trim());
    if (approver.trim()) localStorage.setItem(APPROVER_TOKEN_KEY, approver.trim());
    setHasToken(!!localStorage.getItem(TOKEN_KEY)); setEditing(false); setToken(''); setApprover('');
    window.dispatchEvent(new Event('veilops:auth'));
  }}>
    <span>Connect to the cloud</span>
    <input type="password" aria-label="Dashboard token" placeholder="Paste token" value={token} onChange={e => setToken(e.target.value)} autoComplete="off" required={!hasToken} />
    <input type="password" aria-label="Approver token (optional)" placeholder="Approver token (optional)" value={approver} onChange={e => setApprover(e.target.value)} autoComplete="off" />
    <button type="submit">Save</button>
  </form>;
}
