import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { api, injectDemo, USE_MOCK } from '../api';
import TopBar from '../components/TopBar';
import CloudStatus from '../components/CloudStatus';
import Placeholder from '../components/Placeholder';
import { fleet as initialFleet, advanceFleet } from '../fixtures/fleet';
import { ledgerForMode } from '../fixtures/ledger';
import type { Collector, DemoMode, FleetData, LedgerData } from '../types';
import '../styles/live.css';

function cpuColor(cpu: number) {
  return cpu >= 90 ? 'var(--red)' : cpu >= 75 ? 'var(--yellow)' : 'var(--text-3)';
}

function Sparkline({ collector }: { collector: Collector }) {
  const values = collector.history.slice(-30);
  const points = values.map((v, i) => `${1 + i * 118 / Math.max(1, values.length - 1)},${23 - Math.max(0, Math.min(100, v)) * .22}`).join(' ');
  return <svg width="120" height="24" viewBox="0 0 120 24" role="img"
    aria-label={`${collector.city} CPU over the last 10 minutes`}>
    <polyline points={points} fill="none" stroke={cpuColor(collector.cpu)} strokeWidth="1.3" />
  </svg>;
}

export default function Live() {
  const [mode, setMode] = useState<DemoMode>('calm');
  const [fleet, setFleet] = useState<FleetData | null>(() => USE_MOCK ? structuredClone(initialFleet) : null);
  const [ledger, setLedger] = useState<LedgerData | null>(() => USE_MOCK ? ledgerForMode('calm') : null);
  const [now, setNow] = useState(() => new Date());
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [pending, setPending] = useState(false);
  const injection = useRef<AbortController | null>(null);

  useEffect(() => {
    document.title = 'Live · VeilOps';
    const clock = window.setInterval(() => setNow(new Date()), 1000);
    return () => { window.clearInterval(clock); injection.current?.abort(); };
  }, []);

  useEffect(() => {
    if (USE_MOCK) {
      setLedger(ledgerForMode(mode));
      setFleet(previous => previous ? { ...previous, secretsRedacted: initialFleet.secretsRedacted + (mode === 'secret' ? 1 : 0) } : initialFleet);
      const timer = window.setInterval(() => {
        setFleet(previous => advanceFleet(previous ?? initialFleet, mode));
        setLedger(previous => previous ? { ...previous, crossedKb: previous.crossedKb + .4 } : previous);
      }, 1600);
      return () => window.clearInterval(timer);
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const [nextFleet, nextLedger] = await Promise.all([
          api('/fleet', { signal: controller.signal }),
          api('/ledger?limit=6', { signal: controller.signal }),
        ]);
        if (!controller.signal.aborted) {
          setFleet(nextFleet); setLedger(nextLedger); setLastUpdated(new Date()); setError('');
        }
      } catch {
        if (!controller.signal.aborted) setError('Connection interrupted. Retrying; displayed data may be stale.');
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 2000);
      }
    }
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [mode]);

  async function selectMode(next: DemoMode) {
    if (pending) return;
    if (USE_MOCK || next === 'calm') { setMode(next); return; }
    const controller = new AbortController();
    injection.current = controller;
    setPending(true);
    try {
      await injectDemo(next, controller.signal);
      if (!controller.signal.aborted) { setMode(next); setError(''); }
    } catch {
      if (!controller.signal.aborted) setError('Demo could not be started. Try again.');
    } finally { if (!controller.signal.aborted) setPending(false); }
  }

  const blocked = ledger?.entries.find(entry => entry.receipt === 'blocked');
  const incident = ledger?.incident;
  const headline = blocked ? 'Nothing secret reached us' : incident ? 'One incident needs approval' : 'All payloads matched their receipts';
  const controls = <>
    <div className="demo-control" role="group" aria-label="Demo scenario">
      {([['calm', 'Calm'], ['secret', 'Secret in log'], ['cpu_drift', 'CPU runaway']] as const).map(([value, label]) =>
        <button key={value} type="button" aria-pressed={mode === value} disabled={pending}
          onClick={() => void selectMode(value)}>{label}</button>)}
    </div>
    <time className="utc-clock" dateTime={now.toISOString()}>{now.toISOString().slice(11, 19)} UTC</time>
  </>;

  return <div className="app-shell live-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <TopBar controls={controls} />
    <CloudStatus error={!!error} lastUpdated={lastUpdated} />
    <main id="main" className="live-grid" tabIndex={-1}>
      <section className="network-panel" aria-labelledby="network-title">
        <div className="eyebrow" id="network-title">Inside acme's network</div>
        <h1>{fleet ? `${fleet.collectors.length} collectors, reading everything locally` : <Placeholder />}</h1>
        <div className="collector-table" role="table" aria-label="Collectors">
          <div className="collector-row collector-head" role="row">
            {['collector', 'cpu · 10 min', 'cpu', 'rtt'].map(label => <span role="columnheader" key={label}>{label}</span>)}
          </div>
          {!fleet && Array.from({ length: 4 }, (_, i) => <div className="collector-row" role="row" key={i}>
            {Array.from({ length: 4 }, (_, j) => <div role="cell" key={j}><Placeholder /></div>)}
          </div>)}
          {fleet?.collectors.map(collector => <div className="collector-row" role="row" key={collector.id}>
            <div role="cell"><span className="collector-city">{collector.city}</span><span className="collector-id mono" title={collector.id}>{collector.id}</span></div>
            <div role="cell"><Sparkline collector={collector} /></div>
            <div role="cell" className="mono" style={{ color: cpuColor(collector.cpu) }}>{Math.round(collector.cpu)}%</div>
            <div role="cell" className={`collector-rtt mono${collector.lateSeconds ? ' warning' : ''}`}>
              {collector.lateSeconds ? `late ${collector.lateSeconds} s` : `${collector.rtt} ms`}
            </div>
          </div>)}
        </div>
        <div className="local-stats">
          <div><span>raw logs kept here</span><strong className="mono">{fleet?.rawMb.toLocaleString() ?? '—'} MB</strong></div>
          <div><span>secrets redacted</span><strong className="mono">{fleet?.secretsRedacted.toLocaleString() ?? '—'}</strong></div>
          <div><span>name key</span><strong>never leaves</strong></div>
        </div>
      </section>
      <section className="boundary" aria-label="Payload boundary">
        <div className="boundary-label">Boundary</div>
        <div className="payload-stream" aria-hidden="true">
          {!ledger && Array.from({ length: 6 }, (_, i) => <Placeholder key={i} />)}
          {ledger?.entries.slice(0, 6).map((entry, i) => <span key={entry.id}
            className={`payload-chip mono${entry.receipt === 'blocked' ? ' blocked' : ''}`}
            style={{ '--delay': `${-.53 * i}s` } as CSSProperties}>
            #{entry.id} {entry.receipt === 'blocked' ? '✕' : '→'}
          </span>)}
        </div>
        <div className="boundary-total"><span className="mono">{ledger ? Math.round(ledger.crossedKb).toLocaleString() : '—'} KB</span><span>crossed today</span></div>
      </section>
      <section className="cloud-panel" aria-labelledby="cloud-title">
        <div className="eyebrow">VeilOps cloud · metadata only</div>
        <h1 id="cloud-title">{ledger ? headline : <Placeholder />}</h1>
        {incident && <div className="live-alert">
          <div className="alert-meta mono"><span>{incident.id}</span><span>{incident.host}</span></div>
          <h2>CPU runaway detected</h2>
          <p>CPU is rising above its normal range. A response needs your approval.</p>
          <Link to="/incidents">Open in recorder →</Link>
        </div>}
        {blocked && <div className="live-alert">
          <div className="alert-meta mono"><span>#{blocked.id}</span><span>{blocked.collector}</span></div>
          <h2>A payload was stopped at the boundary</h2>
          <p>The collector found a password and blocked the whole payload.</p>
        </div>}
        <div className="ledger-table" role="table" aria-label="Payload ledger">
          <div className="ledger-row ledger-head" role="row">
            {['payload', 'what', 'hash', 'receipt'].map(label => <span role="columnheader" key={label}>{label}</span>)}
          </div>
          {!ledger && Array.from({ length: 6 }, (_, i) => <div className="ledger-row" role="row" key={i}>
            {Array.from({ length: 4 }, (_, j) => <div role="cell" key={j}><Placeholder /></div>)}
          </div>)}
          {ledger?.entries.slice(0, 6).map(entry => <div className={`ledger-row${entry.receipt === 'blocked' ? ' is-blocked' : ''}`} role="row" key={entry.id}>
            <span role="cell" className="ledger-id mono">#{entry.id}</span>
            <div role="cell" className="ledger-what">{entry.receipt === 'blocked' ? 'Stopped at boundary' : <>
              <span>{entry.fields.join(', ')}</span><span className="record-count">{entry.records} records</span>
            </>}</div>
            <span role="cell" className="ledger-hash mono" title={entry.hash}>{entry.receipt === 'blocked' ? 'never sent' : entry.hash}</span>
            <span role="cell" className="ledger-receipt">{entry.receipt}</span>
          </div>)}
        </div>
        <footer className="cloud-footer"><Link to="/incidents">Open incidents · {ledger?.openIncidents ?? '—'}</Link>
          <span>Hash-chained ledger</span><span>Raw data stays local</span></footer>
      </section>
    </main>
  </div>;
}
