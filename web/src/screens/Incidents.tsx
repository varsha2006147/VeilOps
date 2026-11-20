import { useEffect, useRef, useState } from 'react';
import { USE_MOCK } from '../api';
import { useLiveData } from '../live';
import { loadRecorder } from '../dashboard';
import TopBar from '../components/TopBar';
import CloudStatus from '../components/CloudStatus';
import Placeholder from '../components/Placeholder';
import RecorderTimeline, { recorderTime } from '../components/RecorderTimeline';

import '../styles/recorder.css';

export default function Incidents() {
  const { data, loading, error, lastUpdated, reload } = useLiveData(loadRecorder);
  const incident = data?.incident;
  const entities = data?.entities ?? [];
  const [progress, setProgress] = useState(100);
  const [replaying, setReplaying] = useState(false);
  const [pending, setPending] = useState<'execute' | 'dry_run' | null>(null);
  const [approved, setApproved] = useState(false);
  const [actionMessage, setActionMessage] = useState('');
  const [actionError, setActionError] = useState(false);
  const actionController = useRef<AbortController | null>(null);
  const actionInFlight = useRef(false);

  useEffect(() => {
    document.title = 'Incidents · VeilOps';
    return () => actionController.current?.abort();
  }, []);


  useEffect(() => {
    if (!replaying) return;
    const timer = window.setInterval(() => setProgress(p => Math.min(100, p + 1.25)), 80);
    return () => window.clearInterval(timer);
  }, [replaying]);
  useEffect(() => { if (progress >= 100) setReplaying(false); }, [progress]);

  function replay() {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setProgress(100); setReplaying(false); return;
    }
    setProgress(0); setReplaying(true);
  }

  async function act(mode: 'execute' | 'dry_run') {
    if (!incident || actionInFlight.current || (mode === 'execute' && approved)) return;
    actionInFlight.current = true;
    const controller = new AbortController();
    actionController.current = controller;
    setPending(mode); setActionMessage(''); setActionError(false);
    try {
      if (!USE_MOCK) throw new Error('Action collector and policy binding are unavailable.');
      const result = { status: mode === 'dry_run' ? 'completed' : 'queued' };
      if (!controller.signal.aborted) {
        setActionMessage(`${USE_MOCK ? 'Demo: ' : ''}${mode === 'execute' ? 'Restart' : 'Dry run'} ${result.status}.`);
        setActionError(result.status === 'failed');
        if (mode === 'execute' && result.status !== 'failed') setApproved(true);
      }
    } catch {
      if (!controller.signal.aborted) {
        setActionMessage('Could not confirm the action status. Check the backend before submitting again.');
        setActionError(true);
      }
    } finally {
      actionInFlight.current = false;
      if (!controller.signal.aborted) setPending(null);
    }
  }

  const duration = incident ? (Date.parse(incident.windowEnd) - Date.parse(incident.windowStart)) / 60000 : 0;
  const alertCount = incident?.alerts.filter(alert => alert.minute <= duration * progress / 100).length ?? 0;
  const grouped = !!incident && progress >= 80;
  const headline = !incident && (loading || error || data?.unavailable) ? '—' : grouped
    ? `${incident.alerts.length} alerts became 1 incident` : alertCount ? `${alertCount} alerts, not yet grouped` : 'All quiet';
  const windowLabel = incident ? `${recorderTime(incident.windowStart)} → ${recorderTime(incident.windowEnd)} UTC` : '—';

  return <div className="app-shell recorder-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <TopBar controls={<span className="recorder-window mono">{windowLabel}</span>} />
    <CloudStatus error={!!error || actionError} lastUpdated={lastUpdated} message={!error && actionError ? actionMessage : undefined} onRetry={error ? reload : undefined} />
    <main id="main" tabIndex={-1} className="recorder-grid">
      <section className="recorder-main" aria-labelledby="recorder-title">
        <div className="eyebrow">Flight recorder · last {incident ? duration : '—'} min</div>
        <div className="recorder-heading"><h1 id="recorder-title">{headline}</h1>
          <button className="replay-button" onClick={replay} disabled={replaying || !incident || loading}>
            {replaying ? 'Replaying…' : '↻ Replay'}
          </button>
        </div>
        {!incident && (loading || error) && <svg viewBox="0 0 900 470" width="100%" aria-label="Loading recorder" className="recorder-timeline">
          {Array.from({ length: 6 }, (_, i) => <g key={i}><text x="0" y={43 + i * 70} className="lane-entity">—</text><line x1="150" x2="900" y1={65 + i * 70} y2={65 + i * 70} stroke="var(--line)" /></g>)}
        </svg>}
        {incident && <RecorderTimeline incident={incident} entities={entities} progress={progress} />}
        {!loading && !error && !incident && <p className="recorder-empty">{data?.unavailable ? '— Incident details are not available in the published API contract.' : 'No open incidents in this window.'}</p>}
        <p className="recorder-footer">Lines are minute summaries sent by collectors. No raw log ever reaches this screen.</p>
      </section>
      <aside className="recorder-detail" aria-label="Incident details">
        {grouped ? <>
          <div className="recorder-incident-meta mono">{incident.id} · opened {new Date(incident.openedAt).toISOString().slice(11, 19)} · {incident.secondsAfterBreach} s after breach</div>
          <h2>{incident.title}</h2>
          <p className="incident-explanation">{incident.explanation.map((part, index) => <span key={index}>
            {index > 0 ? ' ' : ''}{part.text}<sup><a href={`#evidence-${part.evidence}`} aria-label={`Evidence ${part.evidence}`}>{part.evidence}</a></sup>
          </span>)}</p>
          <ol className="incident-evidence" aria-label="Supporting evidence">
            {incident.evidence.map(item => <li key={item.id} id={`evidence-${item.id}`} value={item.id}>
              <span className="evidence-metric mono">{item.metric}</span>
              <span>{item.summary}</span>
              <span className="mono">{item.window} · {item.payloadId}</span>
            </li>)}
          </ol>
          <section className="recommendation" aria-label="Suggested fix">
            <div className="recommendation-label">Suggested fix · confidence {incident.recommendation.confidence.toFixed(2)}</div>
            <h3>{incident.recommendation.title}</h3>
            <p>{incident.recommendation.safeguard}</p>
            <div className="recommendation-actions">
              <button className="approve-button" disabled={!!pending || approved} onClick={() => void act('execute')}>
                {pending === 'execute' ? 'Approving…' : approved ? 'Approved' : 'Approve'}
              </button>
              <button className="dry-run-button" disabled={!!pending || approved} onClick={() => void act('dry_run')}>
                {pending === 'dry_run' ? 'Running…' : 'Dry run'}
              </button>
            </div>
            {actionMessage && !actionError && <p className="action-result" role="status">{actionMessage}</p>}
          </section>
        </> : !incident && (loading || error) ? <div aria-label="Loading incident details">
          <Placeholder /><Placeholder className="placeholder-heading" />
          {Array.from({ length: 6 }, (_, i) => <Placeholder key={i} />)}
          <div className="recommendation"><Placeholder /><Placeholder /><Placeholder /></div>
        </div> : <div className="recorder-watching">
          <h2>Watching…</h2>
          <p>{!USE_MOCK ? '—' : alertCount
            ? `${alertCount} alerts so far. Waiting to see if they belong together.` : 'Everything is inside its normal range'}</p>
        </div>}
      </aside>
    </main>
  </div>;
}
