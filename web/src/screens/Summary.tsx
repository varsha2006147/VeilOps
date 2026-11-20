import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import TopBar from '../components/TopBar';
import CloudStatus from '../components/CloudStatus';
import Placeholder from '../components/Placeholder';
import Gauge, { meetsTarget, type GaugeProps } from '../components/Gauge';
import { USE_MOCK } from '../api';
import { useLiveData } from '../live';
import { loadSummary } from '../dashboard';
const display = (value: number | null) => value == null ? '—' : String(value);
import '../styles/summary.css';

export default function Summary() {
  const { data, error, lastUpdated, reload } = useLiveData(loadSummary);
  useEffect(() => { document.title = 'Summary · VeilOps'; }, []);
  const gauges: GaugeProps[] = data ? [
    { name: 'Fleet health', value: data.fleetHealth, display: display(data.fleetHealth), unit: 'of 100', max: 100, target: 90, better: 'hi', targetText: 'Target ≥90', minLabel: '0', maxLabel: '100' },
    { name: 'Collection → dashboard', value: data.collectionToDashboardP95Seconds, display: display(data.collectionToDashboardP95Seconds), unit: 's p95', max: 20, target: 10, better: 'lo', targetText: 'Target ≤10 s', minLabel: '0', maxLabel: '20 s' },
    { name: 'Breach → alert', value: data.breachToAlertSeconds, display: display(data.breachToAlertSeconds), unit: 's', max: 30, target: 15, better: 'lo', targetText: 'Target ≤15 s', minLabel: '0', maxLabel: '30 s' },
    { name: 'Offline detected in', value: data.offlineDetectedSeconds, display: display(data.offlineDetectedSeconds), unit: 's', max: 90, target: 60, better: 'lo', targetText: 'Target ≤60 s', minLabel: '0', maxLabel: '90 s' },
    { name: 'Raw data kept local', value: data.rawDataLocalPercent, display: display(data.rawDataLocalPercent), unit: '%', max: 100, target: 99, better: 'hi', targetText: 'Target ≥99%', minLabel: '0', maxLabel: '100%' },
    { name: 'Receipts matched', value: data.receiptsMatched, display: display(data.receiptsMatched), unit: `of ${display(data.payloadsSent)} payloads`, max: data.payloadsSent, target: data.payloadsSent, better: 'hi', targetText: `${display(data.payloadsLost)} lost · ${display(data.payloadsDuplicated)} duplicated`, minLabel: '0', maxLabel: display(data.payloadsSent), passed: data.receiptsMatched !== null && data.payloadsSent !== null && data.receiptsMatched === data.payloadsSent && data.payloadsLost === 0 && data.payloadsDuplicated === 0 },
  ] : [];
  const passed = gauges.filter(g => g.passed ?? meetsTarget(g.value, g.target, g.better)).length;
  const counts = data ? [
    [display(data.collectorsOnline), 'collectors online'], [display(data.payloadsSent), 'payloads sent'],
    [`${display(data.crossedBoundaryKb)} KB`, 'crossed the boundary'], [display(data.secretsRedacted), 'secrets redacted'],
    [display(data.payloadsBlocked), 'payload blocked'], [`${display(data.alertsMerged)} → ${display(data.incidentsCreated)}`, 'alerts merged into incidents'],
  ] : [];
  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <TopBar controls={<span className="summary-period">{USE_MOCK ? 'Today · since 00:00 UTC' : 'Since start · latest observations'}</span>} />
    <CloudStatus error={error} lastUpdated={lastUpdated} onRetry={reload} />
    <main id="main" tabIndex={-1} className="summary-main">
      <header className="summary-header"><div><div className="eyebrow">Summary</div>
        <h1>{data ? `${passed} of 6 targets met${USE_MOCK ? ' today' : ''}` : <Placeholder />}</h1></div>
        <p>{USE_MOCK ? "Each ring shows today's value. The small mark is the target." : 'Each ring shows the available measurement. The small mark is the target.'}</p>
      </header>
      {!data && <div aria-label="Loading summary">
        <div className="gauge-grid">{['Fleet health', 'Collection → dashboard', 'Breach → alert', 'Offline detected in', 'Raw data kept local', 'Receipts matched'].map(name => <section className="gauge-cell" key={name}>
          <svg width="200" height="160" viewBox="0 0 200 160" aria-hidden="true"><circle cx="100" cy="96" r="70" fill="none" stroke="#1D1E22" strokeWidth="10" strokeLinecap="round" strokeDasharray="293.2 439.8" transform="rotate(150 100 96)" /><text x="100" y="96" textAnchor="middle" className="gauge-unit">—</text></svg>
          <h2>{name}</h2><Placeholder />
        </section>)}</div>
        <div className="summary-counts summary-loading-counts">{Array.from({ length: 6 }, (_, i) => <div key={i}><Placeholder /><Placeholder /></div>)}</div>
      </div>}
      {data && <>
        <div className="gauge-grid">{gauges.map(gauge => <Gauge key={gauge.name} {...gauge} />)}</div>
        <div className="summary-counts">{counts.map(([value, label], index) => <div key={label}>
          <strong className={index === 4 ? 'count-blocked' : undefined}>{value}</strong><span>{label}</span>
        </div>)}</div>
        <footer className="summary-footer"><Link to="/incidents">{display(data.openIncidents)} incidents open →</Link>
          <Link to="/">Watch payloads cross →</Link><span>Targets are the CICADA judging limits.</span>
        </footer>
      </>}
    </main>
  </div>;
}
