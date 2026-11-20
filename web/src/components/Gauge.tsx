import { useEffect, useState } from 'react';

export interface GaugeProps {
  name: string; value: number | null; display: string; unit: string;
  minLabel: string; maxLabel: string; max: number | null; target: number | null;
  better: 'hi' | 'lo'; targetText: string;
  // Receipt equality also requires no lost or duplicate payloads.
  passed?: boolean;
}

export function meetsTarget(value: number | null, target: number | null, better: 'hi' | 'lo') {
  return value !== null && target !== null && (better === 'hi' ? value >= target : value <= target);
}

export default function Gauge(props: GaugeProps) {
  const { name, value, display, unit, minLabel, maxLabel, max, target, better, targetText } = props;
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    let second = 0;
    const first = requestAnimationFrame(() => { second = requestAnimationFrame(() => setMounted(true)); });
    return () => { cancelAnimationFrame(first); cancelAnimationFrame(second); };
  }, []);
  const passed = props.passed ?? meetsTarget(value, target, better);
  const fraction = max !== null && max > 0 && value !== null ? Math.max(0, Math.min(1, value / max)) : 0;
  const angle = (150 + 240 * (max !== null && max > 0 && target !== null ? Math.max(0, Math.min(1, target / max)) : 0)) * Math.PI / 180;
  return <section className="gauge-cell" aria-label={`${name}: ${display} ${unit}. ${targetText}. ${value === null ? '—' : passed ? 'pass' : 'at risk'}`}>
    <svg width="200" height="160" viewBox="0 0 200 160" aria-hidden="true">
      <circle cx="100" cy="96" r="70" fill="none" stroke="#1D1E22" strokeWidth="10" strokeLinecap="round"
        strokeDasharray="293.2 439.8" transform="rotate(150 100 96)" />
      <circle className="gauge-value" cx="100" cy="96" r="70" fill="none"
        stroke={passed ? 'var(--text)' : 'var(--yellow)'} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={`${mounted ? 293.2 * fraction : 0} 439.8`} transform="rotate(150 100 96)"
        style={{ opacity: mounted && fraction > 0 ? 1 : 0 }} />
      <line x1={100 + 60 * Math.cos(angle)} y1={96 + 60 * Math.sin(angle)}
        x2={100 + 80 * Math.cos(angle)} y2={96 + 80 * Math.sin(angle)} stroke="var(--text-3)" strokeWidth="2" />
      <text x="100" y="94" textAnchor="middle" className="gauge-number">{display}</text>
      <text x="100" y="114" textAnchor="middle" className="gauge-unit">{unit}</text>
      <text x="30" y="153" textAnchor="middle" className="gauge-limit">{minLabel}</text>
      <text x="170" y="153" textAnchor="middle" className="gauge-limit">{maxLabel}</text>
    </svg>
    <h2>{name}</h2>
    <p>{targetText} · <span className={value === null || passed ? 'gauge-pass' : 'gauge-risk'}>{value === null ? '—' : passed ? 'pass' : 'at risk'}</span></p>
  </section>;
}
