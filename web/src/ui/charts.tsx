/** Small, dependency-free charts. */
export function Spark({ values, color = "var(--t3)", w = 120, h = 22, minSpan = 10 }: { values: number[]; color?: string; w?: number; h?: number; minSpan?: number }) {
  if (values.length < 2) return <svg width={w} height={h} aria-hidden="true" />;
  const lo = Math.min(...values), hi = Math.max(lo + minSpan, ...values);
  const pts = values.map((v, i) => `${((i * w) / (values.length - 1)).toFixed(1)},${(h - 2 - ((v - lo) / (hi - lo)) * (h - 5)).toFixed(1)}`).join(" ");
  return <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" aria-hidden="true"><polyline points={pts} fill="none" stroke={color} strokeWidth="1.3" vectorEffect="non-scaling-stroke" /></svg>;
}

/** Area chart with an optional threshold line. points = [t, v] sorted by t. */
export function Area({ points, threshold, height = 54, below = false }: { points: [number, number][]; threshold?: number | null; height?: number; below?: boolean }) {
  const W = 200, H = height;
  if (points.length < 2) return <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H}><text x="4" y={H / 2} fill="#6E747C" fontSize="10">no data in range</text></svg>;
  const t0 = points[0][0], t1 = points.at(-1)![0];
  const vals = points.map((p) => p[1]);
  const max = Math.max(...vals, threshold != null && !below ? threshold * 1.15 : 0, 1e-9);
  const min = Math.min(0, ...vals);
  const x = (t: number) => ((t - t0) / Math.max(1, t1 - t0)) * W;
  const y = (v: number) => H - 3 - ((v - min) / (max - min || 1)) * (H - 8);
  const line = points.map(([t, v]) => `${x(t).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const hot = threshold != null && (below ? vals.at(-1)! <= threshold : vals.at(-1)! >= threshold);
  const col = hot ? "#EB5757" : "#9AA0A8";
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" aria-hidden="true">
      {threshold != null && threshold <= max && <line x1="0" x2={W} y1={y(threshold)} y2={y(threshold)} stroke="#F2C94C" strokeOpacity=".5" strokeDasharray="3 3" vectorEffect="non-scaling-stroke" />}
      <polygon points={`0,${H} ${line} ${W},${H}`} fill={hot ? "rgba(235,87,87,.08)" : "rgba(154,160,168,.06)"} />
      <polyline points={line} fill="none" stroke={col} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

const ARC = 293.2, C = 439.8;
export function Gauge({ value, max, target, higherIsBetter, show, unit, lo, hi }: { value: number | null; max: number; target: number; higherIsBetter?: boolean; show: string; unit: string; lo: string; hi: string }) {
  const f = value == null ? 0 : Math.max(0, Math.min(1, value / max));
  const pt = (frac: number, r: number) => { const a = ((150 + 240 * frac) * Math.PI) / 180; return [100 + r * Math.cos(a), 96 + r * Math.sin(a)]; };
  const [x1, y1] = pt(target / max, 60), [x2, y2] = pt(target / max, 80);
  const pass = value != null && (higherIsBetter ? value >= target : value <= target);
  const col = value == null ? "#2A2E35" : pass ? "#E6E8EB" : "#F2C94C";
  return (
    <svg width="200" height="160" viewBox="0 0 200 160" role="img" aria-label={`${show} ${unit}`}>
      <circle cx="100" cy="96" r="70" fill="none" stroke="#1D2025" strokeWidth="10" strokeLinecap="round" strokeDasharray={`${ARC} ${C}`} transform="rotate(150 100 96)" />
      <circle cx="100" cy="96" r="70" fill="none" stroke={col} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(ARC * f).toFixed(1)} ${C}`} transform="rotate(150 100 96)" style={{ transition: "stroke-dasharray 1.2s cubic-bezier(.2,.7,.2,1)" }} />
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#9AA0A8" strokeWidth="2" />
      <text x="100" y="98" textAnchor="middle" fill="#F4F5F7" fontSize="30" fontWeight="500" letterSpacing="-1">{show}</text>
      <text x="100" y="120" textAnchor="middle" fill="#6E747C" fontSize="11.5">{unit}</text>
      <text x="38" y="154" textAnchor="middle" fill="#4E5157" fontSize="10" fontFamily="JetBrains Mono, monospace">{lo}</text>
      <text x="162" y="154" textAnchor="middle" fill="#4E5157" fontSize="10" fontFamily="JetBrains Mono, monospace">{hi}</text>
    </svg>
  );
}
