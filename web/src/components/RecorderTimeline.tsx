import type { EntitySeries, IncidentDetail } from '../types';

export function recorderTime(start: string, minutes = 0) {
  return new Date(Date.parse(start) + minutes * 60000).toISOString().slice(11, 16);
}

export default function RecorderTimeline({ incident, entities, progress }: {
  incident: IncidentDetail; entities: EntitySeries[]; progress: number;
}) {
  const duration = (Date.parse(incident.windowEnd) - Date.parse(incident.windowStart)) / 60000;
  const x = (minute: number) => 150 + minute / duration * 750;
  const playhead = x(duration * progress / 100);
  const lanes = incident.lanes.map((lane, i) => {
    const points = entities.find(e => e.entityId === lane.entityId)?.series.find(s => s.metric === lane.metric)?.points ?? [];
    const max = Math.max(1, ...points.map(point => point.value)) * 1.1;
    const baseline = 65 + i * 70;
    return { ...lane, points, baseline, y: (value: number) => baseline - value / max * 40 };
  });
  const ticks = Array.from({ length: Math.floor(duration / 5) + 1 }, (_, i) => i * 5);
  return <svg className="recorder-timeline" viewBox="0 0 900 470" width="100%" role="img"
    aria-label={`Flight recorder: ${incident.lanes.length} metric lanes, ${incident.alerts.filter(a => a.minute <= duration * progress / 100).length} alerts revealed. Replay ${Math.round(progress)} percent complete.`}>
    {ticks.map(minute => <g key={minute}>
      <line x1={x(minute)} x2={x(minute)} y1="28" y2="430" stroke="#16171A" />
      <text x={x(minute)} y="455" className="chart-time" textAnchor={minute === 0 ? 'start' : 'middle'}>{recorderTime(incident.windowStart, minute)}</text>
    </g>)}
    {lanes.map((lane, i) => <g key={`${lane.entityId}-${lane.metric}`}>
      <text x="0" y={lane.baseline - 22} className="lane-name">{lane.name}</text>
      <text x="0" y={lane.baseline - 5} className="lane-entity"><title>{lane.entityId}</title>{lane.entityId.length > 20 ? `${lane.entityId.slice(0, 19)}…` : lane.entityId}</text>
      <line x1="150" x2="900" y1={lane.baseline} y2={lane.baseline} stroke="var(--line)" />
      <polyline points={lane.points.map(point => `${x(point.minute)},${lane.y(point.value)}`).join(' ')}
        fill="none" stroke={lane.involved ? 'var(--text)' : 'var(--muted)'} strokeWidth="1.4" />
      {incident.alerts.filter(alert => alert.lane === i && alert.minute <= duration * progress / 100).map(alert => {
        const point = lane.points.reduce<{ minute: number; value: number } | undefined>((best, next) =>
          !best || Math.abs(next.minute - alert.minute) < Math.abs(best.minute - alert.minute) ? next : best, undefined);
        return <circle key={alert.id} cx={x(alert.minute)} cy={lane.y(point?.value ?? 0)} r="4"
          fill="var(--bg)" stroke="var(--red)" strokeWidth="1.5" />;
      })}
    </g>)}
    {progress >= 80 && <g>
      <rect x={x(incident.incidentWindow.startMinute)} y="24"
        width={x(incident.incidentWindow.endMinute) - x(incident.incidentWindow.startMinute)} height="196"
        rx="6" stroke="var(--red)" strokeDasharray="4 3" fill="rgba(235,87,87,.05)" />
      <text x={x(incident.incidentWindow.startMinute)} y="15" className="incident-bracket-label">
        {incident.id} · {incident.alerts.length} alerts → 1
      </text>
    </g>}
    {progress < 100 && <rect x={playhead} y="24" width={900 - playhead} height="406" fill="var(--bg)" opacity=".78" />}
    <line x1={playhead} x2={playhead} y1="24" y2="430" stroke="var(--text)" />
    <text x={playhead} y="15" textAnchor={progress > 90 ? 'end' : 'start'} className="playhead-time">
      {recorderTime(incident.windowStart, duration * progress / 100)}
    </text>
  </svg>;
}
