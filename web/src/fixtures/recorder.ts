import type { EntitySeries, IncidentDetail } from '../types';

export const recorder: IncidentDetail = {
  id: 'INC-014', openedAt: '2026-11-20T04:03:12Z', secondsAfterBreach: 2,
  windowStart: '2026-11-20T03:45:00Z', windowEnd: '2026-11-20T04:12:00Z',
  title: 'A checkout process is burning CPU while traffic is flat.',
  explanation: [
    { text: 'CPU on h_7f3a21c90b climbed from 34% to 96% in ninety seconds.', evidence: 1 },
    { text: 'Requests per second did not move.', evidence: 2 },
    { text: 'Checkout latency rose right after. Six alerts on three lanes share one host and one five-minute window, so they are one incident.', evidence: 3 },
  ],
  evidence: [
    { id: 1, metric: 'cpu.util p95', window: '04:01–04:02', payloadId: '#1031', summary: 'CPU rose from 34% to 96%.' },
    { id: 2, metric: 'http.rps mean', window: '—', payloadId: '#1032', summary: 'change 0.4%' },
    { id: 3, metric: 'http.latency p95', window: '—', payloadId: '#1034', summary: '820 ms' },
  ],
  lanes: [
    { name: 'CPU · checkout', entityId: 'h_7f3a21c90b', metric: 'cpu.util_pct', involved: true },
    { name: 'Latency · checkout', entityId: 'h_88f02e4857', metric: 'svc.resp_ms', involved: true },
    { name: 'Errors · checkout', entityId: 'h_88f02e4857', metric: 'log.app.http_5xx', involved: true },
    { name: 'Requests / s', entityId: 'h_7f3a21c90b', metric: 'load.req_rate', involved: false },
    { name: 'RTT · Singapore', entityId: 'h_9a2ebf315c', metric: 'net.latency_ms', involved: false },
    { name: 'Heartbeat · Frankfurt', entityId: 'h_6e3181d923', metric: 'heartbeat', involved: false },
  ],
  alerts: [
    { id: 'a1', lane: 0, minute: 16 }, { id: 'a2', lane: 0, minute: 18 },
    { id: 'a3', lane: 1, minute: 17 }, { id: 'a4', lane: 1, minute: 19 },
    { id: 'a5', lane: 2, minute: 18 }, { id: 'a6', lane: 2, minute: 20 },
  ],
  incidentWindow: { startMinute: 15, endMinute: 21.5 },
  recommendation: { id: 'rec_014', confidence: .84,
    title: 'Restart checkout-svc on the affected host',
    safeguard: 'Snapshot first. If CPU is not under 60% within 30 s, roll back automatically.' },
};

export const recorderEntities: Record<string, EntitySeries> = {};
recorder.lanes.forEach((lane, index) => {
  const entity = recorderEntities[lane.entityId] ??= { entityId: lane.entityId, series: [] };
  entity.series.push({ metric: lane.metric, points: Array.from({ length: 28 }, (_, minute) => {
    const base = [34, 105, 1, 240, 46, 1][index];
    const spike = minute < 15 ? 0 : Math.min(1, (minute - 14) / 4);
    const value = index === 5 ? 1 : base + Math.sin(minute * 1.7 + index) * base * .035
      + (index < 3 ? spike * [62, 715, 18][index] : 0);
    return { minute, value };
  }) });
});
