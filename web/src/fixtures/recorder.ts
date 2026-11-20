import type { EntitySeries, IncidentDetail } from '../types';

export const recorder: IncidentDetail = {
  id: 'INC-014', openedAt: '2026-11-20T04:03:12Z', secondsAfterBreach: 2,
  windowStart: '2026-11-20T03:45:00Z', windowEnd: '2026-11-20T04:12:00Z',
  title: 'A checkout process is burning CPU while traffic is flat.',
  explanation: [
    { text: 'CPU on the checkout host climbed to 94% and stayed there.', evidence: 1 },
    { text: 'Checkout latency and errors rose in the same window.', evidence: 2 },
    { text: 'Request volume stayed flat, so this looks like a stuck process rather than a traffic spike.', evidence: 3 },
  ],
  evidence: [
    { id: 1, metric: 'cpu.util_pct', window: '04:01–04:06 UTC', payloadId: '#1042', summary: 'CPU rose from 42% to 94%.' },
    { id: 2, metric: 'svc.resp_ms · log.app.http_5xx', window: '04:02–04:07 UTC', payloadId: '#1043', summary: 'Latency and errors rose together.' },
    { id: 3, metric: 'load.req_rate', window: '03:55–04:10 UTC', payloadId: '#1044', summary: 'Request volume stayed inside its normal range.' },
  ],
  lanes: [
    { name: 'CPU · checkout', entityId: 'h_8f2a', metric: 'cpu.util_pct', involved: true },
    { name: 'Latency · checkout', entityId: 'svc_7b3c', metric: 'svc.resp_ms', involved: true },
    { name: 'Errors · checkout', entityId: 'svc_7b3c', metric: 'log.app.http_5xx', involved: true },
    { name: 'Requests / s', entityId: 'h_8f2a', metric: 'load.req_rate', involved: false },
    { name: 'RTT · Singapore', entityId: 'lnk_3c91', metric: 'net.latency_ms', involved: false },
    { name: 'Heartbeat · Frankfurt', entityId: 'col_fra_04', metric: 'heartbeat', involved: false },
  ],
  alerts: [
    { id: 'a1', lane: 0, minute: 16 }, { id: 'a2', lane: 0, minute: 18 },
    { id: 'a3', lane: 1, minute: 17 }, { id: 'a4', lane: 1, minute: 19 },
    { id: 'a5', lane: 2, minute: 18 }, { id: 'a6', lane: 2, minute: 20 },
  ],
  incidentWindow: { startMinute: 15, endMinute: 21.5 },
  recommendation: { id: 'rec_014', confidence: .84,
    title: 'Restart checkout-svc on the affected host',
    safeguard: 'Take a snapshot first. Auto-rollback if health does not recover.' },
};

export const recorderEntities: Record<string, EntitySeries> = {};
recorder.lanes.forEach((lane, index) => {
  const entity = recorderEntities[lane.entityId] ??= { entityId: lane.entityId, series: [] };
  entity.series.push({ metric: lane.metric, points: Array.from({ length: 28 }, (_, minute) => {
    const base = [42, 105, 1, 240, 46, 1][index];
    const spike = minute < 15 ? 0 : Math.min(1, (minute - 14) / 4);
    const value = index === 5 ? 1 : base + Math.sin(minute * 1.7 + index) * base * .035
      + (index < 3 ? spike * [52, 540, 18][index] : 0);
    return { minute, value };
  }) });
});
