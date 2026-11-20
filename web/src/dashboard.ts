import { getCloudLink, getEgressProof, getFleet, getIncidents, getSlo, USE_MOCK } from './api';
import { fleet as initialFleet, advanceFleet } from './fixtures/fleet';
import { ledgerForMode } from './fixtures/ledger';
import { today } from './fixtures/today';
import { recorder, recorderEntities } from './fixtures/recorder';
import { getMockMode } from './fixtures/api';
import type { FleetData, LedgerData, TodaySummary } from './types';

let demoFleet = structuredClone(initialFleet);
let tick = 0;
export async function loadLive(signal: AbortSignal) {
  if (USE_MOCK) {
    demoFleet = advanceFleet(demoFleet, getMockMode());
    tick++;
    const ledger = ledgerForMode(getMockMode());
    ledger.crossedKb = (ledger.crossedKb ?? 0) + tick * .002;
    if (getMockMode() !== 'secret') ledger.entries.forEach(entry => { entry.id += tick; });
    return { tenant: 'acme', fleet: { ...demoFleet, secretsRedacted: getMockMode() === 'secret' ? 5 : 4 }, ledger, online: true };
  }
  const [fleet, proofResult, linkResult, incidentsResult] = await Promise.all([
    getFleet(signal),
    getEgressProof(signal).catch(() => null),
    getCloudLink(signal).catch(() => null),
    getIncidents(signal).catch(() => null),
  ]);
  const view: FleetData = {
    collectors: fleet.collectors.map(c => ({ id: c.collector_id, city: c.region, cpu: null, history: [], rtt: null })),
    rawMb: null, secretsRedacted: proofResult?.redaction_summary.secrets_scrubbed ?? null,
  };
  const ledger: LedgerData | null = proofResult ? {
    entries: proofResult.recent_envelopes.map(row => ({
      id: row.seq, collector: linkResult?.collector_id ?? '—', fields: ['—'], records: row.record_count,
      hash: row.payload_hash, receipt: row.has_receipt ? 'matched' : row.status === 'blocked' ? 'blocked' : 'pending',
    })),
    crossedKb: null,
    openIncidents: incidentsResult?.incidents.length === 0 ? 0 : null,
    incident: null,
  } : null;
  return { tenant: fleet.tenant_id, fleet: view, ledger, online: linkResult?.online ?? null };
}

const seconds = (value: number | null) => value === null ? null : Math.round(value / 100) / 10;
export async function loadSummary(signal: AbortSignal): Promise<TodaySummary> {
  if (USE_MOCK) return { ...today,
    collectionToDashboardP95Seconds: Math.round(((today.collectionToDashboardP95Seconds ?? 6.2) + (Math.random() - .5) * .2) * 10) / 10,
    payloadsBlocked: getMockMode() === 'secret' ? 1 : today.payloadsBlocked,
  };
  const [slo, fleet, proof, incidents] = await Promise.all([
    getSlo(signal), getFleet(signal).catch(() => null), getEgressProof(signal).catch(() => null), getIncidents(signal).catch(() => null),
  ]);
  return {
    fleetHealth: null,
    collectionToDashboardP95Seconds: seconds(slo.collection_to_dashboard.since_start.p95_ms),
    breachToAlertSeconds: seconds(slo.breach_to_alert.since_start.p95_ms),
    offlineDetectedSeconds: seconds(slo.collector_offline_detection.since_start.max_ms),
    rawDataLocalPercent: null, receiptsMatched: null,
    collectorsOnline: fleet ? fleet.collectors.filter(c => c.status === 'active').length : null,
    payloadsSent: null, crossedBoundaryKb: null,
    secretsRedacted: proof?.redaction_summary.secrets_scrubbed ?? null,
    payloadsBlocked: proof?.redaction_summary.canaries_blocked ?? null,
    alertsMerged: slo.quality.raw_alerts, incidentsCreated: slo.quality.incidents,
    openIncidents: incidents?.incidents.length === 0 ? 0 : null,
    payloadsLost: slo.reconciliation.missing_count, payloadsDuplicated: slo.reconciliation.duplicate_records_stored,
  };
}
export async function loadRecorder(signal: AbortSignal) {
  if (USE_MOCK) {
    const entities = structuredClone(Object.values(recorderEntities));
    entities.forEach(entity => entity.series.forEach(series => {
      const last = series.points.at(-1);
      if (last) last.value = Math.max(0, last.value * (1 + (Math.random() - .5) * .02));
    }));
    return { incident: recorder, entities, unavailable: false };
  }
  const list = await getIncidents(signal);
  // Correlation/detail contracts are unpublished; never substitute the demo incident.
  return { incident: null, entities: [], unavailable: list.incidents.length > 0 };
}
