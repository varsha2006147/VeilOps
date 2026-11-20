import fleet from './cloud_fleet.json';
import egress from './collector_egress_proof.json';
import cloud from './collector_cloud_link.json';
import chaos from './collector_chaos.json';
import alerts from './cloud_alerts.json';
import metrics from './cloud_entity_metrics.json';
import health from './cloud_entity_health_history.json';
import receipt from './cloud_payload_receipt.json';
import action from './cloud_actions_create.json';
import reconciliation from './cloud_reconciliation.json';
import slo from './cloud_slo.json';
import ack from './cloud_render_ack.json';
import { recorder } from './recorder';
import type { ChaosScenario } from '../api-types';
import type { DemoMode } from '../types';

export const samples = { fleet, egress, cloud, chaos, alerts, metrics, health, receipt, action, reconciliation, slo, ack, incident: recorder };
let scenario: ChaosScenario | 'calm' = 'calm';
let cpu = metrics.metrics[0].avg;
let lastTick = 0;
export const getMockMode = (): DemoMode => scenario === 'secret' ? 'secret' : scenario === 'calm' ? 'calm' : 'cpu_drift';
export function setMockScenario(next: ChaosScenario | 'calm') {
  scenario = next;
  window.dispatchEvent(new Event('veilops:mock'));
}
export function mockResponse() {
  const data = structuredClone(samples);
  if (Date.now() - lastTick >= 1600) {
    cpu = Math.max(0, Math.min(100, cpu + ((scenario === 'cpu_drift' ? 94 : 39) - cpu) * .3 + (Math.random() - .5) * 2.5));
    lastTick = Date.now();
  }
  data.metrics.metrics[0] = { ...data.metrics.metrics[0], avg: cpu, min: cpu - 1, max: cpu + 1, p95: cpu + .8 };
  if (scenario === 'secret') { data.egress.redaction_summary.canaries_blocked++; data.cloud.egress_blocked++; }
  data.slo.collection_to_dashboard.recent_5m.p95_ms += (cpu - 39) * 3;
  return { ...data, incidents: { incidents: [recorder] } };
}
