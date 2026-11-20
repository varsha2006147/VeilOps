import type fleet from './fixtures/cloud_fleet.json';
import type egress from './fixtures/collector_egress_proof.json';
import type cloud from './fixtures/collector_cloud_link.json';
import type chaos from './fixtures/collector_chaos.json';
import type alerts from './fixtures/cloud_alerts.json';
import type metrics from './fixtures/cloud_entity_metrics.json';
import type health from './fixtures/cloud_entity_health_history.json';
import type receipt from './fixtures/cloud_payload_receipt.json';
import type action from './fixtures/cloud_actions_create.json';
import type reconciliation from './fixtures/cloud_reconciliation.json';
import type slo from './fixtures/cloud_slo.json';
import type ack from './fixtures/cloud_render_ack.json';

// Wire contracts retain sample field names; null observations remain nullable.
export type Fleet = typeof fleet;
export type EgressProof = typeof egress;
export type CloudLink = Omit<typeof cloud, 'last_ack_at' | 'last_error' | 'outage_started_at' | 'last_reconcile'> & {
  last_ack_at: string | null; last_error: string | null; outage_started_at: string | null; last_reconcile: unknown;
};
export type ChaosScenario = 'cpu_drift' | 'load_spike' | 'mem_leak' | 'latency' | 'failed_logins' | 'spray' | 'secret' | 'disk_fill' | 'svc_down' | 'out_of_order' | 'dupes';
export type ChaosResult = Omit<typeof chaos, 'target'> & { target: string | null };
export type Alerts = typeof alerts;
export type Incidents = { incidents: unknown[] };
export type EntityMetrics = typeof metrics;
export type HealthHistory = typeof health;
export type PayloadReceipt = typeof receipt;
export interface CreateAction { collector_id: string; action_type: string; policy_ref: string }
export type ActionCreated = typeof action;
export type ReconciliationCollector = Omit<(typeof reconciliation.collectors)[number], 'sent_range' | 'received_range' | 'missing_sequences' | 'backlog' | 'last_run'> & {
  sent_range: number[] | null; received_range: number[] | null; missing_sequences: number[];
  backlog: { episodes: number; last_drain_ms: number | null; last_drained_at: string | null; draining_now: boolean; peak_depth: number };
  last_run: unknown;
};
export interface Reconciliation { collectors: ReconciliationCollector[]; runs: unknown[] }
export interface Distribution { count: number; p50_ms: number | null; p95_ms: number | null; max_ms: number | null }
export interface Windows { recent_5m: Distribution; since_start: Distribution; all_time: Distribution }
export type Slo = Omit<typeof slo, 'collection_to_dashboard' | 'breach_to_alert' | 'collector_offline_detection' | 'reconciliation' | 'quality'> & {
  collection_to_dashboard: Windows;
  breach_to_alert: Windows & { injections: unknown[] };
  collector_offline_detection: Windows & { collectors: Array<{ collector_id: string; state: string; reasons: string[]; last_heartbeat: string | null; last_offline_detection: unknown }> };
  reconciliation: Omit<typeof slo.reconciliation, 'collectors' | 'backlog_last_drain_ms'> & { collectors: ReconciliationCollector[]; backlog_last_drain_ms: number | null };
  quality: Omit<typeof slo.quality, 'alert_to_incident_ratio' | 'noise_reduction_pct'> & { alert_to_incident_ratio: number | null; noise_reduction_pct: number | null };
};
export interface RenderAck { record_key: `payload:${string}`; rendered_at: string; client_sent_at: string }
export type RenderAckResult = typeof ack;
