import type * as Wire from './api-types';
import { samples, mockResponse, setMockScenario } from './fixtures/api';

export const USE_MOCK = (import.meta.env.VITE_USE_MOCK ?? 'true') === 'true';
export const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
export const COLLECTOR_URL = (import.meta.env.VITE_COLLECTOR_URL || 'http://localhost:8100').replace(/\/+$/, '');
export const TOKEN_KEY = 'veilops_token';
export const APPROVER_TOKEN_KEY = 'veilops_token_approver';
export class ApiError extends Error {
  constructor(public readonly status: number, message: string) { super(message); this.name = 'ApiError'; }
}
export function cloudHeaders(approver = false): Headers {
  const token = localStorage.getItem(approver ? APPROVER_TOKEN_KEY : TOKEN_KEY)?.trim();
  if (!token) throw new ApiError(401, approver ? 'An approver token is required.' : 'A dashboard token is required.');
  return new Headers({ Accept: 'application/json', Authorization: `Bearer ${token}` });
}
async function request<T>(path: string, fixture: () => T, options: {
  collector?: boolean; method?: 'GET' | 'POST'; body?: unknown; signal?: AbortSignal; approver?: boolean;
} = {}): Promise<T> {
  options.signal?.throwIfAborted();
  if (USE_MOCK) return structuredClone(fixture());
  const headers = options.collector ? new Headers({ Accept: 'application/json' }) : cloudHeaders(options.approver);
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${options.collector ? COLLECTOR_URL : API_URL}${path}`, {
    method: options.method ?? 'GET', headers, signal: options.signal,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) throw new ApiError(response.status, `Request failed (${response.status})`);
  if (response.status === 204) return undefined as T;
  if (!response.headers.get('content-type')?.includes('application/json')) throw new ApiError(response.status, 'Expected JSON');
  return response.json() as Promise<T>;
}
export const getFleet = (signal?: AbortSignal): Promise<Wire.Fleet> => request('/api/v1/fleet', () => mockResponse().fleet, { signal });
export const getEgressProof = (signal?: AbortSignal): Promise<Wire.EgressProof> => request('/api/egress-proof', () => mockResponse().egress, { collector: true, signal });
export const getCloudLink = (signal?: AbortSignal): Promise<Wire.CloudLink> => request('/local/cloud', () => mockResponse().cloud, { collector: true, signal });
export const getPayloadReceipt = (id: string, signal?: AbortSignal): Promise<Wire.PayloadReceipt> => request(`/api/v1/payloads/${encodeURIComponent(id)}`, () => ({ receipt: { ...samples.receipt.receipt, payload_id: id } }), { signal });
export async function injectDemo(scenario: Wire.ChaosScenario, signal?: AbortSignal): Promise<Wire.ChaosResult> {
  return request(`/local/chaos/${encodeURIComponent(scenario)}`, () => {
    setMockScenario(scenario);
    return { ...samples.chaos, scenario, injected_at: new Date().toISOString() };
  }, { collector: true, method: 'POST', signal });
}
export const getAlerts = (signal?: AbortSignal): Promise<Wire.Alerts> => request('/api/v1/alerts', () => mockResponse().alerts, { signal });
// No feedback/approval response sample is published; consumers must narrow unknown.
export const submitFalseAlarm = (id: string, signal?: AbortSignal): Promise<unknown> => request(`/api/v1/alerts/${encodeURIComponent(id)}/feedback`, () => undefined, { method: 'POST', body: { verdict: 'false_alarm' }, signal });
export const getIncidents = (signal?: AbortSignal): Promise<Wire.Incidents> => request('/api/v1/incidents', () => mockResponse().incidents, { signal });
// The published incidents sample is empty; no production detail schema is assumed.
export const getIncident = (id: string, signal?: AbortSignal): Promise<unknown> => request(`/api/v1/incidents/${encodeURIComponent(id)}`, () => {
  if (id !== samples.incident.id) throw new ApiError(404, 'Incident not found');
  return samples.incident;
}, { signal });
export const getEntityMetrics = (id: string, options: { since?: string; limit?: number; signal?: AbortSignal } = {}): Promise<Wire.EntityMetrics> => {
  const query = new URLSearchParams();
  if (options.since) query.set('since', options.since);
  if (options.limit !== undefined) query.set('limit', String(options.limit));
  return request(`/api/v1/entities/${encodeURIComponent(id)}/metrics${query.size ? `?${query}` : ''}`, () => {
    const data = mockResponse().metrics;
    return { entity: id, metrics: data.metrics.filter(row => !options.since || Date.parse(row.event_ts) >= Date.parse(options.since)).slice(0, options.limit).map(row => ({ ...row, entity: id })) };
  }, { signal: options.signal });
};
export const getEntityHealthHistory = (id: string, signal?: AbortSignal): Promise<Wire.HealthHistory> => request(`/api/v1/entities/${encodeURIComponent(id)}/health-history`, () => ({ ...samples.health, entity: id }), { signal });
export const createAction = (body: Wire.CreateAction, signal?: AbortSignal): Promise<Wire.ActionCreated> => request('/api/v1/actions', () => ({ ...samples.action, action_id: crypto.randomUUID(), expires_at: new Date(Date.now() + 300000).toISOString() }), { method: 'POST', body, signal });
export const approveAction = (id: string, signal?: AbortSignal): Promise<unknown> => request(`/api/v1/actions/${encodeURIComponent(id)}/approve`, () => undefined, { method: 'POST', approver: true, signal });
export const getSlo = (signal?: AbortSignal): Promise<Wire.Slo> => request('/api/v1/slo', () => mockResponse().slo, { signal });
export const getReconciliation = (signal?: AbortSignal): Promise<Wire.Reconciliation> => request('/api/v1/reconciliation', () => samples.reconciliation, { signal });
export const sendRenderAck = (body: Wire.RenderAck, signal?: AbortSignal): Promise<Wire.RenderAckResult> => request('/api/v1/slo/render-ack', () => samples.ack, { method: 'POST', body, signal });
export async function exportSlo(signal?: AbortSignal): Promise<Blob> {
  if (USE_MOCK) return new Blob(['kind,delay_ms\n' + mockResponse().slo.samples.map(row => `${row.kind},${row.delay_ms}`).join('\n')], { type: 'text/csv' });
  const headers = cloudHeaders(); headers.set('Accept', 'text/csv');
  const response = await fetch(`${API_URL}/api/v1/slo/export.csv`, { headers, signal });
  if (!response.ok) throw new ApiError(response.status, `Request failed (${response.status})`);
  return response.blob();
}
