import type { ActionResult, ApiResponses, EntitySeries, IncidentDetail } from './types';

export const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';
export const TOKEN_KEY = 'veilops_token';
const BASE_URL = (import.meta.env.VITE_API_URL || '/api').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export type ApiOptions = Omit<RequestInit, 'method' | 'body'>;

// GET endpoints are coupled to response types, so callers cannot select an
// unrelated return type. Add mutation contracts when the backend publishes them.
export async function api<Path extends keyof ApiResponses>(
  path: Path,
  options: ApiOptions = {},
): Promise<ApiResponses[Path]> {
  options.signal?.throwIfAborted();

  if (USE_MOCK) {
    const { fixtures } = await import('./fixtures');
    options.signal?.throwIfAborted();
    return structuredClone(fixtures[path]);
  }

  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    method: 'GET',
    headers,
  });

  if (!response.ok) {
    // Do not surface arbitrary backend response bodies in the dashboard.
    throw new ApiError(response.status, `Request failed (${response.status})`);
  }
  if (!response.headers.get('content-type')?.includes('application/json')) {
    throw new ApiError(response.status, 'Expected a JSON response');
  }
  return response.json() as Promise<ApiResponses[Path]>;
}

export async function injectDemo(scenario: 'secret' | 'cpu_drift', signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  if (USE_MOCK) return;
  const headers = new Headers({ 'Content-Type': 'application/json', Accept: 'application/json' });
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${BASE_URL}/demo/inject`, {
    method: 'POST', headers, body: JSON.stringify({ scenario }), signal,
  });
  if (!response.ok) throw new ApiError(response.status, `Demo request failed (${response.status})`);
}

async function requestJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body) headers.set('Content-Type', 'application/json');
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  if (!response.ok) throw new ApiError(response.status, `Request failed (${response.status})`);
  return response.json() as Promise<T>;
}

export async function getIncident(id: string, signal?: AbortSignal): Promise<IncidentDetail> {
  signal?.throwIfAborted();
  if (!USE_MOCK) return requestJson(`/incidents/${encodeURIComponent(id)}`, { signal });
  const { recorder } = await import('./fixtures/recorder');
  signal?.throwIfAborted();
  if (recorder.id !== id) throw new ApiError(404, 'Incident not found');
  return structuredClone(recorder);
}

export async function getEntitySeries(id: string, signal?: AbortSignal): Promise<EntitySeries> {
  signal?.throwIfAborted();
  if (!USE_MOCK) return requestJson(`/entities/${encodeURIComponent(id)}`, { signal });
  const { recorderEntities } = await import('./fixtures/recorder');
  signal?.throwIfAborted();
  if (!recorderEntities[id]) throw new ApiError(404, 'Entity not found');
  return structuredClone(recorderEntities[id]);
}

export async function submitAction(recommendationId: string, mode: 'execute' | 'dry_run', signal?: AbortSignal): Promise<ActionResult> {
  signal?.throwIfAborted();
  if (USE_MOCK) return { id: `mock_${mode}_${recommendationId}`, status: mode === 'dry_run' ? 'completed' : 'queued' };
  return requestJson('/actions', { method: 'POST', signal,
    body: JSON.stringify({ recommendation_id: recommendationId, mode }) });
}
