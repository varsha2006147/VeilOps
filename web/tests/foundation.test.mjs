import assert from 'node:assert/strict';
import test from 'node:test';
import { build } from 'esbuild';
import { createRequire } from 'node:module';
import vm from 'node:vm';

// Compile with the existing Vite dependency; no test framework or extra packages.
async function load(entry, mock = false, overrides = {}) {
  const result = await build({
    entryPoints: [entry], bundle: true, write: false, platform: 'node', format: 'cjs',
    external: ['react'], define: { 'import.meta.env': JSON.stringify({ VITE_USE_MOCK: String(mock) }) },
  });
  const storage = new Map([['veilops_token', 'operator-test'], ['veilops_token_approver', 'approver-test']]);
  const calls = [];
  const events = new EventTarget();
  const context = {
    module: { exports: {} }, exports: {}, require: createRequire(import.meta.url), Headers, Response, ReadableStream, TextDecoder,
    AbortController, URLSearchParams, Blob, Date, Math, Set, Error, JSON, structuredClone, crypto,
    setTimeout, clearTimeout,
    localStorage: { getItem: key => storage.get(key) ?? null },
    window: events, Event,
    fetch: async (url, options) => { calls.push({ url, options }); return Response.json({ ok: true }); },
    ...overrides,
  };
  vm.runInNewContext(result.outputFiles[0].text, context);
  return { api: context.module.exports, calls, storage };
}

test('cloud authentication, collector isolation, endpoint paths and mutation bodies', async () => {
  const { api, calls } = await load('src/api.ts');
  await api.getFleet();
  await api.getEgressProof();
  await api.getCloudLink();
  await api.injectDemo('secret');
  await api.getAlerts();
  await api.submitFalseAlarm('alert/a');
  await api.getIncidents();
  await api.getIncident('INC/014');
  await api.getEntityMetrics('h_123', { since: '2026-11-21T00:00:00Z', limit: 3 });
  await api.getEntityHealthHistory('h_123');
  await api.getPayloadReceipt('payload/1');
  await api.createAction({ collector_id: 'col_1', action_type: 'RESTART_SERVICE', policy_ref: 'policy_1' });
  await api.approveAction('action/1');
  await api.getSlo();
  await api.getReconciliation();
  await api.sendRenderAck({ record_key: 'payload:p1', rendered_at: new Date().toISOString(), client_sent_at: new Date().toISOString() });
  await api.exportSlo();
  assert.equal(calls.length, 17);
  for (const call of calls) {
    assert.equal(call.options.headers.get('Authorization'), call.url.startsWith('http://localhost:8100')
      ? null : call.url.endsWith('/approve') ? 'Bearer approver-test' : 'Bearer operator-test');
  }
  assert.equal(calls[0].url, 'http://localhost:8000/api/v1/fleet');
  assert.equal(calls[1].url, 'http://localhost:8100/api/egress-proof');
  assert.equal(calls[2].url, 'http://localhost:8100/local/cloud');
  assert.equal(calls[3].url, 'http://localhost:8100/local/chaos/secret');
  assert.equal(calls[5].url, 'http://localhost:8000/api/v1/alerts/alert%2Fa/feedback');
  assert.equal(calls[5].options.body, '{"verdict":"false_alarm"}');
  assert.equal(calls[7].url, 'http://localhost:8000/api/v1/incidents/INC%2F014');
  assert.match(calls[8].url, /metrics\?since=2026-11-21T00%3A00%3A00Z&limit=3$/);
  assert.equal(calls[11].options.body, '{"collector_id":"col_1","action_type":"RESTART_SERVICE","policy_ref":"policy_1"}');
  assert.equal(calls[12].url, 'http://localhost:8000/api/v1/actions/action%2F1/approve');
  const ack = JSON.parse(calls[15].options.body);
  assert.match(ack.rendered_at, /Z$/); assert.match(ack.client_sent_at, /Z$/);
});

test('missing tokens and aborted requests never send cloud traffic; errors do not expose bodies', async () => {
  const { api, storage, calls } = await load('src/api.ts');
  storage.clear();
  await assert.rejects(api.getFleet(), /token is required/);
  await assert.rejects(api.approveAction('a1'), /approver token/);
  assert.equal(calls.length, 0);
  await api.getEgressProof();
  assert.equal(calls.length, 1);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(api.getFleet(controller.signal));
  const failed = await load('src/api.ts', false, { fetch: async () => new Response('private raw log', { status: 500 }) });
  await assert.rejects(failed.api.getFleet(), { message: 'Request failed (500)' });
});

test('mock endpoints use sample contracts and scenarios without network', async () => {
  const { api, calls } = await load('src/api.ts', true);
  const fleet = await api.getFleet();
  assert.equal(fleet.tenant_id, 't_acme');
  assert.match(fleet.entities[0].entity, /^h_/);
  const before = await api.getEgressProof();
  await api.injectDemo('secret');
  assert.equal((await api.getEgressProof()).redaction_summary.canaries_blocked, before.redaction_summary.canaries_blocked + 1);
  const incident = await api.getIncident('INC-014');
  assert.equal(incident.alerts.length, 6);
  assert.equal(incident.recommendation.confidence, .84);
  assert.equal(calls.length, 0);
});

test('SSE parser handles every chunk boundary, comments, multiline data and event IDs', async () => {
  const { api } = await load('src/live.ts');
  const input = ': keepalive\r\nevent: telemetry_processed\r\nid: 7\r\ndata: {"payload_id":\r\ndata: "p1"}\r\n\r\n: keepalive\n\nevent: telemetry_processed\ndata: {"payload_id":"p2"}\n\n';
  for (let split = 0; split <= input.length; split++) {
    const events = [];
    const parser = new api.SseParser(event => events.push(event));
    parser.push(input.slice(0, split)); parser.push(input.slice(split));
    assert.equal(events.length, 2);
    assert.equal(events[0].type, 'telemetry_processed');
    assert.equal(JSON.parse(events[0].data).payload_id, 'p1');
    assert.equal(events[1].id, '7');
    assert.equal(JSON.parse(events[1].data).payload_id, 'p2');
  }
});

test('SSE uses bearer fetch, notifies only telemetry, and never acknowledges before rendering', async () => {
  const calls = [];
  let stream;
  const { api } = await load('src/live.ts', false, { fetch: async (url, options) => {
    calls.push({ url, options });
    return new Response(new ReadableStream({ start(controller) { stream = controller; } }), { headers: { 'Content-Type': 'text/event-stream' } });
  } });
  const received = [];
  const unsubscribe = api.subscribeToTelemetry(id => received.push(id));
  await new Promise(resolve => setTimeout(resolve, 0));
  const encoder = new TextEncoder();
  stream.enqueue(encoder.encode(': keepalive\n\nevent: other\ndata: {}\n\nevent: telemetry_processed\ndata: bad\n\nevent: telemetry_processed\ndata: {"payload_id":"p1"}\n\n'));
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(received, ['p1']);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://localhost:8000/api/v1/events');
  assert.equal(calls[0].options.headers.get('Authorization'), 'Bearer operator-test');
  unsubscribe();
  assert.equal(calls[0].options.signal.aborted, true);
  stream.close();
});

test('SSE reconnect backs off and stops on unsubscribe; mock SSE is off', async () => {
  const scheduled = [];
  let attempts = 0;
  const { api } = await load('src/live.ts', false, {
    fetch: async () => { attempts++; return new Response(null, { status: 503 }); },
    setTimeout: (fn, delay) => { scheduled.push({ fn, delay }); return scheduled.length; },
    clearTimeout: () => {},
  });
  const stop = api.subscribeToTelemetry(() => {});
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(attempts, 1);
  assert.ok(scheduled[0].delay >= 1000 && scheduled[0].delay < 1250);
  scheduled[0].fn();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(attempts, 2);
  assert.ok(scheduled[1].delay >= 2000 && scheduled[1].delay < 2250);
  stop();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(attempts, 2);
  const mock = await load('src/live.ts', true);
  mock.api.subscribeToTelemetry(() => {})();
  assert.equal(mock.calls.length, 0);
});
