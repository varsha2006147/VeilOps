import { useEffect, useRef, useState } from 'react';
import { API_URL, cloudHeaders, sendRenderAck, TOKEN_KEY, USE_MOCK } from './api';

export interface ServerEvent { type: string; data: string; id?: string }
// Incremental framing supports split UTF-8, CRLF/LF/CR, multiline data and comments.
export class SseParser {
  private buffer = '';
  private type = '';
  private data: string[] = [];
  private id: string | undefined;
  constructor(private readonly emit: (event: ServerEvent) => void) {}
  push(chunk: string) {
    this.buffer += chunk;
    if (this.buffer.length > 1024 * 1024) throw new Error('SSE frame too large');
    for (;;) {
      const match = /\r\n|\r|\n/.exec(this.buffer);
      if (!match || (match[0] === '\r' && match.index === this.buffer.length - 1)) return;
      const line = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);
      if (!line) {
        if (this.data.length) this.emit({ type: this.type || 'message', data: this.data.join('\n'), id: this.id });
        this.type = ''; this.data = [];
      } else if (!line.startsWith(':')) {
        const colon = line.indexOf(':');
        const field = colon < 0 ? line : line.slice(0, colon);
        const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
        if (field === 'event') this.type = value;
        if (field === 'data') this.data.push(value);
        if (field === 'id' && !value.includes('\0')) this.id = value;
      }
    }
  }
}

const subscribers = new Set<(payloadId: string) => void>();
let connection: AbortController | undefined;
function startStream() {
  if (USE_MOCK || connection) return;
  const controller = connection = new AbortController();
  const { signal } = controller;
  void (async () => {
    let failures = 0;
    let lastEventId = '';
    while (!signal.aborted) {
      try {
        const headers = cloudHeaders();
        headers.set('Accept', 'text/event-stream');
        if (lastEventId) headers.set('Last-Event-ID', lastEventId);
        const response = await fetch(`${API_URL}/api/v1/events`, { headers, signal, cache: 'no-store' });
        if (!response.ok || !response.body || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('Stream unavailable');
        const parser = new SseParser(event => {
          if (event.id !== undefined) lastEventId = event.id;
          failures = 0;
          if (event.type !== 'telemetry_processed') return;
          try {
            const data: unknown = JSON.parse(event.data);
            if (data && typeof data === 'object' && 'payload_id' in data && typeof data.payload_id === 'string') {
              subscribers.forEach(subscriber => subscriber(data.payload_id as string));
            }
          } catch { /* Malformed events never produce render acknowledgements. */ }
        });
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            parser.push(decoder.decode(value, { stream: true }));
          }
        } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      } catch { /* Retain the last rendered snapshot; reconnect below. */ }
      if (signal.aborted) break;
      const delay = Math.min(30000, 1000 * 2 ** Math.min(failures++, 5)) + Math.random() * 250;
      await new Promise<void>(resolve => {
        const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve(); };
        const timer = setTimeout(finish, delay);
        signal.addEventListener('abort', finish, { once: true });
      });
    }
  })();
}
export function subscribeToTelemetry(listener: (payloadId: string) => void) {
  if (USE_MOCK) return () => {};
  subscribers.add(listener); startStream();
  return () => {
    subscribers.delete(listener);
    if (!subscribers.size) { connection?.abort(); connection = undefined; }
  };
}
function restartStream() {
  connection?.abort(); connection = undefined;
  if (subscribers.size) startStream();
}
if (typeof window !== 'undefined') {
  window.addEventListener('veilops:auth', restartStream);
  window.addEventListener('storage', restartStream);
}

// A payload is acknowledged only after its refetch succeeds and React commits it.
export function useLiveData<T>(load: (signal: AbortSignal) => Promise<T>) {
  const [snapshot, setSnapshot] = useState<{ data: T; at: Date; payloads: string[] } | null>(null);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const frames = useRef(new Set<number>());
  const awaitingPaint = useRef(new Set<string>());
  useEffect(() => {
    const controller = new AbortController();
    let running = false;
    let again = false;
    const pending = new Set<string>();
    async function refresh(payloadId?: string) {
      if (!USE_MOCK && !localStorage.getItem(TOKEN_KEY)?.trim()) {
        setSnapshot(null); setError(false); return;
      }
      if (payloadId) pending.add(payloadId);
      if (running) { again = true; return; }
      running = true;
      do {
        again = false;
        const payloads = [...pending]; pending.clear();
        try {
          const data = await load(controller.signal);
          if (!controller.signal.aborted) {
            payloads.forEach(id => awaitingPaint.current.add(id));
            setSnapshot({ data, at: new Date(), payloads }); setError(false);
          }
        } catch {
          payloads.forEach(id => pending.add(id));
          if (!controller.signal.aborted) setError(true);
        }
      } while (again && !controller.signal.aborted);
      running = false;
    }
    const trigger = () => { void refresh(); };
    const authChanged = () => {
      setSnapshot(null); pending.clear(); awaitingPaint.current.clear();
      frames.current.forEach(cancelAnimationFrame); frames.current.clear();
      setAttempt(n => n + 1);
    };
    const unsubscribe = subscribeToTelemetry(id => { void refresh(id); });
    window.addEventListener('veilops:auth', authChanged);
    window.addEventListener('veilops:mock', trigger);
    window.addEventListener('storage', authChanged);
    const timer = window.setInterval(trigger, USE_MOCK ? 1600 : 15000);
    trigger();
    return () => {
      controller.abort(); unsubscribe(); clearInterval(timer);
      window.removeEventListener('veilops:auth', authChanged);
      window.removeEventListener('veilops:mock', trigger);
      window.removeEventListener('storage', authChanged);
    };
  }, [load, attempt]);
  useEffect(() => {
    if (USE_MOCK || !snapshot || !awaitingPaint.current.size) return;
    const payloads = [...awaitingPaint.current];
    awaitingPaint.current.clear();
    // Two frames let the committed snapshot paint before recording rendered_at.
    const first = requestAnimationFrame(() => {
      frames.current.delete(first);
      const second = requestAnimationFrame(() => {
        frames.current.delete(second);
        const rendered_at = new Date().toISOString();
        payloads.forEach(payload => {
          void sendRenderAck({ record_key: `payload:${payload}`, rendered_at, client_sent_at: new Date().toISOString() }).catch(() => {});
        });
      });
      frames.current.add(second);
    });
    frames.current.add(first);
  }, [snapshot]);
  useEffect(() => () => { frames.current.forEach(cancelAnimationFrame); frames.current.clear(); }, []);
  return { data: snapshot?.data ?? null, lastUpdated: snapshot?.at ?? null, loading: !snapshot && !error, error, reload: () => setAttempt(n => n + 1) };
}
