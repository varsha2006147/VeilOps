import { createContext, useContext, useEffect, useRef, useState } from "react";

/** Poll a loader; keeps the last good data on error. Returns [data, error, refresh]. */
export function usePoll<T>(load: () => Promise<T>, ms: number, deps: unknown[] = []): [T | null, string | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const tick = useRef(0);
  const run = () => {
    const my = ++tick.current;
    load().then((d) => { if (my === tick.current) { setData(d); setErr(null); } }).catch((e) => setErr(String(e?.message ?? e)));
  };
  useEffect(() => { run(); const t = setInterval(run, ms); return () => clearInterval(t); }, deps); // eslint-disable-line
  return [data, err, run];
}

/** Bumps whenever new telemetry is processed (SSE), so screens refetch immediately. */
export const LiveTick = createContext(0);
export const useLiveTick = () => useContext(LiveTick);
export const Range = createContext<{ minutes: number; set: (m: number) => void }>({ minutes: 30, set: () => {} });
export const useRange = () => useContext(Range);
