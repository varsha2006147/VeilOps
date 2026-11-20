import type { DemoMode, FleetData } from '../types';

export const fleet: FleetData = {
  collectors: [
    { city: 'Bengaluru', id: 'col_blr_01', cpu: 34, rtt: 2 },
    { city: 'Chennai', id: 'col_maa_02', cpu: 31, rtt: 3 },
    { city: 'Singapore', id: 'col_sin_01', cpu: 28, rtt: 41 },
    { city: 'Frankfurt', id: 'col_fra_01', cpu: 22, rtt: 112, lateSeconds: 18 },
  ].map(c => ({ ...c, history: Array.from({ length: 30 }, (_, i) => c.cpu + Math.sin(i * .8) * 5) })),
  rawMb: 2.41, secretsRedacted: 4,
};

export function advanceFleet(previous: FleetData, mode: DemoMode): FleetData {
  return { ...previous, rawMb: (previous.rawMb ?? 0) + .003, collectors: previous.collectors.map(c => {
    const runaway = mode === 'cpu_drift' && c.id === 'col_blr_01';
    const target = runaway ? 94 : fleet.collectors.find(base => base.id === c.id)!.cpu ?? 34;
    const cpu = Math.max(0, Math.min(100, (c.cpu ?? target) + (target - (c.cpu ?? target)) * (runaway ? .28 : .12) + (Math.random() - .5) * 2));
    return { ...c, cpu, history: [...c.history, cpu].slice(-30) };
  }) };
}
