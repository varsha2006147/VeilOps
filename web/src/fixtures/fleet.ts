import type { DemoMode, FleetData } from '../types';

export const fleet: FleetData = {
  collectors: [
    { city: 'Bengaluru', id: 'col_blr_01', cpu: 42, rtt: 24 },
    { city: 'Mumbai', id: 'col_bom_02', cpu: 35, rtt: 18 },
    { city: 'Singapore', id: 'col_sin_03', cpu: 58, rtt: 46 },
    { city: 'Frankfurt', id: 'col_fra_04', cpu: 27, rtt: 112, lateSeconds: 18 },
  ].map(c => ({ ...c, history: Array.from({ length: 30 }, (_, i) => c.cpu + Math.sin(i * .8) * 5) })),
  rawMb: 842, secretsRedacted: 128,
};

export function advanceFleet(previous: FleetData, mode: DemoMode): FleetData {
  return { ...previous, rawMb: previous.rawMb + 1, collectors: previous.collectors.map(c => {
    const runaway = mode === 'cpu_drift' && c.id === 'col_blr_01';
    const target = runaway ? 94 : fleet.collectors.find(base => base.id === c.id)!.cpu;
    const cpu = Math.max(0, Math.min(100, c.cpu + (target - c.cpu) * (runaway ? .28 : .12) + (Math.random() - .5) * 2));
    return { ...c, cpu, history: [...c.history, cpu].slice(-30) };
  }) };
}
