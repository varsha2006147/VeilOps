import type { DemoMode, LedgerData } from '../types';

export const ledger: LedgerData = {
  entries: Array.from({ length: 6 }, (_, i) => ({
    id: 1042 - i, collector: ['col_blr_01', 'col_bom_02', 'col_sin_03', 'col_fra_04'][i % 4],
    fields: ['cpu', 'memory', 'disk'], records: 14,
    hash: ['a71f…c0e9', 'b82a…d1f0', 'c93b…e2a1', 'd04c…f3b2', 'e15d…a4c3', 'f26e…b5d4'][i],
    receipt: 'matched',
  })), crossedKb: 286, openIncidents: 3, incident: null,
};

export function ledgerForMode(mode: DemoMode): LedgerData {
  const next = structuredClone(ledger);
  if (mode === 'secret') next.entries = [{ id: 1043, collector: 'col_blr_01', fields: [], records: 0,
    hash: 'never sent', receipt: 'blocked' as const }, ...next.entries].slice(0, 6);
  if (mode === 'cpu_drift') next.incident = { id: 'INC-014', host: 'h_8f2a' };
  return next;
}
