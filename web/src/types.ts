// Presentation models. Wire contracts derived from API samples live in api-types.ts.
export interface LiveData {
  tenant: string;
  windowSeconds: number;
  summaries: Array<{ entity: string; metric: string; value: number; timestamp: string }>;
}

export interface IncidentsData {
  incidents: Array<{
    id: string;
    severity: 'info' | 'warning' | 'high' | 'critical';
    status: 'open' | 'resolved';
    entity: string;
    rule: string;
    timestamp: string;
  }>;
}

export interface SummaryData {
  payloadCount: number;
  receiptCount: number;
  blockedCount: number;
}

export interface AboutData {
  tagline: string;
  summaryIntervalSeconds: number;
  rawDataLocation: 'customer-network';
  ledger: 'hash-chained';
}

export interface ApiResponses {
  '/summary/today': TodaySummary;
  '/fleet': FleetData;
  '/ledger?limit=6': LedgerData;
  '/live': LiveData;
  '/incidents': IncidentsData;
  '/summary': SummaryData;
  '/about': AboutData;
}

export interface TodaySummary {
  fleetHealth: number | null;
  collectionToDashboardP95Seconds: number | null;
  breachToAlertSeconds: number | null;
  offlineDetectedSeconds: number | null;
  rawDataLocalPercent: number | null;
  receiptsMatched: number | null;
  collectorsOnline: number | null;
  payloadsSent: number | null;
  crossedBoundaryKb: number | null;
  secretsRedacted: number | null;
  payloadsBlocked: number | null;
  alertsMerged: number | null;
  incidentsCreated: number | null;
  openIncidents: number | null;
  payloadsLost: number | null;
  payloadsDuplicated: number | null;
}

export type DemoMode = 'calm' | 'secret' | 'cpu_drift';
export interface RecorderLane {
  name: string; entityId: string; metric: string; involved: boolean;
}
export interface IncidentDetail {
  id: string; openedAt: string; secondsAfterBreach: number;
  windowStart: string; windowEnd: string; title: string;
  explanation: Array<{ text: string; evidence: number }>;
  evidence: Array<{ id: number; metric: string; window: string; payloadId: string; summary: string }>;
  lanes: RecorderLane[];
  alerts: Array<{ id: string; lane: number; minute: number }>;
  incidentWindow: { startMinute: number; endMinute: number };
  recommendation: { id: string; confidence: number; title: string; safeguard: string };
}
export interface EntitySeries {
  entityId: string;
  series: Array<{ metric: string; points: Array<{ minute: number; value: number }> }>;
}
export interface ActionResult {
  id: string; status: 'queued' | 'running' | 'completed' | 'failed';
}
export interface Collector {
  id: string; city: string; cpu: number | null; history: number[]; rtt: number | null; lateSeconds?: number;
}
export interface FleetData { collectors: Collector[]; rawMb: number | null; secretsRedacted: number | null; }
export interface LedgerEntry {
  id: number; collector: string; fields: string[]; records: number; hash: string; receipt: 'matched' | 'blocked' | 'pending';
}
export interface LedgerData {
  entries: LedgerEntry[]; crossedKb: number | null; openIncidents: number | null;
  incident: { id: string; host: string } | null;
}
