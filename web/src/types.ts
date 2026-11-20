// Provisional dashboard contracts; align with cloud/api/openapi.json when published.
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
  fleetHealth: number;
  collectionToDashboardP95Seconds: number;
  breachToAlertSeconds: number;
  offlineDetectedSeconds: number;
  rawDataLocalPercent: number;
  receiptsMatched: number;
  collectorsOnline: number;
  payloadsSent: number;
  crossedBoundaryKb: number;
  secretsRedacted: number;
  payloadsBlocked: number;
  alertsMerged: number;
  incidentsCreated: number;
  openIncidents: number;
  payloadsLost: number;
  payloadsDuplicated: number;
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
  id: string; city: string; cpu: number; history: number[]; rtt: number; lateSeconds?: number;
}
export interface FleetData { collectors: Collector[]; rawMb: number; secretsRedacted: number; }
export interface LedgerEntry {
  id: number; collector: string; fields: string[]; records: number; hash: string; receipt: 'matched' | 'blocked';
}
export interface LedgerData {
  entries: LedgerEntry[]; crossedKb: number; openIncidents: number;
  incident: { id: string; host: string } | null;
}
