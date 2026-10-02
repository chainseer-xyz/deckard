// Wire types. Mirror the json tags in internal/model/model.go and
// internal/store/store.go. Timestamps are RFC 3339 strings.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const severityRank = (s: string): number => SEVERITIES.indexOf(s as Severity);

export type AssetKind =
  | 'zone'
  | 'hostname'
  | 'ip'
  | 'service'
  | 'url'
  | 'certificate'
  | 'cloud_resource';
export const ASSET_KINDS: AssetKind[] = [
  'zone',
  'hostname',
  'ip',
  'service',
  'url',
  'certificate',
  'cloud_resource',
];

export type ScopeClass = 'owned' | 'shared' | 'external' | 'excluded';
export const SCOPES: ScopeClass[] = ['owned', 'shared', 'external', 'excluded'];

export type FindingStatus =
  | 'open'
  | 'acknowledged'
  | 'suppressed'
  | 'false_positive'
  | 'resolved';
export const STATUSES: FindingStatus[] = [
  'open',
  'acknowledged',
  'suppressed',
  'false_positive',
  'resolved',
];

export type RelationType = string;

export interface Asset {
  id: number;
  kind: AssetKind;
  key: string;
  source: string;
  scope: ScopeClass;
  zone?: string;
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  removed_at?: string | null;
}

export interface Finding {
  id: number;
  fingerprint: string;
  check: string;
  asset_id: number;
  asset_key: string;
  zone?: string;
  source?: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: Record<string, unknown>;
  remediation?: string;
  tags?: string[];
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  resolved_at?: string | null;
  missed_runs: number;
  reopened_count: number;
  suppressed_until?: string | null;
  suppression_note?: string;
}

export interface Observation {
  asset_id: number;
  check: string;
  data: Record<string, unknown>;
  observed_at: string;
}

export interface Baseline {
  asset_id: number;
  check: string;
  data: Record<string, unknown>;
  stable: boolean;
  consistent: number;
  updated_at: string;
}

export interface AssetEdge {
  other: Asset;
  type: RelationType;
  outbound: boolean;
}

export interface AssetDetail {
  asset: Asset;
  edges: AssetEdge[];
  observations: Observation[];
  baselines: Baseline[];
  findings: Finding[];
}

export interface GraphNode {
  id: number;
  kind: AssetKind;
  key: string;
  scope: ScopeClass;
}
export interface GraphEdge {
  from: number;
  to: number;
  type: RelationType;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ChangeEvent {
  id: number;
  type: string;
  subject: string;
  data?: Record<string, unknown>;
  at: string;
}

export interface SyncStatus {
  source: string;
  type: string;
  last_run: string;
  last_ok: string;
  error?: string;
  asset_count: number;
  duration_ms: number;
}

export interface ScanRun {
  id: number;
  asset_id: number;
  check: string;
  tier: string;
  started_at: string;
  duration_ms: number;
  error?: string;
  findings: number;
}

export interface Stats {
  assets_by_kind: Record<string, number>;
  assets_by_source: Record<string, number>;
  assets_by_scope: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_by_check: Record<string, number>;
}

export interface Me {
  identity: string;
  can_write: boolean;
  /** Present for cookie sessions; echoed back as X-CSRF-Token on writes. */
  csrf_token?: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export type FindingAction = 'acknowledge' | 'suppress' | 'false-positive' | 'reopen';
export interface FindingActionBody {
  note: string;
  until?: string;
}
