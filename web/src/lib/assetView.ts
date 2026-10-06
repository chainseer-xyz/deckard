import type { Asset, Baseline, Finding, Observation, ScopeClass, Severity, SourceFact } from '../api/types';
import { SEVERITIES } from '../api/types';
import { diffData, evidenceRows } from './evidence';
import type { DataChange, EvidenceRow } from './evidence';
import { emptyCounts } from './triage';

export const SCOPE_INFO: Record<ScopeClass, { label: string; probing: string }> = {
  owned: {
    label: 'Owned',
    probing: 'Yours: Deckard runs passive, active and intrusive checks against it.',
  },
  shared: {
    label: 'Shared',
    probing: 'Shared infrastructure (CDN/SaaS range): passive, hostname-based checks only, never probed by IP.',
  },
  external: {
    label: 'External',
    probing: 'Third party: passive, hostname-based checks only, never probed by IP or service port.',
  },
  excluded: {
    label: 'Excluded',
    probing: 'Matches scope.exclude: Deckard never touches it.',
  },
};

/** Observations older than this are shown as stale; the slowest default check profile runs every 24h. */
export const STALE_OBSERVATION_MS = 36 * 3600 * 1000;

export const isStaleObservation = (observedAt: string, now = Date.now()): boolean =>
  now - Date.parse(observedAt) > STALE_OBSERVATION_MS;

/** Open findings per severity. */
export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const c = emptyCounts();
  for (const f of findings) if (f.status === 'open') c[f.severity] += 1;
  return c;
}

export const hasFindings = (c: Record<Severity, number>): boolean => SEVERITIES.some((s) => c[s] > 0);

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];

/**
 * The API has no asset tags; sources may leave `tags` and `tech` in attrs
 * (see docs/plugins.md), so show those.
 */
export function assetTags(a: Pick<Asset, 'attrs'>): string[] {
  return [...new Set([...strings(a.attrs?.tags), ...strings(a.attrs?.tech)])];
}

/** Canonical source first, then reporters; legacy plugin hints remain readable. */
export function assetSources(a: Pick<Asset, 'source' | 'attrs' | 'reporters' | 'source_facts'>): string[] {
  const reporters = a.reporters ?? strings(a.attrs?.sources);
  return [...new Set([a.source, ...reporters, ...Object.keys(a.source_facts ?? {})].filter(Boolean))];
}

export interface AssetSourceView extends SourceFact {
  source: string;
  canonical: boolean;
  /** False means only legacy canonical metadata (or no metadata) is available. */
  recorded: boolean;
}

/** Keep source facts separate: never copy canonical attributes to another reporter. */
export function assetSourceViews(a: Pick<Asset, 'source' | 'zone' | 'attrs' | 'reporters' | 'source_facts'>): AssetSourceView[] {
  return assetSources(a).map((source) => {
    const canonical = source === a.source;
    const recorded = Object.prototype.hasOwnProperty.call(a.source_facts ?? {}, source);
    const fact = recorded ? a.source_facts?.[source] : canonical ? { zone: a.zone, attrs: a.attrs } : undefined;
    return { source, canonical, recorded, ...fact };
  });
}

export interface BaselineRow {
  key: string;
  label: string;
  kind: EvidenceRow['kind'];
  baseline?: unknown;
  latest?: unknown;
  /** set when the latest observation differs from the baseline */
  change?: DataChange;
}

export interface BaselineView {
  rows: BaselineRow[];
  /** number of keys that differ */
  changes: number;
  /** the observation is newer than the baseline, so differences are real changes since it was learned */
  sinceBaseline: boolean;
}

/** Baseline vs the latest observation of the same check, key by key. */
export function baselineView(b: Baseline, obs: Observation | undefined): BaselineView {
  const base = evidenceRows(b.data);
  const latest = obs ? evidenceRows(obs.data) : [];
  const diff = obs ? diffData(b.data, obs.data) : new Map<string, DataChange>();
  const latestBy = new Map(latest.map((r) => [r.key, r]));
  const rows: BaselineRow[] = base.map((r) => ({
    key: r.key,
    label: r.label,
    kind: r.kind,
    baseline: r.value,
    latest: diff.has(r.key) ? latestBy.get(r.key)?.value : undefined,
    change: diff.get(r.key),
  }));
  for (const r of latest) {
    if (diff.get(r.key) === 'new') rows.push({ key: r.key, label: r.label, kind: r.kind, latest: r.value, change: 'new' });
  }
  return {
    rows,
    changes: diff.size,
    sinceBaseline: !!obs && Date.parse(obs.observed_at) >= Date.parse(b.updated_at),
  };
}
