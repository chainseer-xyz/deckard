import type { Finding } from '../api/types';

export interface RuntimeContext {
  namespace?: string;
  podName?: string;
  policy?: string;
  firstEvent?: string;
  lastEvent?: string;
  batchCount?: number;
}

function text(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string' || value.length > max) return undefined;
  const clean = value.trim();
  return clean || undefined;
}

function eventTime(value: unknown): string | undefined {
  const timestamp = text(value, 64);
  const rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
  return timestamp && rfc3339.test(timestamp) && !timestamp.startsWith('0001-') && Number.isFinite(Date.parse(timestamp)) ? timestamp : undefined;
}

/** Presentation only: reported names never replace the finding's stored identity. */
export function runtimeContext(f: Pick<Finding, 'check' | 'source' | 'evidence'>): RuntimeContext | undefined {
  const tool = f.check === 'ext.tetragon' ? 'tetragon' : f.check === 'ext.falco' ? 'falco' : undefined;
  if (!tool || f.source !== `ingest:${tool}`) return undefined;
  const evidence = f.evidence ?? {};
  const count = evidence.runtime_batch_count;
  return {
    namespace: text(evidence.runtime_namespace, 253),
    podName: text(evidence.runtime_pod_name, 253),
    policy: text(evidence.runtime_rule, 256),
    firstEvent: eventTime(evidence.runtime_first_seen),
    lastEvent: eventTime(evidence.runtime_last_seen),
    batchCount: typeof count === 'number' && Number.isInteger(count) && count > 0 && count <= 1e9 ? count : undefined,
  };
}

export function runtimeSubject(context: RuntimeContext): string {
  if (context.namespace && context.podName) return `${context.namespace}/${context.podName}`;
  if (context.namespace) return `${context.namespace} / Pod name unavailable`;
  return context.podName ?? 'Runtime subject';
}
