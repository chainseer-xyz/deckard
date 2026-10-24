import { describe, expect, it } from 'vitest';
import { runtimeContext, runtimeSubject } from './runtimeFinding';

const runtime = { check: 'ext.tetragon', source: 'ingest:tetragon' };

describe('runtime presentation context', () => {
  it('accepts only the exact runtime producer lineage', () => {
    expect(runtimeContext({ ...runtime, evidence: { runtime_namespace: 'apps' } })).toEqual({ namespace: 'apps' });
    expect(runtimeContext({ check: 'ext.falco', source: 'ingest:falco' })).toEqual({});
    expect(runtimeContext({ ...runtime, source: 'cluster' })).toBeUndefined();
    expect(runtimeContext({ check: 'ext.kubescape', source: 'ingest:kubescape', evidence: { runtime_rule: 'claim' } })).toBeUndefined();
  });

  it('does not render invalid or excessive evidence as runtime facts', () => {
    const context = runtimeContext({ ...runtime, evidence: {
      runtime_namespace: ['apps'], runtime_pod_name: 'x'.repeat(254), runtime_rule: { name: 'policy' },
      runtime_first_seen: '1', runtime_last_seen: 'not a timestamp', runtime_batch_count: '23',
    } });
    expect(context).toEqual({});
  });

  it.each([0, -1, 1.5, Infinity, 1_000_000_001])('rejects invalid batch counts: %s', (count) => {
    expect(runtimeContext({ ...runtime, evidence: { runtime_batch_count: count } })?.batchCount).toBeUndefined();
  });

  it('renders native nanosecond event timestamps and bounded integer batch counts', () => {
    expect(runtimeContext({ ...runtime, evidence: {
      runtime_first_seen: '2026-10-24T10:00:00.123456789Z', runtime_last_seen: '2026-10-24T10:05:00+00:00',
      runtime_batch_count: 1_000_000_000,
    } })).toMatchObject({
      firstEvent: '2026-10-24T10:00:00.123456789Z', lastEvent: '2026-10-24T10:05:00+00:00', batchCount: 1_000_000_000,
    });
  });

  it('does not invent a pod name or infer a controller identity', () => {
    expect(runtimeSubject({ namespace: 'apps', podName: 'web-1' })).toBe('apps/web-1');
    expect(runtimeSubject({ namespace: 'apps' })).toBe('apps / Pod name unavailable');
    expect(runtimeSubject({})).toBe('Runtime subject');
  });
});
