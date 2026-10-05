import { useQueries } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useFindingGroups, useFindings } from '../api/hooks';
import { SEVERITIES } from '../api/types';
import type { Severity } from '../api/types';
import { DAY_MS } from '../lib/triage';

/** Bounded lists plus aggregates over the complete inventory. */
export function useDashboardFindings(now: number) {
  const attention = useFindings({ attention: true, sort: 'attention', limit: 50 });
  const zones = useFindingGroups({ status: ['open'], min_severity: 'medium', group_by: 'zone', sort: 'count', limit: 7 });
  const checks = useFindingGroups({ status: ['open'], min_severity: 'medium', group_by: 'check', sort: 'count', limit: 6 });
  // Keep an exact window stable across renders and query completions.
  const [after, setAfter] = useState(() => new Date(now - DAY_MS).toISOString());
  useEffect(() => {
    const timer = setInterval(() => setAfter(new Date(Date.now() - DAY_MS).toISOString()), 60_000);
    return () => clearInterval(timer);
  }, []);
  const fresh = useQueries({ queries: SEVERITIES.map((severity) => {
    const params = { status: ['open'], severity, first_seen_after: after, limit: 1 };
    return { queryKey: ['findings', 'fresh', params], queryFn: async () => (await api.findings(params)).total };
  }) });
  const freshCounts = fresh.every((q) => q.data !== undefined)
    ? Object.fromEntries(SEVERITIES.map((severity, i) => [severity, fresh[i]?.data])) as Record<Severity, number>
    : undefined;
  const tallies = (items: typeof zones.data) => (items?.items ?? [])
    .filter((g) => g.key !== '')
    .slice(0, 6)
    .map((g) => ({ key: g.key, count: g.total }));
  return { attention, zones, checks, freshCounts, zoneTallies: tallies(zones.data), checkTallies: tallies(checks.data) };
}
