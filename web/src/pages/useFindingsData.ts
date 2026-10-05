import { useFindingGroups, useFindings, useFindingTotal } from '../api/hooks';
import { PAGE_SIZE, toApiParams, withoutSeverity } from '../lib/findingsFilter';
import type { FindingsFilter } from '../lib/findingsFilter';

export const GROUP_PAGE_SIZE = 25;

/** Every view pages the complete server result; groups fetch members on demand. */
export function useFindingsData(filter: FindingsFilter) {
  const params = toApiParams(filter);
  const grouped = filter.groupBy !== 'none';
  const findings = useFindings({ ...params, limit: PAGE_SIZE, offset: (filter.page - 1) * PAGE_SIZE }, !grouped);
  const groups = useFindingGroups({
    ...params,
    group_by: grouped ? filter.groupBy as 'asset' | 'check' | 'zone' : undefined,
    limit: GROUP_PAGE_SIZE,
    offset: (filter.page - 1) * GROUP_PAGE_SIZE,
  }, grouped);
  const matchingTotal = useFindingTotal(params, grouped);
  const total = useFindingTotal(withoutSeverity(params));
  return {
    params,
    findings,
    groups,
    total,
    matchingTotal: grouped ? matchingTotal.data : findings.data?.total,
    query: grouped ? groups : findings,
  };
}
