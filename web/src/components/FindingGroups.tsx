import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { Finding, FindingGroup } from '../api/types';
import type { FindingsParams } from '../api/client';
import { useFindings } from '../api/hooks';
import { SEVERITIES } from '../api/types';
import type { SortDir, SortKey } from '../lib/findingsFilter';
import type { GroupBy } from '../lib/triage';
import { FindingsTable } from './FindingsTable';
import { ErrorBox, Loading, Pagination, SeverityBadge } from './ui';

const BY_LABEL: Record<Exclude<GroupBy, 'none'>, string> = { asset: 'asset', check: 'check', zone: 'zone' };

/** Collapsible groups with per-severity counts; a group's findings expand inline. */
export function FindingGroups({
  groups,
  by,
  params,
  onOpen,
  selectedId,
  sort,
  dir,
  onSort,
}: {
  groups: FindingGroup[];
  by: Exclude<GroupBy, 'none'>;
  params: FindingsParams;
  onOpen: (f: Finding) => void;
  selectedId?: number;
  sort: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (k: string) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  const allOpen = groups.length > 0 && groups.every((g) => open.has(g.key));

  return (
    <div>
      <div className="flex items-center justify-between border-b border-line px-3 py-2 text-xs text-muted">
        <span>
          {groups.length} {BY_LABEL[by]} group{groups.length === 1 ? '' : 's'}
        </span>
        <button className="btn btn-sm" onClick={() => setOpen(allOpen ? new Set() : new Set(groups.map((g) => g.key)))}>
          {allOpen ? 'Collapse all' : 'Expand all'}
        </button>
      </div>
      <ul className="divide-y divide-line">
        {groups.map((g) => {
          const expanded = open.has(g.key);
          return (
            <li key={g.key}>
              <button
                className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-left hover:bg-surface2/50"
                aria-label={`${g.label}, ${g.total} finding${g.total === 1 ? '' : 's'}: ${[...SEVERITIES]
                  .reverse()
                  .filter((s) => g.counts[s] > 0)
                  .map((s) => `${g.counts[s]} ${s}`)
                  .join(', ')}`}
                aria-expanded={expanded}
                aria-controls={`group-${by}-${encodeURIComponent(g.key)}`}
                onClick={() => toggle(g.key)}
              >
                {expanded ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
                <span className="min-w-0 flex-1 truncate font-mono text-sm font-medium">{g.label}</span>
                <span className="text-xs tabular-nums text-muted">
                  {g.total} finding{g.total === 1 ? '' : 's'}
                </span>
                <span className="flex flex-wrap gap-1">
                  {[...SEVERITIES]
                    .reverse()
                    .filter((s) => g.counts[s] > 0)
                    .map((s) => (
                      <span key={s} className="inline-flex items-center gap-1 text-xs tabular-nums">
                        <SeverityBadge severity={s} />
                        {g.counts[s]}
                      </span>
                    ))}
                </span>
              </button>
              {expanded && (
                <div id={`group-${by}-${encodeURIComponent(g.key)}`} className="border-t border-line bg-surface2/20">
                  <GroupMembers
                    key={JSON.stringify(params)}
                    params={{ ...params, group_by: by, group_key: g.key }}
                    onOpen={onOpen}
                    selectedId={selectedId}
                    compact={by === 'asset'}
                    sort={sort}
                    dir={dir}
                    onSort={onSort}
                  />
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function GroupMembers({ params, ...table }: { params: FindingsParams } & Omit<Parameters<typeof FindingsTable>[0], 'items'>) {
  const [page, setPage] = useState(1);
  const limit = 50;
  const query = useFindings({ ...params, limit, offset: (page - 1) * limit });
  return (
    <>
      {query.isLoading && <Loading />}
      {query.isError && <ErrorBox error={query.error} onRetry={() => void query.refetch()} />}
      {query.data && (
        <>
          <FindingsTable {...table} items={query.data.items} />
          <Pagination total={query.data.total} limit={limit} offset={(page - 1) * limit} onPage={setPage} />
        </>
      )}
    </>
  );
}
