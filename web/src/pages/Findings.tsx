import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAllFindings, useFindingTotal, useStats } from '../api/hooks';
import { SEVERITIES, STATUSES } from '../api/types';
import type { Finding, FindingStatus, Severity } from '../api/types';
import { FindingGroups } from '../components/FindingGroups';
import { FindingsTable } from '../components/FindingsTable';
import { Card, ErrorBox, Loading, PageHeader, Pagination } from '../components/ui';
import {
  PAGE_SIZE,
  applyExactSeverity,
  pageOf,
  parseFilter,
  sortFindings,
  toApiParams,
  toSearchParams,
  withoutSeverity,
} from '../lib/findingsFilter';
import type { FindingsFilter, SortKey } from '../lib/findingsFilter';
import { titleCase } from '../lib/format';
import { GROUP_BYS, groupFindings } from '../lib/triage';
import type { GroupBy } from '../lib/triage';

const GROUP_PAGE_SIZE = 25;
const DRAWER_PARAM = 'finding';

export default function Findings() {
  const [sp, setSp] = useSearchParams();
  const filter = useMemo(() => parseFilter(sp), [sp]);
  const drawerId = Number(sp.get(DRAWER_PARAM)) || undefined;
  const stats = useStats();
  const apiParams = useMemo(() => toApiParams(filter), [filter]);
  const q = useAllFindings(apiParams);
  const total = useFindingTotal(withoutSeverity(apiParams));

  // Filters live in the URL; the open drawer (`finding`) is carried along.
  const writeUrl = (next: FindingsFilter) => {
    const out = toSearchParams(next);
    const d = sp.get(DRAWER_PARAM);
    if (d) out.set(DRAWER_PARAM, d);
    setSp(out, { replace: true });
  };
  const update = (patch: Partial<FindingsFilter>, keepPage = false) =>
    writeUrl({ ...filter, ...patch, page: keepPage ? (patch.page ?? filter.page) : 1 });

  const open = (f: Finding) => {
    const n = new URLSearchParams(sp);
    n.set(DRAWER_PARAM, String(f.id));
    setSp(n);
  };

  // search box is debounced into the URL
  const [text, setText] = useState(filter.q);
  useEffect(() => setText(filter.q), [filter.q]);
  useEffect(() => {
    if (text === filter.q) return;
    const t = setTimeout(() => update({ q: text }), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const toggleStatus = (s: FindingStatus) =>
    update({ status: filter.status.includes(s) ? filter.status.filter((x) => x !== s) : [...filter.status, s] });

  const setSort = (key: SortKey) =>
    update(filter.sort === key ? { dir: filter.dir === 'desc' ? 'asc' : 'desc' } : { sort: key, dir: 'desc' }, true);

  const sorted = useMemo(
    () => (q.data ? sortFindings(applyExactSeverity(q.data, filter), filter.sort, filter.dir) : []),
    [q.data, filter],
  );
  const groups = useMemo(
    () => (filter.groupBy === 'none' ? [] : groupFindings(sorted, filter.groupBy)),
    [sorted, filter.groupBy],
  );
  const checks = Object.keys(stats.data?.findings_by_check ?? {});
  const sources = Object.keys(stats.data?.assets_by_source ?? {});
  const showingAll = filter.minSeverity === 'info' && !filter.severity;

  return (
    <>
      <PageHeader title="Findings" />

      <Card className="mb-4">
        <form className="flex flex-wrap items-end gap-3 p-3" role="search" onSubmit={(e) => e.preventDefault()}>
          <div>
            <label htmlFor="f-q" className="mb-1 block text-xs text-muted">Search</label>
            <input id="f-q" type="search" className="input w-56" value={text} onChange={(e) => setText(e.target.value)} placeholder="title, asset…" />
          </div>
          <div>
            <label htmlFor="f-sev" className="mb-1 block text-xs text-muted">Min severity</label>
            <select
              id="f-sev"
              className="input"
              value={filter.minSeverity}
              onChange={(e) => update({ minSeverity: e.target.value as Severity, severity: undefined })}
            >
              {[...SEVERITIES].reverse().map((s) => (
                <option key={s} value={s}>{s === 'info' ? 'info (all)' : s}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="f-check" className="mb-1 block text-xs text-muted">Check</label>
            <select id="f-check" className="input" value={filter.check} onChange={(e) => update({ check: e.target.value })}>
              <option value="">Any</option>
              {filter.check && !checks.includes(filter.check) && <option value={filter.check}>{filter.check}</option>}
              {checks.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-src" className="mb-1 block text-xs text-muted">Source</label>
            <select id="f-src" className="input" value={filter.source} onChange={(e) => update({ source: e.target.value })}>
              <option value="">Any</option>
              {filter.source && !sources.includes(filter.source) && <option value={filter.source}>{filter.source}</option>}
              {sources.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="f-zone" className="mb-1 block text-xs text-muted">Zone</label>
            <input id="f-zone" className="input w-40" defaultValue={filter.zone} key={filter.zone} onBlur={(e) => e.target.value !== filter.zone && update({ zone: e.target.value })} onKeyDown={(e) => { if (e.key === 'Enter') update({ zone: e.currentTarget.value }); }} />
          </div>
          <div>
            <label htmlFor="f-group" className="mb-1 block text-xs text-muted">Group by</label>
            <select id="f-group" className="input" value={filter.groupBy} onChange={(e) => update({ groupBy: e.target.value as GroupBy })}>
              {GROUP_BYS.map((g) => <option key={g} value={g}>{g === 'none' ? 'None' : titleCase(g)}</option>)}
            </select>
          </div>
          <fieldset>
            <legend className="mb-1 text-xs text-muted">Status</legend>
            <div className="flex flex-wrap gap-1">
              {STATUSES.map((s) => {
                const on = filter.status.includes(s);
                return (
                  <button
                    key={s}
                    type="button"
                    aria-pressed={on}
                    onClick={() => toggleStatus(s)}
                    className={`rounded-full border px-2 py-0.5 text-xs ${on ? 'border-accent bg-accent/15 font-semibold' : 'border-line text-muted hover:bg-surface2'}`}
                  >
                    {on && <span aria-hidden="true">✓ </span>}
                    {titleCase(s)}
                  </button>
                );
              })}
            </div>
          </fieldset>
          {filter.severity && (
            <button type="button" className="btn btn-sm" onClick={() => update({ severity: undefined })}>
              Severity: {filter.severity} ×
            </button>
          )}
          {filter.assetId && (
            <button type="button" className="btn btn-sm" onClick={() => update({ assetId: undefined })}>
              Asset #{filter.assetId} ×
            </button>
          )}
        </form>
      </Card>

      <Card>
        <div className="flex min-h-10 flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2 text-sm" aria-live="polite">
          {q.data ? (
            <span>
              {filter.severity ? (
                <>Showing {sorted.length} {filter.severity} findings.</>
              ) : showingAll ? (
                <>Showing all {sorted.length} findings.</>
              ) : (
                <>
                  Showing {sorted.length} of {total.data ?? '…'} findings
                  {filter.minSeverity !== 'info' ? ` (${filter.minSeverity} and above)` : ''}.
                </>
              )}
            </span>
          ) : (
            <span className="text-muted">Loading…</span>
          )}
          {!filter.severity && (
            <button
              className="btn btn-sm"
              aria-pressed={showingAll}
              onClick={() => update({ minSeverity: showingAll ? 'medium' : 'info' })}
            >
              {showingAll ? 'Hide low and info' : 'Include low and info'}
            </button>
          )}
        </div>
        {q.isLoading && <Loading />}
        {q.isError && <ErrorBox error={q.error} onRetry={() => void q.refetch()} />}
        {q.data &&
          (filter.groupBy === 'none' ? (
            <>
              <FindingsTable
                items={pageOf(sorted, filter.page)}
                onOpen={open}
                selectedId={drawerId}
                sort={filter.sort}
                dir={filter.dir}
                onSort={setSort}
              />
              <Pagination total={sorted.length} limit={PAGE_SIZE} offset={(filter.page - 1) * PAGE_SIZE} onPage={(p) => update({ page: p }, true)} />
            </>
          ) : (
            <>
              <FindingGroups
                key={filter.groupBy}
                groups={pageOf(groups, filter.page, GROUP_PAGE_SIZE)}
                by={filter.groupBy}
                onOpen={open}
                selectedId={drawerId}
                sort={filter.sort}
                dir={filter.dir}
                onSort={setSort}
              />
              <Pagination total={groups.length} limit={GROUP_PAGE_SIZE} offset={(filter.page - 1) * GROUP_PAGE_SIZE} onPage={(p) => update({ page: p }, true)} />
            </>
          ))}
      </Card>
    </>
  );
}
