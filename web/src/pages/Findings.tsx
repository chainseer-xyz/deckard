import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { useFindings, useStats } from '../api/hooks';
import { SEVERITIES, STATUSES } from '../api/types';
import type { FindingStatus, Severity } from '../api/types';
import { FindingsTable } from '../components/FindingsTable';
import { Card, ErrorBox, Loading, PageHeader, Pagination } from '../components/ui';
import { PAGE_SIZE, parseFilter, sortFindings, toApiParams, toSearchParams } from '../lib/findingsFilter';
import type { FindingsFilter, SortKey } from '../lib/findingsFilter';
import { titleCase } from '../lib/format';

export default function Findings() {
  const [sp, setSp] = useSearchParams();
  const filter = useMemo(() => parseFilter(sp), [sp]);
  const stats = useStats();
  const q = useFindings(toApiParams(filter));

  const update = (patch: Partial<FindingsFilter>, keepPage = false) =>
    setSp(toSearchParams({ ...filter, ...patch, page: keepPage ? (patch.page ?? filter.page) : 1 }), {
      replace: true,
    });

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
    update(
      filter.sort === key ? { dir: filter.dir === 'desc' ? 'asc' : 'desc' } : { sort: key, dir: 'desc' },
      true,
    );

  const items = useMemo(
    () => (q.data ? sortFindings(q.data.items, filter.sort, filter.dir) : []),
    [q.data, filter.sort, filter.dir],
  );
  const checks = Object.keys(stats.data?.findings_by_check ?? {});
  const sources = Object.keys(stats.data?.assets_by_source ?? {});
  const DirIcon = filter.dir === 'desc' ? ArrowDown : ArrowUp;

  return (
    <>
      <PageHeader title="Findings">
        <div className="flex items-center gap-1 text-xs" role="group" aria-label="Sort by">
          <span className="text-muted">Sort</span>
          {(['severity', 'age'] as SortKey[]).map((k) => (
            <button
              key={k}
              className={`btn btn-sm ${filter.sort === k ? 'border-accent' : ''}`}
              aria-pressed={filter.sort === k}
              onClick={() => setSort(k)}
            >
              {titleCase(k)}
              {filter.sort === k && <DirIcon size={12} aria-label={filter.dir === 'desc' ? 'descending' : 'ascending'} />}
            </button>
          ))}
        </div>
      </PageHeader>

      <Card className="mb-4">
        <form className="flex flex-wrap items-end gap-3 p-3" role="search" onSubmit={(e) => e.preventDefault()}>
          <div>
            <label htmlFor="f-q" className="mb-1 block text-xs text-muted">Search</label>
            <input id="f-q" type="search" className="input w-56" value={text} onChange={(e) => setText(e.target.value)} placeholder="title, asset…" />
          </div>
          <div>
            <label htmlFor="f-sev" className="mb-1 block text-xs text-muted">Min severity</label>
            <select id="f-sev" className="input" value={filter.minSeverity ?? ''} onChange={(e) => update({ minSeverity: (e.target.value || undefined) as Severity | undefined })}>
              <option value="">Any</option>
              {[...SEVERITIES].reverse().map((s) => (
                <option key={s} value={s}>{s}</option>
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
          {filter.assetId && (
            <button type="button" className="btn btn-sm" onClick={() => update({ assetId: undefined })}>
              Asset #{filter.assetId} ×
            </button>
          )}
        </form>
      </Card>

      <Card>
        {q.isLoading && <Loading />}
        {q.isError && <ErrorBox error={q.error} onRetry={() => void q.refetch()} />}
        {q.data && (
          <>
            <FindingsTable items={items} />
            <Pagination total={q.data.total} limit={q.data.limit || PAGE_SIZE} offset={q.data.offset} onPage={(p) => update({ page: p }, true)} />
          </>
        )}
      </Card>
    </>
  );
}
