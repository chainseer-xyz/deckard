import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp } from 'lucide-react';
import type { Finding } from '../api/types';
import { absTime, relTime } from '../lib/format';
import type { SortDir, SortKey } from '../lib/findingsFilter';
import { isKev, isNew24h } from '../lib/triage';
import { Empty, KevBadge, NewBadge, ReopenedBadge, SeverityBadge, StatusChip } from './ui';

function SortTh({
  label,
  k,
  sort,
  dir,
  onSort,
}: {
  label: string;
  k: SortKey;
  sort?: SortKey;
  dir?: SortDir;
  onSort?: (k: SortKey) => void;
}) {
  const active = sort === k;
  const Icon = dir === 'asc' ? ArrowUp : ArrowDown;
  return (
    <th className="th" aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      {onSort ? (
        <button className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-fg" onClick={() => onSort(k)}>
          {label}
          {active && <Icon size={12} aria-hidden="true" />}
        </button>
      ) : (
        label
      )}
    </th>
  );
}

/**
 * Findings as a table. Clicking a title opens the detail drawer via onOpen.
 * `compact` hides the asset and zone columns (asset pages).
 */
export function FindingsTable({
  items,
  onOpen,
  selectedId,
  compact = false,
  sort,
  dir,
  onSort,
  now,
}: {
  items: Finding[];
  onOpen: (f: Finding) => void;
  selectedId?: number;
  compact?: boolean;
  sort?: SortKey;
  dir?: SortDir;
  onSort?: (k: SortKey) => void;
  now?: number;
}) {
  if (items.length === 0) return <Empty>No findings match.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="border-b border-line">
          <tr>
            <SortTh label="Severity" k="severity" sort={sort} dir={dir} onSort={onSort} />
            <th className="th">Finding</th>
            {!compact && <th className="th">Asset</th>}
            {!compact && <th className="th">Zone</th>}
            <th className="th">Check</th>
            <th className="th">Status</th>
            <SortTh label="First seen" k="first_seen" sort={sort} dir={dir} onSort={onSort} />
            <SortTh label="Last seen" k="last_seen" sort={sort} dir={dir} onSort={onSort} />
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr
              key={f.id}
              aria-current={f.id === selectedId ? 'true' : undefined}
              className={`border-b border-line/60 hover:bg-surface2/50 ${f.id === selectedId ? 'bg-surface2' : ''}`}
            >
              <td className="td">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="td max-w-md">
                <button
                  className="text-left font-medium hover:text-accent hover:underline"
                  aria-haspopup="dialog"
                  onClick={() => onOpen(f)}
                >
                  {f.title}
                </button>
                <span className="ml-2 inline-flex flex-wrap items-center gap-1 align-middle">
                  {isKev(f) && <KevBadge />}
                  {isNew24h(f, now) && <NewBadge />}
                  <ReopenedBadge count={f.reopened_count} />
                </span>
              </td>
              {!compact && (
                <td className="td font-mono text-xs">
                  <Link className="text-accent hover:underline" to={`/assets/${f.asset_id}`}>
                    {f.asset_key}
                  </Link>
                </td>
              )}
              {!compact && <td className="td text-xs">{f.zone || '-'}</td>}
              <td className="td font-mono text-xs">{f.check}</td>
              <td className="td">
                <StatusChip status={f.status} />
              </td>
              <td className="td whitespace-nowrap text-xs text-muted" title={absTime(f.first_seen)}>
                {relTime(f.first_seen, now)}
              </td>
              <td className="td whitespace-nowrap text-xs text-muted" title={absTime(f.last_seen)}>
                {relTime(f.last_seen, now)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
