import { useState } from 'react';
import { ArrowRight } from 'lucide-react';
import { absUtc, relTime } from '../lib/format';
import { evidenceRows } from '../lib/evidence';
import type { DataChange, EvidenceRow } from '../lib/evidence';
import { JsonViewer } from './ui';

const MAX_TEXT = 140;
const MAX_ITEMS = 8;

function Collapsible({ text, label }: { text: string; label: string }) {
  const [open, setOpen] = useState(false);
  if (text.length <= MAX_TEXT) return <span className="[overflow-wrap:anywhere]">{text}</span>;
  return (
    <span className="[overflow-wrap:anywhere]">
      {open ? text : `${text.slice(0, MAX_TEXT)}…`}{' '}
      <button
        type="button"
        className="text-xs text-accent hover:underline"
        aria-expanded={open}
        aria-label={`${open ? 'Show less' : 'Show more'}: ${label}`}
        onClick={() => setOpen(!open)}
      >
        {open ? 'show less' : `show more (${text.length} chars)`}
      </button>
    </span>
  );
}

export function PortChips({ ports }: { ports: number[] }) {
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Ports">
      {ports.map((p) => (
        <li key={p} className="min-w-0 max-w-full rounded-sm border border-line bg-surface2 px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere]">
          {p}
        </li>
      ))}
    </ul>
  );
}

/** Absolute (UTC) plus relative time, e.g. `2026-10-12 09:00 UTC (in 6d)`. */
export function TimeValue({ value, now }: { value: string; now?: number }) {
  const rel = relTime(value, now);
  const past = Date.parse(value) < (now ?? Date.now());
  return (
    <time dateTime={value} title={value}>
      {absUtc(value)} <span className={past ? 'text-muted' : 'font-medium'}>({rel})</span>
    </time>
  );
}

export function ChainPath({ hops, endLabel, endBad }: { hops: string[]; endLabel?: string; endBad?: boolean }) {
  return (
    <ol className="flex flex-wrap items-center gap-1" aria-label="Chain">
      {hops.map((h, i) => {
        const last = i === hops.length - 1;
        return (
          <li key={`${h}-${i}`} className="flex min-w-0 max-w-full items-center gap-1">
            {i > 0 && <ArrowRight size={12} aria-hidden="true" className="shrink-0 text-muted" />}
            <span
              className={`min-w-0 rounded-sm border px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere] ${
                last && endBad ? 'border-bad bg-bad/10 font-semibold text-bad' : 'border-line bg-surface2'
              }`}
            >
              {h}
              {last && endLabel && <span className="ml-1.5 font-sans uppercase">{endLabel}</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

/** One evidence value, rendered by its kind. */
export function EvidenceValue({ row, now }: { row: Pick<EvidenceRow, 'kind' | 'label' | 'value'>; now?: number }) {
  const v = row.value;
  switch (row.kind) {
    case 'bool':
      return <span>{v ? 'yes' : 'no'}</span>;
    case 'time':
      return <TimeValue value={v as string} now={now} />;
    case 'days': {
      const n = v as number;
      return <span>{n < 0 ? `expired ${-n} day${-n === 1 ? '' : 's'} ago` : `${n} day${n === 1 ? '' : 's'}`}</span>;
    }
    case 'ports':
      return <PortChips ports={Array.isArray(v) ? (v as number[]) : [v as number]} />;
    case 'chain':
      return <ChainPath hops={v as string[]} />;
    case 'host':
      return <Collapsible text={String(v)} label={row.label} />;
    case 'list': {
      const items = v as (string | number | boolean | null)[];
      if (items.length === 0) return <span className="text-muted">none</span>;
      return <ListValue items={items.map(String)} label={row.label} />;
    }
    default:
      if (v === null || v === undefined || v === '') return <span className="text-muted">none</span>;
      if (typeof v === 'object') return <Collapsible text={JSON.stringify(v)} label={row.label} />;
      return <Collapsible text={String(v)} label={row.label} />;
  }
}

function ListValue({ items, label }: { items: string[]; label: string }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, MAX_ITEMS);
  return (
    <div className="min-w-0 max-w-full">
      <ul className="flex flex-wrap gap-1">
        {shown.map((x, i) => (
          <li key={`${x}-${i}`} className="min-w-0 max-w-full rounded-sm border border-line bg-surface2 px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere]">
            <Collapsible text={x} label={`${label} item ${i + 1}`} />
          </li>
        ))}
      </ul>
      {items.length > MAX_ITEMS && (
        <button
          type="button"
          className="mt-1 text-xs text-accent hover:underline"
          aria-expanded={all}
          aria-label={`${all ? 'Show fewer' : 'Show all'}: ${label}`}
          onClick={() => setAll(!all)}
        >
          {all ? 'show fewer' : `show all ${items.length}`}
        </button>
      )}
    </div>
  );
}

const MARK: Record<DataChange, { text: string; cls: string }> = {
  changed: { text: 'changed', cls: 'border-warn text-warn' },
  new: { text: 'new', cls: 'border-sev-medium text-sev-medium' },
  gone: { text: 'gone', cls: 'border-muted text-muted' },
};

export function ChangeMark({ change }: { change: DataChange }) {
  const m = MARK[change];
  return (
    <span className={`ml-2 inline-flex rounded-sm border px-1 text-[10px] font-semibold uppercase ${m.cls}`}>
      {m.text}
    </span>
  );
}

/**
 * Evidence / observation data as a readable key-value table. Known keys render
 * specially (hosts, expiry times, port lists, CNAME chains); long values
 * collapse; the raw JSON stays one click away.
 */
export function EvidenceTable({
  data,
  label,
  changes,
  now,
  raw = true,
}: {
  data: Record<string, unknown> | undefined | null;
  label: string;
  changes?: Map<string, DataChange>;
  now?: number;
  raw?: boolean;
}) {
  const rows = evidenceRows(data);
  if (rows.length === 0) return <p className="text-sm text-muted">No evidence recorded.</p>;
  return (
    <div className="min-w-0 max-w-full">
      <table className="w-full table-fixed text-sm" aria-label={label}>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="border-b border-line/60 last:border-b-0">
              <th scope="row" className="w-1/3 py-1.5 pr-3 align-top text-xs font-medium text-muted [overflow-wrap:anywhere]">
                {r.label}
              </th>
              <td className="py-1.5 align-top [overflow-wrap:anywhere]">
                <EvidenceValue row={r} now={now} />
                {changes?.get(r.key) && <ChangeMark change={changes.get(r.key) as DataChange} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {raw && data && (
        <details className="mt-1">
          <summary className="cursor-pointer text-xs text-muted">Raw JSON</summary>
          <JsonViewer value={data} label={`${label} (raw)`} />
        </details>
      )}
    </div>
  );
}
