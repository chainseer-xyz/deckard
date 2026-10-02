import type { ReactNode } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  Flame,
  Gauge,
  Info,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react';
import { ApiError } from '../api/client';
import type { FindingStatus, Severity } from '../api/types';
import { titleCase } from '../lib/format';
import { pct, pctile } from '../lib/intel';

const SEV: Record<Severity, { cls: string; Icon: LucideIcon }> = {
  critical: { cls: 'border-sev-critical text-sev-critical bg-sev-critical/10', Icon: ShieldAlert },
  high: { cls: 'border-sev-high text-sev-high bg-sev-high/10', Icon: AlertTriangle },
  medium: { cls: 'border-sev-medium text-sev-medium bg-sev-medium/10', Icon: AlertCircle },
  low: { cls: 'border-sev-low text-sev-low bg-sev-low/10', Icon: ArrowDown },
  info: { cls: 'border-sev-info text-sev-info bg-sev-info/10', Icon: Info },
};

/** Severity is always icon + text, never colour alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV[severity] ?? SEV.info;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold uppercase ${s.cls}`}
    >
      <s.Icon size={12} aria-hidden="true" />
      {severity}
    </span>
  );
}

/** CISA Known Exploited Vulnerabilities badge: icon + text, never colour alone. */
export function KevBadge({ dateAdded }: { dateAdded?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-sev-critical bg-sev-critical/10 px-1.5 py-0.5 text-xs font-semibold uppercase text-sev-critical"
      title={dateAdded ? `Listed in CISA KEV, added ${dateAdded}` : 'Listed in CISA Known Exploited Vulnerabilities'}
    >
      <Flame size={12} aria-hidden="true" />
      KEV
      <span className="sr-only">: known exploited vulnerability</span>
    </span>
  );
}

/** EPSS exploitation probability chip, e.g. "EPSS 94.4%". */
export function EpssChip({ score, percentile }: { score: number; percentile?: number }) {
  const title =
    percentile === undefined
      ? 'FIRST EPSS exploitation probability'
      : `FIRST EPSS exploitation probability, ${pctile(percentile)}`;
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-line bg-surface2 px-1.5 py-0.5 text-xs text-muted"
      title={title}
    >
      <Gauge size={12} aria-hidden="true" />
      EPSS {pct(score)}
    </span>
  );
}

const STATUS_CLS: Record<FindingStatus, string> = {
  open: 'border-bad text-bad',
  acknowledged: 'border-warn text-warn',
  suppressed: 'border-muted text-muted',
  false_positive: 'border-muted text-muted',
  resolved: 'border-ok text-ok',
};

export function StatusChip({ status }: { status: FindingStatus }) {
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs ${STATUS_CLS[status] ?? ''}`}>
      {titleCase(status)}
    </span>
  );
}

const SCOPE_CLS: Record<string, string> = {
  owned: 'border-ok text-ok',
  shared: 'border-warn text-warn',
  external: 'border-muted text-muted',
  excluded: 'border-bad text-bad',
};
export function ScopeBadge({ scope }: { scope: string }) {
  return (
    <span className={`inline-flex rounded border px-1.5 py-0.5 text-xs ${SCOPE_CLS[scope] ?? 'border-line'}`}>
      {scope}
    </span>
  );
}

export function KindBadge({ kind }: { kind: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span
        aria-hidden="true"
        className="inline-block h-2.5 w-2.5 rounded-sm"
        style={{ background: `rgb(var(--k-${kind}, var(--muted)))` }}
      />
      {kind}
    </span>
  );
}

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h1 className="text-lg font-semibold">{title}</h1>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

export function Card({
  title,
  children,
  right,
  className = '',
}: {
  title?: string;
  children: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`} aria-label={title}>
      {title && (
        <header className="flex items-center justify-between border-b border-line px-3 py-2">
          <h2 className="text-sm font-semibold">{title}</h2>
          {right}
        </header>
      )}
      <div>{children}</div>
    </section>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="p-4 text-sm text-muted">
      {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof ApiError ? `${error.message} (${error.code})` : String(error);
  return (
    <div role="alert" className="m-3 rounded-md border border-bad bg-bad/10 p-3 text-sm text-bad">
      <div className="flex items-center gap-2">
        <AlertTriangle size={14} aria-hidden="true" />
        <span>{msg}</span>
        {onRetry && (
          <button className="btn btn-sm ml-auto" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="flex items-center gap-2 p-4 text-sm text-muted">{children}</div>;
}

export function OkMark() {
  return <CheckCircle2 size={14} className="text-ok" aria-hidden="true" />;
}

export function Pagination({
  total,
  limit,
  offset,
  onPage,
}: {
  total: number;
  limit: number;
  offset: number;
  onPage: (page: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-muted">
      <span>
        {from}-{to} of {total}
      </span>
      <span className="flex items-center gap-2">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </button>
        <span>
          Page {page} / {pages}
        </span>
        <button className="btn btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next
        </button>
      </span>
    </nav>
  );
}

export function JsonViewer({ value, label }: { value: unknown; label: string }) {
  return (
    <pre
      tabIndex={0}
      aria-label={label}
      className="max-h-72 overflow-auto rounded-md border border-line bg-surface2 p-2 font-mono text-xs leading-relaxed"
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5 text-sm">{children}</dd>
    </div>
  );
}
