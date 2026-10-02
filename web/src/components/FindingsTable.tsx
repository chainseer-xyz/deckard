import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, ChevronDown, ChevronRight, EyeOff, RotateCcw, ThumbsDown } from 'lucide-react';
import type { Finding, FindingAction } from '../api/types';
import { useFindingAction, useMe } from '../api/hooks';
import { absTime, relTime } from '../lib/format';
import { intelOf, pctile } from '../lib/intel';
import { Empty, EpssChip, JsonViewer, KevBadge, SeverityBadge, StatusChip } from './ui';
import { SuppressModal } from './SuppressModal';

type Pending = { finding: Finding; action: 'suppress' | 'false-positive' } | null;

const ACTIONS: Record<Finding['status'], FindingAction[]> = {
  open: ['acknowledge', 'suppress', 'false-positive'],
  acknowledged: ['suppress', 'false-positive', 'reopen'],
  suppressed: ['reopen'],
  false_positive: ['reopen'],
  resolved: [],
};

const META: Record<FindingAction, { label: string; Icon: typeof Check }> = {
  acknowledge: { label: 'Acknowledge', Icon: Check },
  suppress: { label: 'Suppress', Icon: EyeOff },
  'false-positive': { label: 'False positive', Icon: ThumbsDown },
  reopen: { label: 'Reopen', Icon: RotateCcw },
};

function IntelChips({ f }: { f: Finding }) {
  const intel = intelOf(f);
  if (!intel) return null;
  return (
    <span className="ml-2 inline-flex flex-wrap items-center gap-1 align-middle">
      {intel.kev && <KevBadge dateAdded={intel.kevDateAdded} />}
      {intel.epss !== undefined && <EpssChip score={intel.epss} percentile={intel.epssPercentile} />}
    </span>
  );
}

function IntelDetail({ f }: { f: Finding }) {
  const intel = intelOf(f);
  if (!intel) return null;
  return (
    <div aria-label="Exploit intelligence">
      <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Exploit intelligence</h3>
      <ul className="space-y-1 text-sm">
        {intel.kev && (
          <li>
            <KevBadge dateAdded={intel.kevDateAdded} /> Known exploited (CISA KEV
            {intel.kevDateAdded ? `, added ${intel.kevDateAdded}` : ''})
            {intel.kevRansomware ? '; used in ransomware campaigns' : ''}
            {intel.kevRequiredAction && <div className="mt-0.5 text-xs text-muted">Required action: {intel.kevRequiredAction}</div>}
          </li>
        )}
        {intel.epss !== undefined && (
          <li>
            <EpssChip score={intel.epss} percentile={intel.epssPercentile} /> exploitation probability
            {intel.epssPercentile !== undefined ? ` (${pctile(intel.epssPercentile)})` : ''}
          </li>
        )}
      </ul>
    </div>
  );
}

export function FindingDetail({ f }: { f: Finding }) {
  return (
    <div className="grid gap-3 p-3 md:grid-cols-2">
      <div className="space-y-3">
        <IntelDetail f={f} />
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Description</h3>
          <p className="whitespace-pre-wrap text-sm">{f.description || '-'}</p>
        </div>
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Remediation</h3>
          <p className="whitespace-pre-wrap text-sm">{f.remediation || 'No remediation guidance.'}</p>
        </div>
        <dl className="grid grid-cols-2 gap-2 text-xs text-muted">
          <div>First seen: {absTime(f.first_seen)}</div>
          <div>Last seen: {absTime(f.last_seen)}</div>
          <div>Reopened: {f.reopened_count}x</div>
          <div>Missed runs: {f.missed_runs}</div>
          {f.suppressed_until && <div>Suppressed until: {absTime(f.suppressed_until)}</div>}
          {f.suppression_note && <div className="col-span-2">Note: {f.suppression_note}</div>}
          {f.tags && f.tags.length > 0 && <div className="col-span-2">Tags: {f.tags.join(', ')}</div>}
        </dl>
      </div>
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Evidence</h3>
        {f.evidence && Object.keys(f.evidence).length > 0 ? (
          <JsonViewer value={f.evidence} label={`Evidence for ${f.title}`} />
        ) : (
          <p className="text-sm text-muted">No evidence recorded.</p>
        )}
      </div>
    </div>
  );
}

export function FindingsTable({ items, compact = false }: { items: Finding[]; compact?: boolean }) {
  const me = useMe();
  const mut = useFindingAction();
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<Pending>(null);
  const canWrite = me.data?.can_write ?? false;

  const toggle = (id: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const run = (f: Finding, a: FindingAction) => {
    if (a === 'suppress' || a === 'false-positive') setPending({ finding: f, action: a });
    else mut.mutate({ id: f.id, action: a, body: { note: '' } });
  };

  if (items.length === 0) return <Empty>No findings match.</Empty>;

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b border-line">
            <tr>
              <th className="th w-8">
                <span className="sr-only">Expand</span>
              </th>
              <th className="th">Severity</th>
              <th className="th">Finding</th>
              {!compact && <th className="th">Asset</th>}
              <th className="th">Check</th>
              <th className="th">Status</th>
              <th className="th">Age</th>
              <th className="th">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f) => {
              const expanded = open.has(f.id);
              return (
                <Fragment key={f.id}>
                  <tr className="border-b border-line/60 hover:bg-surface2/50">
                    <td className="td">
                      <button
                        className="rounded-sm p-0.5 hover:bg-surface2"
                        aria-expanded={expanded}
                        aria-controls={`finding-${f.id}`}
                        aria-label={`${expanded ? 'Collapse' : 'Expand'} details for ${f.title}`}
                        onClick={() => toggle(f.id)}
                      >
                        {expanded ? (
                          <ChevronDown size={14} aria-hidden="true" />
                        ) : (
                          <ChevronRight size={14} aria-hidden="true" />
                        )}
                      </button>
                    </td>
                    <td className="td">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="td max-w-md font-medium">
                      {f.title}
                      <IntelChips f={f} />
                    </td>
                    {!compact && (
                      <td className="td font-mono text-xs">
                        <Link className="text-accent hover:underline" to={`/assets/${f.asset_id}`}>
                          {f.asset_key}
                        </Link>
                      </td>
                    )}
                    <td className="td font-mono text-xs">{f.check}</td>
                    <td className="td">
                      <StatusChip status={f.status} />
                    </td>
                    <td className="td whitespace-nowrap text-xs text-muted" title={absTime(f.first_seen)}>
                      {relTime(f.first_seen).replace(' ago', '')}
                    </td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {ACTIONS[f.status].map((a) => {
                          const M = META[a];
                          return (
                            <button
                              key={a}
                              className="btn btn-sm"
                              disabled={!canWrite || mut.isPending}
                              title={canWrite ? undefined : 'Read-only access'}
                              aria-label={`${M.label}: ${f.title}`}
                              onClick={() => run(f, a)}
                            >
                              <M.Icon size={12} aria-hidden="true" />
                              {M.label}
                            </button>
                          );
                        })}
                      </div>
                    </td>
                  </tr>
                  {expanded && (
                    <tr id={`finding-${f.id}`} className="border-b border-line bg-surface2/40">
                      <td colSpan={compact ? 7 : 8}>
                        <FindingDetail f={f} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {mut.isError && (
        <p role="alert" className="px-3 py-2 text-sm text-bad">
          Action failed: {(mut.error as Error).message}
        </p>
      )}
      {pending && (
        <SuppressModal
          title={pending.action === 'suppress' ? 'Suppress finding' : 'Mark as false positive'}
          subject={pending.finding.title}
          submitLabel={pending.action === 'suppress' ? 'Suppress' : 'Mark false positive'}
          withExpiry={pending.action === 'suppress'}
          busy={mut.isPending}
          error={mut.isError ? (mut.error as Error).message : undefined}
          onClose={() => {
            mut.reset();
            setPending(null);
          }}
          onSubmit={(v) =>
            mut.mutate(
              { id: pending.finding.id, action: pending.action, body: v },
              { onSuccess: () => setPending(null) },
            )
          }
        />
      )}
    </>
  );
}
