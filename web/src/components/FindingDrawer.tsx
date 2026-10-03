import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ClipboardCopy, ExternalLink, RefreshCw, X } from 'lucide-react';
import { useFinding, useFindingTotal, useMe, useRescan } from '../api/hooks';
import type { Finding } from '../api/types';
import { absTime, relTime } from '../lib/format';
import { intelOf, pctile } from '../lib/intel';
import { findingMarkdown, isKev, isNew24h } from '../lib/triage';
import { EvidenceTable } from './Evidence';
import { FindingActions } from './FindingActions';
import { EpssChip, ErrorBox, KevBadge, Loading, NewBadge, ReopenedBadge, SeverityBadge, StatusChip } from './ui';

function IntelDetail({ f }: { f: Finding }) {
  const intel = intelOf(f);
  if (!intel) return null;
  return (
    <section aria-label="Exploit intelligence">
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
    </section>
  );
}

/** Clipboard write with a legacy fallback; resolves false when neither works. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

function Related({ f }: { f: Finding }) {
  const onAsset = useFindingTotal({ status: ['open'], asset_id: f.asset_id });
  const sameCheck = useFindingTotal({ status: ['open'], check: f.check, zone: f.zone || undefined });
  const n = (q: { data?: number }) => (q.data === undefined ? '' : ` (${q.data} open)`);
  const zoneQ = f.zone ? `&zone=${encodeURIComponent(f.zone)}` : '';
  return (
    <section aria-label="Related">
      <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Related</h3>
      <ul className="space-y-1 text-sm">
        <li>
          <Link className="inline-flex items-center gap-1 text-accent hover:underline" to={`/assets/${f.asset_id}`}>
            <ExternalLink size={12} aria-hidden="true" /> Open asset {f.asset_key}
          </Link>
        </li>
        <li>
          <Link className="text-accent hover:underline" to={`/findings?asset_id=${f.asset_id}&min_severity=info`}>
            Other findings on this asset
          </Link>
          <span className="text-muted">{n(onAsset)}</span>
        </li>
        <li>
          <Link
            className="text-accent hover:underline"
            to={`/findings?check=${encodeURIComponent(f.check)}${zoneQ}&min_severity=info`}
          >
            Same check{f.zone ? ', same zone' : ''}
          </Link>
          <span className="text-muted">{n(sameCheck)}</span>
        </li>
      </ul>
    </section>
  );
}

/**
 * Right-hand drawer with everything needed to triage one finding. It is driven
 * by the `finding` URL parameter so a link opens straight to it.
 */
export function FindingDrawer({ id, seed, onClose }: { id: number; seed?: Finding; onClose: () => void }) {
  const q = useFinding(id, seed);
  const me = useMe();
  const rescan = useRescan();
  const [copied, setCopied] = useState<'' | 'ok' | 'fail'>('');
  const ref = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const f = q.data;
  const canWrite = me.data?.can_write ?? false;

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    return () => prev?.focus?.();
  }, []);

  const onKey = (e: React.KeyboardEvent) => {
    // events from a nested modal (suppress dialog) belong to that modal
    if ((e.target as HTMLElement).closest('[role=dialog]') !== ref.current) return;
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
    } else if (e.key === 'Tab' && ref.current) {
      const els = ref.current.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input, select, textarea, summary');
      const first = els[0];
      const last = els[els.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    }
  };

  const copy = async (x: Finding) => {
    const link = `${window.location.origin}/findings?finding=${x.id}`;
    setCopied((await copyText(findingMarkdown(x, absTime, link))) ? 'ok' : 'fail');
  };

  return (
    <div className="fixed inset-0 z-40 flex justify-end" onKeyDown={onKey}>
      <button className="absolute inset-0 bg-black/40" aria-label="Close finding details" tabIndex={-1} onClick={onClose} />
      <aside
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label="Finding details"
        className="relative flex h-full w-full max-w-2xl flex-col overflow-y-auto border-l border-line bg-surface shadow-xl"
      >
        <header className="sticky top-0 z-10 flex items-start gap-3 border-b border-line bg-surface px-4 py-3">
          <div className="min-w-0 flex-1">
            {f ? (
              <>
                <div className="mb-1 flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={f.severity} />
                  <StatusChip status={f.status} />
                  {isKev(f) && <KevBadge />}
                  {isNew24h(f) && <NewBadge />}
                  <ReopenedBadge count={f.reopened_count} />
                </div>
                <h2 className="text-base font-semibold leading-snug">{f.title}</h2>
              </>
            ) : (
              <h2 className="text-base font-semibold">Finding #{id}</h2>
            )}
          </div>
          <button ref={closeRef} className="btn btn-sm" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </button>
        </header>

        {q.isLoading && !f && <Loading />}
        {q.isError && !f && <ErrorBox error={q.error} onRetry={() => void q.refetch()} />}
        {f && (
          <div className="space-y-4 p-4">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <div>
                <dt className="text-xs text-muted">Asset</dt>
                <dd className="break-all font-mono text-xs">
                  <Link className="text-accent hover:underline" to={`/assets/${f.asset_id}`}>{f.asset_key}</Link>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Zone</dt>
                <dd className="text-xs">{f.zone || '-'}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Check</dt>
                <dd className="font-mono text-xs">{f.check}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Source</dt>
                <dd className="text-xs">{f.source || '-'}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">First seen</dt>
                <dd className="text-xs">{absTime(f.first_seen)} <span className="text-muted">({relTime(f.first_seen)})</span></dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Last seen</dt>
                <dd className="text-xs">{absTime(f.last_seen)} <span className="text-muted">({relTime(f.last_seen)})</span></dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Reopened</dt>
                <dd className="text-xs">{f.reopened_count}x</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Missed runs</dt>
                <dd className="text-xs">{f.missed_runs}</dd>
              </div>
              {f.suppressed_until && (
                <div>
                  <dt className="text-xs text-muted">Suppressed until</dt>
                  <dd className="text-xs">{absTime(f.suppressed_until)}</dd>
                </div>
              )}
              {f.suppression_note && (
                <div className="col-span-2">
                  <dt className="text-xs text-muted">Note</dt>
                  <dd className="text-xs">{f.suppression_note}</dd>
                </div>
              )}
            </dl>

            <section aria-label="Actions" className="space-y-2 rounded-md border border-line bg-surface2/40 p-3">
              <FindingActions f={f} />
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  className="btn btn-sm"
                  disabled={!canWrite || rescan.isPending}
                  title={canWrite ? undefined : 'Read-only access'}
                  onClick={() => rescan.mutate(f.asset_id)}
                >
                  <RefreshCw size={12} aria-hidden="true" /> Rescan asset
                </button>
                <button className="btn btn-sm" onClick={() => void copy(f)}>
                  <ClipboardCopy size={12} aria-hidden="true" /> Copy as markdown
                </button>
              </div>
              <div role="status" aria-live="polite" className="min-h-4 text-xs">
                {rescan.isSuccess && <span className="text-ok">Rescan queued for {f.asset_key}.</span>}
                {rescan.isError && <span role="alert" className="text-bad">Rescan failed: {(rescan.error as Error).message}</span>}
                {copied === 'ok' && <span className="text-ok">Copied to clipboard.</span>}
                {copied === 'fail' && <span className="text-bad">Could not copy; select the text manually.</span>}
              </div>
            </section>

            <section aria-label="Description">
              <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Description</h3>
              <p className="whitespace-pre-wrap text-sm">{f.description || '-'}</p>
            </section>
            <section aria-label="Remediation">
              <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Remediation</h3>
              <p className="whitespace-pre-wrap text-sm">{f.remediation || 'No remediation guidance.'}</p>
            </section>
            <IntelDetail f={f} />
            {f.tags && f.tags.length > 0 && (
              <section aria-label="Tags">
                <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Tags</h3>
                <ul className="flex flex-wrap gap-1">
                  {f.tags.map((t) => (
                    <li key={t} className="rounded-sm border border-line bg-surface2 px-1.5 py-0.5 text-xs">{t}</li>
                  ))}
                </ul>
              </section>
            )}
            <section aria-label="Evidence">
              <h3 className="mb-1 text-xs font-semibold uppercase text-muted">Evidence</h3>
              <EvidenceTable data={f.evidence} label={`Evidence for ${f.title}`} />
            </section>
            <Related f={f} />
          </div>
        )}
      </aside>
    </div>
  );
}
