import { useState } from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2 } from 'lucide-react';
import type { Finding } from '../api/types';
import { absTime, relTime } from '../lib/format';
import { isExpiry, isKev, isNew24h, isTakeover, remediationHint } from '../lib/triage';
import { Empty, KevBadge, NewBadge, SeverityBadge } from './ui';

const VISIBLE = 8;

function KindTag({ f }: { f: Finding }) {
  const label = isTakeover(f) ? 'Takeover' : isExpiry(f) ? 'Expiry' : null;
  if (!label) return null;
  return (
    <span className="inline-flex rounded-sm border border-line bg-surface2 px-1.5 py-0.5 text-xs font-medium">
      {label}
    </span>
  );
}

export function AttentionRow({ f, now }: { f: Finding; now?: number }) {
  return (
    <li className="px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <SeverityBadge severity={f.severity} />
        <KindTag f={f} />
        {isKev(f) && <KevBadge />}
        {isNew24h(f, now) && <NewBadge />}
        <Link to={`/findings?finding=${f.id}`} className="min-w-0 flex-1 font-medium text-fg hover:text-accent hover:underline">
          {f.title}
        </Link>
      </div>
      <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted">
        <Link to={`/assets/${f.asset_id}`} className="font-mono text-accent hover:underline">
          {f.asset_key}
        </Link>
        <span className="font-mono">{f.check}</span>
        <span title={absTime(f.first_seen)}>first seen {relTime(f.first_seen, now)}</span>
      </div>
      <p className="mt-0.5 text-xs">
        <span className="text-muted">Fix: </span>
        {remediationHint(f)}
      </p>
    </li>
  );
}

/** Open critical/high (and KEV) findings, takeover and expiry first. `items` must already be ordered. */
export function NeedsAttentionList({ items, now }: { items: Finding[]; now?: number }) {
  const [all, setAll] = useState(false);
  if (items.length === 0) {
    return (
      <Empty>
        <CheckCircle2 size={16} className="text-ok" aria-hidden="true" />
        <span>
          Nothing needs attention: no open critical or high findings.{' '}
          <Link className="text-accent hover:underline" to="/findings">
            Review medium findings
          </Link>
        </span>
      </Empty>
    );
  }
  const shown = all ? items : items.slice(0, VISIBLE);
  return (
    <>
      <ul className="divide-y divide-line">
        {shown.map((f) => (
          <AttentionRow key={f.id} f={f} now={now} />
        ))}
      </ul>
      {items.length > VISIBLE && (
        <div className="border-t border-line px-3 py-2">
          <button className="btn btn-sm" aria-expanded={all} onClick={() => setAll(!all)}>
            {all ? 'Show fewer' : `Show all ${items.length}`}
          </button>
        </div>
      )}
    </>
  );
}
