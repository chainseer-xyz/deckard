import { AlertTriangle, CheckCircle2, CircleSlash, Clock } from 'lucide-react';
import type { SyncStatus } from '../api/types';
import { isPartialSync, syncHealth } from '../lib/format';
import type { SyncHealth } from '../lib/format';
import { PartialBadge } from './ui';

const HEALTH: Record<SyncHealth, { label: string; cls: string; Icon: typeof Clock }> = {
  ok: { label: 'Healthy', cls: 'text-ok', Icon: CheckCircle2 },
  stale: { label: 'Stale', cls: 'text-warn', Icon: Clock },
  failing: { label: 'Failing', cls: 'text-bad', Icon: AlertTriangle },
  never: { label: 'Never synced', cls: 'text-muted', Icon: CircleSlash },
};

export function HealthBadge({ s, now }: { s: SyncStatus; now?: number }) {
  const h = HEALTH[syncHealth(s, now)];
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${h.cls}`}>
      <h.Icon size={12} aria-hidden="true" />
      {h.label}
    </span>
  );
}

/** Health plus the PARTIAL badge: a partial source is incomplete and blocks removals. */
export function SourceStatus({ s, now }: { s: SyncStatus; now?: number }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <HealthBadge s={s} now={now} />
      {isPartialSync(s) && <PartialBadge reason={s.warning} />}
    </span>
  );
}
