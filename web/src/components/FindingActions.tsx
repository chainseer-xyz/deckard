import { useState } from 'react';
import { Check, EyeOff, RotateCcw, ThumbsDown } from 'lucide-react';
import type { Finding, FindingAction } from '../api/types';
import { useFindingAction, useMe } from '../api/hooks';
import { SuppressModal } from './SuppressModal';

export const ACTIONS: Record<Finding['status'], FindingAction[]> = {
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

type Pending = 'suppress' | 'false-positive' | null;

/** Status-changing actions for one finding. Suppress and false-positive need a reason. */
export function FindingActions({ f }: { f: Finding }) {
  const me = useMe();
  const mut = useFindingAction();
  const [pending, setPending] = useState<Pending>(null);
  const canWrite = me.data?.can_write ?? false;
  const actions = ACTIONS[f.status];

  const run = (a: FindingAction) => {
    if (a === 'suppress' || a === 'false-positive') setPending(a);
    else mut.mutate({ id: f.id, action: a, body: { note: '' } });
  };

  return (
    <>
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Finding actions">
        {actions.map((a) => {
          const M = META[a];
          return (
            <button
              key={a}
              className="btn btn-sm"
              disabled={!canWrite || mut.isPending}
              title={canWrite ? undefined : 'Read-only access'}
              onClick={() => run(a)}
            >
              <M.Icon size={12} aria-hidden="true" />
              {M.label}
            </button>
          );
        })}
        {actions.length === 0 && <span className="text-xs text-muted">Resolved findings cannot be changed.</span>}
      </div>
      {mut.isError && !pending && (
        <p role="alert" className="mt-1 text-sm text-bad">
          Action failed: {(mut.error as Error).message}
        </p>
      )}
      {pending && (
        <SuppressModal
          title={pending === 'suppress' ? 'Suppress finding' : 'Mark as false positive'}
          subject={f.title}
          submitLabel={pending === 'suppress' ? 'Suppress' : 'Mark false positive'}
          withExpiry={pending === 'suppress'}
          busy={mut.isPending}
          error={mut.isError ? (mut.error as Error).message : undefined}
          onClose={() => {
            mut.reset();
            setPending(null);
          }}
          onSubmit={(v) => mut.mutate({ id: f.id, action: pending, body: v }, { onSuccess: () => setPending(null) })}
        />
      )}
    </>
  );
}
