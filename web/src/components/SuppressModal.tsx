import { useEffect, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { X } from 'lucide-react';
import { untilToISO, validateSuppress } from '../lib/findingsFilter';
import type { SuppressErrors } from '../lib/findingsFilter';

export interface ActionModalProps {
  title: string;
  /** shown under the title, e.g. the finding title */
  subject?: string;
  submitLabel: string;
  /** suppression expiry date field */
  withExpiry?: boolean;
  busy?: boolean;
  error?: string;
  onSubmit: (v: { note: string; until?: string }) => void;
  onClose: () => void;
}

/** Modal that always requires a reason; optionally an expiry date. */
export function SuppressModal(p: ActionModalProps) {
  const [note, setNote] = useState('');
  const [until, setUntil] = useState('');
  const [errs, setErrs] = useState<SuppressErrors>({});
  const ref = useRef<HTMLDivElement>(null);
  const noteRef = useRef<HTMLTextAreaElement>(null);
  const id = useId();

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    noteRef.current?.focus();
    return () => prev?.focus?.();
  }, []);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      p.onClose();
    } else if (e.key === 'Tab' && ref.current) {
      // keep focus inside the dialog
      const f = ref.current.querySelectorAll<HTMLElement>('button, input, textarea, select, [href]');
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateSuppress({ note, until: p.withExpiry ? until : '' });
    setErrs(v);
    if (v.note || v.until) return;
    p.onSubmit({ note: note.trim(), until: p.withExpiry ? untilToISO(until) : undefined });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onKeyDown={onKey}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${id}-t`}
        className="card w-full max-w-md p-4 shadow-xl"
      >
        <div className="mb-3 flex items-start justify-between gap-2">
          <div>
            <h2 id={`${id}-t`} className="text-base font-semibold">
              {p.title}
            </h2>
            {p.subject && <p className="mt-0.5 text-xs text-muted">{p.subject}</p>}
          </div>
          <button className="btn btn-sm" onClick={p.onClose} aria-label="Close dialog" type="button">
            <X size={14} aria-hidden="true" />
          </button>
        </div>
        <form onSubmit={submit} noValidate className="space-y-3">
          <div>
            <label htmlFor={`${id}-n`} className="mb-1 block text-sm font-medium">
              Reason <span aria-hidden="true">*</span>
            </label>
            <textarea
              id={`${id}-n`}
              ref={noteRef}
              rows={3}
              className="input w-full"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              aria-required="true"
              aria-invalid={!!errs.note}
              aria-describedby={errs.note ? `${id}-ne` : undefined}
            />
            {errs.note && (
              <p id={`${id}-ne`} role="alert" className="mt-1 text-xs text-bad">
                {errs.note}
              </p>
            )}
          </div>
          {p.withExpiry && (
            <div>
              <label htmlFor={`${id}-u`} className="mb-1 block text-sm font-medium">
                Expires (optional)
              </label>
              <input
                id={`${id}-u`}
                type="date"
                className="input"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                aria-invalid={!!errs.until}
                aria-describedby={errs.until ? `${id}-ue` : undefined}
              />
              {errs.until && (
                <p id={`${id}-ue`} role="alert" className="mt-1 text-xs text-bad">
                  {errs.until}
                </p>
              )}
              <p className="mt-1 text-xs text-muted">Leave empty to suppress until reopened.</p>
            </div>
          )}
          {p.error && (
            <p role="alert" className="text-xs text-bad">
              {p.error}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" className="btn" onClick={p.onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={p.busy}>
              {p.submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
