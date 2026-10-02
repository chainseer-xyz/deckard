import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Radio, WifiOff } from 'lucide-react';
import { runEventStream, initialConn } from '../api/sse';
import type { ConnState } from '../api/sse';

const LiveCtx = createContext<ConnState>(initialConn);
export const useLive = () => useContext(LiveCtx);

/** Streams /events and invalidates cached queries when the server reports a change. */
export function LiveProvider({ children, enabled = true }: { children: ReactNode; enabled?: boolean }) {
  const qc = useQueryClient();
  const [state, setState] = useState<ConnState>(initialConn);

  useEffect(() => {
    if (!enabled) return;
    const ac = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const invalidate = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        void qc.invalidateQueries({ predicate: (q) => q.queryKey[0] !== 'me' });
      }, 250);
    };
    let wasOffline = false;
    void runEventStream({
      signal: ac.signal,
      onEvent: (m) => {
        if (m.event === 'change') invalidate();
      },
      onState: (s) => {
        setState(s);
        // events missed while offline: refetch once we are back
        if (s.status === 'offline') wasOffline = true;
        if (s.status === 'live' && wasOffline) {
          wasOffline = false;
          invalidate();
        }
      },
      onUnauthorized: () => void qc.resetQueries({ queryKey: ['me'] }),
    });
    return () => {
      ac.abort();
      clearTimeout(timer);
    };
  }, [qc, enabled]);

  return <LiveCtx.Provider value={state}>{children}</LiveCtx.Provider>;
}

export function LiveIndicator() {
  const { status } = useLive();
  const live = status === 'live';
  const label = live ? 'Live' : status === 'connecting' ? 'Connecting' : 'Offline';
  return (
    <span
      role="status"
      aria-label={`Live updates: ${label}`}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs ${
        live ? 'border-ok text-ok' : status === 'connecting' ? 'border-warn text-warn' : 'border-bad text-bad'
      }`}
    >
      {live ? <Radio size={12} aria-hidden="true" /> : <WifiOff size={12} aria-hidden="true" />}
      {label}
    </span>
  );
}
