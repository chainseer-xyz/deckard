// Fetch-based Server-Sent Events. EventSource cannot send an Authorization
// header, so we stream /events with fetch and parse the wire format ourselves.
import { absoluteUrl, API_BASE, authHeaders } from './client';

export interface SSEMessage {
  event: string;
  data: string;
  id?: string;
}

/** Incremental text/event-stream parser. Feed it decoded chunks. */
export class SSEParser {
  private buf = '';
  private event = '';
  private data: string[] = [];
  private id: string | undefined;

  push(chunk: string): SSEMessage[] {
    this.buf += chunk;
    const out: SSEMessage[] = [];
    // Lines end with \r\n, \n or \r. A trailing lone \r may be half of \r\n, so keep it.
    const lines = this.buf.split(/\r\n|\n|\r(?!$)/);
    this.buf = lines.pop() ?? '';
    for (const line of lines) {
      if (line === '') {
        if (this.data.length > 0) {
          out.push({ event: this.event || 'message', data: this.data.join('\n'), id: this.id });
        }
        this.event = '';
        this.data = [];
        continue;
      }
      if (line.startsWith(':')) continue; // comment / keep-alive
      const i = line.indexOf(':');
      const field = i === -1 ? line : line.slice(0, i);
      let value = i === -1 ? '' : line.slice(i + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') this.event = value;
      else if (field === 'data') this.data.push(value);
      else if (field === 'id') this.id = value;
    }
    return out;
  }
}

// ---- reconnect state machine (pure) ---------------------------------------

export type ConnStatus = 'connecting' | 'live' | 'offline';
export interface ConnState {
  status: ConnStatus;
  /** consecutive failures since the last successful open */
  attempt: number;
}
export type ConnAction = { type: 'connect' } | { type: 'open' } | { type: 'fail' };

export const initialConn: ConnState = { status: 'connecting', attempt: 0 };

export function connReducer(s: ConnState, a: ConnAction): ConnState {
  switch (a.type) {
    case 'connect':
      return { ...s, status: 'connecting' };
    case 'open':
      return { status: 'live', attempt: 0 };
    case 'fail':
      return { status: 'offline', attempt: s.attempt + 1 };
  }
}

export const BACKOFF_BASE_MS = 1000;
export const BACKOFF_MAX_MS = 30000;

/** Exponential backoff with "equal jitter": half fixed, half random. */
export function backoffDelay(
  attempt: number,
  rand: () => number = Math.random,
  base = BACKOFF_BASE_MS,
  max = BACKOFF_MAX_MS,
): number {
  const exp = Math.min(max, base * 2 ** Math.max(0, attempt - 1));
  return Math.round(exp / 2 + (rand() * exp) / 2);
}

// ---- streaming loop --------------------------------------------------------

export interface StreamOpts {
  onEvent: (m: SSEMessage) => void;
  onState: (s: ConnState) => void;
  onUnauthorized?: () => void;
  signal: AbortSignal;
  fetchFn?: typeof fetch;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  rand?: () => number;
  url?: string;
}

const defaultSleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        resolve();
      },
      { once: true },
    );
  });

/** Runs until `signal` aborts, reconnecting with backoff after every failure. */
export async function runEventStream(o: StreamOpts): Promise<void> {
  const fetchFn = o.fetchFn ?? fetch.bind(globalThis);
  const sleep = o.sleep ?? defaultSleep;
  let state = initialConn;
  const dispatch = (a: ConnAction) => {
    state = connReducer(state, a);
    o.onState(state);
  };

  while (!o.signal.aborted) {
    dispatch({ type: 'connect' });
    try {
      const res = await fetchFn(o.url ?? absoluteUrl(`${API_BASE}/events`), {
        headers: { ...authHeaders(), Accept: 'text/event-stream' },
        credentials: 'same-origin',
        signal: o.signal,
      });
      if (res.status === 401) {
        o.onUnauthorized?.();
        dispatch({ type: 'fail' });
        return;
      }
      if (!res.ok || !res.body) throw new Error(`events: HTTP ${res.status}`);
      dispatch({ type: 'open' });
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      const parser = new SSEParser();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const m of parser.push(dec.decode(value, { stream: true }))) o.onEvent(m);
      }
      // Clean close by the server: treat as a drop and reconnect.
      dispatch({ type: 'fail' });
    } catch {
      if (o.signal.aborted) return;
      dispatch({ type: 'fail' });
    }
    if (o.signal.aborted) return;
    await sleep(backoffDelay(state.attempt, o.rand), o.signal);
  }
}
