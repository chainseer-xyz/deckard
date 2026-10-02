import { describe, expect, it, vi } from 'vitest';
import {
  BACKOFF_MAX_MS,
  SSEParser,
  backoffDelay,
  connReducer,
  initialConn,
  runEventStream,
} from './sse';
import type { ConnState, SSEMessage } from './sse';

describe('SSEParser', () => {
  it('parses events split across chunks', () => {
    const p = new SSEParser();
    expect(p.push('event: change\ndata: {"a"')).toEqual([]);
    const out = p.push(':1}\n\n');
    expect(out).toEqual([{ event: 'change', data: '{"a":1}', id: undefined }]);
  });
  it('handles CRLF, comments, multi-line data and default event name', () => {
    const p = new SSEParser();
    const out = p.push(': ping\r\n\r\ndata: a\r\ndata: b\r\n\r\n');
    expect(out).toEqual([{ event: 'message', data: 'a\nb', id: undefined }]);
  });
  it('ignores blank dispatches without data', () => {
    expect(new SSEParser().push('event: x\n\n')).toEqual([]);
  });
});

describe('connReducer', () => {
  it('goes live on open and resets attempts', () => {
    let s: ConnState = connReducer(initialConn, { type: 'fail' });
    s = connReducer(s, { type: 'fail' });
    expect(s).toEqual({ status: 'offline', attempt: 2 });
    s = connReducer(s, { type: 'connect' });
    expect(s.status).toBe('connecting');
    expect(connReducer(s, { type: 'open' })).toEqual({ status: 'live', attempt: 0 });
  });
});

describe('backoffDelay', () => {
  it('grows exponentially and caps', () => {
    const max = () => 1; // upper end of jitter
    const min = () => 0;
    expect(backoffDelay(1, max)).toBe(1000);
    expect(backoffDelay(1, min)).toBe(500);
    expect(backoffDelay(3, max)).toBe(4000);
    expect(backoffDelay(20, max)).toBe(BACKOFF_MAX_MS);
    expect(backoffDelay(20, min)).toBe(BACKOFF_MAX_MS / 2);
  });
});

function streamOf(text: string): Response {
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new TextEncoder().encode(text));
      c.close();
    },
  });
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

describe('runEventStream', () => {
  it('delivers events, reconnects with backoff after failures and a clean close', async () => {
    const ac = new AbortController();
    const states: string[] = [];
    const events: SSEMessage[] = [];
    const delays: number[] = [];
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls++;
      if (calls === 1) throw new Error('down');
      if (calls === 2) return new Response('x', { status: 503 });
      if (calls === 3) return streamOf('event: change\ndata: {"id":1}\n\n');
      ac.abort();
      throw new Error('aborted');
    });
    await runEventStream({
      fetchFn: fetchFn as unknown as typeof fetch,
      signal: ac.signal,
      rand: () => 1,
      sleep: async (ms) => {
        delays.push(ms);
      },
      onEvent: (m) => events.push(m),
      onState: (s) => states.push(s.status),
    });
    expect(events).toEqual([{ event: 'change', data: '{"id":1}', id: undefined }]);
    expect(states).toEqual([
      'connecting', 'offline', // 1: network error
      'connecting', 'offline', // 2: HTTP 503
      'connecting', 'live', 'offline', // 3: live then server closes
      'connecting', // 4: aborted
    ]);
    // attempt counter: 1, 2 then reset by the live connection and 1 again
    expect(delays).toEqual([1000, 2000, 1000]);
  });

  it('stops on 401 and reports it', async () => {
    const onUnauthorized = vi.fn();
    const fetchFn = vi.fn(async () => new Response('', { status: 401 }));
    await runEventStream({
      fetchFn: fetchFn as unknown as typeof fetch,
      signal: new AbortController().signal,
      sleep: async () => {},
      onEvent: () => {},
      onState: () => {},
      onUnauthorized,
    });
    expect(onUnauthorized).toHaveBeenCalledOnce();
    expect(fetchFn).toHaveBeenCalledOnce();
  });
});
