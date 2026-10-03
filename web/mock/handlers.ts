import { http, HttpResponse } from 'msw';
import type { Finding, FindingStatus, Stats } from '../src/api/types';
import { severityRank } from '../src/api/types';
import * as d from './data';

export interface MockState {
  findings: Finding[];
  canWrite: boolean;
}

const page = <T,>(items: T[], url: URL) => {
  const limit = Number(url.searchParams.get('limit')) || 50;
  const offset = Number(url.searchParams.get('offset')) || 0;
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset };
};

export function computeStats(findings: Finding[]): Stats {
  const count = (xs: string[]) => xs.reduce<Record<string, number>>((m, x) => ({ ...m, [x]: (m[x] ?? 0) + 1 }), {});
  const open = findings.filter((f) => f.status === 'open');
  const live = d.assets.filter((a) => !a.removed_at);
  return {
    assets_by_kind: count(live.map((a) => a.kind)),
    assets_by_source: count(live.map((a) => a.source)),
    assets_by_scope: count(live.map((a) => a.scope)),
    findings_by_severity: count(open.map((f) => f.severity)),
    findings_by_check: count(open.map((f) => f.check)),
  };
}

const TRANSITION: Record<string, FindingStatus> = {
  acknowledge: 'acknowledged',
  suppress: 'suppressed',
  'false-positive': 'false_positive',
  reopen: 'open',
};

/** Build msw handlers over a mutable state so actions are reflected in lists. */
export function makeHandlers(state: MockState = { findings: d.makeFindings(), canWrite: true }) {
  const B = '*/api/v1';
  return [
    http.get(`${B}/me`, () => HttpResponse.json({ identity: 'mock@example.com', can_write: state.canWrite, csrf_token: d.mockCsrfToken })),
    http.get(`${B}/stats`, () => HttpResponse.json(computeStats(state.findings))),
    http.get(`${B}/assets`, ({ request }) => {
      const u = new URL(request.url);
      const g = (k: string) => u.searchParams.get(k);
      let items = d.assets.filter((a) => u.searchParams.get('include_removed') === 'true' || !a.removed_at);
      if (g('kind')) items = items.filter((a) => a.kind === g('kind'));
      if (g('source')) items = items.filter((a) => a.source === g('source'));
      if (g('scope')) items = items.filter((a) => a.scope === g('scope'));
      if (g('zone')) items = items.filter((a) => a.zone === g('zone'));
      if (g('q')) items = items.filter((a) => a.key.includes(g('q') as string));
      return HttpResponse.json(page(items, u));
    }),
    http.get(`${B}/assets/:id/graph`, ({ params, request }) =>
      HttpResponse.json(d.graphFor(Number(params.id), Number(new URL(request.url).searchParams.get('depth')) || 2)),
    ),
    http.get(`${B}/assets/:id`, ({ params }) => {
      const id = Number(params.id);
      const asset = d.assets.find((a) => a.id === id);
      if (!asset) return HttpResponse.json({ error: { code: 'not_found', message: 'asset not found' } }, { status: 404 });
      return HttpResponse.json({
        asset,
        edges: d.edgesFor(id),
        observations: d.observations(id),
        baselines: d.baselines(id),
        findings: state.findings.filter((f) => f.asset_id === id && f.status === 'open'),
      });
    }),
    http.post(`${B}/assets/:id/rescan`, () => HttpResponse.json({ queued: true }, { status: 202 })),
    http.get(`${B}/findings`, ({ request }) => {
      const u = new URL(request.url);
      const g = (k: string) => u.searchParams.get(k);
      const statuses = u.searchParams.getAll('status');
      let items = state.findings.filter((f) => statuses.length === 0 || statuses.includes(f.status));
      if (g('min_severity')) items = items.filter((f) => severityRank(f.severity) >= severityRank(g('min_severity') as string));
      if (g('check')) items = items.filter((f) => f.check === g('check'));
      if (g('zone')) items = items.filter((f) => f.zone === g('zone'));
      if (g('source')) items = items.filter((f) => f.source === g('source'));
      if (g('asset_id')) items = items.filter((f) => f.asset_id === Number(g('asset_id')));
      if (g('q')) items = items.filter((f) => `${f.title} ${f.asset_key}`.toLowerCase().includes((g('q') as string).toLowerCase()));
      return HttpResponse.json(page(items, u));
    }),
    http.get(`${B}/findings/:id`, ({ params }) => {
      const f = state.findings.find((x) => x.id === Number(params.id));
      return f ? HttpResponse.json(f) : HttpResponse.json({ error: { code: 'not_found', message: 'finding not found' } }, { status: 404 });
    }),
    http.post(`${B}/findings/:id/:action`, async ({ params, request }) => {
      const f = state.findings.find((x) => x.id === Number(params.id));
      const to = TRANSITION[String(params.action)];
      if (!f || !to) return HttpResponse.json({ error: { code: 'not_found', message: 'unknown finding or action' } }, { status: 404 });
      const body = (await request.json()) as { note: string; until?: string };
      f.status = to;
      f.suppression_note = body.note;
      f.suppressed_until = body.until ?? null;
      return HttpResponse.json(f);
    }),
    http.get(`${B}/sources`, () => HttpResponse.json({ items: d.sources, total: d.sources.length, limit: 100, offset: 0 })),
    http.post(`${B}/sources/:name/sync`, () => HttpResponse.json({ started: true }, { status: 202 })),
    http.get(`${B}/scans`, ({ request }) => HttpResponse.json(page(d.scans, new URL(request.url)))),
    http.get(`${B}/changes`, ({ request }) => {
      const u = new URL(request.url);
      // like the server: default window is the last 24h
      const since = Date.parse(u.searchParams.get('since') ?? '') || Date.now() - 24 * 3600_000;
      return HttpResponse.json(page(d.changes.filter((e) => Date.parse(e.at) >= since), u));
    }),
    http.get(`${B}/events`, () => {
      // Emit a keep-alive then a synthetic change event every 10s.
      const enc = new TextEncoder();
      let timer: ReturnType<typeof setInterval> | undefined;
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(enc.encode(': connected\n\n'));
          let n = 100;
          timer = setInterval(() => {
            const ev = { id: ++n, type: 'asset_changed', subject: 'mock tick', at: new Date().toISOString() };
            c.enqueue(enc.encode(`event: change\ndata: ${JSON.stringify(ev)}\n\n`));
          }, 10_000);
        },
        cancel() {
          clearInterval(timer);
        },
      });
      return new HttpResponse(body, { headers: { 'content-type': 'text/event-stream' } });
    }),
  ];
}
