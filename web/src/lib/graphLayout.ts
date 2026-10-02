import type { Graph } from '../api/types';

// Left-to-right column per kind so chains read hostname -> ip -> service.
const COLUMN: Record<string, number> = {
  zone: 0,
  hostname: 1,
  cloud_resource: 1,
  url: 1,
  ip: 2,
  service: 3,
  certificate: 4,
};

export const COL_W = 260;
export const ROW_H = 74;

export interface Placed {
  id: number;
  x: number;
  y: number;
}

/** Deterministic layered layout; each column is vertically centred. */
export function layoutGraph(g: Graph): Placed[] {
  const cols = new Map<number, Graph['nodes']>();
  for (const n of g.nodes) {
    const c = COLUMN[n.kind] ?? 1;
    cols.set(c, [...(cols.get(c) ?? []), n]);
  }
  const used = [...cols.keys()].sort((a, b) => a - b);
  const maxRows = Math.max(1, ...[...cols.values()].map((v) => v.length));
  const out: Placed[] = [];
  used.forEach((c, ci) => {
    const nodes = (cols.get(c) ?? []).slice().sort((a, b) => a.key.localeCompare(b.key));
    const offset = ((maxRows - nodes.length) * ROW_H) / 2;
    nodes.forEach((n, i) => out.push({ id: n.id, x: ci * COL_W, y: offset + i * ROW_H }));
  });
  return out;
}
