import { describe, expect, it } from 'vitest';
import { COL_W, layoutGraph } from './graphLayout';
import { graphFor } from '../../mock/data';

describe('layoutGraph', () => {
  it('orders columns hostname -> ip -> service and places every node once', () => {
    const g = graphFor(2, 3);
    const pos = new Map(layoutGraph(g).map((p) => [p.id, p]));
    expect(pos.size).toBe(g.nodes.length);
    const x = (id: number) => (pos.get(id) as { x: number }).x;
    expect(x(2)).toBeLessThan(x(5)); // hostname left of ip
    expect(x(5)).toBeLessThan(x(7)); // ip left of service
    expect(x(7) - x(5)).toBe(COL_W);
  });
});
