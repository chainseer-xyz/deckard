import { describe, expect, it } from 'vitest';
import { COL_W, layoutGraph } from './graphLayout';
import { graphFor } from '../../mock/data';
import type { Graph } from '../api/types';

describe('layoutGraph', () => {
	it('places workloads, immutable images and packages in dependency order', () => {
		const graph: Graph = { nodes: [
			{ id: 1, kind: 'workload', key: 'pod', scope: 'external' },
			{ id: 2, kind: 'container_image', key: 'sha256:image', scope: 'external' },
			{ id: 3, kind: 'package', key: 'pkg:generic/library@1', scope: 'external' },
		], edges: [], truncated: false };
		const positions = new Map(layoutGraph(graph).map((position) => [position.id, position.x]));
		expect(positions.get(1)).toBeLessThan(positions.get(2)!);
		expect(positions.get(2)).toBeLessThan(positions.get(3)!);
	});
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
