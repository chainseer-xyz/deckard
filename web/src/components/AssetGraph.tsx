import { useMemo } from 'react';
import ReactFlow, { Background, Controls, Handle, Position } from 'reactflow';
import type { Edge, Node, NodeProps } from 'reactflow';
import 'reactflow/dist/style.css';
import { useNavigate } from 'react-router-dom';
import type { Graph, GraphNode } from '../api/types';
import { layoutGraph } from '../lib/graphLayout';
import { ScopeBadge } from './ui';

interface NodeData extends GraphNode {
  focus: boolean;
}

function AssetNode({ data }: NodeProps<NodeData>) {
  return (
    <div
      className={`w-52 rounded-md border bg-surface px-2 py-1.5 text-xs shadow-sm ${data.focus ? 'border-2 border-accent' : 'border-line'}`}
      style={{ borderLeft: `5px solid rgb(var(--k-${data.kind}, var(--muted)))` }}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted" />
      <div className="flex items-center justify-between gap-1">
        <span className="text-[10px] uppercase tracking-wide text-muted">{data.kind}</span>
        <ScopeBadge scope={data.scope} />
      </div>
      <div className="truncate font-mono" title={data.key}>
        {data.key}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-muted" />
    </div>
  );
}

const nodeTypes = { asset: AssetNode };

export default function AssetGraph({ graph, focusId }: { graph: Graph; focusId?: number }) {
  const navigate = useNavigate();
  const { nodes, edges } = useMemo(() => {
    const pos = new Map(layoutGraph(graph).map((p) => [p.id, p]));
    const nodes: Node<NodeData>[] = graph.nodes.map((n) => ({
      id: String(n.id),
      type: 'asset',
      position: { x: pos.get(n.id)?.x ?? 0, y: pos.get(n.id)?.y ?? 0 },
      data: { ...n, focus: n.id === focusId },
    }));
    const edges: Edge[] = graph.edges.map((e, i) => ({
      id: `${e.from}-${e.to}-${e.type}-${i}`,
      source: String(e.from),
      target: String(e.to),
      label: e.type,
      labelStyle: { fontSize: 10 },
      labelBgStyle: { fill: 'rgb(var(--surface))' },
    }));
    return { nodes, edges };
  }, [graph, focusId]);

  return (
    <div className="h-[28rem] rounded-md border border-line" role="figure" aria-label="Asset relationship graph">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        nodesConnectable={false}
        nodesDraggable
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, n) => navigate(`/assets/${n.id}`)}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
