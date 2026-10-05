import { StrictMode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import type { Graph } from '../api/types';
import AssetGraph from './AssetGraph';

afterEach(() => vi.restoreAllMocks());

function Location() {
  return <output aria-label="current route">{useLocation().pathname}</output>;
}

const graph: Graph = {
  nodes: [
    { id: 1, kind: 'hostname', key: 'app.example.test', scope: 'owned' },
    { id: 2, kind: 'ip', key: '192.0.2.1', scope: 'owned' },
  ],
  edges: [{ from: 1, to: 2, type: 'resolves_to' }],
};

describe('real asset graph', () => {
  it('renders, updates and routes node clicks under StrictMode', async () => {
    const errors = vi.spyOn(console, 'error');
    const tree = (value: Graph) => (
      <StrictMode>
        <MemoryRouter>
          <AssetGraph graph={value} focusId={1} />
          <Location />
        </MemoryRouter>
      </StrictMode>
    );
    const result = render(tree(graph));
    expect(await screen.findByText('app.example.test')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'zoom in' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'zoom out' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'fit view' })).toBeInTheDocument();
    result.rerender(tree({
      ...graph,
      nodes: [...graph.nodes, { id: 3, kind: 'hostname', key: 'new.example.test', scope: 'owned' }],
    }));
    fireEvent.click(await screen.findByText('new.example.test'));
    await waitFor(() => expect(screen.getByLabelText('current route')).toHaveTextContent('/assets/3'));
    expect(errors).not.toHaveBeenCalled();
  });
});
