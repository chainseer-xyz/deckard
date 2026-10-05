import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Asset } from '../api/types';
import { mockServer, renderRoute } from '../test/utils';
import AssetDetail from './AssetDetail';
import Inventory from './Inventory';

const sharedIP: Asset = {
  id: 5, kind: 'ip', key: '203.0.113.10', source: 'cloudflare', scope: 'owned',
  zone: 'example.com', attrs: { record_id: 'cf-record-1', region: 'cf-region' },
  reporters: ['cloudflare', 'aws', 'kubernetes', 'aws'],
  source_facts: {
    cloudflare: { zone: 'example.com', attrs: { record_id: 'cf-record-1', region: 'cf-region' } },
    aws: { zone: 'aws.example.com', attrs: { instance_id: 'i-123456', region: 'us-east-1', public_ip: '203.0.113.10' } },
    kubernetes: { attrs: { cluster: 'prod', namespace: 'ingress', service: 'gateway' } },
  },
  first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-10-05T00:00:00Z',
};
const resource: Asset = { ...sharedIP, id: 77, kind: 'cloud_resource', key: 'aws:ec2:i-123456', source: 'aws', reporters: ['aws'], source_facts: { aws: sharedIP.source_facts?.aws ?? {} } };
const { server, state } = mockServer({ assets: [sharedIP], findings: [] });
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  state.assets = [sharedIP];
});

describe('shared asset provenance', () => {
  it('shows a CF-first overlapping IP once, retains AWS/K8s facts and related resources', async () => {
    server.use(http.get('*/api/v1/assets/5', () => HttpResponse.json({
      asset: sharedIP, edges: [{ direction: 'in', type: 'has_public_ip', asset: resource }],
      observations: [], baselines: [], findings: [],
    })));
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/5');
    expect(await screen.findByRole('heading', { name: sharedIP.key })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { name: sharedIP.key })).toHaveLength(1);
    const props = screen.getByRole('region', { name: 'Properties' });
    expect(within(props).getByText('Canonical source').nextElementSibling).toHaveTextContent('cloudflare');
    expect(within(props).getByText('Canonical zone')).toBeInTheDocument();
    const reporters = within(props).getByRole('list', { name: 'Reporting sources' });
    expect(within(reporters).getAllByRole('link').map((link) => link.textContent)).toEqual(['cloudflare', 'aws', 'kubernetes']);
    expect(within(reporters).getByRole('link', { name: 'aws' })).toHaveAttribute('href', '/inventory?source=aws');

    const facts = screen.getByRole('region', { name: 'Source facts' });
    const cf = within(facts).getByRole('group', { name: 'Facts reported by cloudflare' });
    const aws = within(facts).getByRole('group', { name: 'Facts reported by aws' });
    expect(within(cf).getByText('example.com')).toBeInTheDocument();
    expect(within(aws).getByText('aws.example.com')).toBeInTheDocument();
    const cfAttrs = within(cf).getByRole('table', { name: 'Attributes reported by cloudflare' });
    const awsAttrs = within(aws).getByRole('table', { name: 'Attributes reported by aws' });
    expect(within(cfAttrs).getByText('cf-record-1')).toBeInTheDocument();
    expect(within(cfAttrs).queryByText('i-123456')).not.toBeInTheDocument();
    expect(within(awsAttrs).getByText('i-123456')).toBeInTheDocument();
    expect(within(awsAttrs).getByText('us-east-1')).toBeInTheDocument();
    expect(within(awsAttrs).queryByText('cf-region')).not.toBeInTheDocument();
    expect(within(facts).getByRole('group', { name: 'Facts reported by kubernetes' })).toHaveTextContent('prod');
    expect(within(facts).getAllByText('Canonical', { exact: true })).toHaveLength(1);
    expect(within(screen.getByRole('region', { name: 'Relations (1)' })).getByRole('link', { name: resource.key }))
      .toHaveAttribute('href', '/assets/77');
  });

  it('labels missing legacy source facts without assigning canonical attributes to AWS', async () => {
    state.assets = [{ ...sharedIP, reporters: ['cloudflare', 'aws'], source_facts: undefined }];
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/5');
    const facts = await screen.findByRole('region', { name: 'Source facts' });
    const cf = within(facts).getByRole('group', { name: 'Facts reported by cloudflare' });
    const aws = within(facts).getByRole('group', { name: 'Facts reported by aws' });
    expect(cf).toHaveTextContent('Source-specific facts are unavailable for this legacy asset. Showing canonical metadata only.');
    expect(within(cf).getByRole('table', { name: 'Attributes reported by cloudflare' })).toHaveTextContent('cf-record-1');
    expect(aws).toHaveTextContent('No source-specific facts recorded.');
    expect(within(aws).queryByRole('table')).not.toBeInTheDocument();
    expect(aws).not.toHaveTextContent('cf-record-1');
  });

  it('preserves a legacy asset without reporters or source facts', async () => {
    state.assets = [{ ...sharedIP, reporters: undefined, source_facts: undefined }];
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/5');
    const facts = await screen.findByRole('region', { name: 'Source facts' });
    await userEvent.click(within(facts).getByText('cloudflare'));
    expect(within(facts).getByRole('table', { name: 'Attributes reported by cloudflare' })).toHaveTextContent('cf-record-1');
    expect(within(facts).getByText(/Source-specific facts are unavailable/)).toBeVisible();
  });

  it('offers an overlapping-only source before its asset is on the current page and filters to one identity', async () => {
    state.assets = [
      ...Array.from({ length: 50 }, (_, i): Asset => ({
        ...sharedIP, id: i + 100, kind: 'hostname', key: `cf-${i}.example.com`, reporters: ['cloudflare'], source_facts: undefined,
      })),
      sharedIP,
    ];
    renderRoute(<Inventory />, '/inventory');
    await screen.findByRole('link', { name: 'cf-0.example.com' });
    expect(screen.queryByRole('link', { name: sharedIP.key })).not.toBeInTheDocument();
    const source = screen.getByLabelText('Source');
    await within(source).findByRole('option', { name: 'aws' });
    await userEvent.selectOptions(source, 'aws');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('source=aws'));
    const row = (await screen.findByRole('link', { name: sharedIP.key })).closest('tr') as HTMLElement;
    expect(within(row).getByText('cloudflare, aws, kubernetes')).toHaveAttribute('title', 'Canonical source: cloudflare');
    expect(screen.getAllByRole('link', { name: sharedIP.key })).toHaveLength(1);
    expect(screen.getByText('1-1 of 1')).toBeInTheDocument();
    expect(screen.getByLabelText('Source')).toHaveValue('aws');
  });
});
