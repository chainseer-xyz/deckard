import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { isProbeTarget } from '../api/types';
import type { Asset, AssessmentTool } from '../api/types';
import { Card, ErrorBox } from './ui';

export function AssessmentControls({ asset, canWrite }: { asset: Asset; canWrite: boolean }) {
  const eligible = asset.scope === 'owned' && !asset.removed_at && isProbeTarget(asset) && asset.kind !== 'zone';
  const [tool, setTool] = useState<AssessmentTool>();
  const [authorized, setAuthorized] = useState(false);
  const capabilities = useQuery({ queryKey: ['assessment-capabilities'], queryFn: api.assessmentCapabilities, enabled: eligible });
  const start = useMutation({ mutationFn: (chosen: AssessmentTool) => api.startAssessment(chosen, [asset.id]) });
  const session = useQuery({
    queryKey: ['assessment', start.data?.id],
    queryFn: () => api.assessment(start.data!.id),
    enabled: !!start.data?.id,
    retry: false,
    refetchInterval: (query) => !query.state.error && ['starting', 'running'].includes(query.state.data?.status ?? 'running') ? 2000 : false,
  });
  if (!eligible) return null;
  const configured = capabilities.data;
  const selected = tool ?? configured?.tools[0];
  const current = session.data ?? start.data;
  const unavailable = session.error instanceof ApiError && session.error.status === 404;
  const running = start.isPending || !!current && ['starting', 'running'].includes(current.status);
  return (
    <Card title="Isolated assessment">
      {capabilities.isError && <ErrorBox error={capabilities.error} onRetry={() => void capabilities.refetch()} />}
      {capabilities.isPending && <p className="text-sm text-muted">Checking assessment configuration…</p>}
      {configured && !configured.enabled && <p className="text-sm text-muted">Isolated assessment execution is disabled. No ZGrab2, ZAP or Strix coverage is implied.</p>}
      {configured?.enabled && (
        <div className="space-y-3 text-sm">
          <p className="text-muted">Runs only against this owned asset. Active tests can change application data. Results are additive; an empty report does not resolve findings.</p>
          <label className="block">Scanner
            <select aria-label="Assessment scanner" className="ml-2 rounded border border-line bg-surface px-2 py-1" value={selected ?? ''} onChange={(event) => { setTool(event.target.value as AssessmentTool); setAuthorized(false); }} disabled={!canWrite || running}>
              {configured.tools.map((name) => <option key={name} value={name}>{name === 'zap' ? 'ZAP' : name === 'strix' ? 'Strix' : 'ZGrab2'}</option>)}
            </select>
          </label>
          <label className="flex items-start gap-2"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} disabled={!canWrite || running} />I authorize active testing of this asset and any resulting application changes.</label>
          <button className="btn btn-sm" disabled={!canWrite || !authorized || !selected || running} onClick={() => { if (selected) { start.mutate(selected); setAuthorized(false); } }}>Start assessment</button>
          {!canWrite && <p className="text-muted">Read-only access.</p>}
          {start.isError && <p role="alert" className="text-bad">Start failed: {start.error.message}</p>}
          {session.isError && <p role="alert" className="text-bad">Status unavailable: {session.error.message}</p>}
          {session.isError && !unavailable && <button className="btn btn-sm" onClick={() => void session.refetch()}>Check status</button>}
          {unavailable && <><p className="text-muted">An unavailable session is not a clean assessment. A controller restart can lose status while old Jobs finish. New runs still require manager admission.</p><button className="btn btn-sm" onClick={() => start.reset()}>Clear unavailable session</button></>}
          {current && !unavailable && <p role="status" className="break-all">Session <span className="font-mono">{current.id}</span>: {current.status}{current.reason ? ` (${current.reason})` : ''}.{current.cleanup_pending ? ' Cleanup pending: inspect assessment resources before retrying.' : ''}</p>}
        </div>
      )}
    </Card>
  );
}
