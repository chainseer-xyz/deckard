import type { Asset } from '../api/types';
import { assetSourceViews } from '../lib/assetView';
import { EvidenceTable } from './Evidence';
import { Card } from './ui';

/** A shared identity retains each source's facts without blending conflicting values. */
export function AssetSourceFacts({ asset }: { asset: Asset }) {
  const sources = assetSourceViews(asset);
  return (
    <Card title="Source facts">
      <p className="border-b border-line px-3 py-2 text-xs text-muted">
        One asset identity, with facts attributed to each reporting source. Canonical metadata comes from {asset.source || 'the primary source'}.
      </p>
      <div className="divide-y divide-line">
        {sources.map((fact) => (
          <details key={fact.source} open={sources.length > 1} className="px-3 py-2">
            <summary className="cursor-pointer text-sm">
              <span className="break-all font-medium">{fact.source}</span>
              {fact.canonical && <span className="ml-2 rounded-sm border border-line px-1 text-[10px] uppercase text-muted">Canonical</span>}
            </summary>
            <div className="mt-2 space-y-2" role="group" aria-label={`Facts reported by ${fact.source}`}>
              {!fact.recorded && (
                <p className="text-xs text-muted">
                  {fact.canonical ? 'Source-specific facts are unavailable for this legacy asset. Showing canonical metadata only.' : 'No source-specific facts recorded.'}
                </p>
              )}
              {(fact.recorded || fact.canonical) && (
                <>
                  <dl className="flex items-baseline gap-3 text-sm">
                    <dt className="text-xs text-muted">Zone</dt>
                    <dd className="break-all">
                      {fact.zone || <span className="text-muted">Not recorded</span>}
                    </dd>
                  </dl>
                  {fact.attrs && Object.keys(fact.attrs).length > 0 ? (
                    <EvidenceTable data={fact.attrs} label={`Attributes reported by ${fact.source}`} />
                  ) : <p className="text-xs text-muted">No attributes recorded.</p>}
                </>
              )}
            </div>
          </details>
        ))}
      </div>
    </Card>
  );
}
