import { Link } from 'react-router-dom';
import type { AssetDetail } from '../api/types';
import { SEVERITIES } from '../api/types';
import { SCOPE_INFO, assetSources, assetTags, hasFindings, isStaleObservation, severityCounts } from '../lib/assetView';
import { absTime, relTime } from '../lib/format';
import { Card, Field, KindBadge, ScopeBadge, SeverityBadge } from './ui';

/** Everything you want to know about an asset before reading its findings. */
export function AssetProperties({ d, now }: { d: AssetDetail; now?: number }) {
  const { asset, findings, observations } = d;
  const counts = severityCounts(findings);
  const tags = assetTags(asset);
  const sources = assetSources(asset);
  const removed = !!asset.removed_at;
  const scope = SCOPE_INFO[asset.scope];
  const checks = [...observations].sort((a, b) => a.check.localeCompare(b.check));

  return (
    <Card title="Properties">
      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 p-3 md:grid-cols-4">
        <Field label="Kind">
          <KindBadge kind={asset.kind} />
        </Field>
        <div className="col-span-2">
          <dt className="text-xs text-muted">Scope</dt>
          <dd className="mt-0.5 text-sm">
            <ScopeBadge scope={asset.scope} />
            {scope && <p className="mt-1 text-xs text-muted">{scope.probing}</p>}
          </dd>
        </div>
        <Field label="Canonical source">{asset.source || '-'}</Field>
        <div className="col-span-2 md:col-span-4">
          <dt className="text-xs text-muted">Reported by</dt>
          <dd className="mt-1">
            <ul className="flex flex-wrap gap-1" aria-label="Reporting sources">
              {sources.map((source) => (
                <li key={source}>
                  <Link className="inline-flex rounded-sm border border-line bg-surface2 px-1.5 py-0.5 text-xs text-accent hover:underline" to={`/inventory?source=${encodeURIComponent(source)}`}>
                    {source}
                  </Link>
                </li>
              ))}
            </ul>
          </dd>
        </div>
        <Field label="Canonical zone">
          {asset.zone ? (
            <Link className="text-accent hover:underline" to={`/inventory?zone=${encodeURIComponent(asset.zone)}`}>
              {asset.zone}
            </Link>
          ) : (
            '-'
          )}
        </Field>
        <Field label="First seen">
          <span title={absTime(asset.first_seen)}>
            {absTime(asset.first_seen)} <span className="text-muted">({relTime(asset.first_seen, now)})</span>
          </span>
        </Field>
        <Field label="Last seen">
          <span title={absTime(asset.last_seen)}>{relTime(asset.last_seen, now)}</span>
        </Field>
        <Field label="Status">
          {removed ? (
            <span className="inline-flex items-center gap-1 rounded-sm border border-bad px-1.5 py-0.5 text-xs font-semibold uppercase text-bad">
              Removed <span className="font-normal normal-case" title={absTime(asset.removed_at)}>{relTime(asset.removed_at, now)}</span>
            </span>
          ) : (
            <span className="inline-flex items-center rounded-sm border border-ok px-1.5 py-0.5 text-xs font-semibold uppercase text-ok">
              Live
            </span>
          )}
        </Field>
        <Field label="Tags">
          {tags.length === 0 ? (
            <span className="text-muted">none</span>
          ) : (
            <ul className="flex flex-wrap gap-1">
              {tags.map((t) => (
                <li key={t} className="rounded-sm border border-line bg-surface2 px-1.5 py-0.5 text-xs">{t}</li>
              ))}
            </ul>
          )}
        </Field>
        <div className="col-span-2 md:col-span-4">
          <dt className="text-xs text-muted">Open findings</dt>
          <dd className="mt-1">
            {hasFindings(counts) ? (
              <ul className="flex flex-wrap gap-2">
                {[...SEVERITIES].reverse().filter((s) => counts[s] > 0).map((s) => (
                  <li key={s}>
                    <Link
                      to={`/findings?asset_id=${asset.id}&severity=${s}`}
                      className="inline-flex items-center gap-1 text-sm hover:underline"
                      aria-label={`${counts[s]} open ${s} findings`}
                    >
                      <SeverityBadge severity={s} />
                      <span className="tabular-nums">{counts[s]}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-sm text-ok">No open findings</span>
            )}
          </dd>
        </div>
        <div className="col-span-2 md:col-span-4">
          <dt className="text-xs text-muted">Last observed per check</dt>
          <dd className="mt-1">
            {checks.length === 0 ? (
              <span className="text-sm text-muted">Never scanned: no observations yet. Use Rescan now.</span>
            ) : (
              <ul className="grid gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
                {checks.map((o) => {
                  const stale = isStaleObservation(o.observed_at, now);
                  return (
                    <li key={o.check} className="flex items-baseline justify-between gap-2 text-sm">
                      <span className="font-mono text-xs">{o.check}</span>
                      <time
                        dateTime={o.observed_at}
                        title={absTime(o.observed_at)}
                        className={`text-xs ${stale ? 'font-semibold text-warn' : 'text-muted'}`}
                      >
                        {relTime(o.observed_at, now)}
                        {stale && ' · stale'}
                      </time>
                    </li>
                  );
                })}
              </ul>
            )}
          </dd>
        </div>
      </dl>
    </Card>
  );
}
