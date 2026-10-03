import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './client';
import type { AssetsParams, FindingsParams } from './client';
import type { Asset, Finding, FindingAction, FindingActionBody, Page } from './types';

export const useMe = () =>
  useQuery({ queryKey: ['me'], queryFn: ({ signal }) => api.me(signal), staleTime: 5 * 60_000 });
export const useStats = () => useQuery({ queryKey: ['stats'], queryFn: api.stats });
export const useAssets = (p: AssetsParams) =>
  useQuery({ queryKey: ['assets', p], queryFn: () => api.assets(p), placeholderData: keepPreviousData });
export const useAsset = (id: number) =>
  useQuery({ queryKey: ['asset', id], queryFn: () => api.asset(id), enabled: Number.isFinite(id) });
export const useGraph = (id: number | undefined, depth: number) =>
  useQuery({
    queryKey: ['graph', id, depth],
    queryFn: () => api.graph(id as number, depth),
    enabled: id !== undefined,
  });
export const useFindings = (p: FindingsParams) =>
  useQuery({ queryKey: ['findings', p], queryFn: () => api.findings(p), placeholderData: keepPreviousData });
export const useFinding = (id: number | undefined, placeholder?: Finding) =>
  useQuery({
    queryKey: ['finding', id],
    queryFn: () => api.finding(id as number),
    enabled: id !== undefined,
    placeholderData: placeholder,
  });
export const useSources = () => useQuery({ queryKey: ['sources'], queryFn: api.sources });
export const useScans = (limit: number, offset: number) =>
  useQuery({ queryKey: ['scans', limit, offset], queryFn: () => api.scans(limit, offset) });
export const useChanges = (limit = 15) =>
  useQuery({ queryKey: ['changes', limit], queryFn: () => api.changes(limit) });

/** The API caps a page at 500; the UI never walks past this many rows. */
export const MAX_PAGE = 500;
export const MAX_ROWS = 5000;

async function fetchAll<T>(fetchPage: (limit: number, offset: number) => Promise<Page<T>>): Promise<T[]> {
  const out: T[] = [];
  for (let offset = 0; offset < MAX_ROWS; offset += MAX_PAGE) {
    const p = await fetchPage(MAX_PAGE, offset);
    out.push(...p.items);
    if (out.length >= p.total || p.items.length === 0) break;
  }
  return out;
}

/**
 * Every finding matching the server-side filters. The API has no sort or group
 * parameter, so sorting, grouping and paging are done over the full set.
 */
export const useAllFindings = (p: Omit<FindingsParams, 'limit' | 'offset'>, enabled = true) =>
  useQuery({
    queryKey: ['findings', 'all', p],
    queryFn: () => fetchAll<Finding>((limit, offset) => api.findings({ ...p, limit, offset })),
    placeholderData: keepPreviousData,
    enabled,
  });

/** Total matching findings, using a one-row page. */
export const useFindingTotal = (p: Omit<FindingsParams, 'limit' | 'offset'>, enabled = true) =>
  useQuery({
    queryKey: ['findings', 'total', p],
    queryFn: async () => (await api.findings({ ...p, limit: 1, offset: 0 })).total,
    placeholderData: keepPreviousData,
    enabled,
  });

export const useAllAssets = (p: Omit<AssetsParams, 'limit' | 'offset'>, enabled = true) =>
  useQuery({
    queryKey: ['assets', 'all', p],
    queryFn: () => fetchAll<Asset>((limit, offset) => api.assets({ ...p, limit, offset })),
    placeholderData: keepPreviousData,
    enabled,
  });

export function useFindingAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: number; action: FindingAction; body: FindingActionBody }) =>
      api.findingAction(v.id, v.action, v.body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] });
      void qc.invalidateQueries({ queryKey: ['finding'] });
      void qc.invalidateQueries({ queryKey: ['asset'] });
      void qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useRescan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (assetId: number) => api.rescan(assetId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['scans'] }),
  });
}

export function useSyncSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.syncSource(name),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['sources'] }),
  });
}
