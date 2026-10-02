import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './client';
import type { AssetsParams, FindingsParams } from './client';
import type { FindingAction, FindingActionBody } from './types';

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
export const useSources = () => useQuery({ queryKey: ['sources'], queryFn: api.sources });
export const useScans = (limit: number, offset: number) =>
  useQuery({ queryKey: ['scans', limit, offset], queryFn: () => api.scans(limit, offset) });
export const useChanges = (limit = 15) =>
  useQuery({ queryKey: ['changes', limit], queryFn: () => api.changes(limit) });

export function useFindingAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: number; action: FindingAction; body: FindingActionBody }) =>
      api.findingAction(v.id, v.action, v.body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] });
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
