import { useAssets } from '../api/hooks';
import { INVENTORY_PAGE_SIZE, toAssetsApi } from '../lib/inventory';
import type { InventoryFilter } from '../lib/inventory';

export function useInventoryData(filter: InventoryFilter, enabled: boolean) {
  const query = useAssets({
    ...toAssetsApi(filter),
    limit: INVENTORY_PAGE_SIZE,
    offset: (filter.page - 1) * INVENTORY_PAGE_SIZE,
  }, enabled);
  return { query, rows: query.data?.items ?? [], total: query.data?.total ?? 0 };
}
