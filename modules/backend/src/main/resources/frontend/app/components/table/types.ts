import type { TemplateResult, nothing } from 'lit';

/** Page size choices for the shared list table (local mode default). */
export const DATA_TABLE_PAGE_SIZES = [10, 25, 50, 100] as const;

export type DataTableSortDir = 'asc' | 'desc';

export type DataTablePager = 'bottom' | 'both' | 'none';

export type DataTableColumn<T> = {
  /** Stable id; used as the sort key when {@link value} is omitted and `T[id]` exists. */
  id: string;
  label: string;
  /** When false, the header is plain text. Default true. */
  sortable?: boolean;
  /** When false, the column is ignored by the filter box. Default true. */
  filterable?: boolean;
  align?: 'left' | 'right';
  /** Optional CSS width for a matching `<col>` (e.g. `12.5rem`, `13%`). */
  width?: string;
  /** First sort direction when this column becomes active (remote and local). Default `asc`. */
  initialSortDir?: DataTableSortDir;
  /** Sort / filter value; defaults to `String(row[id] ?? '')`. */
  value?: (row: T) => string | number | boolean | null | undefined;
  /** Cell content; defaults to the string of {@link value}. */
  cell?: (row: T) => TemplateResult | string | number | typeof nothing;
};

export type DataTableSortDetail = { id: string; dir: DataTableSortDir };
export type DataTablePageDetail = { page: number; fromBottom?: boolean };
export type DataTablePageSizeDetail = { pageSize: number };
