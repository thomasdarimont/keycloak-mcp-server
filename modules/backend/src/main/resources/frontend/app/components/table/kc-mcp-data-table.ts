import { LitElement, html, nothing, type TemplateResult } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import './kc-mcp-table-pager.js';
import { dataTableStyles } from './styles.js';
import {
  DATA_TABLE_PAGE_SIZES,
  type DataTableColumn,
  type DataTablePageDetail,
  type DataTablePageSizeDetail,
  type DataTablePager,
  type DataTableSortDetail,
  type DataTableSortDir,
} from './types.js';

/**
 * Reusable list table: client-side filter, column sort and paging by default. Set {@link remote} for
 * server-driven lists (audit): the parent owns rows, total, sort and page, and listens for events.
 */
@customElement('kc-mcp-data-table')
export class DataTable extends LitElement {
  static styles = dataTableStyles;

  @property({ attribute: false })
  columns: DataTableColumn<unknown>[] = [];

  @property({ attribute: false })
  rows: unknown[] = [];

  @property()
  filterPlaceholder = 'Filter…';

  @property()
  empty = 'No rows.';

  @property({ type: Boolean })
  busy = false;

  /** Hide the filter box (sort and paging still apply in local mode). */
  @property({ type: Boolean })
  noFilter = false;

  /**
   * Server-driven mode: do not filter/sort/slice locally; use controlled sort/page/total and emit events.
   */
  @property({ type: Boolean })
  remote = false;

  @property()
  pager: DataTablePager = 'bottom';

  @property({ attribute: false })
  pageSizes: readonly number[] = DATA_TABLE_PAGE_SIZES;

  /** Controlled page size (remote) or local page size. */
  @property({ type: Number })
  pageSize: number = DATA_TABLE_PAGE_SIZES[1];

  /** Controlled 0-based page index (remote). */
  @property({ type: Number })
  page = 0;

  /** Controlled total row count across all pages (remote). */
  @property({ type: Number })
  total = 0;

  /** When set in remote mode, Next follows this instead of page math (cursor paging). */
  @property({ type: Boolean })
  hasMore = false;

  /** Controlled sort column id (remote). */
  @property({ attribute: false })
  sortId: string | null = null;

  /** Controlled sort direction (remote). */
  @property()
  sortDir: DataTableSortDir = 'asc';

  /** Stable key for expand state; required with {@link detail}. */
  @property({ attribute: false })
  rowKey?: (row: unknown) => string | number;

  /** When set, each row can expand to show this content. */
  @property({ attribute: false })
  detail?: (row: unknown) => TemplateResult | typeof nothing;

  @state()
  private filter = '';

  @state()
  private localSortId: string | null = null;

  @state()
  private localSortDir: DataTableSortDir = 'asc';

  @state()
  private localPage = 0;

  @state()
  private opened = new Set<string>();

  protected willUpdate(changed: Map<string, unknown>): void {
    if (changed.has('rows')) {
      this.opened = new Set();
    }
  }

  protected updated(changed: Map<string, unknown>): void {
    if (this.remote) {
      return;
    }
    if (changed.has('rows') || changed.has('pageSize') || changed.has('filter')) {
      const pages = Math.max(1, Math.ceil(this.filteredSorted().length / this.pageSize));
      if (this.localPage > pages - 1) {
        this.localPage = Math.max(0, pages - 1);
      }
    }
  }

  private activeSortId(): string | null {
    return this.remote ? this.sortId : this.localSortId;
  }

  private activeSortDir(): DataTableSortDir {
    return this.remote ? this.sortDir : this.localSortDir;
  }

  private colValue(col: DataTableColumn<unknown>, row: unknown): string {
    if (col.value) {
      const v = col.value(row);
      return v == null ? '' : String(v);
    }
    if (row && typeof row === 'object' && col.id in (row as object)) {
      const v = (row as Record<string, unknown>)[col.id];
      return v == null ? '' : String(v);
    }
    return '';
  }

  private filteredSorted(): unknown[] {
    const q = this.filter.trim().toLowerCase();
    let list = this.rows;
    if (q) {
      const cols = this.columns.filter((c) => c.filterable !== false);
      list = list.filter((row) => cols.some((c) => this.colValue(c, row).toLowerCase().includes(q)));
    }
    const sortId = this.localSortId;
    if (sortId) {
      const col = this.columns.find((c) => c.id === sortId);
      if (col) {
        const dir = this.localSortDir === 'asc' ? 1 : -1;
        list = [...list].sort((a, b) => {
          const av = this.colValue(col, a).toLowerCase();
          const bv = this.colValue(col, b).toLowerCase();
          if (av < bv) {
            return -1 * dir;
          }
          if (av > bv) {
            return 1 * dir;
          }
          return 0;
        });
      }
    }
    return list;
  }

  private setFilter(e: Event): void {
    this.filter = (e.target as HTMLInputElement).value;
    this.localPage = 0;
  }

  private toggleSort(id: string): void {
    const col = this.columns.find((c) => c.id === id);
    const initial = col?.initialSortDir ?? 'asc';
    let dir: DataTableSortDir;
    if (this.activeSortId() === id) {
      dir = this.activeSortDir() === 'asc' ? 'desc' : 'asc';
    } else {
      dir = initial;
    }
    if (this.remote) {
      this.dispatchEvent(
        new CustomEvent<DataTableSortDetail>('sort', {
          detail: { id, dir },
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }
    this.localSortId = id;
    this.localSortDir = dir;
    this.localPage = 0;
  }

  private onPagerPage(e: CustomEvent<DataTablePageDetail>): void {
    e.stopPropagation();
    const page = e.detail.page;
    const fromBottom = !!e.detail.fromBottom;
    if (this.remote) {
      this.dispatchEvent(
        new CustomEvent<DataTablePageDetail>('page-change', {
          detail: { page, fromBottom },
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }
    this.localPage = page;
    if (fromBottom) {
      this.scrollIntoView({ block: 'start' });
    }
  }

  private onPagerPageSize(e: CustomEvent<DataTablePageSizeDetail>): void {
    e.stopPropagation();
    const pageSize = e.detail.pageSize;
    if (this.remote) {
      this.dispatchEvent(
        new CustomEvent<DataTablePageSizeDetail>('page-size-change', {
          detail: { pageSize },
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }
    this.pageSize = pageSize;
    this.localPage = 0;
  }

  private keyOf(row: unknown): string {
    const k = this.rowKey?.(row);
    return k == null ? '' : String(k);
  }

  private toggleOpen(row: unknown): void {
    const key = this.keyOf(row);
    if (!key) {
      return;
    }
    const opened = new Set(this.opened);
    if (!opened.delete(key)) {
      opened.add(key);
    }
    this.opened = opened;
  }

  private renderCell(col: DataTableColumn<unknown>, row: unknown) {
    if (col.cell) {
      return col.cell(row);
    }
    const text = this.colValue(col, row);
    return text || html`<span class="muted">—</span>`;
  }

  private renderPagerSlot(
    top: boolean,
    from: number,
    to: number,
    total: number,
    page: number,
    pages: number,
    canNext: boolean,
  ) {
    if (this.pager === 'none' || (top && this.pager !== 'both')) {
      return nothing;
    }
    return html`<kc-mcp-table-pager
      ?top=${top}
      .from=${from}
      .to=${to}
      .total=${total}
      .page=${page}
      .pages=${pages}
      .pageSize=${this.pageSize}
      .pageSizes=${this.pageSizes}
      .busy=${this.busy}
      .canNext=${canNext}
      .showFirst=${this.remote}
      .showPageOf=${this.remote}
      @page-change=${this.onPagerPage}
      @page-size-change=${this.onPagerPageSize}
    ></kc-mcp-table-pager>`;
  }

  private renderTable(slice: unknown[]) {
    const expandable = !!this.detail;
    const colCount = this.columns.length + (expandable ? 1 : 0);
    const fixed = this.columns.some((c) => c.width) || expandable;
    return html`
      <div class="scroll">
        <table class=${fixed ? 'fixed' : ''}>
          ${fixed
            ? html`<colgroup>
                ${expandable ? html`<col style="width: 2.5rem" />` : nothing}
                ${this.columns.map((c) =>
                  c.width ? html`<col style=${`width: ${c.width}`} />` : html`<col />`,
                )}
              </colgroup>`
            : nothing}
          <thead>
            <tr>
              ${expandable ? html`<th><span aria-hidden="true"></span></th>` : nothing}
              ${this.columns.map((col) => {
                const sortable = col.sortable !== false;
                const active = this.activeSortId() === col.id;
                const mark = active
                  ? this.activeSortDir() === 'asc'
                    ? ' ▲'
                    : ' ▼'
                  : this.remote
                    ? ' ↕'
                    : ' ▾';
                return html`<th
                  class=${col.align === 'right' ? 'right' : ''}
                  aria-sort=${active
                    ? this.activeSortDir() === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : 'none'}
                >
                  ${sortable
                    ? html`<button
                        class="sort ${active ? 'active' : ''}"
                        type="button"
                        title="Sort by ${col.label.toLowerCase()}"
                        @click=${() => this.toggleSort(col.id)}
                      >
                        ${col.label}<span aria-hidden="true">${mark}</span>
                      </button>`
                    : col.label}
                </th>`;
              })}
            </tr>
          </thead>
          <tbody>
            ${slice.map((row) => {
              const key = this.keyOf(row);
              const open = expandable && key !== '' && this.opened.has(key);
              return html`
                <tr class=${open ? 'open' : ''}>
                  ${expandable
                    ? html`<td>
                        <button
                          class="toggle"
                          type="button"
                          aria-expanded=${open ? 'true' : 'false'}
                          aria-label=${open ? 'Hide details' : 'Show details'}
                          title=${open ? 'Hide details' : 'Show details'}
                          @click=${() => this.toggleOpen(row)}
                        >
                          ${open ? '▼' : '▶'}
                        </button>
                      </td>`
                    : nothing}
                  ${this.columns.map(
                    (col) => html`<td class=${col.align === 'right' ? 'right' : col.id === 'when' ? 'when' : ''}>
                      ${this.renderCell(col, row)}
                    </td>`,
                  )}
                </tr>
                ${open && this.detail
                  ? html`<tr class="detail">
                      <td colspan=${colCount}>${this.detail(row)}</td>
                    </tr>`
                  : nothing}
              `;
            })}
          </tbody>
        </table>
      </div>
    `;
  }

  render() {
    let slice: unknown[];
    let total: number;
    let page: number;
    let pages: number;
    let from: number;
    let to: number;
    let canNext: boolean;

    if (this.remote) {
      slice = this.rows;
      total = this.total;
      page = this.page;
      pages = Math.max(1, Math.ceil(total / this.pageSize) || 1);
      from = total === 0 || slice.length === 0 ? 0 : page * this.pageSize + 1;
      to = from === 0 ? 0 : from + slice.length - 1;
      canNext = this.hasMore;
    } else {
      const all = this.filteredSorted();
      total = all.length;
      pages = Math.max(1, Math.ceil(total / this.pageSize) || 1);
      page = Math.min(this.localPage, pages - 1);
      const start = total === 0 ? 0 : page * this.pageSize;
      slice = all.slice(start, start + this.pageSize);
      from = total === 0 ? 0 : start + 1;
      to = start + slice.length;
      canNext = page < pages - 1;
    }

    const showEmpty = slice.length === 0;
    const emptyMsg =
      this.remote || this.rows.length === 0 ? this.empty : 'No rows match this filter.';

    return html`
      ${this.noFilter || this.remote
        ? nothing
        : html`<div class="toolbar">
            <div class="grow">
              <input
                type="search"
                .value=${this.filter}
                placeholder=${this.filterPlaceholder}
                aria-label=${this.filterPlaceholder}
                ?disabled=${this.busy}
                @input=${(e: Event) => this.setFilter(e)}
              />
            </div>
          </div>`}
      ${showEmpty
        ? this.busy
          ? html`<p class="empty">Loading…</p>`
          : html`<p class="empty">${emptyMsg}</p>`
        : html`
            ${this.renderPagerSlot(true, from, to, total, page, pages, canNext)}
            ${this.renderTable(slice)}
            ${this.pager === 'bottom' || this.pager === 'both'
              ? this.renderPagerSlot(false, from, to, total, page, pages, canNext)
              : nothing}
          `}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-data-table': DataTable;
  }
  interface HTMLElementEventMap {
    sort: CustomEvent<DataTableSortDetail>;
    'page-change': CustomEvent<DataTablePageDetail>;
    'page-size-change': CustomEvent<DataTablePageSizeDetail>;
  }
}
