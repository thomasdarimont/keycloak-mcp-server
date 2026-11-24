import { LitElement, css, html, nothing } from 'lit';
import { customElement, property } from 'lit/decorators.js';
import { DATA_TABLE_PAGE_SIZES, type DataTablePageDetail, type DataTablePageSizeDetail } from './types.js';

/**
 * Shared list pager: range label, per-page select, First (optional) / Previous / Next.
 */
@customElement('kc-mcp-table-pager')
export class TablePager extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--muted, #656d76);
      font-size: 0.85rem;
    }
    nav {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      margin: 0.75rem 0 0;
    }
    :host([top]) nav {
      margin: 0 0 0.75rem;
    }
    .buttons {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem;
    }
    .per-page {
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    select {
      font: inherit;
      font-size: 0.9rem;
      height: 2.1rem;
      box-sizing: border-box;
      padding: 0 0.5rem;
      border: 1px solid var(--border, #d0d7de);
      border-radius: 6px;
      background: var(--card, #fff);
      color: var(--fg, inherit);
    }
    select:focus-visible,
    button:focus-visible {
      outline: 2px solid var(--accent, #1f6feb);
      outline-offset: 1px;
    }
    button {
      font: inherit;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      border: 1px solid var(--border, #8b949e);
      background: transparent;
      color: var(--fg, inherit);
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
  `;

  @property({ type: Number })
  from = 0;

  @property({ type: Number })
  to = 0;

  @property({ type: Number })
  total = 0;

  @property({ type: Number })
  page = 0;

  @property({ type: Number })
  pages = 1;

  @property({ type: Number })
  pageSize: number = DATA_TABLE_PAGE_SIZES[1];

  @property({ attribute: false })
  pageSizes: readonly number[] = DATA_TABLE_PAGE_SIZES;

  @property({ type: Boolean })
  busy = false;

  @property({ type: Boolean })
  canNext = false;

  /** Show « First and use ‹ Previous / Next › labels (remote / cursor paging). */
  @property({ type: Boolean })
  showFirst = false;

  /** When true, show "page N of M" after the range. */
  @property({ type: Boolean })
  showPageOf = false;

  @property({ type: Boolean, reflect: true })
  top = false;

  private setPageSize(e: Event): void {
    const pageSize = Number((e.target as HTMLSelectElement).value);
    this.dispatchEvent(
      new CustomEvent<DataTablePageSizeDetail>('page-size-change', {
        detail: { pageSize },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private goPage(page: number): void {
    this.dispatchEvent(
      new CustomEvent<DataTablePageDetail>('page-change', {
        detail: { page, fromBottom: !this.top },
        bubbles: true,
        composed: true,
      }),
    );
  }

  render() {
    const canPrev = this.page > 0;
    return html`
      <nav aria-label="Table pages">
        <span
          >${this.from}–${this.to} of ${this.total}${this.showPageOf
            ? html` · page ${this.page + 1} of ${this.pages}`
            : nothing}</span
        >
        <div class="buttons">
          <label class="per-page">
            Per page
            <select
              .value=${String(this.pageSize)}
              ?disabled=${this.busy}
              @change=${(e: Event) => this.setPageSize(e)}
            >
              ${this.pageSizes.map((n) => html`<option value=${n}>${n}</option>`)}
            </select>
          </label>
          ${this.showFirst
            ? html`<button type="button" ?disabled=${!canPrev || this.busy} @click=${() => this.goPage(0)}>
                « First
              </button>`
            : nothing}
          <button type="button" ?disabled=${!canPrev || this.busy} @click=${() => this.goPage(this.page - 1)}>
            ${this.showFirst ? '‹ Previous' : 'Previous'}
          </button>
          <button type="button" ?disabled=${!this.canNext || this.busy} @click=${() => this.goPage(this.page + 1)}>
            ${this.showFirst ? 'Next ›' : 'Next'}
          </button>
        </div>
      </nav>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-table-pager': TablePager;
  }
  interface HTMLElementEventMap {
    'page-change': CustomEvent<DataTablePageDetail>;
    'page-size-change': CustomEvent<DataTablePageSizeDetail>;
  }
}
