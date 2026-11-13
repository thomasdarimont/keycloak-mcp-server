import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  BffError,
  getAuditEvent,
  searchAudit,
  type AuditEvent,
  type AuditFilter,
  type AuditValueField,
} from '../../bff.js';
import '../../kc-mcp-data-table.js';
import type {
  DataTableColumn,
  DataTablePageDetail,
  DataTablePageSizeDetail,
  DataTableSortDetail,
} from '../../kc-mcp-data-table.js';
import '../../components/kc-mcp-help.js';
import { systemHref } from '../../router.js';
import { sessionContext, type SessionState } from '../../session-context.js';
import './filter.js';
import type { AuditFilterChangeDetail } from './filter.js';
import {
  EMPTY,
  FIRST_ORDER,
  PAGE_SIZES,
  filterOf,
  fromQuery,
  timeAgo,
  toQuery,
  type FilterForm,
  type SortBy,
} from './model.js';

/**
 * The audit trail (GET /bff/api/audit): one row per tool call, newest first, filtered and paged on the server. A
 * filter applies as it is chosen (no search button); the chips under the filters name what is applied and remove
 * it one by one. Read only; operators and viewers alike.
 */
@customElement('kc-mcp-audit-page')
export class AuditPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.75rem;
    }
    p {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
    }
    .error {
      color: var(--error, #c9190b);
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private form: FilterForm = { ...EMPTY };

  @state()
  private events: AuditEvent[] = [];

  @state()
  private next: string | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  /** The filter of the rows shown, so the other pages continue the same query. */
  private applied: AuditFilter = {};

  /** The form the rows shown were searched with: what the chips name, and what a change is compared to. */
  @state()
  private appliedForm: FilterForm = { ...EMPTY };

  private applyTimer?: ReturnType<typeof setTimeout>;

  @state()
  private copied = false;

  /** The cursor of every page reached so far; the first page has none. */
  private cursors: (string | undefined)[] = [undefined];

  @state()
  private pageIndex = 0;

  @state()
  private total = 0;

  /** Events per page; not a filter, so Clear keeps it. */
  @state()
  private pageSize: number = PAGE_SIZES[0];

  /** Arguments asked for, by event id: loading, the arguments, or why they could not be read. */
  @state()
  private args = new Map<number, 'loading' | { value: unknown } | { error: string }>();

  private get columns(): DataTableColumn<AuditEvent>[] {
    return [
      {
        id: 'when',
        label: 'When',
        width: '12.5rem',
        initialSortDir: FIRST_ORDER.when,
        cell: (e) => html`<span title=${e.at}>${new Date(e.at).toLocaleString()}</span>`,
      },
      {
        id: 'caller',
        label: 'Caller',
        width: '13%',
        initialSortDir: FIRST_ORDER.caller,
        cell: (e) => {
          const caller = e.caller?.name || e.caller?.subject;
          return html`<div class="line">
            ${e.caller?.name
              ? html`<button
                  class="link"
                  type="button"
                  title="only this caller"
                  @click=${() => this.narrow('caller', e.caller?.name)}
                >
                  ${e.caller.name}
                </button>`
              : caller
                ? html`<span title=${caller}>${caller}</span>`
                : html`<span class="muted">anonymous</span>`}
            ${e.caller?.delegated
              ? html` <span class="badge" title="called with the caller's token">delegated</span>`
              : nothing}
          </div>`;
        },
      },
      {
        id: 'tool',
        label: 'Tool',
        width: '25%',
        sortable: false,
        cell: (e) => html`<div class="line tool">
          <span class="badge ${e.level.toLowerCase()}">${e.level.toLowerCase()}</span>
          <button
            class="link"
            type="button"
            title=${`only this tool: ${e.tool}`}
            @click=${() => this.narrow('tool', e.tool)}
          >
            <code>${e.tool}</code>
          </button>
        </div>`,
      },
      {
        id: 'target',
        label: 'System / realm',
        width: '13%',
        sortable: false,
        cell: (e) => html`<div class="line">
          ${e.system
            ? html`<a href=${systemHref(e.system)}>${e.system}</a>${e.realm
                  ? html`<span class="muted"> / ${e.realm}</span>`
                  : nothing}`
            : html`<span class="muted">–</span>`}
        </div>`,
      },
      {
        id: 'outcome',
        label: 'Outcome',
        sortable: false,
        cell: (e) => {
          const failed = e.outcome !== 'ok';
          return html`<div class="line" title=${e.message ?? ''}>
            <span class="badge ${failed ? 'failed' : ''}">${e.outcome}</span>
            ${e.message ? html`<span class="muted">${e.message}</span>` : nothing}
          </div>`;
        },
      },
      {
        id: 'took',
        label: 'Took',
        width: '5.5rem',
        align: 'right',
        initialSortDir: FIRST_ORDER.took,
        cell: (e) => html`${e.durationMs} ms`,
      },
    ];
  }

  connectedCallback(): void {
    super.connectedCallback();
    // a shared link: the filters of its query string
    const shared = fromQuery(new URLSearchParams(location.search));
    this.form = shared.form;
    this.pageSize = shared.pageSize;
    void this.search();
  }

  /**
   * Keeps the applied filters in the address bar, so the link can be bookmarked or shared; the same entry of the
   * history, not a new one per filter. The caller is left out: a person's name does not belong in a URL (browser
   * history, proxy logs, a chat the link is pasted into).
   */
  private writeUrl(): void {
    const query = toQuery(this.appliedForm, this.pageSize).toString();
    const url = location.pathname + (query ? `?${query}` : '');
    if (url !== location.pathname + location.search) {
      history.replaceState(history.state, '', url);
    }
  }

  private async copyLink(): Promise<void> {
    try {
      await navigator.clipboard.writeText(location.href);
      this.copied = true;
      setTimeout(() => (this.copied = false), 2000);
    } catch {
      // no clipboard access: the address bar has the same link
    }
  }

  /** The first page of what the form asks for. */
  private async search(): Promise<void> {
    clearTimeout(this.applyTimer);
    this.applied = filterOf(this.form, this.pageSize);
    this.appliedForm = { ...this.form };
    this.writeUrl();
    this.cursors = [undefined];
    this.args = new Map();
    await this.showPage(0);
  }

  /**
   * Page `index` (0 is the newest) of the applied filter. The API pages by cursor, not by number: the cursor of a
   * page is the `next` of the one before, so only the pages up to one past the furthest seen can be reached.
   */
  private async showPage(index: number): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const page = await searchAudit({ ...this.applied, cursor: this.cursors[index] });
      this.events = page.events;
      this.next = page.next;
      this.total = page.total;
      this.pageIndex = index;
      this.cursors = [...this.cursors.slice(0, index + 1), ...(page.next ? [page.next] : [])];
      this.args = new Map();
    } catch (e) {
      this.events = [];
      this.next = null;
      this.total = 0;
      if (e instanceof BffError) {
        this.error = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
        }
      } else {
        this.error = e instanceof Error ? e.message : String(e);
      }
    } finally {
      this.busy = false;
    }
  }

  /** From the pager under the table: back to the top of the page as well. */
  private async turnTo(index: number, fromBottom: boolean): Promise<void> {
    await this.showPage(index);
    if (fromBottom) {
      this.scrollIntoView({ block: 'start' });
    }
  }

  /** Searches when the form differs from what is shown: filters apply as they are chosen, without a button. */
  private applyIfChanged(): void {
    if (JSON.stringify(this.form) !== JSON.stringify(this.appliedForm)) {
      void this.search();
    }
  }

  /** For values that are typed (the number of "last ..."): a moment after the last key. */
  private applySoon(): void {
    clearTimeout(this.applyTimer);
    this.applyTimer = setTimeout(() => this.applyIfChanged(), 400);
  }

  private onFilterChange(e: CustomEvent<AuditFilterChangeDetail>): void {
    this.form = e.detail.form;
    if (e.detail.when === 'draft') {
      return;
    }
    if (e.detail.when === 'soon') {
      this.applySoon();
      return;
    }
    this.applyIfChanged();
  }

  private onSort(e: CustomEvent<DataTableSortDetail>): void {
    const sort = e.detail.id as SortBy;
    if (sort !== 'when' && sort !== 'took' && sort !== 'caller') {
      return;
    }
    this.form = { ...this.form, sort, order: e.detail.dir };
    this.applyIfChanged();
  }

  private onPageChange(e: CustomEvent<DataTablePageDetail & { fromBottom: boolean }>): void {
    void this.turnTo(e.detail.page, e.detail.fromBottom);
  }

  private onPageSizeChange(e: CustomEvent<DataTablePageSizeDetail>): void {
    this.pageSize = e.detail.pageSize;
    void this.search();
  }

  private narrow(field: AuditValueField, value: string | null | undefined): void {
    if (value) {
      this.form = { ...this.form, [field]: value };
      this.applyIfChanged();
    }
  }

  /**
   * Arguments are fetched for one event, when asked for: they may hold personal data, so they are neither sent with
   * the list nor shown by opening an entry.
   */
  private async showArguments(id: number): Promise<void> {
    this.args = new Map(this.args).set(id, 'loading');
    try {
      const event = await getAuditEvent(id);
      this.args = new Map(this.args).set(id, { value: event.args ?? {} });
    } catch (e) {
      const error = e instanceof BffError ? `${e.status} ${e.code}: ${e.message}` : String(e);
      this.args = new Map(this.args).set(id, { error });
      if (e instanceof BffError && e.sessionLost) {
        this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
      }
    }
  }

  private hideArguments(id: number): void {
    const args = new Map(this.args);
    args.delete(id);
    this.args = args;
  }

  /**
   * The trace id, linked to the tracing or logging system when the server names one (kc-mcp.ui.trace-url, a
   * template with {traceId} and {spanId}); only http(s) links are followed.
   */
  private traceLink(e: AuditEvent) {
    if (!e.traceId) {
      return null;
    }
    const url = (this.session?.me?.traceUrl ?? '')
      .replaceAll('{traceId}', encodeURIComponent(e.traceId))
      .replaceAll('{spanId}', encodeURIComponent(e.spanId ?? ''));
    return /^https?:\/\//i.test(url)
      ? html`<a href=${url} target="_blank" rel="noopener noreferrer" title="Open the trace"
          ><code>${e.traceId}</code></a
        >`
      : html`<code>${e.traceId}</code>`;
  }

  private renderDetail(e: AuditEvent) {
    const args = this.args.get(e.id);
    const row = (label: string, value: unknown) =>
      value === null || value === undefined || value === '' ? nothing : html`<dt>${label}</dt><dd>${value}</dd>`;
    return html`
      <dl>
        ${row('Message', e.message)}
        ${row('Time', html`${e.at} <span class="muted">(${timeAgo(e.at)})</span>`)}
        ${row('Caller', e.caller?.name)}
        ${row('Subject', e.caller?.subject)} ${row('Caller realm', e.caller?.realm)} ${row('Client', e.client)}
        ${row('Called', e.via === 'execute_tool' ? 'through execute_tool' : e.via)}
        ${row('Connection', e.connectionId)} ${row('Event', e.id)} ${row('Trace', this.traceLink(e))}
        ${row('Span', e.spanId ? html`<code>${e.spanId}</code>` : null)}
        <dt>Arguments</dt>
        <dd>
          ${!e.hasArgs
            ? html`<span class="muted">none recorded</span>`
            : args === undefined
              ? html`<button class="link" type="button" @click=${() => this.showArguments(e.id)}>
                    Show arguments
                  </button>
                  <span class="muted">· may contain personal data</span>`
              : args === 'loading'
                ? html`<span class="muted">loading …</span>`
                : 'error' in args
                  ? html`<span class="error">${args.error}</span>`
                  : html`<button class="link" type="button" @click=${() => this.hideArguments(e.id)}>
                        Hide arguments
                      </button>
                      <pre>${typeof args.value === 'string' ? args.value : JSON.stringify(args.value, null, 2)}</pre>`}
        </dd>
      </dl>
    `;
  }

  render() {
    return html`
      <h2>
        Audit
        <kc-mcp-help label="About the audit trail">
          Every tool call the server answered, refusals included, newest first unless a column is sorted. Open an
          entry for its details; its arguments are read only when asked for, as they were recorded: secrets replaced
          by <code>***</code>, personal data as the audit scrubber left it.
        </kc-mcp-help>
      </h2>
      <kc-mcp-audit-filter
        .form=${this.form}
        .appliedForm=${this.appliedForm}
        .busy=${this.busy}
        .copied=${this.copied}
        @filter-change=${this.onFilterChange}
        @copy-link=${this.copyLink}
        @refresh=${() => this.search()}
      ></kc-mcp-audit-filter>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${!this.error
        ? html`<kc-mcp-data-table
            remote
            noFilter
            pager="both"
            .columns=${this.columns}
            .rows=${this.events}
            .busy=${this.busy}
            .page=${this.pageIndex}
            .pageSize=${this.pageSize}
            .pageSizes=${PAGE_SIZES}
            .total=${this.total}
            .hasMore=${!!this.next}
            .sortId=${this.appliedForm.sort}
            .sortDir=${this.appliedForm.order}
            .rowKey=${(row: unknown) => (row as AuditEvent).id}
            .detail=${(row: unknown) => this.renderDetail(row as AuditEvent)}
            empty="No events match."
            @sort=${this.onSort}
            @page-change=${this.onPageChange}
            @page-size-change=${this.onPageSizeChange}
          ></kc-mcp-data-table>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-audit-page': AuditPage;
  }
}
