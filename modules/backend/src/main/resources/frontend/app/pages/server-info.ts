import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { BffError, serverInfo, type ServerInfo, type ServerInfoProvider } from '../bff.js';
import { serverInfoHref, type ServerInfoTab } from '../router.js';

/**
 * The server and its runtime on one tab, the extensions with what they report about themselves on another; operators
 * only. Warnings of extensions show above both.
 */
@customElement('kc-mcp-server-info-page')
export class ServerInfoPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1.1rem;
      margin: 0 0 0.35rem;
    }
    h3 {
      font-size: 0.95rem;
      margin: 1.25rem 0 0.35rem;
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.25rem 1rem;
      margin: 0.5rem 0 0;
    }
    dt,
    .muted {
      color: var(--muted, #6a6e73);
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .error {
      color: var(--error, #c9190b);
    }
    .tabs {
      display: flex;
      gap: 0.25rem;
      border-bottom: 1px solid var(--border, #d2d2d2);
      margin: 0.75rem 0 1rem;
    }
    .tabs a {
      color: var(--fg, inherit);
      text-decoration: none;
      padding: 0.5rem 0.85rem;
      border-bottom: 2px solid transparent;
      margin-bottom: -1px;
      font-weight: 500;
      font-size: 0.9rem;
    }
    .tabs a:hover {
      color: var(--accent, #0066cc);
    }
    .tabs a[aria-current='page'] {
      color: var(--accent, #0066cc);
      border-bottom-color: var(--accent, #0066cc);
    }
    .warnings {
      margin: 0.75rem 0 0;
      padding: 0.6rem 0.9rem;
      border: 1px solid var(--warning, #f0ab00);
      border-radius: 6px;
      list-style: none;
    }
    .warnings li + li {
      margin-top: 0.3rem;
    }
    .scroll {
      overflow-x: auto;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      font-size: 0.9rem;
    }
    th,
    td {
      text-align: left;
      vertical-align: top;
      padding: 0.35rem 0.75rem 0.35rem 0;
      border-bottom: 1px solid var(--border, #d2d2d2);
    }
    th {
      color: var(--muted, #6a6e73);
      font-weight: 600;
    }
    .filter {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem 0.75rem;
      margin: 0 0 0.5rem;
    }
    .filter label {
      color: var(--muted, #6a6e73);
    }
    .filter input {
      font: inherit;
      padding: 0.35rem 0.6rem;
      min-width: min(20rem, 100%);
      border: 1px solid var(--border, #6a6e73);
      border-radius: 6px;
      background: var(--card, transparent);
      color: var(--fg, inherit);
    }
    tr.group th {
      padding-top: 1.1rem;
      color: var(--fg, inherit);
      font-size: 0.95rem;
      border-bottom: 2px solid var(--border, #d2d2d2);
    }
    tr.group code,
    td.extension code {
      font-weight: 400;
      font-size: 0.8rem;
      color: var(--muted, #6a6e73);
      margin-left: 0.35rem;
    }
    .count {
      font-weight: 400;
      font-size: 0.8rem;
      margin-left: 0.5rem;
    }
    .about {
      font-weight: 400;
      font-size: 0.85rem;
      margin-top: 0.15rem;
      max-width: 60rem;
    }
    td.extension {
      padding-left: 1rem;
    }
    td.action {
      text-align: right;
      white-space: nowrap;
    }
    button {
      font: inherit;
      font-size: 0.85rem;
      padding: 0.2rem 0.7rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--border, #6a6e73);
      background: transparent;
      color: var(--fg, inherit);
      cursor: pointer;
    }
    tr.detail td {
      padding: 0.5rem 0.75rem 0.75rem 1.5rem;
      background: color-mix(in srgb, var(--fg, #151515) 4%, transparent);
    }
    tr.detail dl {
      margin: 0;
    }
    tr.detail p {
      margin: 0.35rem 0 0;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
    .warn {
      color: var(--warning-fg, #795600);
    }
  `;

  @property()
  tab: ServerInfoTab = 'server';

  @state()
  private info: ServerInfo | null = null;

  @state()
  private error: string | null = null;

  /** What the Extensions tab is narrowed to. */
  @state()
  private filter = '';

  /** The rows whose server info is shown, as `<spi>/<id>`. */
  @state()
  private expanded: Set<string> = new Set();

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.error = null;
    try {
      this.info = await serverInfo();
    } catch (e) {
      this.info = null;
      if (e instanceof BffError) {
        this.error = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
        }
      } else {
        this.error = e instanceof Error ? e.message : String(e);
      }
    }
  }

  private static megabytes(bytes: number): string {
    return `${Math.round(bytes / (1024 * 1024))} MB`;
  }

  private static uptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return [d ? `${d} d` : '', d || h ? `${h} h` : '', `${m} min`].filter(Boolean).join(' ');
  }

  private toggle(key: string): void {
    const next = new Set(this.expanded);
    if (!next.delete(key)) {
      next.add(key);
    }
    this.expanded = next;
  }

  /** The heading row of an extension point, then its extensions. */
  private renderGroup(spi: string, name: string, list: ServerInfoProvider[]) {
    const description = this.info?.extensionPoints?.[spi]?.description;
    return html`
      <tr class="group">
        <th colspan="4" scope="colgroup">
          ${name} <code>${spi}</code>
          <span class="muted count">${list.length === 1 ? '1 extension' : `${list.length} extensions`}</span>
          ${description ? html`<div class="muted about">${description}</div>` : nothing}
        </th>
      </tr>
      ${list.map((p) => this.renderProvider(spi, p))}
    `;
  }

  private renderProvider(spi: string, p: ServerInfoProvider) {
    const key = `${spi}/${p.id}`;
    const open = this.expanded.has(key);
    const facts = Object.entries(p.info ?? {});
    const warnings = p.warnings ?? [];
    const detailId = `info-${spi}-${p.id}`;
    return html`
      <tr>
        <td class="extension">${p.displayName} <code>${p.id}</code></td>
        <td>${p.status}</td>
        <td>${p.origin}</td>
        <td class="action">
          <button
            type="button"
            aria-expanded=${open ? 'true' : 'false'}
            aria-controls=${detailId}
            @click=${() => this.toggle(key)}
          >
            ${open ? 'Hide' : 'Server info'}${warnings.length ? html` <span class="warn">⚠</span>` : nothing}
          </button>
        </td>
      </tr>
      ${open
        ? html`<tr class="detail" id=${detailId}>
            <td colspan="4">
              ${facts.length
                ? html`<dl>
                    ${facts.map(
                      ([fact, value]) =>
                        html`<dt>${fact}</dt>
                          <dd>${value}</dd>`,
                    )}
                  </dl>`
                : nothing}
              ${warnings.map((w) => html`<p class="warn">${w}</p>`)}
              ${!facts.length && !warnings.length
                ? html`<p class="muted">
                    ${p.status === 'active' || p.status === 'selected'
                      ? 'This extension reports nothing about itself.'
                      : `Not asked: the extension is ${p.status}.`}
                  </p>`
                : nothing}
            </td>
          </tr>`
        : nothing}
    `;
  }

  render() {
    if (this.error) {
      return html`<h2>Server info</h2>
        <p class="error" role="alert">${this.error}</p>`;
    }
    const info = this.info;
    if (!info) {
      return html`<h2>Server info</h2>
        <p class="muted">…</p>`;
    }
    return html`
      <h2>Server info</h2>
      ${info.warnings.length
        ? html`<ul class="warnings" aria-label="Warnings">
            ${info.warnings.map((w) => html`<li><strong>${w.spi} / ${w.id}</strong>: ${w.message}</li>`)}
          </ul>`
        : nothing}

      <nav class="tabs" aria-label="Server info">
        <a href=${serverInfoHref('server')} aria-current=${this.tab === 'server' ? 'page' : nothing}>Server</a>
        <a href=${serverInfoHref('extensions')} aria-current=${this.tab === 'extensions' ? 'page' : nothing}
          >Extensions</a
        >
      </nav>
      ${this.tab === 'extensions' ? this.renderExtensions(info) : this.renderServer(info)}
    `;
  }

  private renderServer(info: ServerInfo) {
    return html`
      <h3>Server</h3>
      <dl>
        <dt>Version</dt>
        <dd>${info.server.version}${info.server.devMode ? html` <span class="muted">(dev mode)</span>` : nothing}</dd>
        <dt>Started</dt>
        <dd>
          ${new Date(info.server.startedAt).toLocaleString()}
          <span class="muted">(up ${ServerInfoPage.uptime(info.server.uptimeSeconds)})</span>
        </dd>
        <dt>Instance role</dt>
        <dd>
          ${info.server.instanceRole}
          <span class="muted"
            >${info.server.instanceRole === 'mcp'
              ? 'the MCP endpoint only'
              : info.server.instanceRole === 'admin'
                ? 'the admin API and this UI only'
                : 'the MCP endpoint, the admin API and this UI'}</span
          >
        </dd>
        <dt>Security profile</dt>
        <dd>${info.server.securityProfile}</dd>
        <dt>Tool exposure</dt>
        <dd>${info.server.toolExposure}</dd>
        <dt>Systems</dt>
        <dd>${info.systems.count}</dd>
      </dl>

      <h3>Runtime</h3>
      <dl>
        <dt>Java</dt>
        <dd>${info.runtime.javaVersion} <span class="muted">${info.runtime.javaVm}, ${info.runtime.javaVendor}</span></dd>
        <dt>Operating system</dt>
        <dd>${info.runtime.os} <span class="muted">${info.runtime.architecture}</span></dd>
        <dt>Processors</dt>
        <dd>${info.runtime.processors}</dd>
        <dt>Memory</dt>
        <dd>
          ${ServerInfoPage.megabytes(info.runtime.memoryUsedBytes)} used of
          ${ServerInfoPage.megabytes(info.runtime.memoryMaxBytes)}
        </dd>
      </dl>
    `;
  }

  /**
   * The extensions the filter leaves, by extension point: those whose id contains the text, and all of an extension
   * point whose own id does. Names count too, so "vault" finds the key vault whatever its id.
   */
  private filtered(info: ServerInfo): [string, ServerInfoProvider[]][] {
    const text = this.filter.trim().toLowerCase();
    const all = Object.entries(info.providers);
    if (!text) {
      return all;
    }
    const has = (value: string | undefined) => !!value && value.toLowerCase().includes(text);
    return all
      .map(([spi, list]): [string, ServerInfoProvider[]] =>
        has(spi) || has(info.extensionPoints?.[spi]?.displayName)
          ? [spi, list]
          : [spi, list.filter((p) => has(p.id) || has(p.displayName))],
      )
      .filter(([, list]) => list.length > 0);
  }

  private renderExtensions(info: ServerInfo) {
    const groups = this.filtered(info);
    const shown = groups.reduce((n, [, list]) => n + list.length, 0);
    const total = Object.values(info.providers).reduce((n, list) => n + list.length, 0);
    return html`
      <div class="filter">
        <label for="extension-filter">Filter</label>
        <input
          id="extension-filter"
          type="search"
          placeholder="Extension or extension point id"
          autocomplete="off"
          spellcheck="false"
          .value=${this.filter}
          @input=${(e: Event) => (this.filter = (e.target as HTMLInputElement).value)}
        />
        <span class="muted" role="status">${this.filter.trim() ? `${shown} of ${total}` : `${total} extensions`}</span>
      </div>
      ${groups.length
        ? html`<div class="scroll">
            <table>
              <thead>
                <tr>
                  <th>Extension</th>
                  <th>Status</th>
                  <th>Origin</th>
                  <th><span class="sr-only">Server info</span></th>
                </tr>
              </thead>
              <tbody>
                ${groups.map(([spi, list]) =>
                  this.renderGroup(spi, info.extensionPoints?.[spi]?.displayName ?? spi, list),
                )}
              </tbody>
            </table>
          </div>`
        : html`<p class="muted">No extension matches “${this.filter.trim()}”.</p>`}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-server-info-page': ServerInfoPage;
  }
}
