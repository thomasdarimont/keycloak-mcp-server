import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, listSystems, type System } from '../../bff.js';
import '../../kc-mcp-data-table.js';
import type { DataTableColumn } from '../../kc-mcp-data-table.js';
import '../../components/kc-mcp-help.js';
import { newSystemHref, systemHref } from '../../router.js';
import { operatorRoleHint, sessionCanWrite, sessionContext, type SessionState } from '../../session-context.js';

/** Systems list via GET /bff/api/systems; each row is a Keycloak cluster/environment. */
@customElement('kc-mcp-systems-page')
export class SystemsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.5rem;
    }
    p {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    button,
    a.btn {
      font: inherit;
      padding: 0.4rem 1rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--kc-mcp-c-button--m-primary--BorderColor, var(--accent, #0066cc));
      background: var(--kc-mcp-c-button--m-primary--BackgroundColor, var(--accent, #0066cc));
      color: var(--kc-mcp-c-button--m-primary--Color, #fff);
      cursor: pointer;
      text-decoration: none;
      font-weight: 500;
      display: inline-block;
    }
    button:hover,
    a.btn:hover {
      background: var(--kc-mcp-c-button--m-primary--hover--BackgroundColor, #004d99);
      border-color: var(--kc-mcp-c-button--m-primary--hover--BackgroundColor, #004d99);
      color: var(--kc-mcp-c-button--m-primary--Color, #fff);
      text-decoration: none;
    }
    button.secondary {
      background: var(--kc-mcp-c-button--m-secondary--BackgroundColor, transparent);
      color: var(--kc-mcp-c-button--m-secondary--Color, var(--fg, inherit));
      border-color: var(--kc-mcp-c-button--m-secondary--BorderColor, var(--border, #707070));
    }
    button.secondary:hover {
      background: color-mix(in srgb, var(--fg, #151515) 5%, transparent);
      border-color: var(--fg, #151515);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .error {
      color: var(--error, #c9190b);
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private items: System[] = [];

  @state()
  private canCreate = false;

  @state()
  private canCreateHint: string | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  private get canWrite(): boolean {
    return sessionCanWrite(this.session);
  }

  private get columns(): DataTableColumn<System>[] {
    const canWrite = this.canWrite;
    return [
      {
        id: 'alias',
        label: 'Alias',
        value: (s) => `${s.displayName || ''} ${s.alias}`,
        cell: (s) => html`
          <a href=${systemHref(s.alias)}>${s.displayName || s.alias}</a>
          ${s.displayName ? html`<div class="muted"><code>${s.alias}</code></div>` : nothing}
        `,
      },
      {
        id: 'url',
        label: 'URL',
        cell: (s) => html`<code>${s.url}</code>`,
      },
      {
        id: 'realms',
        label: 'Realms',
        value: (s) => this.realmsSummary(s),
        cell: (s) => html`<a href=${systemHref(s.alias, 'realms')}>${this.realmsSummary(s)}</a>`,
      },
      {
        id: 'source',
        label: 'Source',
        value: (s) => `${s.source ?? ''} ${s.writable === false ? 'read-only' : ''}`,
        cell: (s) => html`
          <span class="badge">${s.source ?? '—'}</span>
          ${s.writable === false ? html` <span class="badge">read-only</span>` : nothing}
        `,
      },
      {
        id: 'open',
        label: '',
        sortable: false,
        filterable: false,
        cell: (s) => html`<a href=${systemHref(s.alias)}
          >${s.writable === false || !canWrite ? 'View' : 'Open'}</a
        >`,
      },
    ];
  }

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const data = await listSystems();
      const canWrite = this.canWrite;
      this.items = data.systems ?? [];
      this.canCreate = !!data.canCreate && canWrite;
      this.canCreateHint = canWrite
        ? (data.canCreateHint ?? null)
        : operatorRoleHint(this.session, 'Registering or changing systems');
    } catch (e) {
      this.items = [];
      this.canCreate = false;
      this.canCreateHint = null;
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

  private realmsSummary(s: System): string {
    const allowed = s.allowedRealms ?? [];
    if (allowed.length === 0) {
      return s.defaultRealm ? `all (default ${s.defaultRealm})` : 'all realms';
    }
    if (allowed.length <= 3) {
      return allowed
        .map((r) => (r === s.defaultRealm ? `${r}*` : r))
        .join(', ');
    }
    return `${allowed.length} realms`;
  }

  render() {
    return html`
      <h2>
        Systems
        <kc-mcp-help label="About systems">
          Keycloak clusters and environments known to this server. Each system has a front-door URL and zero or more
          managed realms (all realms, or an explicit allowlist).
        </kc-mcp-help>
      </h2>
      <div class="row">
        ${this.canCreate ? html`<a class="btn" href=${newSystemHref()}>Add system</a>` : nothing}
        <button class="secondary" type="button" ?disabled=${this.busy} @click=${() => this.load()}>
          Refresh
        </button>
      </div>
      ${!this.canCreate && this.canCreateHint && !this.error
        ? html`<p class="muted">${this.canCreateHint}</p>`
        : nothing}
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${!this.error
        ? html`<kc-mcp-data-table
            .columns=${this.columns}
            .rows=${this.items}
            .busy=${this.busy}
            filterPlaceholder="Filter systems…"
            empty="No systems registered."
          ></kc-mcp-data-table>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-systems-page': SystemsPage;
  }
}
