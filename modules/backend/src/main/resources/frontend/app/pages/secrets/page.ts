import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, listSecrets, type Secret } from '../../bff.js';
import '../../kc-mcp-data-table.js';
import type { DataTableColumn } from '../../kc-mcp-data-table.js';
import '../../components/kc-mcp-help.js';
import { systemHref } from '../../router.js';

/** Secrets list via GET /bff/api/secrets: names, vault, usedBy — never values. */
@customElement('kc-mcp-secrets-page')
export class SecretsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.5rem;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.75rem;
      font-size: 0.9rem;
    }
    .meta dt {
      color: var(--muted, #656d76);
      margin: 0;
    }
    .meta dd {
      margin: 0 1rem 0 0;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
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
    .error {
      color: var(--error, #cf222e);
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      border: 1px solid var(--border, #d0d7de);
      color: var(--muted, #656d76);
    }
  `;

  @state()
  private vault: string | null = null;

  @state()
  private writable = false;

  @state()
  private items: Secret[] = [];

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  private readonly columns: DataTableColumn<Secret>[] = [
    {
      id: 'name',
      label: 'Name',
      cell: (s) => html`<code>${s.name}</code>`,
    },
    {
      id: 'reference',
      label: 'Reference',
      cell: (s) => html`<code>${s.reference}</code>`,
    },
    {
      id: 'usedBy',
      label: 'Used by',
      value: (s) => (s.usedBy ?? []).join(' '),
      cell: (s) =>
        s.usedBy?.length
          ? html`<div class="used-by">
              ${s.usedBy.map((alias) => html`<a href=${systemHref(alias)}>${alias}</a>`)}
            </div>`
          : html`<span class="muted">—</span>`,
    },
  ];

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const data = await listSecrets();
      this.vault = data.vault ?? null;
      this.writable = !!data.writable;
      this.items = data.secrets ?? [];
    } catch (e) {
      this.vault = null;
      this.writable = false;
      this.items = [];
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

  render() {
    return html`
      <h2>
        Secrets
        <kc-mcp-help label="About secrets">
          Names held in the key vault and which systems reference them as vault:… Values never appear here; store or
          rotate them in the vault (database vault via the admin API, or OpenBao / HashiCorp Vault). This UI does not
          edit secret values.
        </kc-mcp-help>
      </h2>
      ${this.vault
        ? html`<dl class="meta">
            <dt>Vault</dt>
            <dd><code>${this.vault}</code></dd>
            <dt>Storage</dt>
            <dd>
              <span class="badge">${this.writable ? 'writable' : 'read-only'}</span>
            </dd>
          </dl>`
        : nothing}
      <div class="row">
        <button type="button" ?disabled=${this.busy} @click=${() => this.load()}>Refresh</button>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${!this.error
        ? html`<kc-mcp-data-table
            .columns=${this.columns}
            .rows=${this.items}
            .busy=${this.busy}
            filterPlaceholder="Filter secrets…"
            empty="No secrets in the vault."
          ></kc-mcp-data-table>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-secrets-page': SecretsPage;
  }
}
