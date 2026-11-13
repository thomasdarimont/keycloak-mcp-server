import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { BffError, getSystem, type System } from '../../bff.js';
import { systemHref, systemsHref, type SystemTab } from '../../router.js';
import './adopt.js';
import './keys.js';
import './realm.js';
import './realms.js';
import './settings.js';

/** One system: header, Settings | Realms | Adopt | Keys tabs, child outlet. */
@customElement('kc-mcp-system-page')
export class SystemPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    a.back {
      color: var(--accent, #0066cc);
      text-decoration: none;
      font-size: 0.9rem;
    }
    a.back:hover {
      text-decoration: underline;
    }
    h2 {
      font-size: 1.1rem;
      margin: 0.35rem 0 0.25rem;
    }
    .lead {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
    }
    .lead code {
      font-size: 0.85em;
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: var(--radius, 6px);
      border: 1px solid var(--border, #d2d2d2);
      color: var(--muted, #6a6e73);
      margin-left: 0.35rem;
    }
    .tabs {
      display: flex;
      gap: 0.25rem;
      border-bottom: 1px solid var(--border, #d2d2d2);
      margin: 0 0 1rem;
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
    .error {
      color: var(--error, #c9190b);
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
  `;

  @property()
  alias = '';

  @property()
  tab: SystemTab = 'settings';

  /** When set on the Realms tab, show that realm's settings instead of the list. */
  @property()
  realm = '';

  @state()
  private system: System | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  protected updated(changed: Map<string, unknown>): void {
    if (changed.has('alias') && changed.get('alias') !== undefined) {
      void this.load();
    }
  }

  private async load(): Promise<void> {
    if (!this.alias) {
      this.system = null;
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      this.system = await getSystem(this.alias);
    } catch (e) {
      this.system = null;
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

  private onSaved(event: Event): void {
    const detail = (event as CustomEvent<System>).detail;
    if (detail?.alias) {
      this.system = detail;
    } else {
      void this.load();
    }
  }

  render() {
    if (!this.alias) {
      return html`<p class="error">No system selected.</p>`;
    }
    if (this.busy && !this.system) {
      return html`<p class="muted">Loading…</p>`;
    }
    if (!this.system) {
      return html`
        <a class="back" href=${systemsHref()}>← Systems</a>
        ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      `;
    }
    const s = this.system;
    const title = s.displayName || s.alias;
    const active: SystemTab =
      this.tab === 'realms' || this.realm
        ? 'realms'
        : this.tab === 'keys' || this.tab === 'adopt'
          ? this.tab
          : 'settings';
    return html`
      <a class="back" href=${systemsHref()}>← Systems</a>
      <h2>${title}</h2>
      <p class="lead">
        Alias <code>${s.alias}</code>
        ${s.source ? html` · source <code>${s.source}</code>` : nothing}
        ${s.writable === false ? html` <span class="badge">read-only source</span>` : nothing}
      </p>
      <nav class="tabs" aria-label="System">
        <a
          href=${systemHref(s.alias, 'settings')}
          aria-current=${active === 'settings' ? 'page' : nothing}
          >Settings</a
        >
        <a
          href=${systemHref(s.alias, 'realms')}
          aria-current=${active === 'realms' ? 'page' : nothing}
          >Realms</a
        >
        <a
          href=${systemHref(s.alias, 'adopt')}
          aria-current=${active === 'adopt' ? 'page' : nothing}
          >Adopt</a
        >
        <a
          href=${systemHref(s.alias, 'keys')}
          aria-current=${active === 'keys' ? 'page' : nothing}
          >Keys</a
        >
      </nav>
      ${active === 'realms'
        ? this.realm
          ? html`<kc-mcp-system-realm-page
              embedded
              .alias=${s.alias}
              .realm=${this.realm}
            ></kc-mcp-system-realm-page>`
          : html`<kc-mcp-system-realms .system=${s}></kc-mcp-system-realms>`
        : active === 'adopt'
          ? html`<kc-mcp-system-adopt
              .system=${s}
              @system-saved=${(e: Event) => this.onSaved(e)}
            ></kc-mcp-system-adopt>`
          : active === 'keys'
          ? html`<kc-mcp-system-keys
              .system=${s}
              @system-saved=${(e: Event) => this.onSaved(e)}
            ></kc-mcp-system-keys>`
          : html`<kc-mcp-system-settings
              embedded
              .alias=${s.alias}
              @system-saved=${(e: Event) => this.onSaved(e)}
            ></kc-mcp-system-settings>`}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-page': SystemPage;
  }
}
