import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, listSystems, type System } from '../../bff.js';
import '../../kc-mcp-help.js';
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
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th,
    td {
      text-align: left;
      padding: 0.55rem 0.65rem;
      border-bottom: 1px solid var(--border, #d2d2d2);
      vertical-align: top;
    }
    th {
      color: var(--muted, #6a6e73);
      font-weight: 600;
    }
    a:not(.btn) {
      color: var(--accent, #0066cc);
      text-decoration: none;
      font-weight: 600;
    }
    a:not(.btn):hover {
      text-decoration: underline;
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: var(--radius, 6px);
      border: 1px solid var(--border, #d2d2d2);
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
        ${this.canCreate
          ? html`<a class="btn" href=${newSystemHref()}>Add system</a>`
          : nothing}
        <button class="secondary" type="button" ?disabled=${this.busy} @click=${() => this.load()}>
          Refresh
        </button>
      </div>
      ${!this.canCreate && this.canCreateHint && !this.error
        ? html`<p class="muted">${this.canCreateHint}</p>`
        : nothing}
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${!this.error && !this.busy && this.items.length === 0
        ? html`<p class="muted">No systems registered.</p>`
        : nothing}
      ${this.items.length
        ? html`<table>
            <thead>
              <tr>
                <th>Alias</th>
                <th>URL</th>
                <th>Realms</th>
                <th>Source</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${this.items.map((s) => this.renderRow(s))}
            </tbody>
          </table>`
        : nothing}
    `;
  }

  private renderRow(s: System) {
    const href = systemHref(s.alias);
    const realmsHref = systemHref(s.alias, 'realms');
    return html`
      <tr>
        <td>
          <a href=${href}>${s.displayName || s.alias}</a>
          ${s.displayName ? html`<div class="muted"><code>${s.alias}</code></div>` : nothing}
        </td>
        <td><code>${s.url}</code></td>
        <td>
          <a href=${realmsHref}>${this.realmsSummary(s)}</a>
        </td>
        <td>
          <span class="badge">${s.source ?? '—'}</span>
          ${s.writable === false ? html` <span class="badge">read-only</span>` : nothing}
        </td>
        <td
          ><a href=${href}
            >${s.writable === false || !this.canWrite ? 'View' : 'Open'}</a
          ></td
        >
      </tr>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-systems-page': SystemsPage;
  }
}
