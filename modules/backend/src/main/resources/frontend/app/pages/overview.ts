import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, listSystems } from '../bff.js';
import '../kc-mcp-help.js';
import { systemsHref } from '../router.js';
import { sessionContext, type SessionState } from '../session-context.js';

/** Server-at-a-glance landing: whoami, system count, Systems → Realms framing. */
@customElement('kc-mcp-overview-page')
export class OverviewPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1.1rem;
      margin: 0 0 0.35rem;
    }
    .lead {
      margin: 0 0 1rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
      max-width: 40rem;
    }
    .lead a {
      color: var(--accent, #0066cc);
      font-weight: 600;
      text-decoration: none;
    }
    .lead a:hover {
      text-decoration: underline;
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.25rem 1rem;
      margin: 0.5rem 0 0;
    }
    dt {
      color: var(--muted, #6a6e73);
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .error {
      color: var(--error, #c9190b);
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--border, #6a6e73);
      background: transparent;
      color: var(--fg, inherit);
      cursor: pointer;
      margin-left: 0.5rem;
    }
    h3 {
      font-size: 0.95rem;
      margin: 1.25rem 0 0.35rem;
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private systemCount: number | null = null;

  @state()
  private systemsError: string | null = null;

  /** The BFF sent the browser back here because a sign-in could not be completed. */
  @state()
  private signInFailed = false;

  connectedCallback(): void {
    super.connectedCallback();
    const params = new URLSearchParams(location.search);
    if (params.get('signin') === 'failed') {
      this.signInFailed = true;
      // shown once: a reload or a bookmark does not repeat it
      params.delete('signin');
      const query = params.toString();
      history.replaceState(history.state, '', location.pathname + (query ? `?${query}` : '') + location.hash);
    }
    void this.loadSystems();
  }

  private async loadSystems(): Promise<void> {
    this.systemsError = null;
    try {
      const data = await listSystems();
      this.systemCount = data.systems?.length ?? 0;
    } catch (e) {
      this.systemCount = null;
      if (e instanceof BffError) {
        this.systemsError = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
        }
      } else {
        this.systemsError = e instanceof Error ? e.message : String(e);
      }
    }
  }

  render() {
    const s = this.session?.me;
    if (!s?.authenticated) {
      return html`
        <h2>Overview</h2>
        ${this.signInFailed
          ? html`<p class="error" role="alert">
              The sign-in could not be completed: the identity provider's answer was rejected, for example because a
              clock is out of sync after the computer woke up. Sign in again.
            </p>`
          : nothing}
        <p class="lead">Sign in to manage Keycloak systems through the server-side session (BFF).</p>
      `;
    }
    const lastCheck = this.session?.lastCheck ?? null;
    return html`
      <h2>
        Overview
        <kc-mcp-help label="About systems and realms">
          A <strong>system</strong> is one Keycloak cluster or environment (for example qa or prod), reached through a
          single front-door URL. Under each system you manage which <strong>realms</strong> the MCP server may use — all
          realms, or an explicit allowlist. Open <a href=${systemsHref()}>Systems</a> to browse them.
        </kc-mcp-help>
      </h2>

      <h3>You</h3>
      <dl>
        <dt>User</dt>
        <dd>${s.username} ${s.email ? html`<span class="muted">(${s.email})</span>` : nothing}</dd>
        <dt>Identity provider</dt>
        <dd>${s.idp} <span class="muted">${s.issuer}</span></dd>
        <dt>Roles</dt>
        <dd>${s.roles?.join(', ') || html`<span class="muted">none</span>`}</dd>
        <dt>Operator role</dt>
        <dd>${s.adminRole} ${s.admin ? '✓' : html`<span class="muted">no</span>`}</dd>
        ${s.viewerRole
          ? html`<dt>Viewer role</dt>
              <dd>${s.viewerRole} ${s.viewer ? '✓' : html`<span class="muted">no</span>`}</dd>`
          : nothing}
        <dt>Capabilities</dt>
        <dd>
          ${s.capabilities?.length
            ? s.capabilities.join(', ')
            : html`<span class="error">none — need operator or viewer role for the API</span>`}
        </dd>
        <dt>Session expires</dt>
        <dd>${s.sessionExpiresAt ? new Date(s.sessionExpiresAt).toLocaleString() : '–'}</dd>
        <dt>Last session check</dt>
        <dd>
          ${lastCheck
            ? html`${lastCheck.at.toLocaleTimeString()}
              ${lastCheck.ok ? '✓' : html`<span class="error">session ended</span>`}`
            : html`<span class="muted">when this tab becomes visible again</span>`}
          <button
            type="button"
            @click=${() => this.dispatchEvent(new CustomEvent('check-session', { bubbles: true }))}
          >
            Check now
          </button>
        </dd>
      </dl>

      <h3>Systems</h3>
      ${this.systemsError
        ? html`<p class="error">${this.systemsError}</p>`
        : html`<dl>
            <dt>Registered</dt>
            <dd>
              ${this.systemCount === null
                ? html`<span class="muted">…</span>`
                : html`${this.systemCount}
                  <a href=${systemsHref()}>view</a>`}
            </dd>
          </dl>`}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-overview-page': OverviewPage;
  }
}
