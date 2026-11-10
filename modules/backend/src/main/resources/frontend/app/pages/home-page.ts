import { LitElement, css, html, nothing } from 'lit';
import { customElement, property } from 'lit/decorators.js';
import type { Me } from '../bff.js';

/** Session summary on the home route. */
@customElement('kc-mcp-home-page')
export class HomePage extends LitElement {
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
      margin: 0 0 0.5rem;
      color: var(--muted, #656d76);
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.25rem 1rem;
      margin: 0.5rem 0 0;
    }
    dt {
      color: var(--muted, #656d76);
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .error {
      color: var(--error, #cf222e);
    }
    .muted {
      color: var(--muted, #656d76);
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--border, #8b949e);
      background: transparent;
      color: var(--fg, inherit);
      cursor: pointer;
      margin-left: 0.5rem;
    }
  `;

  @property({ attribute: false })
  session: Me | null = null;

  @property({ attribute: false })
  lastCheck: { at: Date; ok: boolean } | null = null;

  render() {
    const s = this.session;
    if (!s?.authenticated) {
      return html`
        <h2>Home</h2>
        <p>Sign in to manage Keycloak systems through the server-side session (BFF).</p>
      `;
    }
    return html`
      <h2>Signed in</h2>
      <dl>
        <dt>User</dt>
        <dd>${s.username} ${s.email ? html`<span class="muted">(${s.email})</span>` : nothing}</dd>
        <dt>Identity provider</dt>
        <dd>${s.idp} <span class="muted">${s.issuer}</span></dd>
        <dt>Roles</dt>
        <dd>${s.roles?.join(', ') || html`<span class="muted">none</span>`}</dd>
        <dt>Management role</dt>
        <dd>${s.adminRole} ${s.admin ? '✓' : html`<span class="error">missing</span>`}</dd>
        <dt>Session expires</dt>
        <dd>${s.sessionExpiresAt ? new Date(s.sessionExpiresAt).toLocaleString() : '–'}</dd>
        <dt>Last session check</dt>
        <dd>
          ${this.lastCheck
            ? html`${this.lastCheck.at.toLocaleTimeString()}
              ${this.lastCheck.ok ? '✓' : html`<span class="error">session ended</span>`}`
            : html`<span class="muted">when this tab becomes visible again</span>`}
          <button type="button" @click=${() => this.dispatchEvent(new CustomEvent('check-session', { bubbles: true }))}>
            Check now
          </button>
        </dd>
      </dl>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-home-page': HomePage;
  }
}
