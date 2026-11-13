import { Router } from '@lit-labs/router';
import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement } from 'lit/decorators.js';
import { login, type Me } from './bff.js';
import { auditHref, DEFAULT_PATH, ensureDefaultPath, UI_BASE, type SystemTab } from './router.js';
import { sessionContext, type SessionState } from './session-context.js';
import './pages/audit/page.js';
import './pages/overview.js';
import './pages/placeholder.js';
import './pages/systems/detail.js';
import './pages/systems/page.js';
import './pages/systems/settings.js';

type GotoDetail = { path: string };

function notifyNavigate(): void {
  window.dispatchEvent(new Event('kc-mcp-navigate'));
}

/**
 * Route outlet and auth gate: sign-in, session errors, or the matched page.
 * Owns `@lit-labs/router`; shell chrome lives in {@code index.html}.
 */
@customElement('kc-mcp-outlet')
export class KcMcpOutlet extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    .card {
      background: var(--kc-mcp-c-card--BackgroundColor, var(--card, #fff));
      border: 1px solid var(--kc-mcp-c-card--BorderColor, var(--border, #d2d2d2));
      border-radius: var(--kc-mcp-c-card--BorderRadius, var(--radius, 6px));
      box-shadow: var(--kc-mcp-c-card--BoxShadow, var(--shadow, none));
      padding: var(--kc-mcp-c-card--Padding, 1.5rem);
      color: var(--fg, inherit);
      max-width: var(--kc-mcp-c-card--MaxWidth, 56rem);
    }
    /* tables with many columns (the audit trail) use the screen; forms stay narrow */
    .card.wide {
      max-width: var(--kc-mcp-c-card--m-wide--MaxWidth, 120rem);
    }
    h2 {
      font-family: var(--kc-mcp-c-title--FontFamily, var(--font-heading, 'Red Hat Display', sans-serif));
      font-size: var(--kc-mcp-c-title--FontSize, 1.5rem);
      font-weight: var(--kc-mcp-c-title--FontWeight, 400);
      margin: 0 0 1rem;
    }
    button {
      font: inherit;
      padding: 0.4rem 1rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--kc-mcp-c-button--m-primary--BorderColor, var(--accent, #0066cc));
      background: var(--kc-mcp-c-button--m-primary--BackgroundColor, var(--accent, #0066cc));
      color: var(--kc-mcp-c-button--m-primary--Color, #fff);
      cursor: pointer;
    }
    button:hover {
      background: var(--kc-mcp-c-button--m-primary--hover--BackgroundColor, #004d99);
      border-color: var(--kc-mcp-c-button--m-primary--hover--BackgroundColor, #004d99);
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
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
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

  private readonly router = new Router(
    this,
    [
      {
        name: 'system-new',
        path: `${UI_BASE}/systems/new`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () => html`<kc-mcp-system-settings .create=${true}></kc-mcp-system-settings>`,
      },
      {
        name: 'system-realm',
        path: `${UI_BASE}/systems/:alias/realms/:realm`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: ({ alias, realm }) =>
          html`<kc-mcp-system-page
            .alias=${alias ?? ''}
            tab="realms"
            .realm=${realm ?? ''}
          ></kc-mcp-system-page>`,
      },
      {
        name: 'system-tab',
        path: `${UI_BASE}/systems/:alias/:tab`,
        enter: async ({ alias, tab }) => {
          notifyNavigate();
          if (tab !== 'realms' && tab !== 'settings' && tab !== 'adopt' && tab !== 'keys') {
            const path = `${UI_BASE}/systems/${alias ?? ''}`;
            history.replaceState({}, '', path);
            await this.router.goto(path);
            return false;
          }
          return true;
        },
        render: ({ alias, tab }) =>
          html`<kc-mcp-system-page
            .alias=${alias ?? ''}
            .tab=${this.systemTab(tab)}
            .realm=${''}
          ></kc-mcp-system-page>`,
      },
      {
        name: 'system',
        path: `${UI_BASE}/systems/:alias`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: ({ alias }) =>
          html`<kc-mcp-system-page
            .alias=${alias ?? ''}
            tab="settings"
            .realm=${''}
          ></kc-mcp-system-page>`,
      },
      {
        name: 'systems',
        path: `${UI_BASE}/systems`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () => html`<kc-mcp-systems-page></kc-mcp-systems-page>`,
      },
      {
        name: 'secrets',
        path: `${UI_BASE}/secrets`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () =>
          html`<kc-mcp-placeholder-page
            heading="Secrets"
            description="Names, vault provenance, and usedBy will appear here. Secrets are managed in the vault (or OpenBao / HashiCorp Vault) — this UI will not edit values."
          ></kc-mcp-placeholder-page>`,
      },
      {
        name: 'storage',
        path: `${UI_BASE}/storage`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () =>
          html`<kc-mcp-placeholder-page
            heading="Storage"
            description="Encryption status, key ids, and the system-source (repository) chain will appear here. Adding a repository remains a providers/ + config change, not a UI write."
          ></kc-mcp-placeholder-page>`,
      },
      {
        name: 'audit',
        path: `${UI_BASE}/audit`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () => html`<kc-mcp-audit-page></kc-mcp-audit-page>`,
      },
      {
        name: 'overview',
        path: `${UI_BASE}/overview`,
        enter: async () => {
          notifyNavigate();
          return true;
        },
        render: () => html`<kc-mcp-overview-page></kc-mcp-overview-page>`,
      },
    ],
    {
      fallback: {
        enter: async () => {
          history.replaceState({}, '', DEFAULT_PATH + location.search);
          await this.router.goto(DEFAULT_PATH);
          notifyNavigate();
          return false;
        },
      },
    },
  );

  private readonly onGoto = (event: Event) => {
    const path = (event as CustomEvent<GotoDetail>).detail?.path;
    if (path) {
      void this.router.goto(path);
      notifyNavigate();
    }
  };

  private systemTab(tab: string | undefined): SystemTab {
    if (tab === 'realms' || tab === 'adopt' || tab === 'keys') {
      return tab;
    }
    return 'settings';
  }

  connectedCallback(): void {
    ensureDefaultPath();
    super.connectedCallback();
    window.addEventListener('kc-mcp-goto', this.onGoto);
  }

  disconnectedCallback(): void {
    window.removeEventListener('kc-mcp-goto', this.onGoto);
    super.disconnectedCallback();
  }

  private retry(): void {
    this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
  }

  render() {
    const s = this.session?.me;
    if (this.session?.error) {
      return html`<section class="card">
        <h2>Session</h2>
        <p class="error">${this.session.error}</p>
        <button class="secondary" type="button" @click=${() => this.retry()}>Retry</button>
      </section>`;
    }
    if (!s) {
      return nothing;
    }
    if (!s.authenticated) {
      return this.renderSignIn(s);
    }
    const wide = location.pathname.startsWith(auditHref());
    return html`<section class="card ${wide ? 'wide' : ''}">${this.router.outlet()}</section>`;
  }

  private renderSignIn(s: Me) {
    const suggested = s.suggestedIdp ?? this.session?.suggestedIdp;
    const last = s.idps.find((idp) => idp.alias === suggested);
    const others = s.idps.filter((idp) => idp !== last);
    return html`<section class="card">
      <h2>Not signed in</h2>
      <p class="muted">The server signs you in at the identity provider and keeps the session on its side.</p>
      <div class="row">
        ${last
          ? html`<button type="button" @click=${() => login(last)}>${last.displayName}</button>
              ${others.length ? html`<span class="muted">or</span>` : nothing}`
          : nothing}
        ${others.map(
          (idp) =>
            html`<button class=${last ? 'secondary' : ''} type="button" @click=${() => login(idp)}>
              ${idp.displayName}
            </button>`,
        )}
      </div>
    </section>`;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-outlet': KcMcpOutlet;
  }
}
