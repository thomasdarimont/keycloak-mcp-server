import { Router } from '@lit-labs/router';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { checkSession, login, me, type Me, type SessionCheck } from './bff.js';
import { DEFAULT_PATH, ensureDefaultPath, UI_BASE } from './router.js';
import './kc-mcp-nav.js';
import './kc-mcp-toolbar.js';
import './pages/home-page.js';
import './pages/placeholder-page.js';
import './pages/system-settings.js';
import './pages/systems-page.js';

/**
 * Shell: masthead, vertical nav (when signed in), content. Systems is the default section.
 * Routing uses `@lit-labs/router` on pathnames under `/ui/` (served by UiRoutes).
 */
@customElement('kc-mcp-app')
export class KcMcpApp extends LitElement {
  static styles = css`
    :host {
      --fg: #1f2328;
      --muted: #656d76;
      --bg: #f6f8fa;
      --card: #ffffff;
      --border: #d0d7de;
      --error: #cf222e;
      --pre-bg: #f6f8fa;
      --accent: #1f6feb;
      --nav-width: 13.5rem;
      display: flex;
      flex-direction: column;
      font: 15px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      color: var(--fg);
      background: var(--bg);
      min-height: 100vh;
    }
    @media (prefers-color-scheme: dark) {
      :host {
        --fg: #e6edf3;
        --muted: #8b949e;
        --bg: #0d1117;
        --card: #161b22;
        --border: #30363d;
        --error: #ff7b72;
        --pre-bg: #0d1117;
        --accent: #2f81f7;
      }
    }
    .body {
      display: flex;
      flex: 1;
      min-height: 0;
    }
    .body kc-mcp-nav {
      flex: 0 0 var(--nav-width);
      align-self: stretch;
    }
    main {
      flex: 1;
      min-width: 0;
      padding: 1.5rem;
      display: grid;
      gap: 1rem;
      align-content: start;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      color: var(--fg);
      max-width: 56rem;
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.5rem;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--accent);
      background: var(--accent);
      color: #fff;
      cursor: pointer;
    }
    button.secondary {
      background: transparent;
      color: var(--fg);
      border-color: var(--border);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .error {
      color: var(--error);
    }
    .muted {
      color: var(--muted);
    }
    @media (max-width: 640px) {
      .body {
        flex-direction: column;
      }
      .body kc-mcp-nav {
        flex: none;
      }
    }
  `;

  private readonly router = new Router(this, [
    {
      name: 'system-new',
      path: `${UI_BASE}/systems/new`,
      render: () => html`<kc-mcp-system-settings create></kc-mcp-system-settings>`,
    },
    {
      name: 'system',
      path: `${UI_BASE}/systems/:alias`,
      render: ({ alias }) =>
        html`<kc-mcp-system-settings .alias=${alias ?? ''}></kc-mcp-system-settings>`,
    },
    {
      name: 'systems',
      path: `${UI_BASE}/systems`,
      render: () => html`<kc-mcp-systems-page></kc-mcp-systems-page>`,
    },
    {
      name: 'secrets',
      path: `${UI_BASE}/secrets`,
      render: () =>
        html`<kc-mcp-placeholder-page
          heading="Secrets"
          description="Placeholder for vault secret metadata via the BFF."
        ></kc-mcp-placeholder-page>`,
    },
    {
      name: 'storage',
      path: `${UI_BASE}/storage`,
      render: () =>
        html`<kc-mcp-placeholder-page
          heading="Storage"
          description="Placeholder for encryption status and rekey via the BFF."
        ></kc-mcp-placeholder-page>`,
    },
    {
      name: 'home',
      path: `${UI_BASE}/home`,
      render: () =>
        html`<kc-mcp-home-page
          .session=${this.session}
          .lastCheck=${this.lastCheck}
        ></kc-mcp-home-page>`,
    },
  ], {
    fallback: {
      enter: async () => {
        history.replaceState({}, '', DEFAULT_PATH + location.search);
        await this.router.goto(DEFAULT_PATH);
        return false;
      },
    },
  });

  @state() private session: Me | null = null;
  @state() private sessionError: string | null = null;
  @state() private lastCheck: { at: Date; ok: boolean } | null = null;
  private suggestedIdp: string | undefined;
  private checking = false;
  private readonly onVisible = () => {
    if (document.visibilityState === 'visible' && this.session?.authenticated && !this.checking) {
      void this.checkSession();
    }
  };

  connectedCallback(): void {
    ensureDefaultPath();
    const url = new URL(window.location.href);
    this.suggestedIdp = url.searchParams.get('idp') ?? undefined;
    if (url.searchParams.has('state')) {
      url.searchParams.delete('state');
      window.history.replaceState(null, '', url.pathname + url.search + url.hash);
    }
    super.connectedCallback();
    void this.refresh();
    this.trackActivity();
  }

  disconnectedCallback(): void {
    document.removeEventListener('visibilitychange', this.onVisible);
    window.removeEventListener('focus', this.onVisible);
    super.disconnectedCallback();
  }

  private trackActivity(): void {
    document.addEventListener('visibilitychange', this.onVisible);
    window.addEventListener('focus', this.onVisible);
  }

  private async checkSession(): Promise<void> {
    this.checking = true;
    try {
      const check: SessionCheck | false = await checkSession();
      this.lastCheck = { at: new Date(), ok: check !== false };
      await this.refresh();
    } catch (e) {
      this.sessionError = e instanceof Error ? e.message : String(e);
    } finally {
      this.checking = false;
    }
  }

  private async refresh(): Promise<void> {
    try {
      this.session = await me(this.suggestedIdp);
      if (this.session.authenticated && this.session.idp) {
        this.suggestedIdp = this.session.idp;
      }
      this.sessionError = null;
    } catch (e) {
      this.session = null;
      this.sessionError = e instanceof Error ? e.message : String(e);
    }
  }

  render() {
    const s = this.session;
    const signedIn = !!s?.authenticated;
    return html`
      <kc-mcp-toolbar .session=${this.session}></kc-mcp-toolbar>
      <div class="body">
        ${signedIn ? html`<kc-mcp-nav .path=${location.pathname}></kc-mcp-nav>` : nothing}
        <main>
          ${this.sessionError
            ? html`<section class="card">
                <h2>Session</h2>
                <p class="error">${this.sessionError}</p>
                <button class="secondary" type="button" @click=${() => this.refresh()}>Retry</button>
              </section>`
            : !s
              ? html`<section class="card"><p class="muted">Loading…</p></section>`
              : !s.authenticated
                ? this.renderSignIn(s)
                : html`<section
                    class="card"
                    @check-session=${() => this.checkSession()}
                    @session-lost=${() => this.refresh()}
                  >
                    ${this.router.outlet()}
                  </section>`}
        </main>
      </div>
    `;
  }

  private renderSignIn(s: Me) {
    const suggested = s.suggestedIdp ?? this.suggestedIdp;
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
    'kc-mcp-app': KcMcpApp;
  }
}
