import { LitElement, css, html, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { BffError, listSystems, type System } from "../bff.js";
import { newSystemHref, systemHref } from "../router.js";

/** Systems list via GET /bff/api/systems; open a row to edit settings. */
@customElement("kc-mcp-systems-page")
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
      color: var(--muted, #656d76);
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
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--accent, #1f6feb);
      background: var(--accent, #1f6feb);
      color: #fff;
      cursor: pointer;
      text-decoration: none;
      font-weight: 500;
      display: inline-block;
    }
    button.secondary {
      background: transparent;
      color: var(--fg, inherit);
      border-color: var(--border, #8b949e);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .error {
      color: var(--error, #cf222e);
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
      border-bottom: 1px solid var(--border, #d0d7de);
      vertical-align: top;
    }
    th {
      color: var(--muted, #656d76);
      font-weight: 600;
    }
    a {
      color: var(--accent, #1f6feb);
      text-decoration: none;
      font-weight: 600;
    }
    a:hover {
      text-decoration: underline;
    }
    .muted {
      color: var(--muted, #656d76);
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
  private items: System[] = [];

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const data = await listSystems();
      this.items = data.systems ?? [];
    } catch (e) {
      this.items = [];
      if (e instanceof BffError) {
        this.error = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          this.dispatchEvent(
            new CustomEvent("session-lost", { bubbles: true, composed: true }),
          );
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
      <h2>Systems</h2>
      <p>
        Keycloak connections known to this server. Add a system or open one to
        edit its settings.
      </p>
      <div class="row">
        <a class="btn" href=${newSystemHref()}>Add system</a>
        <button
          class="secondary"
          type="button"
          ?disabled=${this.busy}
          @click=${() => this.load()}
        >
          Refresh
        </button>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${
        !this.error && !this.busy && this.items.length === 0
          ? html`<p class="muted">No systems registered.</p>`
          : nothing
      }
      ${
        this.items.length
          ? html`<table>
              <thead>
                <tr>
                  <th>Alias</th>
                  <th>URL</th>
                  <th>Auth</th>
                  <th>Source</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${this.items.map((s) => this.renderRow(s))}
              </tbody>
            </table>`
          : nothing
      }
    `;
  }

  private renderRow(s: System) {
    const href = systemHref(s.alias);
    return html`
      <tr>
        <td>
          <a href=${href}>${s.displayName || s.alias}</a>
          ${s.displayName ? html`<div class="muted"><code>${s.alias}</code></div>` : nothing}
        </td>
        <td><code>${s.url}</code></td>
        <td>${s.clientAuth}</td>
        <td>
          ${s.source ?? "—"}
          ${s.writable === false ? html` <span class="badge">read-only</span>` : nothing}
        </td>
        <td><a href=${href}>${s.writable === false ? "View" : "Edit"}</a></td>
      </tr>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "kc-mcp-systems-page": SystemsPage;
  }
}
