import { LitElement, css, html, nothing } from 'lit';
import { customElement, property } from 'lit/decorators.js';
import { DEFAULT_PATH, navPath, routes } from './router.js';

/**
 * Vertical page nav under the masthead (Keycloak Admin Console–style sidebar).
 */
@customElement('kc-mcp-nav')
export class KcMcpNav extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
      background: var(--card, #fff);
      border-right: 1px solid var(--border, #d0d7de);
      min-height: 100%;
      box-sizing: border-box;
    }
    @media (max-width: 640px) {
      :host {
        border-right: none;
        border-bottom: 1px solid var(--border, #d0d7de);
      }
      nav {
        flex-direction: row;
        flex-wrap: wrap;
        padding: 0.5rem 0.75rem;
      }
      a {
        border-left: none;
        border-bottom: 3px solid transparent;
        padding: 0.45rem 0.75rem;
      }
      a[aria-current='page'] {
        border-left-color: transparent;
        border-bottom-color: var(--accent, #1f6feb);
      }
    }
    nav {
      display: flex;
      flex-direction: column;
      padding: 0.75rem 0;
      gap: 0.15rem;
    }
    a {
      display: block;
      color: var(--fg, inherit);
      text-decoration: none;
      padding: 0.55rem 1.25rem;
      border-left: 3px solid transparent;
    }
    a:hover {
      background: color-mix(in srgb, var(--fg, #1f2328) 6%, transparent);
    }
    a[aria-current='page'] {
      font-weight: 600;
      border-left-color: var(--accent, #1f6feb);
      background: color-mix(in srgb, var(--accent, #1f6feb) 12%, transparent);
    }
  `;

  @property()
  path = DEFAULT_PATH;

  render() {
    return html`
      <nav aria-label="Management">
        ${routes.map(
          (route) => html`
            <a
              href=${route.path}
              aria-current=${navPath(this.path) === route.path ? 'page' : nothing}
              >${route.label}</a
            >
          `,
        )}
      </nav>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-nav': KcMcpNav;
  }
}
