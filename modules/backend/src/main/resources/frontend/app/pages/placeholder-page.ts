import { LitElement, css, html } from 'lit';
import { customElement, property } from 'lit/decorators.js';

/** Placeholder until Secrets / Storage talk to the BFF. */
@customElement('kc-mcp-placeholder-page')
export class PlaceholderPage extends LitElement {
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
      margin: 0;
      color: var(--muted, #656d76);
    }
  `;

  @property()
  heading = 'Page';

  @property()
  description = 'Placeholder — not wired to the BFF yet.';

  render() {
    return html`
      <h2>${this.heading}</h2>
      <p>${this.description}</p>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-placeholder-page': PlaceholderPage;
  }
}
