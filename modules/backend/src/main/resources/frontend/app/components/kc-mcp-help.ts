import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';

/**
 * A help icon next to a page title: the explanation of the page is its content and shows in a small panel on click,
 * instead of a paragraph that is always there.
 *
 *   <h2>Audit <kc-mcp-help label="About the audit trail">Every tool call ...</kc-mcp-help></h2>
 *
 * The panel closes on Escape, on a click outside and on a second click on the icon.
 */
@customElement('kc-mcp-help')
export class KcMcpHelp extends LitElement {
  static styles = css`
    :host {
      display: inline-block;
      position: relative;
      vertical-align: middle;
      font-size: 0.875rem;
      font-weight: 400;
    }
    button {
      width: 1.3rem;
      height: 1.3rem;
      padding: 0;
      border-radius: 50%;
      border: 1px solid var(--border, #6a6e73);
      background: transparent;
      color: var(--muted, #6a6e73);
      font: inherit;
      font-size: 0.8rem;
      font-weight: 600;
      line-height: 1;
      cursor: pointer;
    }
    button:hover,
    button[aria-expanded='true'] {
      border-color: var(--accent, #0066cc);
      color: var(--accent, #0066cc);
    }
    button:focus-visible {
      outline: 2px solid var(--accent, #0066cc);
      outline-offset: 1px;
    }
    .panel {
      position: absolute;
      z-index: 10;
      top: calc(100% + 0.4rem);
      left: 0;
      width: min(34rem, 80vw);
      padding: 0.75rem 0.9rem;
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      background: var(--card, #fff);
      color: var(--fg, inherit);
      box-shadow: 0 6px 20px rgb(0 0 0 / 15%);
      line-height: 1.45;
    }
  `;

  /** What the icon is for, read to screen readers and shown as its tooltip. */
  @property()
  label = 'About this page';

  @state()
  private expanded = false;

  private readonly onDocumentClick = (e: Event) => {
    if (!e.composedPath().includes(this)) {
      this.expanded = false;
    }
  };

  private readonly onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      this.expanded = false;
    }
  };

  disconnectedCallback(): void {
    this.listen(false);
    super.disconnectedCallback();
  }

  protected updated(): void {
    this.listen(this.expanded);
  }

  /** The page is watched for a click outside and Escape only while the panel is shown. */
  private listen(on: boolean): void {
    document.removeEventListener('click', this.onDocumentClick);
    document.removeEventListener('keydown', this.onKey);
    if (on) {
      document.addEventListener('click', this.onDocumentClick);
      document.addEventListener('keydown', this.onKey);
    }
  }

  render() {
    return html`
      <button
        type="button"
        aria-label=${this.label}
        title=${this.label}
        aria-expanded=${this.expanded ? 'true' : 'false'}
        @click=${() => (this.expanded = !this.expanded)}
      >
        ?
      </button>
      ${this.expanded ? html`<div class="panel" role="note"><slot></slot></div>` : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-help': KcMcpHelp;
  }
}
