import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { BffError, rotateSigningKey, type System } from '../../bff.js';
import '../../kc-mcp-help.js';
import { sessionCanWrite, sessionContext, type SessionState } from '../../session-context.js';

/** A grace period in seconds as people read it: 1 hour, 90 minutes, 45 seconds. */
function duration(seconds: number): string {
  const unit = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;
  if (seconds >= 3600 && seconds % 3600 === 0) {
    return unit(seconds / 3600, 'hour');
  }
  if (seconds >= 60 && seconds % 60 === 0) {
    return unit(seconds / 60, 'minute');
  }
  return unit(seconds, 'second');
}

/** Signing key details and rotate for private_key_jwt systems. */
@customElement('kc-mcp-system-keys')
export class SystemKeys extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    .lead {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
    }
    .meta {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.2rem 1rem;
      margin: 0 0 1rem;
      font-size: 0.9rem;
    }
    .meta dt {
      color: var(--muted, #6a6e73);
    }
    .meta dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    code {
      font-size: 0.85em;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--accent, #0066cc);
      background: var(--accent, #0066cc);
      color: #fff;
      cursor: pointer;
    }
    button.secondary {
      background: transparent;
      color: var(--fg, inherit);
      border-color: var(--border, #6a6e73);
    }
    button.danger {
      background: transparent;
      color: var(--error, #c9190b);
      border-color: var(--error, #c9190b);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .error {
      color: var(--error, #c9190b);
      margin: 0 0 0.75rem;
    }
    .ok {
      color: var(--muted, #6a6e73);
      margin: 0 0 0.75rem;
    }
    h3 {
      font-size: 0.95rem;
      margin: 0 0 0.75rem;
    }
    .warn {
      border-left: 3px solid var(--warning, #f0ab00);
      padding: 0.35rem 0.75rem;
      margin: 0.5rem 0;
      font-size: 0.9rem;
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
    .confirm {
      margin-top: 0.75rem;
      padding: 0.85rem 1rem;
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
    }
  `;

  @property({ attribute: false })
  system: System | null = null;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private busy = false;

  @state()
  private error: string | null = null;

  @state()
  private ok: string | null = null;

  @state()
  private confirmRotate = false;

  /** The previous key leaked: it leaves the JWKS with the rotation, without a grace period. */
  @state()
  private dropPrevious = false;

  private get canWrite(): boolean {
    return sessionCanWrite(this.session);
  }

  private async rotate(): Promise<void> {
    if (!this.system) {
      return;
    }
    this.busy = true;
    this.error = null;
    this.ok = null;
    try {
      const updated = await rotateSigningKey(this.system.alias, this.dropPrevious);
      this.confirmRotate = false;
      this.ok = this.dropPrevious
        ? 'Signing key rotated; the previous key is out of the JWKS. Clear the keys cache in Keycloak too.'
        : 'Signing key rotated.';
      this.dropPrevious = false;
      this.dispatchEvent(
        new CustomEvent('system-saved', { detail: updated, bubbles: true, composed: true }),
      );
    } catch (e) {
      this.report(e);
    } finally {
      this.busy = false;
    }
  }

  private report(e: unknown): void {
    if (e instanceof BffError) {
      this.error = `${e.status} ${e.code}: ${e.message}`;
      if (e.sessionLost) {
        this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
      }
    } else {
      this.error = e instanceof Error ? e.message : String(e);
    }
  }

  render() {
    const s = this.system;
    if (!s) {
      return html`<p class="muted">No system loaded.</p>`;
    }
    if (s.clientAuth !== 'private_key_jwt') {
      return html`
        <p class="lead">
          This system uses <code>${s.clientAuth}</code>. Signing keys apply only to
          <code>private_key_jwt</code>.
        </p>
      `;
    }
    const key = s.signingKey;
    const writable = this.canWrite && s.writable !== false;
    return html`
      <h3>
        Signing key
        <kc-mcp-help label="About signing keys">
          The JWKS the Keycloak client trusts for this system's assertions. Rotate creates a new key; the JWKS keeps
          the previous one for the retired key grace period
          (<code>kc-mcp.spi.key-vault.db.retired-key-grace-seconds</code>), so that instances still signing with it
          are accepted. After that its private key is deleted. A leaked key can be dropped at once when rotating.
        </kc-mcp-help>
      </h3>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.ok ? html`<p class="ok">${this.ok}</p>` : nothing}
      ${key
        ? html`<dl class="meta">
            ${key.kid
              ? html`<dt>kid</dt>
                  <dd><code>${key.kid}</code></dd>`
              : nothing}
            ${key.algorithm
              ? html`<dt>Algorithm</dt>
                  <dd><code>${key.algorithm}</code></dd>`
              : nothing}
            ${key.createdAt
              ? html`<dt>Created</dt>
                  <dd title=${key.createdAt}>${new Date(key.createdAt).toLocaleString()}</dd>`
              : nothing}
            ${key.vault
              ? html`<dt>Vault</dt>
                  <dd><code>${key.vault}</code></dd>`
              : nothing}
            ${key.retiredKeyGraceSeconds !== undefined
              ? html`<dt>Retired key grace period</dt>
                  <dd>
                    ${key.retiredKeyGraceSeconds > 0
                      ? html`${key.retiredKeyGraceSeconds} seconds
                          <span class="muted">(${duration(key.retiredKeyGraceSeconds)})</span>`
                      : html`off <span class="muted">(a rotated key leaves the JWKS at once)</span>`}
                  </dd>`
              : nothing}
            ${key.configured
              ? html`<dt>Source</dt>
                  <dd>configured key</dd>`
              : nothing}
            ${key.jwksUrl
              ? html`<dt>
                    JWKS URL
                    <kc-mcp-help label="About the JWKS URL">
                      What the Keycloak client's <em>Keys</em> tab takes as <em>JWKS URL</em>, with
                      <em>Use JWKS URL</em> on.
                    </kc-mcp-help>
                  </dt>
                  <dd><code>${key.jwksUrl}</code></dd>`
              : nothing}
          </dl>`
        : html`<p class="muted">No signing key details on this system yet.</p>`}
      ${writable
        ? this.confirmRotate
          ? html`<div class="confirm">
              <p class="lead" style="margin:0 0 0.5rem">
                Rotate the signing key for <code>${s.alias}</code>? Clients must refresh JWKS.
              </p>
              <label>
                <input
                  type="checkbox"
                  .checked=${this.dropPrevious}
                  ?disabled=${this.busy}
                  @change=${(e: Event) => {
                    this.dropPrevious = (e.target as HTMLInputElement).checked;
                  }}
                />
                The previous key leaked: drop it now, without a grace period
              </label>
              ${this.dropPrevious
                ? html`<p class="warn">
                    The previous key leaves the JWKS at once and its private key is deleted. Keycloak keeps the JWKS
                    it fetched: clear its keys cache as well (realm settings → Action → Clear keys cache, or
                    <code>POST /admin/realms/{realm}/clear-keys-cache</code>) for the realm the client lives in.
                    Other instances of this server sign with the new key from their next token request.
                  </p>`
                : nothing}
              <div class="row">
                <button class="danger" type="button" ?disabled=${this.busy} @click=${() => this.rotate()}>
                  ${this.dropPrevious ? 'Rotate and drop the previous key' : 'Rotate key'}
                </button>
                <button
                  class="secondary"
                  type="button"
                  ?disabled=${this.busy}
                  @click=${() => {
                    this.confirmRotate = false;
                    this.dropPrevious = false;
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>`
          : html`<button
              type="button"
              ?disabled=${this.busy}
              @click=${() => {
                this.confirmRotate = true;
                this.ok = null;
              }}
            >
              Rotate…
            </button>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-keys': SystemKeys;
  }
}
