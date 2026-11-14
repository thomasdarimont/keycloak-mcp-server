import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  BffError,
  deleteSystemRealm,
  getSystem,
  getSystemRealm,
  saveSystemRealm,
  type System,
  type SystemRealm,
  type SystemRealmSave,
} from '../../bff.js';
import { navigate, systemHref } from '../../router.js';
import { sessionCanWrite, sessionContext, type SessionState } from '../../session-context.js';

type FormState = {
  displayName: string;
  description: string;
  realmId: string;
  preset: string;
};

/** Edit labels and preset for one realm's stored settings. */
@customElement('kc-mcp-system-realm-page')
export class SystemRealmPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    a.back {
      color: var(--accent, #0066cc);
      text-decoration: none;
      font-size: 0.9rem;
    }
    a.back:hover {
      text-decoration: underline;
    }
    h2 {
      font-size: 1.1rem;
      margin: 0.35rem 0 0.25rem;
    }
    .lead {
      margin: 0 0 1rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
    }
    fieldset {
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      margin: 0 0 1rem;
      padding: 0.85rem 1rem 1rem;
      min-width: 0;
    }
    legend {
      padding: 0 0.35rem;
      font-weight: 600;
      font-size: 0.9rem;
    }
    .grid {
      display: grid;
      gap: 0.75rem 1rem;
      grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    }
    label {
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
      font-size: 0.85rem;
      color: var(--muted, #6a6e73);
    }
    .span-2 {
      grid-column: 1 / -1;
    }
    input,
    select,
    textarea {
      font: inherit;
      color: var(--fg, inherit);
      background: var(--bg, #f0f0f0);
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      padding: 0.4rem 0.55rem;
    }
    textarea {
      min-height: 3.5rem;
      resize: vertical;
    }
    input:disabled,
    select:disabled,
    textarea:disabled {
      opacity: 0.7;
      cursor: default;
    }
    .hint {
      font-size: 0.8rem;
      color: var(--muted, #6a6e73);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-top: 0.25rem;
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
    .muted {
      color: var(--muted, #6a6e73);
    }
    code {
      font-size: 0.85em;
    }
    .confirm {
      margin-top: 1rem;
      padding: 0.85rem 1rem;
      border: 1px solid var(--error, #c9190b);
      border-radius: var(--radius, 6px);
    }
  `;

  @property()
  alias = '';

  @property()
  realm = '';

  /** When true, omit the standalone page chrome (used inside the system Realms tab). */
  @property({ type: Boolean })
  embedded = false;

  @state()
  private system: System | null = null;

  @state()
  private stored: SystemRealm | null = null;

  @state()
  private form: FormState | null = null;

  @state()
  private busy = false;

  @state()
  private error: string | null = null;

  @state()
  private savedAt: Date | null = null;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private confirmDelete = false;

  @state()
  private deleteTyped = '';

  private get canWrite(): boolean {
    return sessionCanWrite(this.session);
  }

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  protected updated(changed: Map<string, unknown>): void {
    if (
      (changed.has('alias') && changed.get('alias') !== undefined) ||
      (changed.has('realm') && changed.get('realm') !== undefined)
    ) {
      void this.load();
    }
  }

  private toForm(r: SystemRealm): FormState {
    return {
      displayName: r.displayName ?? '',
      description: r.description ?? '',
      realmId: r.realmId ?? '',
      preset: r.preset ?? '',
    };
  }

  private async load(): Promise<void> {
    if (!this.alias || !this.realm) {
      this.system = null;
      this.stored = null;
      this.form = null;
      return;
    }
    this.busy = true;
    this.error = null;
    this.savedAt = null;
    this.confirmDelete = false;
    this.deleteTyped = '';
    try {
      this.system = await getSystem(this.alias);
      this.stored = await getSystemRealm(this.alias, this.realm);
      this.form = this.toForm(this.stored);
    } catch (e) {
      this.system = null;
      this.stored = null;
      this.form = null;
      this.report(e);
    } finally {
      this.busy = false;
    }
  }

  private onInput(field: keyof FormState, event: Event): void {
    if (!this.form) {
      return;
    }
    const target = event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
    this.form = { ...this.form, [field]: target.value };
    this.savedAt = null;
  }

  private async save(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.form || !this.system) {
      return;
    }
    const writable = this.canWrite && !!this.system.writable;
    if (!writable) {
      return;
    }
    this.busy = true;
    this.error = null;
    const body: SystemRealmSave = {
      displayName: this.form.displayName.trim() || undefined,
      description: this.form.description.trim() || undefined,
      realmId: this.form.realmId.trim() || undefined,
      preset: this.form.preset.trim() || undefined,
    };
    if (!body.displayName && !body.description && !body.realmId && !body.preset) {
      this.error = 'Keep at least one of display name, description, realm id or preset.';
      this.busy = false;
      return;
    }
    try {
      this.stored = await saveSystemRealm(this.alias, this.realm, body);
      this.form = this.toForm(this.stored);
      this.savedAt = new Date();
    } catch (e) {
      this.report(e);
    } finally {
      this.busy = false;
    }
  }

  private async deleteThisRealm(): Promise<void> {
    if (!this.system || this.deleteTyped !== this.realm) {
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      await deleteSystemRealm(this.alias, this.realm);
      this.form = null;
      this.stored = null;
      navigate(systemHref(this.alias, 'realms'), true);
    } catch (e) {
      this.report(e);
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

  private presetOptions(system: System): string[] {
    return Object.keys(system.presets ?? {}).sort((a, b) => a.localeCompare(b));
  }

  render() {
    if (!this.alias || !this.realm) {
      return html`<p class="error">No realm selected.</p>`;
    }
    if (this.busy && !this.form) {
      return html`<p class="muted">Loading…</p>`;
    }
    if (!this.form || !this.system || !this.stored) {
      return html`
        <a class="back" href=${systemHref(this.alias, 'realms')}>← Realms</a>
        ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      `;
    }
    const writable = this.canWrite && !!this.system.writable;
    const presets = this.presetOptions(this.system);
    const title = this.stored.displayName || this.realm;
    return html`
      <a class="back" href=${systemHref(this.alias, 'realms')}>← Realms</a>
      <h2>${title}</h2>
      <p class="lead">
        Realm <code>${this.realm}</code>
        ${this.embedded ? nothing : html` on system <code>${this.alias}</code>`}
        ${this.stored.entry ? html` · MCP <code>${this.stored.entry}</code>` : nothing}
        ${writable ? nothing : html` · read-only`}
      </p>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.savedAt ? html`<p class="ok">Saved at ${this.savedAt.toLocaleTimeString()}.</p>` : nothing}

      <form @submit=${(e: Event) => this.save(e)}>
        <fieldset>
          <legend>Labels</legend>
          <div class="grid">
            <label
              >Display name
              <input
                .value=${this.form.displayName}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('displayName', e)}
              />
            </label>
            <label
              >Realm id
              <input
                .value=${this.form.realmId}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('realmId', e)}
                placeholder="Keycloak internal id"
              />
              <span class="hint">Stays when the realm is renamed in Keycloak.</span>
            </label>
            <label class="span-2"
              >Description
              <textarea
                .value=${this.form.description}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('description', e)}
              ></textarea>
            </label>
            <label
              >Preset
              <select
                .value=${this.form.preset}
                ?disabled=${!writable || this.busy}
                @change=${(e: Event) => this.onInput('preset', e)}
              >
                <option value="">(none)</option>
                ${presets.map((p) => html`<option value=${p}>${p}</option>`)}
                ${this.form.preset && !presets.includes(this.form.preset)
                  ? html`<option value=${this.form.preset}>${this.form.preset}</option>`
                  : nothing}
              </select>
              <span class="hint">System presets first; Access and Tools editing comes in a later stage.</span>
            </label>
          </div>
        </fieldset>
        <div class="row">
          ${writable
            ? html`<button type="submit" ?disabled=${this.busy}>Save</button>`
            : nothing}
          <button class="secondary" type="button" ?disabled=${this.busy} @click=${() => this.load()}>
            Reset
          </button>
        </div>
      </form>

      ${writable
        ? html`<div class="confirm">
            <p class="lead" style="margin:0 0 0.5rem">
              Delete realm settings — the system's settings apply again. The realm stays reachable; to end
              the access, unadopt it on the <a href=${systemHref(this.alias, 'adopt')}>Adopt</a> tab. Type
              <code>${this.realm}</code> to confirm.
            </p>
            ${this.confirmDelete
              ? html`<div class="row">
                  <input
                    .value=${this.deleteTyped}
                    ?disabled=${this.busy}
                    @input=${(e: Event) => {
                      this.deleteTyped = (e.target as HTMLInputElement).value;
                    }}
                    placeholder=${this.realm}
                    aria-label="Type realm name to confirm delete"
                  />
                  <button
                    class="danger"
                    type="button"
                    ?disabled=${this.busy || this.deleteTyped !== this.realm}
                    @click=${() => this.deleteThisRealm()}
                  >
                    Delete settings
                  </button>
                  <button
                    class="secondary"
                    type="button"
                    ?disabled=${this.busy}
                    @click=${() => {
                      this.confirmDelete = false;
                      this.deleteTyped = '';
                    }}
                  >
                    Cancel
                  </button>
                </div>`
              : html`<button
                  class="danger"
                  type="button"
                  ?disabled=${this.busy}
                  @click=${() => {
                    this.confirmDelete = true;
                  }}
                >
                  Delete settings…
                </button>`}
          </div>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-realm-page': SystemRealmPage;
  }
}
