import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  BffError,
  deleteSystem,
  getSystem,
  listSystems,
  saveSystem,
  type System,
  type SystemSave,
} from '../../bff.js';
import { navigate, systemHref, systemsHref } from '../../router.js';
import { sessionCanWrite, sessionContext, type SessionState } from '../../session-context.js';

type FormState = {
  alias: string;
  displayName: string;
  description: string;
  url: string;
  issuer: string;
  authRealm: string;
  clientAuth: string;
  clientId: string;
  clientSecret: string;
  defaultRealm: string;
  allowedRealms: string;
  trustedIssuers: string;
  version: string;
};

const ALIAS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function emptyForm(): FormState {
  return {
    alias: '',
    displayName: '',
    description: '',
    url: '',
    issuer: '',
    authRealm: 'master',
    clientAuth: 'private_key_jwt',
    clientId: 'keycloak-mcp-server',
    clientSecret: '',
    defaultRealm: '',
    allowedRealms: '',
    trustedIssuers: '',
    version: '',
  };
}

function toForm(s: System): FormState {
  return {
    alias: s.alias,
    displayName: s.displayName ?? '',
    description: s.description ?? '',
    url: s.url,
    issuer: s.issuer ?? '',
    authRealm: s.authRealm,
    clientAuth: s.clientAuth,
    clientId: s.clientId ?? '',
    clientSecret: s.clientSecret?.startsWith('vault:') ? s.clientSecret : '',
    defaultRealm: s.defaultRealm ?? '',
    allowedRealms: (s.allowedRealms ?? []).join(', '),
    trustedIssuers: (s.trustedIssuers ?? []).join(', '),
    version: s.version ?? '',
  };
}

function parseList(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((r) => r.trim())
    .filter(Boolean);
}

/** Create / edit form for one Keycloak system's connection settings. */
@customElement('kc-mcp-system-settings')
export class SystemSettings extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1.1rem;
      margin: 0 0 0.25rem;
    }
    .lead {
      margin: 0 0 1rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
    }
    .lead code {
      font-size: 0.85em;
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
    a.back {
      color: var(--accent, #0066cc);
      text-decoration: none;
      font-size: 0.9rem;
    }
    a.back:hover {
      text-decoration: underline;
    }
    button.danger {
      background: transparent;
      color: var(--error, #c9190b);
      border-color: var(--error, #c9190b);
    }
    .confirm {
      margin-top: 1.25rem;
      padding: 0.85rem 1rem;
      border: 1px solid var(--error, #c9190b);
      border-radius: var(--radius, 6px);
    }
  `;

  /** When true, register a new system instead of editing an existing one. */
  @property({ type: Boolean })
  create = false;

  /** When true, omit the page chrome (used inside the system detail tabs). */
  @property({ type: Boolean })
  embedded = false;

  @property()
  alias = '';

  @state()
  private system: System | null = null;

  @state()
  private form: FormState | null = null;

  @state()
  private busy = false;

  @state()
  private error: string | null = null;

  @state()
  private savedAt: Date | null = null;

  @state()
  private createBlockedHint: string | null = null;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private confirmDelete = false;

  @state()
  private deleteTyped = '';

  private secretConfigured = false;

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
      (changed.has('create') && changed.get('create') !== undefined)
    ) {
      void this.load();
    }
  }

  private async load(): Promise<void> {
    this.error = null;
    this.savedAt = null;
    this.createBlockedHint = null;
    this.confirmDelete = false;
    this.deleteTyped = '';
    this.busy = true;
    try {
      if (this.create) {
        this.system = null;
        this.secretConfigured = false;
        if (!this.canWrite) {
          this.createBlockedHint =
            'Sign in with the operator role (kc-mcp.admin.role) to register systems. Viewers may only read.';
          this.form = null;
          return;
        }
        const list = await listSystems();
        if (!list.canCreate) {
          this.createBlockedHint =
            list.canCreateHint ??
            'No mutable repository: set quarkus.datasource.jdbc.url and kc-mcp.dynamic-systems=true.';
          this.form = null;
        } else {
          this.form = emptyForm();
        }
        return;
      }
      if (!this.alias) {
        this.form = null;
        this.system = null;
        return;
      }
      const system = await getSystem(this.alias);
      this.system = system;
      this.secretConfigured = !!system.clientSecret;
      this.form = toForm(system);
    } catch (e) {
      this.system = null;
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
    if (!this.form) {
      return;
    }
    const writable = this.canWrite && (this.create || !!this.system?.writable);
    if (!writable) {
      return;
    }
    const alias = (this.create ? this.form.alias : this.alias).trim();
    if (!ALIAS_PATTERN.test(alias)) {
      this.error =
        "Alias must start with a letter or digit and use only letters, digits, '.', '_' or '-' (max 128).";
      return;
    }
    if (this.create && this.form.clientAuth === 'client_secret' && !this.form.clientSecret.trim()) {
      this.error = 'Client secret is required for client_secret authentication.';
      return;
    }
    this.busy = true;
    this.error = null;
    this.savedAt = null;
    const body: SystemSave = {
      url: this.form.url.trim(),
      displayName: this.form.displayName.trim() || undefined,
      description: this.form.description.trim() || undefined,
      issuer: this.form.issuer.trim() || undefined,
      authRealm: this.form.authRealm.trim() || 'master',
      grantType: 'client_credentials',
      clientAuth: this.form.clientAuth,
      clientId: this.form.clientId.trim() || undefined,
      defaultRealm: this.form.defaultRealm.trim() || undefined,
      allowedRealms: parseList(this.form.allowedRealms),
      trustedIssuers: parseList(this.form.trustedIssuers),
      version: this.form.version.trim() || undefined,
    };
    const secret = this.form.clientSecret.trim();
    if (secret) {
      body.clientSecret = secret;
    }
    if (this.create && this.form.clientAuth === 'private_key_jwt') {
      body.signingKey = 'generate';
    }
    try {
      const saved = await saveSystem(alias, body);
      if (this.create) {
        // Drop the create form before the router swaps in the system page; leave
        // busy so we don't flash the empty create chrome while goto runs.
        this.form = null;
        this.system = null;
        navigate(systemHref(saved.alias), true);
        return;
      }
      this.system = saved;
      this.secretConfigured = !!saved.clientSecret;
      this.form = toForm(saved);
      this.savedAt = new Date();
      this.dispatchEvent(
        new CustomEvent('system-saved', { detail: saved, bubbles: true, composed: true }),
      );
    } catch (e) {
      this.report(e);
    } finally {
      if (this.form !== null || !this.create) {
        this.busy = false;
      }
    }
  }

  private async deleteThisSystem(): Promise<void> {
    if (!this.system || this.deleteTyped !== this.system.alias) {
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      await deleteSystem(this.system.alias);
      this.form = null;
      this.system = null;
      navigate(systemsHref(), true);
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

  render() {
    if (!this.create && !this.alias) {
      return html`<p class="error">No system selected.</p>`;
    }
    if (!this.form && this.busy) {
      return html`<p class="lead">${this.create ? 'Opening system…' : 'Loading…'}</p>`;
    }
    if (this.create && this.createBlockedHint) {
      return html`
        <a class="back" href=${systemsHref()}>← Systems</a>
        <h2>New system</h2>
        <p class="error">${this.createBlockedHint}</p>
        <p class="lead">
          A system is a Keycloak cluster/environment. Registration needs a mutable repository (database storage +
          <code>kc-mcp.dynamic-systems=true</code>). With <code>bin/kcmcp.sh start-dev</code> that is assumed for H2
          builds.
        </p>
      `;
    }
    if (!this.form || (!this.create && !this.system)) {
      return html`
        <a class="back" href=${systemsHref()}>← Systems</a>
        ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      `;
    }
    const writable = this.canWrite && (this.create || !!this.system?.writable);
    const secretHint = this.create
      ? 'Plain secret or vault:name.'
      : this.secretConfigured
        ? 'Leave blank to keep the stored secret, or set a new value / vault:name.'
        : 'Plain secret or vault:name.';
    const title = this.create
      ? 'New system'
      : this.system!.displayName || this.system!.alias;
    return html`
      ${this.embedded
        ? nothing
        : html`<a class="back" href=${systemsHref()}>← Systems</a>
            <h2>${title}</h2>
            <p class="lead">
              ${this.create
                ? html`Register a Keycloak cluster (environment) in the mutable repository.`
                : html`Alias <code>${this.system!.alias}</code>
                    ${this.system!.source
                      ? html` · source <code>${this.system!.source}</code>`
                      : nothing}
                    ${writable
                      ? nothing
                      : html` · read-only (not stored in the mutable repository)`}`}
            </p>`}
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.savedAt
        ? html`<p class="ok">Saved at ${this.savedAt.toLocaleTimeString()}.</p>`
        : nothing}

      ${!this.create && this.system
        ? html`<dl class="meta">
            ${this.system.updatedAt
              ? html`<dt>Updated</dt>
                  <dd>${new Date(this.system.updatedAt).toLocaleString()}</dd>`
              : nothing}
            ${this.system.signingKey?.jwksUrl
              ? html`<dt>JWKS</dt>
                  <dd><code>${this.system.signingKey.jwksUrl}</code></dd>`
              : nothing}
          </dl>`
        : nothing}

      <form @submit=${(e: Event) => this.save(e)}>
        <fieldset>
          <legend>Identity</legend>
          <div class="grid">
            ${this.create
              ? html`<label
                  >Alias
                  <input
                    required
                    pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
                    .value=${this.form.alias}
                    ?disabled=${this.busy}
                    @input=${(e: Event) => this.onInput('alias', e)}
                    placeholder="e.g. acme"
                  />
                  <span class="hint">Technical name; cannot be changed later.</span>
                </label>`
              : nothing}
            <label
              >Display name
              <input
                .value=${this.form.displayName}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('displayName', e)}
              />
            </label>
            <label class="span-2"
              >Description
              <textarea
                .value=${this.form.description}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('description', e)}
              ></textarea>
            </label>
          </div>
        </fieldset>

        <fieldset>
          <legend>Connection</legend>
          <div class="grid">
            <label class="span-2"
              >URL
              <input
                required
                .value=${this.form.url}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('url', e)}
                placeholder="https://keycloak.example.com"
              />
            </label>
            <label
              >Issuer
              <input
                .value=${this.form.issuer}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('issuer', e)}
                placeholder="only when Keycloak's public URL differs: https://sso.example.com/realms/master"
              />
            </label>
            <label
              >Auth realm
              <input
                .value=${this.form.authRealm}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('authRealm', e)}
              />
            </label>
            <label
              >Version
              <input
                .value=${this.form.version}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('version', e)}
                placeholder="e.g. 26.0.0"
              />
            </label>
          </div>
        </fieldset>

        <fieldset>
          <legend>Authentication</legend>
          <div class="grid">
            <label
              >Client auth
              <select
                .value=${this.form.clientAuth}
                ?disabled=${!writable || this.busy}
                @change=${(e: Event) => this.onInput('clientAuth', e)}
              >
                <option value="private_key_jwt">private_key_jwt</option>
                <option value="client_secret">client_secret</option>
              </select>
            </label>
            <label
              >Client ID
              <input
                .value=${this.form.clientId}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('clientId', e)}
              />
            </label>
            ${this.form.clientAuth === 'client_secret'
              ? html`<label class="span-2"
                  >Client secret
                  <input
                    type="password"
                    autocomplete="off"
                    .value=${this.form.clientSecret}
                    ?disabled=${!writable || this.busy}
                    @input=${(e: Event) => this.onInput('clientSecret', e)}
                    placeholder=${!this.create && this.secretConfigured ? 'unchanged' : ''}
                    ?required=${this.create}
                  />
                  <span class="hint">${secretHint}</span>
                </label>`
              : html`<p class="hint span-2">
                  ${this.create
                    ? 'A signing key will be generated in the vault on create.'
                    : "private_key_jwt uses the system's signing key in the vault (JWKS above)."}
                </p>`}
          </div>
        </fieldset>

        <fieldset>
          <legend>Realms</legend>
          <div class="grid">
            <label
              >Default realm
              <input
                .value=${this.form.defaultRealm}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('defaultRealm', e)}
              />
              <span class="hint">Used when a tool call omits <code>realm</code>.</span>
            </label>
            <label class="span-2"
              >Allowed realms
              <input
                .value=${this.form.allowedRealms}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('allowedRealms', e)}
                placeholder="comma-separated; empty = all"
              />
              <span class="hint"
                >Empty means every realm on this cluster is allowed. Per-realm labels and presets are edited on the
                Realms tab (not in this PUT).</span
              >
            </label>
            <label class="span-2"
              >Trusted issuers
              <input
                .value=${this.form.trustedIssuers}
                ?disabled=${!writable || this.busy}
                @input=${(e: Event) => this.onInput('trustedIssuers', e)}
                placeholder="optional issuer URLs or Keycloak base URLs"
              />
              <span class="hint"
                >Issuers besides this Keycloak whose caller tokens the server may hand to it (same as the admin API
                <code>trustedIssuers</code>).</span
              >
            </label>
          </div>
        </fieldset>

        <div class="row">
          ${writable
            ? html`<button type="submit" ?disabled=${this.busy}>
                ${this.create ? 'Create' : 'Save'}
              </button>`
            : nothing}
          ${this.create
            ? nothing
            : html`<button
                class="secondary"
                type="button"
                ?disabled=${this.busy}
                @click=${() => this.load()}
              >
                Reset
              </button>`}
          ${this.embedded ? nothing : html`<a class="back" href=${systemsHref()}>Cancel</a>`}
        </div>
      </form>

      ${!this.create && writable
        ? html`<div class="confirm">
            <p class="lead" style="margin:0 0 0.5rem">
              Delete this system from the mutable repository. Signing keys stay in the vault. Type
              <code>${this.system!.alias}</code> to confirm.
            </p>
            ${this.confirmDelete
              ? html`<div class="row">
                  <input
                    .value=${this.deleteTyped}
                    ?disabled=${this.busy}
                    @input=${(e: Event) => {
                      this.deleteTyped = (e.target as HTMLInputElement).value;
                    }}
                    placeholder=${this.system!.alias}
                    aria-label="Type system alias to confirm delete"
                  />
                  <button
                    class="danger"
                    type="button"
                    ?disabled=${this.busy || this.deleteTyped !== this.system!.alias}
                    @click=${() => this.deleteThisSystem()}
                  >
                    Delete system
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
                  Delete system…
                </button>`}
          </div>`
        : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-settings': SystemSettings;
  }
}
