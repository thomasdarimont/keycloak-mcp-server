import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  BffError,
  adoptRealms,
  getClientSetup,
  getKeycloakRealms,
  unadoptRealm,
  type AdoptionResult,
  type ClientSetup,
  type ClientSetupOptions,
  type KeycloakRealms,
  type System,
} from '../../bff.js';
import { realmHref, systemHref } from '../../router.js';
import { sessionCanWrite, sessionContext, type SessionState } from '../../session-context.js';

type Roles = NonNullable<ClientSetupOptions['roles']>;
type Credential = NonNullable<ClientSetupOptions['credential']>;

/**
 * Adopting the realms of a Keycloak: (1) the client this server needs there, as JSON and a kcadm.sh script,
 * (2) the realms its service account sees, (3) registering a choice of them.
 */
@customElement('kc-mcp-system-adopt')
export class SystemAdopt extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    section {
      margin: 0 0 1.5rem;
    }
    h3 {
      font-size: 1rem;
      margin: 0 0 0.35rem;
    }
    .lead {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
      font-size: 0.9rem;
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
    .error {
      color: var(--error, #c9190b);
      margin: 0.5rem 0;
      overflow-wrap: anywhere;
    }
    .ok {
      margin: 0.5rem 0;
    }
    .warn {
      border-left: 3px solid var(--warning, #f0ab00);
      padding: 0.35rem 0.75rem;
      margin: 0.5rem 0;
      font-size: 0.9rem;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1rem;
      align-items: center;
      margin: 0.5rem 0;
    }
    label {
      font-size: 0.9rem;
    }
    input[type='text'],
    input:not([type]),
    select {
      font: inherit;
      color: var(--fg, inherit);
      background: var(--bg, #f0f0f0);
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      padding: 0.3rem 0.5rem;
    }
    button {
      font: inherit;
      padding: 0.35rem 1rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--kc-mcp-c-button--m-primary--BorderColor, var(--accent, #0066cc));
      background: var(--kc-mcp-c-button--m-primary--BackgroundColor, var(--accent, #0066cc));
      color: var(--kc-mcp-c-button--m-primary--Color, #fff);
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
    }
    button.secondary {
      background: var(--kc-mcp-c-button--m-secondary--BackgroundColor, transparent);
      color: var(--kc-mcp-c-button--m-secondary--Color, var(--fg, inherit));
      border-color: var(--kc-mcp-c-button--m-secondary--BorderColor, var(--border, #707070));
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .copy {
      padding: 0.15rem 0.45rem;
      font-size: 0.75rem;
    }
    pre {
      margin: 0.35rem 0 0.75rem;
      padding: 0.6rem 0.75rem;
      background: var(--code-bg, color-mix(in srgb, var(--fg, #151515) 5%, transparent));
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      overflow: auto;
      max-height: 22rem;
      font-size: 0.8rem;
    }
    ul.notes {
      margin: 0.25rem 0 0.75rem;
      padding-left: 1.2rem;
      font-size: 0.85rem;
    }
    .table-wrap {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th,
    td {
      text-align: left;
      padding: 0.45rem 0.6rem;
      border-bottom: 1px solid var(--border, #d2d2d2);
      vertical-align: top;
    }
    th {
      color: var(--muted, #6a6e73);
      font-weight: 600;
    }
    code {
      font-size: 0.85em;
      overflow-wrap: anywhere;
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: var(--radius, 6px);
      border: 1px solid var(--border, #d2d2d2);
      color: var(--muted, #6a6e73);
      margin: 0 0.35rem 0 0;
    }
    button.danger {
      background: transparent;
      color: var(--error, #c9190b);
      border-color: var(--error, #c9190b);
    }
    button.small {
      padding: 0.1rem 0.6rem;
      font-size: 0.8rem;
    }
    .confirm {
      display: flex;
      gap: 0.4rem;
      align-items: center;
      flex-wrap: wrap;
    }
    a {
      color: var(--accent, #0066cc);
      text-decoration: none;
      font-weight: 600;
    }
    a:hover {
      text-decoration: underline;
    }
  `;

  @property({ attribute: false })
  system: System | null = null;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state() private roles: Roles = 'admin';
  @state() private roleRealms = '';
  @state() private credential: Credential = 'jwks-url';
  @state() private setup: ClientSetup | null = null;
  @state() private setupError: string | null = null;

  @state() private listing: KeycloakRealms | null = null;
  @state() private listError: string | null = null;
  @state() private filter = '';
  @state() private selected = new Set<string>();

  @state() private allRealms = false;
  @state() private restrict = false;
  @state() private preset = '';
  @state() private result: AdoptionResult | null = null;
  @state() private adoptError: string | null = null;

  /** The realm whose Unadopt waits for its confirmation. */
  @state() private unadopting: string | null = null;
  @state() private unadoptMessage: string | null = null;
  @state() private unadoptError: string | null = null;

  @state() private busy = false;

  private get writable(): boolean {
    return sessionCanWrite(this.session) && !!this.system?.writable;
  }

  private get master(): boolean {
    return (this.system?.authRealm ?? 'master') === 'master';
  }

  protected updated(changed: Map<string, unknown>): void {
    const previous = changed.get('system') as System | null | undefined;
    if (changed.has('system') && previous && this.system && previous.alias !== this.system.alias) {
      this.setup = null;
      this.listing = null;
      this.selected = new Set();
      this.result = null;
      this.unadopting = null;
      this.unadoptMessage = null;
      this.unadoptError = null;
    }
  }

  private message(e: unknown): string {
    if (e instanceof BffError) {
      if (e.sessionLost) {
        this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
      }
      return `${e.code}: ${e.message}`;
    }
    return e instanceof Error ? e.message : String(e);
  }

  private async loadSetup(): Promise<void> {
    if (!this.system) {
      return;
    }
    this.busy = true;
    this.setupError = null;
    try {
      const realms = this.roleRealms
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r);
      this.setup = await getClientSetup(this.system.alias, {
        roles: this.roles,
        realms: this.roles === 'admin' ? [] : realms,
        credential: this.system.clientAuth === 'private_key_jwt' ? this.credential : undefined,
      });
    } catch (e) {
      this.setup = null;
      this.setupError = this.message(e);
    } finally {
      this.busy = false;
    }
  }

  private async loadRealms(): Promise<void> {
    if (!this.system) {
      return;
    }
    this.busy = true;
    this.listError = null;
    try {
      this.listing = await getKeycloakRealms(this.system.alias);
      const listed = new Set(this.listing.realms.map((r) => r.name));
      this.selected = new Set([...this.selected].filter((r) => listed.has(r)));
    } catch (e) {
      this.listing = null;
      this.listError = this.message(e);
    } finally {
      this.busy = false;
    }
  }

  private async adopt(): Promise<void> {
    if (!this.system || !this.listing) {
      return;
    }
    this.busy = true;
    this.adoptError = null;
    this.result = null;
    try {
      this.result = await adoptRealms(this.system.alias, {
        realms: this.allRealms ? [] : [...this.selected].sort(),
        allRealms: this.allRealms,
        restrict: !this.listing.restricted && !this.allRealms ? this.restrict : undefined,
        preset: this.preset.trim() || undefined,
      });
      this.selected = new Set();
      this.restrict = false;
      // the system's allowlist and realms changed: the page reloads it
      this.dispatchEvent(new CustomEvent('system-saved', { bubbles: true, composed: true }));
      this.busy = false;
      await this.loadRealms();
    } catch (e) {
      this.adoptError = this.message(e);
    } finally {
      this.busy = false;
    }
  }

  private async unadopt(realm: string): Promise<void> {
    if (!this.system || !this.listing) {
      return;
    }
    this.busy = true;
    this.unadoptError = null;
    this.unadoptMessage = null;
    try {
      const r = await unadoptRealm(this.system.alias, realm, !this.listing.restricted);
      this.unadopting = null;
      this.unadoptMessage =
        `Gave up ${realm}${r.settingsRemoved ? ' and removed its settings' : ''}. ` +
        `Allowlist: ${r.allowedRealms.join(', ')}.`;
      this.dispatchEvent(new CustomEvent('system-saved', { bubbles: true, composed: true }));
      this.busy = false;
      await this.loadRealms();
    } catch (e) {
      this.unadoptError = this.message(e);
    } finally {
      this.busy = false;
    }
  }

  /** Unadopt for a realm this system adopted or allows, with its confirmation in place. */
  private renderUnadopt(realm: string, othersListed: number) {
    const l = this.listing;
    if (!this.writable || !l) {
      return nothing;
    }
    if (this.unadopting !== realm) {
      return html`<button
        class="secondary small"
        type="button"
        ?disabled=${this.busy}
        @click=${() => {
          this.unadopting = realm;
          this.unadoptError = null;
          this.unadoptMessage = null;
        }}
      >
        Unadopt
      </button>`;
    }
    const what = l.restricted
      ? 'It leaves the allowlist and loses its settings.'
      : `The system reaches every realm now: its allowlist becomes the ${othersListed} other realm(s) Keycloak ` +
        'lists, and realms created later are not reachable.';
    return html`<div class="confirm">
      <span class="muted">${what}</span>
      <button class="danger small" type="button" ?disabled=${this.busy} @click=${() => this.unadopt(realm)}>
        Unadopt ${realm}
      </button>
      <button class="secondary small" type="button" @click=${() => (this.unadopting = null)}>Cancel</button>
    </div>`;
  }

  private async copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // ignore clipboard failures
    }
  }

  private toggle(name: string, on: boolean): void {
    const next = new Set(this.selected);
    if (on) {
      next.add(name);
    } else {
      next.delete(name);
    }
    this.selected = next;
  }

  private visibleRealms() {
    const f = this.filter.trim().toLowerCase();
    const all = this.listing?.realms ?? [];
    return f
      ? all.filter((r) => r.name.toLowerCase().includes(f) || (r.displayName ?? '').toLowerCase().includes(f))
      : all;
  }

  private renderSetup(s: System) {
    const jwt = s.clientAuth === 'private_key_jwt';
    return html`
      <section>
        <h3>1. Client in Keycloak</h3>
        <p class="lead">
          This server creates nothing in Keycloak. Create the client <code>${s.clientId ?? 'keycloak-mcp-server'}</code>
          in the realm <code>${s.authRealm}</code> of <code>${s.url}</code> from the JSON below, or run the
          <code>kcadm.sh</code> script, which also gives its service account the roles.
        </p>
        <div class="row">
          <label
            >Roles
            <select
              .value=${this.roles}
              @change=${(e: Event) => {
                this.roles = (e.target as HTMLSelectElement).value as Roles;
              }}
            >
              <option value="admin">${this.master ? 'admin (every realm, later ones too)' : 'realm-admin'}</option>
              <option value="read">read (view and query roles)</option>
              <option value="manage">manage (view, query and manage roles)</option>
            </select>
          </label>
          ${this.roles !== 'admin' && this.master
            ? html`<label
                >Realms
                <input
                  .value=${this.roleRealms}
                  placeholder="acme, beta"
                  @input=${(e: Event) => {
                    this.roleRealms = (e.target as HTMLInputElement).value;
                  }}
              /></label>`
            : nothing}
          ${jwt
            ? html`<label
                >Key
                <select
                  .value=${this.credential}
                  @change=${(e: Event) => {
                    this.credential = (e.target as HTMLSelectElement).value as Credential;
                  }}
                >
                  <option value="jwks-url">JWKS URL (Keycloak fetches it)</option>
                  <option value="public-key">public key copied into the client</option>
                </select>
              </label>`
            : nothing}
          <button class="secondary" type="button" ?disabled=${this.busy} @click=${() => this.loadSetup()}>
            Show setup
          </button>
          ${this.setup || this.setupError
            ? html`<button
                class="secondary"
                type="button"
                @click=${() => {
                  this.setup = null;
                  this.setupError = null;
                }}
              >
                Hide setup
              </button>`
            : nothing}
        </div>
        ${this.setupError ? html`<p class="error">${this.setupError}</p>` : nothing}
        ${this.setup
          ? html`
              <ul class="notes">
                ${this.setup.notes.map((n) => html`<li>${n}</li>`)}
              </ul>
              <div class="row">
                <strong>Client JSON</strong>
                <button
                  class="secondary copy"
                  type="button"
                  @click=${() => this.copy(JSON.stringify(this.setup?.client, null, 2))}
                >
                  Copy
                </button>
              </div>
              <pre>${JSON.stringify(this.setup.client, null, 2)}</pre>
              <div class="row">
                <strong>kcadm.sh script</strong>
                <button class="secondary copy" type="button" @click=${() => this.copy(this.setup?.script ?? '')}>
                  Copy
                </button>
              </div>
              <pre>${this.setup.script}</pre>
            `
          : nothing}
      </section>
    `;
  }

  private renderRealms(s: System) {
    const l = this.listing;
    const visible = this.visibleRealms();
    const allVisibleSelected = visible.length > 0 && visible.every((r) => this.selected.has(r.name));
    return html`
      <section>
        <h3>2. Realms in Keycloak</h3>
        <p class="lead">The realms the service account of <code>${s.alias}</code> can see.</p>
        <div class="row">
          <button type="button" ?disabled=${this.busy} @click=${() => this.loadRealms()}>
            ${l ? 'Reload' : 'Load realms'}
          </button>
          ${l
            ? html`<input
                  .value=${this.filter}
                  placeholder="filter"
                  aria-label="Filter realms"
                  @input=${(e: Event) => {
                    this.filter = (e.target as HTMLInputElement).value;
                  }}
                /><span class="muted">${l.count} realm(s), ${this.selected.size} selected</span>`
            : nothing}
        </div>
        ${this.listError
          ? html`<p class="error">${this.listError}</p>
              <p class="lead">
                ${this.listError.startsWith('keycloak_unreachable')
                  ? 'Check the system’s URL: this server, not Keycloak, must reach it.'
                  : 'Check the client and its roles (step 1).'}
              </p>`
          : nothing}
        ${l
          ? html`<div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        aria-label="Select all shown"
                        .checked=${allVisibleSelected}
                        ?disabled=${this.allRealms}
                        @change=${(e: Event) => {
                          const on = (e.target as HTMLInputElement).checked;
                          const next = new Set(this.selected);
                          visible.forEach((r) => (on ? next.add(r.name) : next.delete(r.name)));
                          this.selected = next;
                        }}
                      />
                    </th>
                    <th>Realm</th>
                    <th>Here</th>
                    <th>Keycloak id</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${visible.length === 0
                    ? html`<tr>
                        <td colspan="5" class="muted">No realm.</td>
                      </tr>`
                    : visible.map(
                        (r) => html`<tr>
                          <td>
                            <input
                              type="checkbox"
                              aria-label=${`Select ${r.name}`}
                              .checked=${this.allRealms || this.selected.has(r.name)}
                              ?disabled=${this.allRealms}
                              @change=${(e: Event) => this.toggle(r.name, (e.target as HTMLInputElement).checked)}
                            />
                          </td>
                          <td>
                            ${r.adopted
                              ? html`<a href=${realmHref(s.alias, r.name)}>${r.displayName || r.name}</a>`
                              : html`${r.displayName || r.name}`}
                            ${r.displayName && r.displayName !== r.name
                              ? html`<div class="muted"><code>${r.name}</code></div>`
                              : nothing}
                          </td>
                          <td>
                            ${r.adopted ? html`<span class="badge">adopted</span>` : nothing}
                            ${r.allowed
                              ? l.restricted
                                ? html`<span class="badge">on allowlist</span>`
                                : r.adopted
                                  ? nothing
                                  : html`<span class="badge" title="No allowlist: the system reaches every realm"
                                      >reachable, no settings</span
                                    >`
                              : html`<span class="badge">not reachable</span>`}
                            ${r.enabled === false ? html`<span class="badge">disabled</span>` : nothing}
                            ${r.renamedFrom
                              ? html`<span class="badge">renamed from ${r.renamedFrom}</span>`
                              : nothing}
                          </td>
                          <td><code class="muted">${r.id}</code></td>
                          <td>
                            ${r.adopted || (l.restricted && r.allowed)
                              ? this.renderUnadopt(r.name, l.realms.length - 1)
                              : nothing}
                          </td>
                        </tr>`,
                      )}
                </tbody>
              </table>
            </div>
            ${l.notListed.length
              ? html`<p class="lead">
                    Known here, not listed by Keycloak (deleted, renamed or out of the account's sight):
                  </p>
                  <ul>
                    ${l.notListed.map(
                      (n) => html`<li><code>${n.name}</code> ${this.renderUnadopt(n.name, l.realms.length)}</li>`,
                    )}
                  </ul>`
              : nothing}
            ${this.unadoptError ? html`<p class="error">${this.unadoptError}</p>` : nothing}
            ${this.unadoptMessage ? html`<p class="ok">${this.unadoptMessage}</p>` : nothing}`
          : nothing}
      </section>
    `;
  }

  private renderAdopt(s: System) {
    const l = this.listing;
    if (!l) {
      return nothing;
    }
    const presets = Object.keys(s.presets ?? {});
    const count = this.allRealms ? l.count : this.selected.size;
    // without an allowlist adopting only stores settings; restricting is opt-in
    const canRestrict = !l.restricted && !this.allRealms && this.selected.size > 0;
    const losing = canRestrict
      ? l.realms.filter((r) => !r.adopted && !this.selected.has(r.name)).map((r) => r.name)
      : [];
    const can = this.writable && count > 0 && !this.busy;
    return html`
      <section>
        <h3>3. Adopt</h3>
        <p class="lead">
          Keycloak's realm id and display name become realm settings here. A system with an allowlist gets the
          realms added to it; one without keeps reaching every realm. Settings already kept stay; they gain the
          realm id. Who may use a realm is up to its access settings and
          presets (<a href=${systemHref(s.alias, 'realms')}>Realms</a>).
        </p>
        <div class="row">
          <label>
            <input
              type="checkbox"
              .checked=${this.allRealms}
              @change=${(e: Event) => {
                this.allRealms = (e.target as HTMLInputElement).checked;
              }}
            />
            Every realm, including ones created later (clears the allowlist)
          </label>
        </div>
        <div class="row">
          <label
            >Preset for new realms
            <input
              list="adopt-presets"
              .value=${this.preset}
              placeholder="none"
              @input=${(e: Event) => {
                this.preset = (e.target as HTMLInputElement).value;
              }}
            />
          </label>
          <datalist id="adopt-presets">${presets.map((p) => html`<option value=${p}></option>`)}</datalist>
        </div>
        ${canRestrict
          ? html`<div class="row">
                <label>
                  <input
                    type="checkbox"
                    .checked=${this.restrict}
                    @change=${(e: Event) => {
                      this.restrict = (e.target as HTMLInputElement).checked;
                    }}
                  />
                  Also restrict <code>${s.alias}</code> to the selected and the already adopted realms
                </label>
              </div>
              ${this.restrict && losing.length
                ? html`<div class="warn">
                    These realms become unreachable: ${losing.map((n) => html`<code>${n}</code> `)}
                  </div>`
                : nothing}`
          : nothing}
        <div class="row">
          <button type="button" ?disabled=${!can} @click=${() => this.adopt()}>
            Adopt ${count} realm(s)
          </button>
          ${!this.writable ? html`<span class="muted">Read-only: needs the operator role and a mutable system.</span>` : nothing}
        </div>
        ${this.adoptError ? html`<p class="error">${this.adoptError}</p>` : nothing}
        ${this.result
          ? html`<p class="ok">
              Adopted ${this.result.adopted.length}, updated ${this.result.updated.length}, unchanged
              ${this.result.unchanged.length}.
              ${this.result.restricted
                ? html`Allowlist: ${this.result.allowedRealms.map((r) => html`<code>${r}</code> `)}`
                : html`Every realm is reachable.`}
              ${this.result.unreachable?.length
                ? html`No longer reachable: ${this.result.unreachable.map((r) => html`<code>${r}</code> `)}`
                : nothing}
            </p>`
          : nothing}
      </section>
    `;
  }

  render() {
    const s = this.system;
    if (!s) {
      return html`<p class="muted">No system loaded.</p>`;
    }
    return html`${this.renderSetup(s)} ${this.renderRealms(s)} ${this.renderAdopt(s)}`;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-adopt': SystemAdopt;
  }
}
