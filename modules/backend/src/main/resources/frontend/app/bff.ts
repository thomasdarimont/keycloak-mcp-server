/**
 * The browser side of the BFF (/bff): same-origin fetches with the session cookie, never a token. Every call carries
 * X-Requested-With: JavaScript, which makes the server answer 499 instead of redirecting to the identity provider
 * when there is no session, and which the server demands on every request that changes something (CSRF).
 */
export const BFF = '/bff';

export interface Idp {
  alias: string;
  displayName: string;
  loginPath: string;
}

export interface Me {
  authenticated: boolean;
  logoutPath: string;
  /** The providers of the login page (hidden ones never) */
  idps: Idp[];
  /** The provider named by ?idp= (the return from a logout), if it is on the page; offered first. */
  suggestedIdp?: string;
  idp?: string;
  subject?: string;
  username?: string;
  name?: string;
  email?: string;
  realm?: string;
  issuer?: string;
  roles?: string[];
  adminRole?: string;
  /** True when the session holds kc-mcp.admin.role (operator). */
  admin?: boolean;
  /** True when the session holds kc-mcp.ui.viewer-role (read-only), if configured. */
  viewer?: boolean;
  viewerRole?: string;
  /** Where an audit event's trace is linked to: a URL with `{traceId}` (and `{spanId}`); unset: no link. */
  traceUrl?: string;
  /** BFF-enforced capabilities; the UI only hides. */
  capabilities?: string[];
  sessionExpiresAt?: string;
}

/** Capability strings from GET /bff/me. */
export const Cap = {
  systemsRead: 'systems:read',
  systemsWrite: 'systems:write',
  secretsRead: 'secrets:read',
  storageRead: 'storage:read',
  auditRead: 'audit:read',
} as const;

export function hasCapability(me: Me | null | undefined, capability: string): boolean {
  return !!me?.capabilities?.includes(capability);
}

/** One Keycloak system as returned by GET /bff/api/systems[/{alias}]. */
export interface System {
  alias: string;
  displayName?: string;
  description?: string;
  url: string;
  issuer?: string;
  authRealm: string;
  grantType: string;
  clientAuth: string;
  clientId?: string;
  /** Masked as "***", or a vault: reference. */
  clientSecret?: string;
  username?: string;
  password?: string;
  defaultRealm?: string;
  allowedRealms: string[];
  /** Issuers besides this Keycloak whose caller tokens may be used here. */
  trustedIssuers?: string[];
  version?: string;
  /** System-level preset name when set. */
  preset?: string;
  /** Named presets defined on this system (keys are preset names). */
  presets?: Record<string, unknown>;
  /** Per-realm settings keyed by realm name (embedded on the system GET). */
  realms?: Record<string, Omit<SystemRealm, 'name' | 'system' | 'entry'>>;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
  source?: string;
  /** True when the admin/BFF API can replace this system (mutable repository). */
  writable?: boolean;
  createdAt?: string;
  updatedAt?: string;
  signingKey?: {
    algorithm?: string;
    kid?: string;
    vault?: string;
    configured?: boolean;
    jwksPath?: string;
    jwksUrl?: string;
  };
  entries?: string[];
}

/** One realm's stored settings as returned by GET /bff/api/systems/{alias}/realms[/{realm}]. */
export interface SystemRealm {
  name: string;
  system: string;
  realmId?: string;
  displayName?: string;
  description?: string;
  preset?: string;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
  entry?: string;
}

export interface SystemRealmsList {
  realms: SystemRealm[];
}

/** Body for PUT /bff/api/systems/{alias}/realms/{realm}. */
export type SystemRealmSave = {
  realmId?: string;
  displayName?: string;
  description?: string;
  preset?: string;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
};

export interface SystemsList {
  systems: System[];
  /** False when there is no mutable repository or registration is closed. */
  canCreate?: boolean;
  mutableSource?: string;
  canCreateHint?: string;
}

/** Body for PUT /bff/api/systems/{alias} (omit secrets to keep stored values). */
export type SystemSave = {
  url: string;
  displayName?: string;
  description?: string;
  issuer?: string;
  authRealm?: string;
  grantType?: string;
  clientAuth?: string;
  clientId?: string;
  clientSecret?: string;
  defaultRealm?: string;
  allowedRealms?: string[];
  trustedIssuers?: string[];
  version?: string;
  signingKey?: string;
};

export class BffError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }

  /** 499: the session is gone (expired, signed out elsewhere); 401 is the server's own fallback. */
  get sessionLost(): boolean {
    return this.status === 499 || this.status === 401;
  }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('X-Requested-With', 'JavaScript');
  headers.set('Accept', 'application/json');
  const response = await fetch(`${BFF}${path}`, { ...init, headers, credentials: 'same-origin' });
  if (response.ok) {
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
  let code = `http_${response.status}`;
  let message = response.statusText || `HTTP ${response.status}`;
  try {
    const body = (await response.json()) as { error?: string; message?: string };
    code = body.error ?? code;
    message = body.message ?? message;
  } catch {
    // no JSON body (499 has none)
  }
  throw new BffError(response.status, code, message);
}

/**
 * Who is signed in. A cookie whose session is gone (expired, signed out at the provider) makes the first call answer
 * 499 and clears the cookie; the second call is anonymous and lists the identity providers.
 */
export async function me(idp?: string): Promise<Me> {
  // `idp` names the provider the page was opened for (a tenant's link, the return from a logout)
  const path = idp ? `/me?idp=${encodeURIComponent(idp)}` : '/me';
  try {
    return await call<Me>(path);
  } catch (e) {
    if (e instanceof BffError && e.sessionLost) {
      return call<Me>(path);
    }
    throw e;
  }
}

/** Outcome of an explicit session check (POST /bff/check-session). */
export interface SessionCheck {
  active: true;
  checkedAt: string;
  sessionExpiresAt?: string;
  cookieExpiresAt?: string;
  accessTokenExpiresAt?: string;
}

/**
 * Is the session still alive at the identity provider? The server redeems the refresh token there, which also counts
 * as activity (the SSO idle timeout moves) and renews the cookie. Resolves false when the session ended elsewhere
 * (logout in another app or the account console, an administrator, the idle timeout): the UI must reset then.
 */
export async function checkSession(): Promise<SessionCheck | false> {
  try {
    return await call<SessionCheck>('/check-session', { method: 'POST' });
  } catch (e) {
    if (e instanceof BffError && e.sessionLost) {
      return false;
    }
    throw e;
  }
}

/** All known systems (GET /bff/api/systems). */
export const listSystems = (): Promise<SystemsList> => call<SystemsList>('/api/systems');

/** @deprecated use listSystems */
export const systems = (): Promise<SystemsList> => listSystems();

/** One system (GET /bff/api/systems/{alias}). */
export const getSystem = (alias: string): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}`);

/** Replace a mutable system (PUT /bff/api/systems/{alias}). */
export const saveSystem = (alias: string, body: SystemSave): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

/** Remove a mutable system (DELETE /bff/api/systems/{alias}). Keys stay in the vault. */
export const deleteSystem = (alias: string): Promise<void> =>
  call<void>(`/api/systems/${encodeURIComponent(alias)}`, { method: 'DELETE' });

/** Rotate the system's signing key (POST /bff/api/systems/{alias}/signing-key). */
export const rotateSigningKey = (alias: string): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}/signing-key`, { method: 'POST' });

/** Realm settings kept for a system (GET /bff/api/systems/{alias}/realms). */
export const listSystemRealms = (alias: string): Promise<SystemRealmsList> =>
  call<SystemRealmsList>(`/api/systems/${encodeURIComponent(alias)}/realms`);

/** One realm's settings (GET /bff/api/systems/{alias}/realms/{realm}). */
export const getSystemRealm = (alias: string, realm: string): Promise<SystemRealm> =>
  call<SystemRealm>(
    `/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`,
  );

/** Add or replace realm settings (PUT /bff/api/systems/{alias}/realms/{realm}). */
export const saveSystemRealm = (
  alias: string,
  realm: string,
  body: SystemRealmSave,
): Promise<SystemRealm> =>
  call<SystemRealm>(
    `/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );

/** Remove realm settings so the system's settings apply again. */
export const deleteSystemRealm = (alias: string, realm: string): Promise<void> =>
  call<void>(`/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`, {
    method: 'DELETE',
  });

/** Options of GET /bff/api/systems/{alias}/client-setup. */
export interface ClientSetupOptions {
  /** `admin`: master's admin role; `read` / `manage`: realm-management roles of `realms` only. */
  roles?: 'admin' | 'read' | 'manage';
  realms?: string[];
  /** `jwks-url`: Keycloak fetches the keys from this server; `public-key`: the key copied into the client. */
  credential?: 'jwks-url' | 'public-key';
}

/** The Keycloak client this server needs, its roles and a kcadm.sh script doing both. */
export interface ClientSetup {
  system: string;
  url: string;
  realm: string;
  clientId: string;
  clientAuth: string;
  credential: string;
  /** JSON for POST /admin/realms/{realm}/clients. */
  client: Record<string, unknown>;
  roles: {
    mode: string;
    serviceAccount: string;
    realmRoles?: string[];
    clientRoles?: Record<string, string[]>;
  };
  script: string;
  notes: string[];
}

export const getClientSetup = (alias: string, options: ClientSetupOptions = {}): Promise<ClientSetup> => {
  const params = new URLSearchParams();
  if (options.roles) {
    params.set('roles', options.roles);
  }
  if (options.realms?.length) {
    params.set('realms', options.realms.join(','));
  }
  if (options.credential) {
    params.set('credential', options.credential);
  }
  const query = params.toString();
  return call<ClientSetup>(
    `/api/systems/${encodeURIComponent(alias)}/client-setup${query ? `?${query}` : ''}`,
  );
};

/** A realm as Keycloak lists it for the system's service account. */
export interface KeycloakRealm {
  name: string;
  id: string;
  displayName?: string;
  enabled?: boolean;
  /** This server keeps settings for it. */
  adopted: boolean;
  /** Calls may reach it (allowlist). */
  allowed: boolean;
  /** Settings with this realm's id are kept under that older name. */
  renamedFrom?: string;
}

export interface KeycloakRealms {
  system: string;
  url: string;
  authRealm: string;
  clientId?: string;
  /** The system has an allowlist. */
  restricted: boolean;
  count: number;
  realms: KeycloakRealm[];
  /** Known here but not listed by Keycloak: deleted, renamed or out of the account's sight. */
  notListed: { name: string; settings: boolean; allowed: boolean; realmId?: string }[];
}

/** Keycloak's realms for the system's service account (GET /bff/api/systems/{alias}/keycloak-realms). */
export const getKeycloakRealms = (alias: string): Promise<KeycloakRealms> =>
  call<KeycloakRealms>(`/api/systems/${encodeURIComponent(alias)}/keycloak-realms`);

export interface AdoptionRequest {
  realms?: string[];
  /** Every listed realm, and the allowlist cleared so later realms are reachable too. */
  allRealms?: boolean;
  /**
   * On a system without an allowlist: restrict it to the selected and the already adopted
   * realms. Without it such a system keeps reaching every realm.
   */
  restrict?: boolean;
  /** Preset of newly adopted realms. */
  preset?: string;
}

export interface AdoptionResult {
  system: string;
  adopted: string[];
  updated: string[];
  unchanged: string[];
  restricted: boolean;
  allowedRealms: string[];
  /** Listed realms the system reached before and no longer does. */
  unreachable: string[];
}

/** Register realms Keycloak lists (POST /bff/api/systems/{alias}/adoption). */
export const adoptRealms = (alias: string, body: AdoptionRequest): Promise<AdoptionResult> =>
  call<AdoptionResult>(`/api/systems/${encodeURIComponent(alias)}/adoption`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

export interface UnadoptionResult {
  system: string;
  realm: string;
  settingsRemoved: boolean;
  restricted: boolean;
  allowedRealms: string[];
}

/** Give up an adopted realm (DELETE /bff/api/systems/{alias}/adoption/{realm}). */
export const unadoptRealm = (alias: string, realm: string, restrict: boolean): Promise<UnadoptionResult> =>
  call<UnadoptionResult>(
    `/api/systems/${encodeURIComponent(alias)}/adoption/${encodeURIComponent(realm)}${restrict ? '?restrict=true' : ''}`,
    { method: 'DELETE' },
  );

/** One tool call of the audit trail (GET /bff/api/audit). */
export interface AuditEvent {
  id: number;
  /** ISO-8601 instant. */
  at: string;
  tool: string;
  level: 'READ' | 'WRITE' | 'DESTRUCTIVE';
  system?: string | null;
  realm?: string | null;
  /** `ok` or the error code. */
  outcome: string;
  message?: string | null;
  /** The OpenTelemetry trace and span the call ran in; null when tracing was off. */
  traceId?: string | null;
  spanId?: string | null;
  /** Whether arguments were recorded; the list does not carry them. */
  hasArgs: boolean;
  /** The arguments, secrets replaced by `***`: only on one event fetched with {@link getAuditEvent}. */
  args?: Record<string, unknown> | string;
  via?: string | null;
  caller: { subject?: string | null; name?: string | null; realm?: string | null; delegated: boolean };
  client?: string | null;
  connectionId?: string | null;
  durationMs: number;
}

export interface AuditPage {
  events: AuditEvent[];
  /** Cursor of the next page; null on the last. */
  next: string | null;
  /** How many events the filter matches on all pages together. */
  total: number;
}

/** Filters of GET /bff/api/audit; unset or empty ones are left out. */
export interface AuditFilter {
  subject?: string;
  caller?: string;
  system?: string;
  realm?: string;
  tool?: string;
  level?: string;
  /** `ok`, `error` or one error code. */
  outcome?: string;
  /** `only`: calls without a caller; `exclude`: calls with one. */
  anonymous?: string;
  /** `when` (default), `took` or `caller`, with `order` `desc` (default) or `asc`. */
  sort?: string;
  order?: string;
  /** ISO-8601 instants; `to` is exclusive. */
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

/** One page of the audit trail, newest first (GET /bff/api/audit). */
export const searchAudit = (filter: AuditFilter = {}): Promise<AuditPage> => {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value !== undefined && value !== null && `${value}`.trim() !== '') {
      params.set(key, `${value}`.trim());
    }
  }
  const query = params.toString();
  return call<AuditPage>(`/api/audit${query ? `?${query}` : ''}`);
};

/** One event with its arguments (GET /bff/api/audit/{id}). */
export const getAuditEvent = (id: number): Promise<AuditEvent> => call<AuditEvent>(`/api/audit/${id}`);

/** Fields of the audit trail with completions. */
export type AuditValueField = 'caller' | 'system' | 'realm' | 'tool';

/** Recorded values of a field that contain a text, at most 20 (GET /bff/api/audit/values/{field}). */
export const auditValues = async (field: AuditValueField, containing: string): Promise<string[]> => {
  const query = containing.trim() ? `?containing=${encodeURIComponent(containing.trim())}` : '';
  return (await call<{ values: string[] }>(`/api/audit/values/${field}${query}`)).values;
};

/** Full-page navigations: the code flow and the RP-initiated logout are redirects, not fetches. */
export const login = (idp: Idp): void => {
  window.location.assign(idp.loginPath);
};
export const logout = (me: Me): void => {
  window.location.assign(me.logoutPath);
};
