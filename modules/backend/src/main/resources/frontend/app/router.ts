/** Path helpers and nav items for the management UI (`@lit-labs/router` owns matching). */

export type NavRoute = {
  path: string;
  label: string;
  /** When set, the sidebar shows the item only if /bff/me lists this capability. */
  capability?: string;
};

export type SystemTab = 'settings' | 'realms' | 'adopt' | 'keys';

/** Quarkus mount point for the SPA (`UiRoutes`). */
export const UI_BASE = '/ui';

/** Default landing path when signed in. */
export const DEFAULT_PATH = `${UI_BASE}/overview`;

export const routes: NavRoute[] = [
  { path: `${UI_BASE}/overview`, label: 'Overview' },
  { path: `${UI_BASE}/systems`, label: 'Systems', capability: 'systems:read' },
  { path: `${UI_BASE}/secrets`, label: 'Secrets', capability: 'secrets:read' },
  { path: `${UI_BASE}/storage`, label: 'Storage', capability: 'storage:read' },
  { path: `${UI_BASE}/audit`, label: 'Audit', capability: 'audit:read' },
];

export function overviewHref(): string {
  return `${UI_BASE}/overview`;
}

export function auditHref(): string {
  return `${UI_BASE}/audit`;
}

export function systemsHref(): string {
  return `${UI_BASE}/systems`;
}

export function newSystemHref(): string {
  return `${UI_BASE}/systems/new`;
}

/** System detail; default tab is Settings (`/ui/systems/{alias}`). */
export function systemHref(alias: string, tab: SystemTab = 'settings'): string {
  const base = `${UI_BASE}/systems/${encodeURIComponent(alias)}`;
  return tab === 'settings' ? base : `${base}/${tab}`;
}

/** Realm settings page under a system. */
export function realmHref(alias: string, realm: string): string {
  return `${UI_BASE}/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`;
}

/** Highlight Systems in the sidebar for both list and detail routes. */
export function navPath(pathname = location.pathname): string {
  if (pathname === UI_BASE || pathname === `${UI_BASE}/` || pathname === `${UI_BASE}/home`) {
    return DEFAULT_PATH;
  }
  if (pathname.startsWith(`${UI_BASE}/systems/`)) {
    return `${UI_BASE}/systems`;
  }
  return pathname;
}

/** Ensure `/ui` and `/ui/` land on Overview before the router matches. */
export function ensureDefaultPath(): void {
  if (
    location.pathname === UI_BASE ||
    location.pathname === `${UI_BASE}/` ||
    location.pathname === `${UI_BASE}/home`
  ) {
    history.replaceState({}, '', DEFAULT_PATH + location.search);
  }
}

/**
 * In-app navigation that updates history and asks {@link KcMcpApp}'s router to
 * `goto` the path, for code that navigates after a save or delete; links are
 * plain `<a href>`, which the router intercepts. (A page left mounted above the
 * next one comes from a component overriding a DOM member such as `remove()`,
 * not from the navigation: see docs/development.md.)
 */
export function navigate(path: string, replace = false): void {
  if (replace) {
    history.replaceState({}, '', path);
  } else {
    history.pushState({}, '', path);
  }
  window.dispatchEvent(new CustomEvent('kc-mcp-goto', { detail: { path } }));
}
