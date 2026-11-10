/** Path helpers and nav items for the management UI (`@lit-labs/router` owns matching). */

export type NavRoute = {
  path: string;
  label: string;
};

/** Quarkus mount point for the SPA (`UiRoutes`). */
export const UI_BASE = '/ui';

/** Default landing path when signed in (Systems is the primary section). */
export const DEFAULT_PATH = `${UI_BASE}/systems`;

export const routes: NavRoute[] = [
  { path: `${UI_BASE}/systems`, label: 'Systems' },
  { path: `${UI_BASE}/secrets`, label: 'Secrets' },
  { path: `${UI_BASE}/storage`, label: 'Storage' },
];

export function systemsHref(): string {
  return `${UI_BASE}/systems`;
}

export function newSystemHref(): string {
  return `${UI_BASE}/systems/new`;
}

export function systemHref(alias: string): string {
  return `${UI_BASE}/systems/${encodeURIComponent(alias)}`;
}

/** Highlight Systems in the sidebar for both list and detail routes. */
export function navPath(pathname = location.pathname): string {
  if (pathname === UI_BASE || pathname === `${UI_BASE}/`) {
    return DEFAULT_PATH;
  }
  if (pathname.startsWith(`${UI_BASE}/systems/`)) {
    return `${UI_BASE}/systems`;
  }
  return pathname;
}

/** Ensure `/ui` and `/ui/` land on Systems before the router matches. */
export function ensureDefaultPath(): void {
  if (location.pathname === UI_BASE || location.pathname === `${UI_BASE}/`) {
    history.replaceState({}, '', DEFAULT_PATH + location.search);
  }
}
