import { createContext } from '@lit/context';
import { Cap, hasCapability, type Me } from './bff.js';

/** Session provided by {@link KcMcpSession} for the shell and pages. */
export type SessionState = {
  me: Me | null;
  lastCheck: { at: Date; ok: boolean } | null;
  /** Set when `/bff/me` or the session check failed. */
  error: string | null;
  /** IdP alias from `?idp=` / last login, for the sign-in buttons. */
  suggestedIdp?: string;
};

export const sessionContext = createContext<SessionState>('kc-mcp-session');

/** What a page tells someone who may read but not change: the role they lack, as the server names it. */
export function operatorRoleHint(session: SessionState | undefined, action: string): string {
  const role = session?.me?.adminRole;
  return `${action} needs the operator role${role ? ` ${role}` : ''}, which your account does not have.`;
}

export function sessionCanWrite(session: SessionState | undefined): boolean {
  return hasCapability(session?.me, Cap.systemsWrite);
}
