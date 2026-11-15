package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Decides whether a caller's token, issued by one Keycloak, may be used at a system:
 * forwarded to it in delegation mode {@code forward}, or handed to its token endpoint in
 * mode {@code exchange}. The built-in policy allows the system's own Keycloak (its URL or
 * its public issuer, every realm of it) and the issuers listed in
 * {@code kc-mcp.systems.<name>.trusted-issuers}, where an entry naming a realm means that
 * realm's issuer alone and an entry naming only the Keycloak means all of its realms, and
 * denies everything else, so a token never crosses into a trust domain that did not issue
 * it. Register your own ({@code @AutoService(CallerIssuerPolicy.class)} or a CDI bean) to
 * decide from a federation directory or a tenant registry: custom policies run first,
 * lowest {@link #order()} first, the chain stops at the first decision that is not
 * {@link Decision#ABSTAIN}, and the built-in one runs last and never abstains.
 * <p>
 * A policy decides what this server may send, nothing more: allowing a foreign issuer
 * does not make the target Keycloak accept its tokens. That is configured in Keycloak,
 * through an identity provider with the JWT authorization grant (RFC 7523, Keycloak 26.5
 * preview), where a client presents the external token as {@code assertion} and gets a
 * local token, the standard replacement for the external-to-internal token exchange. The
 * server does not perform that grant yet; in mode {@code forward} an allowed foreign
 * token is sent as it is and refused by Keycloak unless it is configured to take it.
 */
public interface CallerIssuerPolicy extends Extension {

    enum Decision {
        ALLOW, DENY, ABSTAIN
    }

    /**
     * @param issuer the {@code iss} of the caller's token, e.g.
     * {@code https://sso.example.com/realms/demo}
     * @param system the Keycloak system the call targets
     */
    Decision decide(String issuer, KeycloakSystem system);
}
