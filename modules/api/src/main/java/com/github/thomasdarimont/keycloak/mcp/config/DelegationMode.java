package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Whose credentials reach the Keycloak Admin API. There is no mode that sends the
 * caller's own token there: the MCP authorization specification forbids passing the token
 * received from the MCP client through to an upstream API. The token used at Keycloak is
 * always one Keycloak issued to this server as its client.
 */
public enum DelegationMode {
    /** The server's own service account / admin user. Default. */
    OFF,
    /**
     * The caller's access token is exchanged for a delegated token (RFC 8693 delegation,
     * Keycloak 26.8 feature {@code token-exchange-delegation}): the server's own client
     * is the actor, the caller the subject. The caller must have consented to the scope
     * {@code delegation:client:<client id>} at login and Keycloak must grant the client
     * the {@code delegate} permission (Admin Permissions). The delegated token carries
     * the caller's roles within the client's scope, the {@code act} claim names the
     * client, and Keycloak's audit shows both. Needs
     * {@code quarkus.oidc.tenant-enabled=true} and a confidential client with service
     * account ({@code client_credentials}).
     */
    EXCHANGE;

    public static DelegationMode parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "OFF", "NONE", "SERVICE_ACCOUNT" -> OFF;
            case "FORWARD" -> throw new IllegalArgumentException("Delegation mode 'forward' was removed: the MCP"
                    + " specification forbids passing the caller's token through to the Admin API. Use 'exchange'"
                    + " (the caller's token is exchanged for a delegated one, see docs/security.md) or 'off'.");
            case "EXCHANGE", "TOKEN_EXCHANGE", "DELEGATION" -> EXCHANGE;
            default ->
                throw new IllegalArgumentException("Unknown delegation mode '" + value + "', expected off or exchange");
        };
    }

    /** The caller acts on their own behalf: {@link #EXCHANGE}. */
    public boolean delegating() {
        return this != OFF;
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<DelegationMode> {
        @Override
        public DelegationMode convert(String value) {
            return parse(value);
        }
    }
}
