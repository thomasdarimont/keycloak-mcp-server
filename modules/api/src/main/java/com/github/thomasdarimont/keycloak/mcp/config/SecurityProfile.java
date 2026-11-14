package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Security profile ({@code kc-mcp.security-profile}): the set of security defaults the
 * server starts with. The individual settings can still be set; the profile decides what
 * they mean when they are not, and {@link #SHARED} refuses to start without the settings
 * a network-reachable server needs. What an instance serves is a separate matter
 * ({@link InstanceRole}): the instances of a split deployment share one profile and
 * differ in their role.
 */
public enum SecurityProfile {
    /**
     * One person's own machine, the default: anonymous MCP endpoint behind DNS rebinding
     * protection, {@code confirm: true} accepted from clients without elicitation,
     * defaults fill in system and realm, outbound hosts unrestricted, encryption of the
     * database storage optional (warned).
     */
    LOCAL,
    /**
     * A server other people reach over the network: callers of the MCP endpoint must
     * authenticate ({@code quarkus.oidc.tenant-enabled=true} and a
     * {@code quarkus.oidc.token.audience} are required; not checked on an instance
     * without the MCP endpoint, {@link InstanceRole#ADMIN}), destructive tools are
     * confirmed through elicitation only ({@code confirm-fallback=deny}), destructive
     * tools name their system and realm ({@code explicit-target=destructive}),
     * {@code kc-mcp.allowed-hosts} is required, the admin API's issuer needs an audience,
     * the database storage needs a {@code secret-key}, and changes are refused while the
     * audit trail cannot be written ({@code audit-on-failure=refuse-changes}).
     */
    SHARED;

    public boolean shared() {
        return this == SHARED;
    }

    public static SecurityProfile parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "LOCAL", "DEV", "DEVELOPMENT" -> LOCAL;
            case "SHARED", "PROD", "PRODUCTION", "ENTERPRISE" -> SHARED;
            default -> throw new IllegalArgumentException("Unknown profile '" + value + "', expected local or shared");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<SecurityProfile> {
        @Override
        public SecurityProfile convert(String value) {
            return parse(value);
        }
    }
}
