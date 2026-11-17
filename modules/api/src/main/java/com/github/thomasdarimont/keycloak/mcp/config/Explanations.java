package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * For whom the explanations are written when a tool cannot run on this Keycloak server
 * ({@code kc-mcp.explanations}): decides how much server configuration detail a refusal
 * carries. Not related to the OAuth token audience.
 */
public enum Explanations {
    /**
     * People who run Keycloak: the message names the feature or version and the result
     * carries {@code howToFix} with the exact configuration per deployment form. Default
     * when nothing is known about the caller.
     */
    ADMINS,
    /**
     * Support staff and other users: the message says that this is not available on this
     * server and that a Keycloak administrator can change it, without configuration
     * details.
     */
    USERS,
    /**
     * {@link #USERS} for callers acting on their own behalf (delegation {@code exchange})
     * whose token holds neither the master admin nor a {@code realm-admin} role,
     * {@link #ADMINS} otherwise.
     */
    AUTO;

    public static Explanations parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "ADMIN", "ADMINS", "TECHNICAL" -> ADMINS;
            case "USER", "USERS", "SUPPORT", "PLAIN" -> USERS;
            case "AUTO" -> AUTO;
            default -> throw new IllegalArgumentException(
                    "Unknown explanations '" + value + "', expected admins, users or auto");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<Explanations> {
        @Override
        public Explanations convert(String value) {
            return parse(value);
        }
    }
}
