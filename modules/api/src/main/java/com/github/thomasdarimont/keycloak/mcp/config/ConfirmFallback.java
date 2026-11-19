package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * What confirms a DESTRUCTIVE tool when the MCP client does not support elicitation
 * ({@code kc-mcp.confirm.fallback}). With elicitation the human is always asked.
 */
public enum ConfirmFallback {
    /**
     * The {@code confirm: true} argument counts as the confirmation. Convenient on one's
     * own machine, but the argument is written by the model, so it is a UX hint, not an
     * authorization. Default of profile {@code local}.
     */
    FLAG,
    /**
     * Destructive tools are refused ({@code confirmation_required}) until the client
     * supports elicitation or another {@code Confirmer} decides; {@code confirm: true} is
     * ignored and the argument is not offered. Default of profile {@code shared}.
     */
    DENY;

    public boolean acceptsFlag() {
        return this == FLAG;
    }

    public static ConfirmFallback parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "FLAG", "ARGUMENT", "ALLOW" -> FLAG;
            case "DENY", "REFUSE", "ELICITATION_ONLY" -> DENY;
            default ->
                throw new IllegalArgumentException("Unknown confirm-fallback '" + value + "', expected flag or deny");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<ConfirmFallback> {
        @Override
        public ConfirmFallback convert(String value) {
            return parse(value);
        }
    }
}
