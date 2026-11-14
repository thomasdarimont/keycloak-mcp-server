package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * What the server does with tools that change Keycloak while the audit trail cannot be
 * written ({@code kc-mcp.audit-on-failure}): a listener that keeps the trail (the
 * database listener, or an extension that says so) failed its last delivery and has not
 * recovered yet. Reading tools run either way.
 */
public enum AuditOnFailure {
    /**
     * Changes run; their audit line still reaches the log, their row does not. Default of
     * profile {@code local}.
     */
    ALLOW,
    /**
     * WRITE and DESTRUCTIVE tools answer {@code audit_unavailable} until the trail can be
     * written again. The first change after the trail fails still runs, as nothing has
     * failed before it. Default of profile {@code shared}.
     */
    REFUSE_CHANGES;

    public boolean refusesChanges() {
        return this == REFUSE_CHANGES;
    }

    public static AuditOnFailure parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "ALLOW" -> ALLOW;
            case "REFUSE_CHANGES", "REFUSE" -> REFUSE_CHANGES;
            default -> throw new IllegalArgumentException(
                    "Unknown audit-on-failure '" + value + "', expected allow or refuse-changes");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<AuditOnFailure> {
        @Override
        public AuditOnFailure convert(String value) {
            return parse(value);
        }
    }
}
