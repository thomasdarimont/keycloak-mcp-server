package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.List;
import java.util.Locale;

/**
 * What happens to the tools an allow-list does not name: {@code kc-mcp.tools.unlisted} on
 * the server, {@code tools.unlisted} for a system, realm or preset. Without it, the old
 * rule: {@link #ALLOW} without an allow-list, {@link #DENY} with one.
 */
public enum UnlistedTools {
    /** Available, as if listed. */
    ALLOW,
    /**
     * Available if they only read: new read tools appear by themselves, new write and
     * destructive tools wait until someone lists them.
     */
    READ,
    /** Not available: only what is listed. */
    DENY;

    /** The setting's effective value: as set, else what the allow-list implies. */
    public static UnlistedTools effective(java.util.Optional<UnlistedTools> set, List<String> allowed) {
        return set.orElse(allowed == null || allowed.isEmpty() ? ALLOW : DENY);
    }

    /**
     * Whether an unlisted tool is available.
     *
     * @param readOnly whether the tool only reads
     */
    public boolean admits(boolean readOnly) {
        return this == ALLOW || (this == READ && readOnly);
    }

    public static UnlistedTools parse(String value) {
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "allow" -> ALLOW;
            case "read", "read-only" -> READ;
            case "deny" -> DENY;
            default -> throw new IllegalArgumentException(
                    "Unknown value '" + value + "' for unlisted tools, expected allow, read or deny");
        };
    }

    public String id() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<UnlistedTools> {
        @Override
        public UnlistedTools convert(String value) {
            return parse(value);
        }
    }
}
