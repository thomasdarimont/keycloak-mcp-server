package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;

/**
 * Which tools must name their target instead of relying on the default system and default
 * realm ({@code kc-mcp.tools.explicit-target}): a model that omits the arguments then
 * gets {@code system_required} / {@code realm_required} rather than the default. A
 * system-specific MCP endpoint ({@code /mcp/<system>[/<realm>]}) counts as explicit.
 */
public enum ExplicitTarget {
    /** Defaults always fill in. Default of profile {@code local}. */
    OFF,
    /** DESTRUCTIVE tools name system and realm. Default of profile {@code shared}. */
    DESTRUCTIVE,
    /** WRITE and DESTRUCTIVE tools name system and realm. */
    WRITE;

    /** Whether a tool of that level has to name its target. */
    public boolean appliesTo(ToolLevel level) {
        return switch (this) {
            case OFF -> false;
            case DESTRUCTIVE -> level == ToolLevel.DESTRUCTIVE;
            case WRITE -> level.isWrite();
        };
    }

    public static ExplicitTarget parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "OFF", "NONE", "FALSE" -> OFF;
            case "DESTRUCTIVE" -> DESTRUCTIVE;
            case "WRITE", "WRITES", "MUTATIONS" -> WRITE;
            default -> throw new IllegalArgumentException(
                    "Unknown explicit-target '" + value + "', expected off, destructive or write");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<ExplicitTarget> {
        @Override
        public ExplicitTarget convert(String value) {
            return parse(value);
        }
    }
}
