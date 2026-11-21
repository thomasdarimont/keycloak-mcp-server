package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * Controls what {@code tools/list} returns.
 */
public enum ExposureMode {
    /**
     * Every catalog tool is listed; meta-tools hidden. Parity with the reference
     * implementation.
     */
    DIRECT,
    /** Only {@code search_tools} and {@code execute_tool}. Minimum context. */
    LAZY,
    /** Meta-tools plus the configured hot tools. Default. */
    HYBRID,
    /**
     * Hybrid plus whatever the last {@code search_tools} call surfaced, per connection.
     */
    PROGRESSIVE;

    public static ExposureMode parse(String value) {
        return valueOf(value.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<ExposureMode> {
        @Override
        public ExposureMode convert(String value) {
            return parse(value);
        }
    }
}
