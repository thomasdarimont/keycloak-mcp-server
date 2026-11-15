package com.github.thomasdarimont.keycloak.mcp.audit;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code audit-scrubber}: {@link AuditScrubber}, configured under
 * {@code kc-mcp.spi.audit-scrubber.<id>.*}.
 */
public final class AuditScrubberSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "audit-scrubber";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return AuditScrubber.class;
    }
}
