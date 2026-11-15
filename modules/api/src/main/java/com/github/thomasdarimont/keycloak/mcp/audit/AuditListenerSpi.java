package com.github.thomasdarimont.keycloak.mcp.audit;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code audit-listener}: {@link AuditListener}, configured under
 * {@code kc-mcp.spi.audit-listener.<id>.*}.
 */
public final class AuditListenerSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "audit-listener";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return AuditListener.class;
    }
}
