package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code access-check}: {@link AccessCheck}, configured under
 * {@code kc-mcp.spi.access-check.<id>.*}.
 */
public final class AccessCheckSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "access-check";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return AccessCheck.class;
    }
}
