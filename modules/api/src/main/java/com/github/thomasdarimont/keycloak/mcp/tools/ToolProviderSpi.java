package com.github.thomasdarimont.keycloak.mcp.tools;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code tools}: {@link ToolProvider}, configured under
 * {@code kc-mcp.spi.tools.<id>.*}.
 */
public final class ToolProviderSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "tools";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return ToolProvider.class;
    }

    @Override
    public boolean resolvedByRegistry() {
        return false;
    }
}
