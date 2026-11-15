package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code authorization-engine}: {@link AuthorizationEngine},
 * configured under {@code kc-mcp.spi.authorization-engine.<id>.*}.
 */
public final class AuthorizationEngineSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "authorization-engine";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return AuthorizationEngine.class;
    }
}
