package com.github.thomasdarimont.keycloak.mcp.keycloak;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code system-repository}: {@link KeycloakSystemRepository},
 * configured under {@code kc-mcp.spi.system-repository.<id>.*}.
 */
public final class KeycloakSystemRepositorySpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "system-repository";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return KeycloakSystemRepository.class;
    }

    @Override
    public boolean resolvedByRegistry() {
        return false;
    }
}
