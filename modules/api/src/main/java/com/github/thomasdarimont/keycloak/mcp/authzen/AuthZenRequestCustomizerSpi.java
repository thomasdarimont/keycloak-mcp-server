package com.github.thomasdarimont.keycloak.mcp.authzen;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code authzen-customizer}: {@link AuthZenRequestCustomizer},
 * configured under {@code kc-mcp.spi.authzen-customizer.<id>.*}.
 */
public final class AuthZenRequestCustomizerSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "authzen-customizer";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return AuthZenRequestCustomizer.class;
    }
}
