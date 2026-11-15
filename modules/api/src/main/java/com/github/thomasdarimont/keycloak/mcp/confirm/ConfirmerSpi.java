package com.github.thomasdarimont.keycloak.mcp.confirm;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code confirmer}: {@link Confirmer}, configured under
 * {@code kc-mcp.spi.confirmer.<id>.*}.
 */
public final class ConfirmerSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "confirmer";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return Confirmer.class;
    }
}
