package com.github.thomasdarimont.keycloak.mcp.state;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code state-store}: {@link StateStore}, configured under
 * {@code kc-mcp.spi.state-store.<id>.*}.
 */
public final class StateStoreSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "state-store";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return StateStore.class;
    }

    @Override
    public boolean singleProvider() {
        return true;
    }
}
