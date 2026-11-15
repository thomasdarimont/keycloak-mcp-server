package com.github.thomasdarimont.keycloak.mcp.web;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code session-store}: {@link UserSessionStore}, configured under
 * {@code kc-mcp.spi.session-store.<id>.*}.
 */
public final class UserSessionStoreSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "session-store";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return UserSessionStore.class;
    }

    @Override
    public boolean singleProvider() {
        return true;
    }

    @Override
    public boolean resolvedByRegistry() {
        return false;
    }
}
