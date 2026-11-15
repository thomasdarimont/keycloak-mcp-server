package com.github.thomasdarimont.keycloak.mcp.config;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code profile-check}: {@link ProfileCheck}, configured under
 * {@code kc-mcp.spi.profile-check.<id>.*}.
 */
public final class ProfileCheckSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "profile-check";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return ProfileCheck.class;
    }
}
