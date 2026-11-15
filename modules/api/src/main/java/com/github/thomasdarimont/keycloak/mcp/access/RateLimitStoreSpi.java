package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code rate-limit-store}: {@link RateLimitStore}, configured under
 * {@code kc-mcp.spi.rate-limit-store.<id>.*}.
 */
public final class RateLimitStoreSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "rate-limit-store";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return RateLimitStore.class;
    }

    @Override
    public boolean singleProvider() {
        return true;
    }
}
