package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/** The extension point {@code test-point} of the tests: {@link TestPoint}. */
public final class TestPointSpi implements Spi {

    public static final String NAME = "test-point";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return TestPoint.class;
    }

    @Override
    public boolean singleProvider() {
        return true;
    }
}
