package com.github.thomasdarimont.keycloak.mcp.keycloak;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code key-generator}: {@link SigningKeyGenerator}, configured
 * under {@code kc-mcp.spi.key-generator.<id>.*}.
 */
public final class SigningKeyGeneratorSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "key-generator";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return SigningKeyGenerator.class;
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
