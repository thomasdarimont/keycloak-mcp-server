package com.github.thomasdarimont.keycloak.mcp.keycloak;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code key-vault}: {@link KeyVault}, configured under
 * {@code kc-mcp.spi.key-vault.<id>.*}.
 */
public final class KeyVaultSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "key-vault";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return KeyVault.class;
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
