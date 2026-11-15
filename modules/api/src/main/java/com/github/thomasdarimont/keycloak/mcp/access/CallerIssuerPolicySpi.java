package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code issuer-policy}: {@link CallerIssuerPolicy}, configured under
 * {@code kc-mcp.spi.issuer-policy.<id>.*}.
 */
public final class CallerIssuerPolicySpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "issuer-policy";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return CallerIssuerPolicy.class;
    }

    @Override
    public boolean resolvedByRegistry() {
        return false;
    }
}
