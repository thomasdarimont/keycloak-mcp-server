package com.github.thomasdarimont.keycloak.mcp.confirm;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code approval-store}: {@link PendingApprovalStore}, configured
 * under {@code kc-mcp.spi.approval-store.<id>.*}.
 */
public final class PendingApprovalStoreSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "approval-store";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return PendingApprovalStore.class;
    }

    @Override
    public boolean singleProvider() {
        return true;
    }
}
