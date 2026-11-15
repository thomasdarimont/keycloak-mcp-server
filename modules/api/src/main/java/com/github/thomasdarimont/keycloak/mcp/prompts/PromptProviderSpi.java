package com.github.thomasdarimont.keycloak.mcp.prompts;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The extension point {@code prompts}: {@link PromptProvider}, configured under
 * {@code kc-mcp.spi.prompts.<id>.*}.
 */
public final class PromptProviderSpi implements Spi {

    /** This extension point's name in configuration keys. */
    public static final String NAME = "prompts";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Class<? extends Extension> extensionType() {
        return PromptProvider.class;
    }
}
