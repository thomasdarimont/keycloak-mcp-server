package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;

import io.quarkiverse.mcp.server.FeatureManager.FeatureArguments;

/**
 * Resolves the {@link Caller} for the current tool invocation. The default implementation
 * reads the Quarkus {@code SecurityIdentity} of the MCP request (populated when the
 * endpoint is protected with OIDC).
 */
public interface CallerProvider {

    Caller current(FeatureArguments args);

    /**
     * The caller's raw access token, exchanged for a delegated one in delegation mode
     * {@code exchange}; {@code null} when the caller is anonymous or the provider has no
     * token.
     */
    default String accessToken(FeatureArguments args) {
        return null;
    }
}
