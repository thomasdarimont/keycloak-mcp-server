package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.List;
import java.util.Optional;

import org.eclipse.microprofile.config.ConfigProvider;

/**
 * The realm the default OIDC tenant verifies callers against; see
 * {@link DefaultTenantInterceptorFactory}.
 */
public final class DefaultTenant {

    private DefaultTenant() {
    }

    /**
     * {@code kc-mcp.mcp.oauth.issuer}, configured or derived from the default Keycloak
     * system; {@code http://localhost:8080/realms/master} when there is no system at all.
     */
    public static String authServerUrl() {
        return ConfigProvider.getConfig()
            .getOptionalValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL, String.class)
            .filter(v -> !v.isBlank())
            .orElse("http://localhost:8080/realms/master");
    }

    /**
     * Why the default OIDC tenant has nothing to verify callers against, if so: callers
     * are authenticated, {@code kc-mcp.mcp.oauth.issuer} is neither set nor derived, and
     * several static systems leave the default open. Quarkus would disable the tenant
     * without a word and refuse every caller of {@code /mcp}. A deployment whose systems
     * all come from repositories has no static system to derive from and binds callers
     * per entry instead, so it is left alone.
     * @param staticSystems the names of the configured static systems
     */
    public static Optional<String> problem(boolean oidcEnabled, boolean authServerUrlSet, List<String> staticSystems) {
        if (!oidcEnabled || authServerUrlSet || staticSystems.size() < 2) {
            return Optional.empty();
        }
        return Optional.of("Several Keycloak systems " + staticSystems + " and none is the default, so the MCP"
                + " endpoint has no realm to verify callers against: set kc-mcp.default-system (env"
                + " KC_MCP_DEFAULT_SYSTEM) to one of them, or kc-mcp.mcp.oauth.issuer to the realm that issues"
                + " the caller tokens");
    }
}
